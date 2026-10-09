from __future__ import annotations

import time
import uuid

from django.db.models import Avg, Count
from django.db.models.functions import TruncDate
from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import CanManageRules, CanScan, CanViewLogs
from apps.api.serializers import (
    BatchScanSerializer,
    FirewallConfigSerializer,
    PromptScanSerializer,
    RequestLogSerializer,
    ResponseScanSerializer,
    RuleSerializer,
)
from apps.auditlog import services as audit
from apps.auditlog.models import RequestLog, verify_chain
from apps.firewall.models import FirewallConfig, Rule
from apps.firewall.ratelimit import check_and_consume, register_attack
from apps.firewall.services import active_rule_count, build_engine, bump_engine_version
from firewall_core.scoring import RiskLevel


def _identity(request) -> str:
    if request.user and request.user.is_authenticated:
        return f"user:{request.user.id}"
    return f"ip:{audit.client_ip(request)}"


class HealthView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(summary="Health + firewall status")
    def get(self, request):
        return Response({
            "status": "ok",
            "rules": active_rule_count(),
            "ai_enabled": FirewallConfig.load().use_ai,
            "log_chain": verify_chain()["ok"],
        })


class PromptScanView(APIView):
    permission_classes = [CanScan]

    @extend_schema(request=PromptScanSerializer, summary="Inspect a prompt before it reaches an LLM")
    def post(self, request):
        s = PromptScanSerializer(data=request.data)
        s.is_valid(raise_exception=True)

        identity = _identity(request)
        decision = check_and_consume(identity)
        if not decision.allowed:
            return Response(
                {"detail": decision.reason, "retry_after": decision.retry_after},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(decision.retry_after)},
            )

        engine = build_engine()
        started = time.perf_counter()
        result = engine.inspect_request(
            s.validated_data["prompt"],
            conversation=s.validated_data.get("conversation") or None,
        )
        elapsed = (time.perf_counter() - started) * 1000
        request_id = uuid.uuid4().hex

        if result.risk.level in (RiskLevel.high, RiskLevel.critical):
            register_attack(identity)

        audit.record_request(
            request=request, request_id=request_id, inspection=result,
            response_time_ms=elapsed, raw_text=s.validated_data["prompt"],
            model_used=s.validated_data.get("model", ""),
        )

        payload = result.as_dict()
        payload["request_id"] = request_id
        payload["response_time_ms"] = round(elapsed, 2)
        return Response(payload)


class ResponseScanView(APIView):
    permission_classes = [CanScan]

    @extend_schema(request=ResponseScanSerializer, summary="Scan an LLM response before returning it")
    def post(self, request):
        s = ResponseScanSerializer(data=request.data)
        s.is_valid(raise_exception=True)

        engine = build_engine()
        started = time.perf_counter()
        result = engine.inspect_response(s.validated_data["response"], mask=s.validated_data["mask"])
        elapsed = (time.perf_counter() - started) * 1000
        request_id = uuid.uuid4().hex

        audit.record_response(
            request=request, request_id=request_id, output_result=result,
            response_time_ms=elapsed, model_used=s.validated_data.get("model", ""),
        )

        payload = result.as_dict()
        payload["request_id"] = request_id
        payload["response_time_ms"] = round(elapsed, 2)
        return Response(payload)


class BatchScanView(APIView):
    permission_classes = [CanScan]

    @extend_schema(request=BatchScanSerializer, summary="Inspect many prompts at once")
    def post(self, request):
        s = BatchScanSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        engine = build_engine()
        results = []
        for prompt in s.validated_data["prompts"]:
            r = engine.inspect_request(prompt)
            results.append({"prompt": prompt[:120], **r.as_dict()})
        return Response({"count": len(results), "results": results})


class RuleViewSet(viewsets.ModelViewSet):
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer
    permission_classes = [CanManageRules]

    def perform_create(self, serializer):
        serializer.save()
        bump_engine_version()

    def perform_update(self, serializer):
        serializer.save()
        bump_engine_version()

    def perform_destroy(self, instance):
        instance.delete()
        bump_engine_version()

    @extend_schema(summary="Export all rules as JSON")
    @action(detail=False, methods=["get"])
    def export(self, request):
        return Response(RuleSerializer(self.get_queryset(), many=True).data)

    @extend_schema(summary="Import a list of rules (upsert by rule_id)")
    @action(detail=False, methods=["post"])
    def import_rules(self, request):
        items = request.data if isinstance(request.data, list) else request.data.get("rules", [])
        created = updated = 0
        for item in items:
            rule_id = item.get("rule_id")
            if not rule_id:
                continue
            obj = Rule.objects.filter(rule_id=rule_id).first()
            ser = RuleSerializer(instance=obj, data=item, partial=bool(obj))
            ser.is_valid(raise_exception=True)
            ser.save()
            updated += int(bool(obj))
            created += int(not obj)
        bump_engine_version()
        return Response({"created": created, "updated": updated}, status=status.HTTP_200_OK)


class FirewallConfigView(APIView):
    permission_classes = [CanManageRules]

    @extend_schema(responses=FirewallConfigSerializer, summary="Read firewall configuration")
    def get(self, request):
        return Response(FirewallConfigSerializer(FirewallConfig.load()).data)

    @extend_schema(request=FirewallConfigSerializer, summary="Update firewall configuration")
    def patch(self, request):
        cfg = FirewallConfig.load()
        ser = FirewallConfigSerializer(cfg, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        bump_engine_version()
        return Response(ser.data)


class LogListView(ListAPIView):
    serializer_class = RequestLogSerializer
    permission_classes = [CanViewLogs]

    def get_queryset(self):
        qs = RequestLog.objects.all()
        params = self.request.query_params
        if action_f := params.get("action"):
            qs = qs.filter(action=action_f)
        if level := params.get("risk_level"):
            qs = qs.filter(risk_level=level)
        if ip := params.get("ip"):
            qs = qs.filter(ip_address=ip)
        if q := params.get("q"):
            qs = qs.filter(request_id__icontains=q)
        return qs


class AnalyticsView(APIView):
    permission_classes = [CanViewLogs]

    @extend_schema(summary="Aggregate analytics for the dashboard")
    def get(self, request):
        qs = RequestLog.objects.all()
        total = qs.count()
        by_action = dict(qs.values_list("action").annotate(n=Count("id")))
        by_level = dict(qs.values_list("risk_level").annotate(n=Count("id")))
        by_category: dict[str, int] = {}
        for attacks in qs.values_list("detected_attacks", flat=True):
            for cat in attacks or []:
                by_category[cat] = by_category.get(cat, 0) + 1
        timeline = list(
            qs.annotate(day=TruncDate("created_at"))
            .values("day").annotate(n=Count("id")).order_by("day")
        )
        top_ips = list(
            qs.exclude(ip_address__isnull=True)
            .values("ip_address").annotate(n=Count("id")).order_by("-n")[:10]
        )
        return Response({
            "total_requests": total,
            "by_action": by_action,
            "by_risk_level": by_level,
            "top_attack_categories": sorted(by_category.items(), key=lambda kv: -kv[1])[:10],
            "timeline": [{"day": str(t["day"]), "count": t["n"]} for t in timeline],
            "top_sources": top_ips,
            "avg_latency_ms": round(qs.aggregate(a=Avg("response_time_ms"))["a"] or 0.0, 2),
            "false_positives": qs.filter(marked_false_positive=True).count(),
            "false_negatives": qs.filter(marked_false_negative=True).count(),
        })
