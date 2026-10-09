"""HTTP security boundary for independent applications. Never calls an LLM."""
import time
import uuid

from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import CanScan
from apps.auditlog.models import RequestLog, Direction
from apps.auditlog.services import prompt_hash
from apps.firewall.ratelimit import check_and_consume, register_attack
from apps.firewall.services import build_engine
from firewall_core.engine import Action
from firewall_core.scoring import RiskLevel
from firewall_core.output_scan import OutputScanner


class Turn(serializers.Serializer):
    role = serializers.ChoiceField(choices=['user', 'assistant'])
    content = serializers.CharField(max_length=16000, trim_whitespace=False)


class Input(serializers.Serializer):
    message = serializers.CharField(max_length=16000, trim_whitespace=False)
    history = Turn(many=True, required=False, default=list)
    protected_text = serializers.CharField(max_length=4000)

    def validate_history(self, value):
        if len(value) > 40 or sum(len(t['content']) for t in value) > 64000:
            raise serializers.ValidationError('History too long.')
        return value


class Output(serializers.Serializer):
    text = serializers.CharField(max_length=64000, trim_whitespace=False)
    protected_text = serializers.CharField(max_length=4000)


class Boundary(APIView):
    permission_classes = [CanScan]

    def record(self, request, direction, action, score, text='', categories=None, rules=None):
        rid = uuid.uuid4().hex
        RequestLog.objects.create(request_id=rid, user=request.user,
            direction=direction, ip_address=request.META.get('REMOTE_ADDR'),
            action=action, risk_score=score, prompt_hash=prompt_hash(text) if text else '',
            detected_attacks=categories or [], matched_rules=rules or [])
        return rid


class GatewayInputView(Boundary):
    def post(self, request):
        serializer = Input(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        identity = f'gateway:{request.user.pk}'
        rate = check_and_consume(identity)
        if not rate.allowed:
            return Response({'detail': rate.reason}, status=429)
        engine = build_engine(local_only=True, enforce_security=True)
        history = data['history']
        result = engine.inspect_request(data['message'], conversation=[t['content'] for t in history])
        blocked = result.action == Action.block or result.risk.level in (RiskLevel.high, RiskLevel.critical)
        for turn in history:
            prior = engine.inspect_request(turn['content'])
            blocked |= prior.action not in (Action.allow, Action.warn) or prior.risk.level not in (RiskLevel.safe, RiskLevel.low)
            if turn['role'] == 'assistant':
                blocked |= engine.inspect_response(turn['content'], protected_texts=[data['protected_text']]).action != Action.allow
        safe = data['message']
        if not blocked and result.action == Action.sanitize:
            safe = result.sanitized_text or ''
            recheck = engine.inspect_request(safe, conversation=[t['content'] for t in history])
            blocked |= not safe.strip() or recheck.action not in (Action.allow, Action.warn) or recheck.risk.level not in (RiskLevel.safe, RiskLevel.low)
        if blocked:
            register_attack(identity)
        action = 'block' if blocked else result.action.value
        rid = self.record(request, Direction.REQUEST, action, result.risk.score, data['message'],
                          sorted({m.category for m in result.rule_matches}), [m.rule_id for m in result.rule_matches])
        return Response({'approved': not blocked, 'action': action, 'risk': result.risk.level.value,
            'score': result.risk.score, 'request_id': rid,
            'text': safe if not blocked else '',
            'stored_text': OutputScanner().scan(safe).masked_text if not blocked else ''}, status=403 if blocked else 200)


class GatewayOutputView(Boundary):
    def post(self, request):
        serializer = Output(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        engine = build_engine(local_only=True, enforce_security=True)
        result = engine.inspect_response(data['text'], protected_texts=[data['protected_text']])
        safe = result.scan.masked_text
        blocked = result.action == Action.block
        if not blocked and result.action == Action.sanitize:
            blocked = engine.inspect_response(safe, protected_texts=[data['protected_text']]).action != Action.allow
        action = 'block' if blocked else result.action.value
        rid = self.record(request, Direction.RESPONSE, action, result.scan.score,
                          categories=[f.label for f in result.scan.findings])
        return Response({'approved': not blocked, 'action': action, 'score': result.scan.score,
            'request_id': rid, 'text': safe if not blocked else ''}, status=403 if blocked else 200)
