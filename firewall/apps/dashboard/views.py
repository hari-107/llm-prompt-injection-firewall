from __future__ import annotations

import re
import time
import uuid

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.permissions import role_of
from apps.accounts.models import Role
from apps.auditlog import exports
from apps.auditlog.models import RequestLog, verify_chain
from apps.firewall.models import FirewallConfig, PolicyDraft, PolicyProfile, Rule
from apps.firewall.policy_import import PolicyImportError, activate_draft, create_draft
from apps.firewall.services import active_rule_count, build_engine, bump_engine_version


def _can_manage(request) -> bool:
    return role_of(request.user) in {Role.ADMIN, Role.ANALYST}


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:overview")
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password"),
        )
        if user is not None:
            login(request, user)
            return redirect("dashboard:overview")
        messages.error(request, "Invalid credentials.")
    return render(request, "dashboard/login.html")


def logout_view(request):
    logout(request)
    return redirect("dashboard:login")


@login_required
def overview(request):
    qs = RequestLog.objects.all()
    total = qs.count()
    ctx = {
        "total": total,
        "blocked": qs.filter(action="block").count(),
        "sanitized": qs.filter(action="sanitize").count(),
        "allowed": qs.filter(action="allow").count(),
        "warned": qs.filter(action="warn").count(),
        "avg_latency": round(qs.aggregate(a=Avg("response_time_ms"))["a"] or 0.0, 1),
        "rules_active": active_rule_count(),
        "recent": qs[:15],
        "chain_ok": verify_chain()["ok"],
        "active": "overview",
    }
    return render(request, "dashboard/overview.html", ctx)


@login_required
def logs(request):
    qs = RequestLog.objects.all()
    action_f = request.GET.get("action", "")
    level_f = request.GET.get("risk_level", "")
    q = request.GET.get("q", "")
    if action_f:
        qs = qs.filter(action=action_f)
    if level_f:
        qs = qs.filter(risk_level=level_f)
    if q:
        qs = qs.filter(request_id__icontains=q)

    fmt = request.GET.get("export")
    if fmt == "csv":
        resp = HttpResponse(exports.to_csv(qs), content_type="text/csv")
        resp["Content-Disposition"] = "attachment; filename=audit_logs.csv"
        return resp
    if fmt == "json":
        resp = HttpResponse(exports.to_json(qs), content_type="application/json")
        resp["Content-Disposition"] = "attachment; filename=audit_logs.json"
        return resp

    ctx = {
        "logs": qs[:200], "action_f": action_f, "level_f": level_f, "q": q,
        "active": "logs",
    }
    return render(request, "dashboard/logs.html", ctx)


@login_required
def log_detail(request, pk: int):
    log = get_object_or_404(RequestLog, pk=pk)
    if request.method == "POST" and _can_manage(request):
        if "false_positive" in request.POST:
            log.marked_false_positive = not log.marked_false_positive
            log.save(update_fields=["marked_false_positive"])
        elif "false_negative" in request.POST:
            log.marked_false_negative = not log.marked_false_negative
            log.save(update_fields=["marked_false_negative"])
        return redirect("dashboard:log_detail", pk=pk)
    return render(request, "dashboard/log_detail.html", {"log": log, "active": "logs"})


@login_required
def rules(request):
    if request.method == "POST":
        if not _can_manage(request):
            messages.error(request, "You do not have permission to manage rules.")
            return redirect("dashboard:rules")
        rid = request.POST.get("toggle")
        if rid:
            rule = get_object_or_404(Rule, pk=rid)
            rule.enabled = not rule.enabled
            rule.save(update_fields=["enabled"])
            bump_engine_version()
        return redirect("dashboard:rules")
    config = FirewallConfig.load()
    ctx = {"rules": Rule.objects.select_related("policy_profile").all(),
           "profiles": PolicyProfile.objects.all().order_by("name"),
           "recent_drafts": PolicyDraft.objects.order_by("-created_at")[:5],
           "active_policy": config.active_policy,
           "can_manage": _can_manage(request), "active": "rules"}
    return render(request, "dashboard/rules.html", ctx)


@login_required
def policy_upload(request):
    if request.method != "POST":
        return redirect("dashboard:rules")
    if not _can_manage(request):
        return HttpResponseForbidden("You cannot manage provider policies.")
    upload = request.FILES.get("terms")
    if not upload:
        messages.error(request, "Choose a PDF, DOCX, or TXT terms file.")
        return redirect("dashboard:rules")
    try:
        draft = create_draft(provider_name=request.POST.get("provider_name", ""),
                             upload=upload, user=request.user)
    except PolicyImportError as exc:
        messages.error(request, str(exc))
        return redirect("dashboard:rules")
    return redirect("dashboard:policy_preview", pk=draft.pk)


@login_required
def policy_preview(request, pk: int):
    draft = get_object_or_404(PolicyDraft, pk=pk)
    trial = None
    if request.method == "POST":
        if not _can_manage(request):
            return HttpResponseForbidden("You cannot activate provider policies.")
        if "try_prompt" in request.POST:
            prompt = request.POST.get("prompt", "")[:1000]
            trial = {"prompt": prompt,
                     "matches": [candidate["label"] for candidate in draft.candidates
                                 if re.search(candidate["pattern"], prompt)]}
        else:
            try:
                selected = [int(value) for value in request.POST.getlist("candidate")]
                profile, count = activate_draft(draft, selected, user=request.user)
            except (PolicyImportError, ValueError) as exc:
                messages.error(request, str(exc))
                return redirect("dashboard:policy_preview", pk=pk)
            messages.success(request, f"Activated {count} reviewed rules for {profile.name}.")
            return redirect("dashboard:rules")
    candidates = list(enumerate(draft.candidates))
    return render(request, "dashboard/policy_preview.html", {
        "draft": draft, "candidates": candidates, "trial": trial,
        "can_manage": _can_manage(request), "active": "rules",
    })


@login_required
def policy_switch(request):
    if request.method != "POST":
        return redirect("dashboard:rules")
    if not _can_manage(request):
        return HttpResponseForbidden("You cannot change the active provider policy.")
    profile_id = request.POST.get("profile_id")
    profile = get_object_or_404(PolicyProfile, pk=profile_id) if profile_id else None
    config = FirewallConfig.load()
    config.active_policy = profile
    config.save(update_fields=["active_policy", "updated_at"])
    bump_engine_version()
    messages.success(request, f"Active policy: {profile.name if profile else 'Built-in defaults only'}.")
    return redirect("dashboard:rules")


@login_required
def analytics(request):
    return render(request, "dashboard/analytics.html", {"active": "analytics"})


@login_required
def tester(request):
    result = None
    prompt = ""
    if request.method == "POST":
        prompt = request.POST.get("prompt", "")
        if prompt:
            engine = build_engine()
            started = time.perf_counter()
            r = engine.inspect_request(prompt)
            elapsed = (time.perf_counter() - started) * 1000
            result = r.as_dict()
            result["response_time_ms"] = round(elapsed, 2)
    return render(request, "dashboard/tester.html", {"result": result, "prompt": prompt, "active": "tester"})
