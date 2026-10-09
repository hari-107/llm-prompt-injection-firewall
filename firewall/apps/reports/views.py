from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404

from apps.auditlog.models import RequestLog
from apps.reports.pdf import build_log_report


@login_required
def log_pdf(request, pk: int):
    log = get_object_or_404(RequestLog, pk=pk)
    pdf = build_log_report(log)
    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="report_{log.request_id[:12]}.pdf"'
    return resp
