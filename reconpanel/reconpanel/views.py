"""Main application views."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Tuple

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import func

from .extensions import db
from .forms import NewScanForm
from .models import Finding, ScanTask
from .tasks import run_scan


main_bp = Blueprint("main", __name__)


def _list_directory_files(directory: str) -> List[Tuple[str, str]]:
    base = Path(directory)
    if not base.exists():
        return []
    files: List[Tuple[str, str]] = []
    for child in sorted(base.iterdir()):
        if child.is_file():
            relative = child.relative_to(base)
            files.append((str(relative), child.name))
    return files


def _list_template_directories(directory: str) -> List[Tuple[str, str]]:
    base = Path(directory)
    if not base.exists():
        return []
    entries: List[Tuple[str, str]] = []
    for child in sorted(base.iterdir()):
        if child.is_dir():
            relative = child.relative_to(base)
            entries.append((str(relative), child.name))
    return entries


def _read_log_tail(path: Path, max_bytes: int = 200_000) -> str:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(-max_bytes, os.SEEK_END)
        data = handle.read().decode("utf-8", errors="replace")
    if size > max_bytes:
        return "... (truncated) ...\n" + data
    return data


@main_bp.route("/")
@login_required
def index():
    return redirect(url_for("main.dashboard"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    recent_scans = ScanTask.query.order_by(ScanTask.created_at.desc()).limit(5).all()
    status_counts = dict(
        db.session.query(ScanTask.status, func.count(ScanTask.id)).group_by(ScanTask.status)
    )
    total_findings = db.session.query(func.count(Finding.id)).scalar() or 0
    return render_template(
        "dashboard.html",
        recent_scans=recent_scans,
        status_counts=status_counts,
        total_findings=total_findings,
    )


@main_bp.route("/scans")
@login_required
def list_scans():
    page = request.args.get("page", default=1, type=int)
    page = max(page, 1)
    pagination = ScanTask.query.order_by(ScanTask.created_at.desc()).paginate(page=page, per_page=10)
    return render_template("scans/list.html", pagination=pagination)


@main_bp.route("/scans/new", methods=["GET", "POST"])
@login_required
def create_scan():
    config = current_app.config
    form = NewScanForm()
    wordlists = _list_directory_files(config["WORDLIST_DIRECTORY"])
    if not wordlists:
        flash("No wordlists available in /data/wordlists", "warning")
    form.set_wordlist_choices([(wl, name) for wl, name in wordlists])
    form.set_line_choices([10, 50, 100, 250, 500, 1000])
    templates = _list_template_directories(config["NUCLEI_TEMPLATE_DIRECTORY"])
    if templates:
        form.set_template_choices([(tpl, name) for tpl, name in templates])
    else:
        form.set_template_choices([("", "No templates available")])

    if form.validate_on_submit():
        if not wordlists:
            flash("No wordlists available to run a scan.", "danger")
            return redirect(url_for("main.create_scan"))
        selected_wordlist = form.wordlist.data
        severities = form.nuclei_severities.data
        if not severities:
            flash("Select at least one severity", "danger")
            return render_template("scans/new.html", form=form)

        scan = ScanTask(
            name=form.name.data or None,
            wordlist_path=selected_wordlist,
            wordlist_lines_used=form.line_count.data,
            subfinder_args=json.dumps(
                {
                    "use_all": form.subfinder_use_all.data,
                    "use_silent": form.subfinder_use_silent.data,
                    "use_recursive": form.subfinder_use_recursive.data,
                }
            ),
            nuclei_args=json.dumps(
                {
                    "template": form.nuclei_template.data,
                    "severities": severities,
                    "rate_limit": form.nuclei_rate_limit.data,
                    "concurrency": form.nuclei_concurrency.data,
                    "fast_mode": form.nuclei_fast_mode.data,
                }
            ),
        )
        db.session.add(scan)
        db.session.commit()

        run_scan.delay(scan.id)
        flash("Scan queued successfully", "success")
        return redirect(url_for("main.list_scans"))

    return render_template("scans/new.html", form=form)


@main_bp.route("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    scan = ScanTask.query.get_or_404(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.created_at.desc()).all()
    return render_template("scans/detail.html", scan=scan, findings=findings)


@main_bp.route("/scans/<int:scan_id>/log")
@login_required
def scan_log(scan_id: int):
    scan = ScanTask.query.get_or_404(scan_id)
    if not scan.log_path:
        flash("Log not available yet", "warning")
        return redirect(url_for("main.scan_detail", scan_id=scan_id))

    log_path = Path(scan.log_path)
    if not log_path.exists():
        flash("Log file not found", "danger")
        return redirect(url_for("main.scan_detail", scan_id=scan_id))

    content = _read_log_tail(log_path)
    return render_template("scans/log.html", scan=scan, log_content=content)
