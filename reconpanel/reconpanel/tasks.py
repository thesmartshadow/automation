"""Celery tasks for executing reconnaissance scans."""

from __future__ import annotations

import json
 codex/design-and-implement-reconpanel-web-app-c5u9lc
import logging
import subprocess
import traceback
import subprocess
 main
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from celery import Celery
from flask import current_app

from .extensions import db
from .models import Finding, ScanTask


 codex/design-and-implement-reconpanel-web-app-c5u9lc
logger = logging.getLogger(__name__)


 main
celery = Celery("reconpanel")


def init_celery(app) -> Celery:
    """Configure Celery to run within the Flask application context."""

    celery.conf.update(app.config.get("CELERY", {}))
    celery.conf.broker_url = app.config["CELERY_BROKER_URL"]
    celery.conf.result_backend = app.config["CELERY_RESULT_BACKEND"]

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


def _safe_path(base_dir: str, relative_path: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / relative_path).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("Invalid path outside allowed directory")
    return target


def _ensure_directories(*paths: str) -> None:
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


def _read_wordlist_subset(path: Path, lines: int, output_path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as source, output_path.open(
        "w", encoding="utf-8"
    ) as dest:
        for line in source:
            if lines and count >= lines:
                break
            stripped = line.strip()
            if stripped:
                dest.write(stripped + "\n")
                count += 1
    return count


 codex/design-and-implement-reconpanel-web-app-c5u9lc
def _append_log(log_file: Path, message: str) -> None:
    timestamp = datetime.utcnow().isoformat(timespec="seconds")
    with log_file.open("a", encoding="utf-8") as log:
        log.write(f"[{timestamp}] {message}\n")


def _run_command(command: List[str], log_file: Path) -> subprocess.CompletedProcess:
    _append_log(log_file, "$ " + " ".join(command))
    process = subprocess.run(command, capture_output=True, text=True)
    with log_file.open("a", encoding="utf-8") as log:
        if process.stdout:
            log.write(process.stdout.rstrip("\n") + "\n")
        if process.stderr:
            log.write("[stderr]\n" + process.stderr.rstrip("\n") + "\n")

def _run_command(command: List[str], log_file: Path) -> subprocess.CompletedProcess:
    process = subprocess.run(command, capture_output=True, text=True)
    with log_file.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(command) + "\n")
        if process.stdout:
            log.write(process.stdout + "\n")
        if process.stderr:
            log.write("[stderr]\n" + process.stderr + "\n")
 main
    process.check_returncode()
    return process


def _parse_nuclei_results(result_path: Path) -> Iterable[tuple[Dict[str, Any], str]]:
    if not result_path.exists():
        return []
    with result_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                yield data, line
            except json.JSONDecodeError:
                yield {"raw": line}, line


@celery.task(name="reconpanel.run_scan")
def run_scan(scan_id: int) -> None:
 codex/design-and-implement-reconpanel-web-app-c5u9lc
    logger.info("Starting scan %s", scan_id)
    scan = db.session.get(ScanTask, scan_id)
    if not scan:
        logger.warning("Scan %s no longer exists", scan_id)

    scan = db.session.get(ScanTask, scan_id)
    if not scan:
 main
        return

    config = current_app.config
    log_dir = config["LOG_DIRECTORY"]
    tmp_dir = config["TMP_DIRECTORY"]
    _ensure_directories(log_dir, tmp_dir)

    log_path = Path(log_dir) / f"scan_{scan_id}.log"
 codex/design-and-implement-reconpanel-web-app-c5u9lc
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)

    scan.log_path = str(log_path)
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    scan.error_message = None
    db.session.commit()

    _append_log(log_path, "Scan started")


    scan.log_path = str(log_path)
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    db.session.commit()

 main
    wordlist_base = config["WORDLIST_DIRECTORY"]
    nuclei_template_base = config["NUCLEI_TEMPLATE_DIRECTORY"]

    try:
        wordlist_path = _safe_path(wordlist_base, scan.wordlist_path)
        if not wordlist_path.exists():
            raise FileNotFoundError(f"Wordlist {wordlist_path} does not exist")

        subset_path = Path(tmp_dir) / f"scan_{scan_id}_targets.txt"
        used_lines = _read_wordlist_subset(wordlist_path, scan.wordlist_lines_used, subset_path)
 codex/design-and-implement-reconpanel-web-app-c5u9lc
        if used_lines == 0:
            raise ValueError("Selected wordlist produced no targets to scan")
        scan.wordlist_lines_used = used_lines
        _append_log(log_path, f"Prepared target subset with {used_lines} entries")

        scan.wordlist_lines_used = used_lines
 main

        subfinder_output = Path(tmp_dir) / f"scan_{scan_id}_subfinder.txt"
        scan.subfinder_output_path = str(subfinder_output)

        subfinder_opts = scan.subfinder_options
        subfinder_command = ["subfinder", "-dL", str(subset_path)]
        if subfinder_opts.get("use_all"):
            subfinder_command.append("-all")
        if subfinder_opts.get("use_silent"):
            subfinder_command.append("-silent")
        if subfinder_opts.get("use_recursive"):
            subfinder_command.append("-recursive")
        subfinder_command.extend(["-o", str(subfinder_output)])

 codex/design-and-implement-reconpanel-web-app-c5u9lc
        _append_log(log_path, "Running subfinder")
 main
        _run_command(subfinder_command, log_path)

        nuclei_output = Path(tmp_dir) / f"scan_{scan_id}_nuclei.jsonl"
        nuclei_opts = scan.nuclei_options
        nuclei_command = ["nuclei", "-l", str(subfinder_output), "-json"]

        severities = nuclei_opts.get("severities") or []
        if severities:
            nuclei_command.extend(["-severity", ",".join(severities)])

        template_relative = nuclei_opts.get("template")
        if template_relative:
            template_path = _safe_path(nuclei_template_base, template_relative)
            nuclei_command.extend(["-t", str(template_path)])

        rate_limit = nuclei_opts.get("rate_limit")
        if rate_limit:
            nuclei_command.extend(["-rate-limit", str(rate_limit)])

        concurrency = nuclei_opts.get("concurrency")
        if concurrency:
            nuclei_command.extend(["-c", str(concurrency)])

        if nuclei_opts.get("fast_mode"):
            nuclei_command.append("-stats")

        nuclei_command.extend(["-o", str(nuclei_output)])

 codex/design-and-implement-reconpanel-web-app-c5u9lc
        _append_log(log_path, "Running nuclei")
        _run_command(nuclei_command, log_path)

        finding_count = 0
        for result, raw_line in _parse_nuclei_results(nuclei_output):
            target = result.get("host") or result.get("matched-at") or result.get("url") or "unknown"
            template_id = result.get("template-id") or result.get("templateID")
            severity = None
            info = result.get("info")
            if isinstance(info, dict):
                severity = info.get("severity")
            if severity is None:
                severity = result.get("severity")


        _run_command(nuclei_command, log_path)

        for result, raw_line in _parse_nuclei_results(nuclei_output):
            target = result.get("host") or result.get("matched-at") or result.get("url") or "unknown"
            template_id = result.get("template-id") or result.get("templateID")
            severity = result.get("info", {}).get("severity") if isinstance(result.get("info"), dict) else result.get("severity")
 main
            finding = Finding(
                scan_id=scan.id,
                target=target,
                template_id=template_id,
                severity=severity,
                raw_line=raw_line,
            )
            db.session.add(finding)
 codex/design-and-implement-reconpanel-web-app-c5u9lc
            finding_count += 1


 main
        scan.status = "finished"
        scan.finished_at = datetime.utcnow()
        scan.error_message = None
        db.session.commit()
 codex/design-and-implement-reconpanel-web-app-c5u9lc

        _append_log(log_path, f"Scan finished successfully with {finding_count} findings")
        logger.info("Scan %s finished successfully (%s findings)", scan_id, finding_count)
    except subprocess.CalledProcessError as exc:
        logger.exception("Scan %s failed while running command", scan_id)
        db.session.rollback()
        scan = db.session.get(ScanTask, scan_id)
        if scan:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            scan.error_message = f"Command failed: {' '.join(exc.cmd)}"
            db.session.commit()
        _append_log(log_path, f"Command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}")
        if exc.stdout:
            _append_log(log_path, exc.stdout.rstrip("\n"))
        if exc.stderr:
            _append_log(log_path, "stderr: " + exc.stderr.rstrip("\n"))
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Scan %s encountered an unexpected error", scan_id)
        db.session.rollback()
        scan = db.session.get(ScanTask, scan_id)
        if scan:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            scan.error_message = str(exc)
            db.session.commit()
        _append_log(log_path, f"Unhandled error: {exc}")
        _append_log(log_path, traceback.format_exc())
    finally:
        db.session.remove()

    except subprocess.CalledProcessError as exc:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"Command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}\n")
            if exc.output:
                log.write(exc.output + "\n")
            if exc.stderr:
                log.write(exc.stderr + "\n")
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        scan.error_message = f"Command failed: {' '.join(exc.cmd)}"
        db.session.commit()
    except Exception as exc:  # pylint: disable=broad-except
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"Unhandled error: {exc}\n")
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        scan.error_message = str(exc)
        db.session.commit()
 main
