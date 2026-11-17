"""HTTP routes: one HTML page + a small JSON API."""
import threading

from flask import Blueprint, Response, jsonify, render_template, request

from app import storage
from scanner import nmap_runner, parser, reporter, validators, vuln_checks
from scanner.profiles import PROFILES

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    return render_template("index.html", profiles=PROFILES, nmap_ok=nmap_runner.nmap_available())


def _worker(scan_id, target, profile):
    storage.set_running(scan_id)
    try:
        result = parser.parse_xml(nmap_runner.run_scan(target, profile))
        result["findings"] = vuln_checks.analyze(result)
        result["summary"] = vuln_checks.summarize(result, result["findings"])
        storage.finish(scan_id, result)
    except Exception as exc:  # report any failure to the UI
        storage.fail(scan_id, str(exc))


@bp.post("/api/scans")
def start_scan():
    data = request.get_json(silent=True) or {}
    if not data.get("authorized"):
        return jsonify(error="You must confirm you are authorised to scan this target."), 400
    profile = data.get("profile", "quick")
    if profile not in PROFILES:
        return jsonify(error="Unknown profile."), 400
    try:
        target = validators.validate_target(data.get("target", ""))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    scan_id = storage.create(target, profile)
    threading.Thread(target=_worker, args=(scan_id, target, profile), daemon=True).start()
    return jsonify(id=scan_id), 202


@bp.get("/api/scans")
def list_scans():
    return jsonify(storage.list_all())


@bp.get("/api/scans/<int:scan_id>")
def get_scan(scan_id):
    scan = storage.get(scan_id)
    return (jsonify(scan), 200) if scan else (jsonify(error="Not found"), 404)


@bp.delete("/api/scans/<int:scan_id>")
def delete_scan(scan_id):
    storage.delete(scan_id)
    return "", 204


@bp.get("/api/scans/<int:scan_id>/export")
def export(scan_id):
    scan = storage.get(scan_id)
    if not scan or scan["status"] != "done":
        return jsonify(error="Scan not available"), 404
    fmt = request.args.get("fmt", "json")
    makers = {"json": (reporter.to_json, "application/json"),
              "csv": (reporter.to_csv, "text/csv"),
              "html": (reporter.to_html, "text/html")}
    if fmt not in makers:
        return jsonify(error="fmt must be json, csv or html"), 400
    fn, mime = makers[fmt]
    return Response(fn(scan), mimetype=mime,
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.{fmt}"})
