"""CF_AI — FastAPI layer.

Provides:
  • Pydantic-validated request/response models for every endpoint
  • WebSocket /ws/scan/{job_id} — streams live scan output to the browser
  • WebSocket /ws/live          — pushes aggregated stats every 15 s
  • BackgroundTasks for scan execution (Starlette built-in)
  • All REST endpoints matching the Flask app, fully type-annotated

Run standalone (development):
    uvicorn dashboard.api_fast:app --reload --port 8889

Or mount inside any ASGI host.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import ipaddress
import urllib.parse as _up_parse
import urllib.request as _up_req

# ── Path bootstrap ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── FastAPI / Starlette / Pydantic imports ────────────────────────────────────
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator, model_validator

import dashboard.db as db
from dashboard.remediations import REMEDIATIONS
from dashboard.mitre_rules import evaluate_rules, get_coverage

db.init_db()

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CF_AI Security Intelligence",
    description="AI-powered web security scanning dashboard",
    version="2.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_TMPL_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TMPL_DIR))

# ── In-memory stores ──────────────────────────────────────────────────────────
_scan_jobs: Dict[str, Dict[str, Any]] = {}
_ws_clients: Dict[str, List[WebSocket]] = {}   # job_id → connected websockets
_geo_cache: Dict[str, str] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic models
# ═══════════════════════════════════════════════════════════════════════════════

class ScanCredentials(BaseModel):
    site_type:    Literal["none","wordpress","cpanel","ssh","sftp"] = "none"
    wp_user:      str = ""
    wp_pass:      str = ""
    wp_app_pass:  str = ""
    cpanel_user:  str = ""
    cpanel_pass:  str = ""
    ssh_host:     str = ""
    ssh_user:     str = "root"
    ssh_pass:     str = ""
    ssh_port:     str = "22"
    ssh_key:      str = ""
    ftp_host:     str = ""
    ftp_user:     str = ""
    ftp_pass:     str = ""
    ftp_port:     str = ""


class ScanRequest(BaseModel):
    target:     str = Field(..., min_length=1, description="Domain or URL to scan")
    agent_type: str = Field("apit", description="Agent key (info, apit, athn, …)")
    model:      str = Field("", description="Claude model override")
    credentials: ScanCredentials = Field(default_factory=ScanCredentials)

    @field_validator("target")
    @classmethod
    def _normalize_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        return v


class LogAnalyzeRequest(BaseModel):
    domain:   str = Field(..., min_length=1)
    ssh_host: str = ""
    ssh_user: str = ""
    ssh_pass: str = ""
    ssh_port: int = Field(22, ge=1, le=65535)


class NetworkMonitorRequest(BaseModel):
    domain:   str = Field(..., min_length=1)
    ssh_host: str = ""
    ssh_user: str = ""
    ssh_pass: str = ""
    ssh_port: int = Field(22, ge=1, le=65535)


class IncidentCreate(BaseModel):
    title:           str = Field(..., min_length=1, max_length=300)
    description:     str = ""
    severity:        Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    target:          str = ""
    scan_id:         Optional[int] = None
    mitre_tactic:    str = ""
    mitre_technique: str = ""
    rule_id:         str = ""


class IncidentUpdate(BaseModel):
    status:      Optional[Literal["open", "investigating", "resolved"]] = None
    notes:       Optional[str] = None
    severity:    Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = None
    title:       Optional[str] = None
    description: Optional[str] = None

    @model_validator(mode="after")
    def _at_least_one(self) -> "IncidentUpdate":
        if not any(v is not None for v in self.model_dump().values()):
            raise ValueError("At least one field must be provided")
        return self


class ScanSaveRequest(BaseModel):
    target:     str
    agent_type: str
    model:      str = ""
    status:     str = "ok"
    latency_s:  float = 0.0
    tool_count: int = 0
    output:     str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Helper utilities (shared with Flask app)
# ═══════════════════════════════════════════════════════════════════════════════

def _geoip(ip_or_url: str) -> str:
    raw = (ip_or_url or "").strip()
    if not raw or raw in ("-", "--", ""):
        return ""
    if raw.startswith("http"):
        raw = _up_parse.urlparse(raw).netloc or raw
    ip = raw.split(":")[0].strip()
    if not ip:
        return ""
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            _geo_cache[ip] = ""
            return ""
    except ValueError:
        pass
    try:
        url = f"http://ip-api.com/json/{_up_parse.quote(ip)}?fields=status,country,city"
        req = _up_req.Request(url, headers={"User-Agent": "CF_AI/2.0"})
        with _up_req.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            result = f"{data.get('country','')} ({data.get('city','')})"
            _geo_cache[ip] = result
            return result
    except Exception:
        pass
    _geo_cache[ip] = ""
    return ""


def _build_cred_block(site_type: str, creds: ScanCredentials, domain: str) -> str:
    """Build credential instruction block for agents."""
    if not site_type or site_type == "none":
        return ""
    from dashboard.app import _build_cred_block as _flask_build
    return _flask_build(site_type, creds.model_dump(), domain)


def _run_scan_background(
    job_id: str,
    target: str,
    agent_type: str,
    model: str,
    site_type: str,
    creds: ScanCredentials,
) -> None:
    """Runs in a daemon thread; writes chunks to _scan_jobs[job_id] and
       broadcasts them to any connected WebSocket clients."""
    from agents.pentest import run_full_pentest, WSTG_REGISTRY
    from agents.wstg_agents import WSTG_REGISTRY as _REG

    job = _scan_jobs[job_id]
    domain = target.replace("https://", "").replace("http://", "").rstrip("/")
    job["domain"] = domain

    import urllib.parse as _up
    clean_url = target if target.startswith("http") else f"https://{target}"

    cred_block = _build_cred_block(site_type, creds, domain)

    def _push(chunk: dict) -> None:
        job["chunks"].append(chunk)
        # Broadcast to WebSocket clients (fire-and-forget via asyncio)
        for ws in list(_ws_clients.get(job_id, [])):
            try:
                asyncio.run_coroutine_threadsafe(
                    ws.send_json(chunk), _ws_loop
                )
            except Exception:
                pass

    def on_text(t: str) -> None:
        if job.get("aborted"):
            raise InterruptedError("aborted")
        _push({"k": "txt", "d": t})

    def on_tool(name: str, inp: dict) -> None:
        if job.get("aborted"):
            raise InterruptedError("aborted")
        _push({"k": "tool", "d": name, "i": str(inp)[:120]})

    def on_result(res: dict) -> None:
        _push({"k": "done", "d": res})

    start = time.monotonic()
    try:
        run_full_pentest(
            target=clean_url,
            model=model,
            on_text=on_text,
            on_tool=on_tool,
            on_result=on_result,
            cred_block=cred_block,
            agent_key=agent_type,
        )
    except InterruptedError:
        job["status"] = "aborted"
        return
    except Exception as exc:
        job["error"] = str(exc)[:400]
        job["status"] = "error"
        _push({"k": "err", "d": str(exc)[:400]})
        return
    finally:
        elapsed = round(time.monotonic() - start, 2)
        full_output = "".join(
            c["d"] for c in job["chunks"] if c.get("k") == "txt"
        )
        tool_count = sum(1 for c in job["chunks"] if c.get("k") == "tool")
        scan_id = db.save_scan(
            target=target,
            agent_type=agent_type,
            model=model,
            status=job.get("status", "ok"),
            latency_s=elapsed,
            tool_count=tool_count,
            output=full_output,
        )
        job["scan_id"] = scan_id

    if job.get("status") not in ("error", "aborted"):
        job["status"] = "done"


# Background asyncio event loop for WebSocket broadcasts from threads
_ws_loop = asyncio.new_event_loop()

def _start_ws_loop() -> None:
    asyncio.set_event_loop(_ws_loop)
    _ws_loop.run_forever()

threading.Thread(target=_start_ws_loop, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard page
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(request: Request) -> HTMLResponse:
    from dashboard.app import _build_template_context
    ctx = _build_template_context()
    ctx["request"] = request
    return templates.TemplateResponse("index.html", ctx)


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/scan/{job_id}")
async def ws_scan(websocket: WebSocket, job_id: str) -> None:
    """Stream live scan chunks to the browser.

    The browser receives JSON objects:
      {"k":"txt","d":"…"}   — agent text output
      {"k":"tool","d":"…"}  — tool call
      {"k":"done","d":{…}}  — result summary
      {"k":"err","d":"…"}   — error
      {"k":"ping"}           — keep-alive
    """
    await websocket.accept()
    job = _scan_jobs.get(job_id)
    if not job:
        await websocket.send_json({"k": "err", "d": "Job not found"})
        await websocket.close()
        return

    # Register this socket for live broadcasts
    _ws_clients.setdefault(job_id, []).append(websocket)

    # Replay chunks the client missed (offset in query string)
    try:
        offset = int(websocket.query_params.get("offset", "0"))
    except ValueError:
        offset = 0
    for chunk in job["chunks"][offset:]:
        await websocket.send_json(chunk)

    # Keep connection alive until the scan finishes or client disconnects
    try:
        while True:
            if job.get("status") in ("done", "error", "aborted"):
                await websocket.send_json(
                    {"k": "status", "d": job["status"], "scan_id": job.get("scan_id")}
                )
                break
            await asyncio.sleep(0.8)
            await websocket.send_json({"k": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        clients = _ws_clients.get(job_id, [])
        if websocket in clients:
            clients.remove(websocket)
        await websocket.close(code=1000)


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    """Push aggregated dashboard stats every 15 s.

    Payload:
      {"total_scans":N, "open_incidents":N, "latest_target":"…", "ts":"…"}
    """
    await websocket.accept()
    try:
        while True:
            try:
                stats    = db.get_stats()
                inc      = db.get_incident_stats()
                recent   = db.get_recent_scans(1)
                payload  = {
                    "total_scans":    stats["total_scans"],
                    "unique_targets": stats["unique_targets"],
                    "open_incidents": inc["open"],
                    "latest_target":  recent[0]["target"] if recent else "",
                    "latest_status":  recent[0]["status"] if recent else "",
                    "ts":             time.strftime("%H:%M:%S UTC", time.gmtime()),
                }
                await websocket.send_json(payload)
            except Exception:
                pass
            await asyncio.sleep(15)
    except WebSocketDisconnect:
        pass
    finally:
        await websocket.close(code=1000)


# ═══════════════════════════════════════════════════════════════════════════════
# Scan management endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/connect/scan", status_code=202)
async def api_connect_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """Start a background security scan.  Returns ``{"job_id": "<uuid>"}``."""
    job_id = str(uuid.uuid4())
    _scan_jobs[job_id] = {
        "status":  "running",
        "target":  body.target,
        "agent":   body.agent_type,
        "chunks":  [],
        "domain":  "",
        "scan_id": None,
        "error":   None,
        "aborted": False,
    }
    background_tasks.add_task(
        _run_scan_background,
        job_id, body.target, body.agent_type, body.model,
        body.credentials.site_type, body.credentials,
    )
    return {"job_id": job_id}


@app.get("/api/connect/scan/{job_id}")
async def api_scan_poll(
    job_id: str,
    offset: int = Query(0, ge=0),
) -> dict:
    """Poll for new chunks.

    Returns: status, domain, scan_id, error, chunks[offset:], next_offset.
    """
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    new_chunks = job["chunks"][offset:]
    return {
        "status":      job["status"],
        "domain":      job.get("domain", ""),
        "scan_id":     job.get("scan_id"),
        "error":       job.get("error"),
        "chunks":      new_chunks,
        "next_offset": offset + len(new_chunks),
    }


@app.post("/api/connect/scan/{job_id}/abort")
async def api_scan_abort(job_id: str) -> dict:
    """Signal a running scan to stop."""
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    job["aborted"] = True
    job["status"]  = "aborted"
    job["chunks"].append({"k": "txt", "d": "\n[SCAN ABORTED by user]"})
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# Scan data endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stats")
async def api_stats() -> dict:
    return db.get_stats()


@app.get("/api/scans/recent")
async def api_scans_recent(limit: int = Query(50, ge=1, le=500)) -> list:
    return db.get_recent_scans(limit)


@app.get("/api/scan/{scan_id}")
async def api_scan(scan_id: int) -> dict:
    row = db.get_scan(scan_id)
    if not row:
        raise HTTPException(404, "Scan not found")
    return row


@app.post("/api/scan", status_code=201)
async def api_save_scan(body: ScanSaveRequest) -> dict:
    sid = db.save_scan(
        target=body.target, agent_type=body.agent_type, model=body.model,
        status=body.status, latency_s=body.latency_s,
        tool_count=body.tool_count, output=body.output,
    )
    return {"id": sid}


# ═══════════════════════════════════════════════════════════════════════════════
# Incident Management
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/incidents")
async def api_incidents_get(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    rows = db.get_incidents(status=status_filter, limit=limit)
    stats = db.get_incident_stats()
    return {"incidents": rows, "stats": stats}


@app.post("/api/incidents", status_code=201)
async def api_incidents_create(body: IncidentCreate) -> dict:
    iid = db.create_incident(
        title=body.title, description=body.description,
        severity=body.severity, target=body.target,
        scan_id=body.scan_id, mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique, rule_id=body.rule_id,
    )
    return {"created": True, "id": iid}


@app.patch("/api/incidents/{iid}")
async def api_incidents_update(iid: int, body: IncidentUpdate) -> dict:
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    ok = db.update_incident(iid, **updates)
    if not ok:
        raise HTTPException(400, "No valid fields to update")
    return {"updated": True}


# ═══════════════════════════════════════════════════════════════════════════════
# Security Signals
# ═══════════════════════════════════════════════════════════════════════════════

_HIGH_SIGNALS  = re.compile(r'sql\s*inject|remote\s*code|rce|shell\s*upload|credential\s*expos|path\s*travers|XXE|SSRF', re.I)
_MED_SIGNALS   = re.compile(r'xss|csrf|open\s*redirect|weak\s*(cipher|protocol)|directory\s*list|exposure|outdated', re.I)
_LOW_SIGNALS   = re.compile(r'missing\s*header|cookie\s*flag|information\s*disclos|verbose\s*error|banner\s*grab', re.I)

import re

@app.get("/api/security-signals")
async def api_security_signals(days: int = Query(30, ge=1, le=365)) -> dict:
    scans = db.get_recent_scans(200)
    events: list = []
    daily: dict  = {}

    for s in scans:
        text = s.get("output", "")
        date = s.get("created_at", "")[:10]
        target = s.get("target", "")
        for pattern, severity in [(_HIGH_SIGNALS, "HIGH"), (_MED_SIGNALS, "MEDIUM"), (_LOW_SIGNALS, "LOW")]:
            for m in pattern.finditer(text):
                snippet = text[max(0, m.start()-40): m.end()+60].replace("\n", " ").strip()
                events.append({"date": date, "severity": severity, "event": snippet[:100], "target": target})
            if pattern.search(text):
                bucket = daily.setdefault(date, {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
                bucket[severity] = bucket.get(severity, 0) + 1

    timeline = [{"date": d, **v} for d, v in sorted(daily.items())[-days:]]
    counts   = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CRITICAL": 0, "INFO": 0}
    for e in events:
        counts[e["severity"]] = counts.get(e["severity"], 0) + 1

    return {"events": events[:500], "timeline": timeline, "counts": counts}


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Coverage
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/mitre/coverage")
async def api_mitre_coverage() -> dict:
    scans = db.get_recent_scans(100)
    coverage = get_coverage(scans)
    from dashboard.mitre_rules import TACTICS
    return {
        "coverage":     coverage["by_tactic"],
        "total":        coverage["total"],
        "severities":   coverage["severities"],
        "tactic_order": [t["name"] for t in TACTICS],
    }


@app.get("/api/mitre/rules/{tactic_name}")
async def api_mitre_tactic_rules(tactic_name: str) -> dict:
    """Return all rules for a specific MITRE tactic, with match status."""
    from dashboard.mitre_rules import DETECTION_RULES
    scans = db.get_recent_scans(50)
    all_text = " ".join(s.get("output", "") for s in scans)

    rules = [r for r in DETECTION_RULES if r["tactic"].lower() == tactic_name.lower()]
    result = []
    for rule in rules:
        matched = any(p.search(all_text) for p in rule.get("_compiled", []))
        result.append({
            "id":             rule["id"],
            "title":          rule["title"],
            "severity":       rule["severity"],
            "tactic":         rule["tactic"],
            "tactic_id":      rule["tactic_id"],
            "technique":      rule["technique"],
            "technique_name": rule["technique_name"],
            "desc":           rule["desc"],
            "source":         rule.get("source", ""),
            "matched":        matched,
        })
    return {"tactic": tactic_name, "rules": result}


# ═══════════════════════════════════════════════════════════════════════════════
# Log Analysis
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/logs/analyze")
async def api_logs_analyze(body: LogAnalyzeRequest) -> dict:
    try:
        from tools.log_analyzer import analyze_from_ssh, analyze_from_probe
        if body.ssh_host and body.ssh_user and body.ssh_pass:
            result = analyze_from_ssh(body.ssh_host, body.ssh_user, body.ssh_pass, body.ssh_port)
        else:
            result = analyze_from_probe(body.domain)
        return result
    except ImportError:
        raise HTTPException(501, "log_analyzer module not available")
    except Exception as exc:
        return {"error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════════════
# Network Monitor
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/monitor/network")
async def api_monitor_network(body: NetworkMonitorRequest) -> dict:
    import subprocess
    import shutil

    domain = body.domain.replace("https://", "").replace("http://", "").split("/")[0]
    nodes: list = [{"id": "target", "type": "target", "group": "target", "label": domain}]
    edges: list = []
    services: list = []
    traffic: dict = {}

    # Nmap scan
    if shutil.which("nmap"):
        try:
            result = subprocess.run(
                ["nmap", "-sV", "--open", "-T4", "-p", "21,22,23,25,53,80,443,3306,5432,6379,8080,8443,27017", domain],
                capture_output=True, text=True, timeout=60,
            )
            port_re = re.compile(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)")
            for m in port_re.finditer(result.stdout):
                port, svc, ver = int(m.group(1)), m.group(2), m.group(3).strip()
                nid = f"{svc}-{port}"
                nodes.append({"id": nid, "type": "service", "group": svc, "label": f"{svc}\nport {port}"})
                edges.append({"from": "target", "to": nid, "label": str(port)})
                services.append({"port": port, "service": svc, "version": ver[:60]})
        except Exception:
            pass

    # SSH netstat
    if body.ssh_host and body.ssh_user and body.ssh_pass:
        import shlex
        sshcmd = ["sshpass", "-p", body.ssh_pass, "ssh",
                  "-o", "StrictHostKeyChecking=no",
                  "-p", str(body.ssh_port),
                  f"{body.ssh_user}@{body.ssh_host}"]
        try:
            r = subprocess.run(
                sshcmd + ["ss -tnlp"],
                capture_output=True, text=True, timeout=20,
            )
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "LISTEN":
                    addr = parts[3]
                    port_m = re.search(r":(\d+)$", addr)
                    if port_m:
                        p = int(port_m.group(1))
                        if p < 1024 and not any(s["port"] == p for s in services):
                            services.append({"port": p, "service": "tcp", "version": ""})
        except Exception:
            pass

        # Interface traffic
        try:
            r = subprocess.run(
                sshcmd + ["cat /proc/net/dev"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(":")
                    try:
                        rx = round(int(parts[1]) / 1_048_576, 2)
                        tx = round(int(parts[9]) / 1_048_576, 2)
                        traffic[iface] = {"rx_mb": rx, "tx_mb": tx}
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass

    return {"nodes": nodes, "edges": edges, "services": services, "traffic": traffic}


# ═══════════════════════════════════════════════════════════════════════════════
# Unified Observability Overview
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/unified/overview")
async def api_unified_overview() -> dict:
    from collections import defaultdict

    scans    = db.get_recent_scans(50)
    coverage = get_coverage(scans)
    daily: dict = defaultdict(int)

    for s in scans:
        day  = s.get("created_at", "")[:10]
        text = s.get("output", "")
        if re.search(r"sql\s*inject|xss|rce|brute.force|exposed.*key|path.traversal", text, re.I):
            daily[day] += 1

    slowest = sorted(
        [{"target": s["target"], "latency": s.get("latency_s", 0), "agent": s.get("agent_type", "")}
         for s in scans],
        key=lambda x: x["latency"], reverse=True,
    )[:10]

    total  = len(scans)
    errors = sum(1 for s in scans if s.get("status") != "ok")

    recent_signals = []
    seen: set = set()
    for s in scans[:20]:
        for match in evaluate_rules(s.get("output", ""), s.get("target", "")):
            if match["severity"] == "HIGH" and match["id"] not in seen:
                seen.add(match["id"])
                recent_signals.append({**match, "date": s.get("created_at", "")[:10]})

    return {
        "signal_timeline":     dict(sorted(daily.items())[-14:]),
        "slowest_pages":       slowest,
        "error_rate_pct":      round(errors / max(total, 1) * 100, 1),
        "total_scans":         total,
        "mitre_total":         coverage["total"],
        "mitre_severities":    coverage["severities"],
        "recent_high_signals": recent_signals[:10],
        "incident_stats":      db.get_incident_stats(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Target analytics
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/target/{target:path}/analytics")
async def api_target_analytics(target: str) -> dict:
    scans  = db.get_scans_for_target(target)
    if not scans:
        raise HTTPException(404, "No scans for this target")
    latest = scans[0]
    mitre  = evaluate_rules(latest.get("output", ""), target)
    return {
        "scan_count":    len(scans),
        "latest_scan":   latest,
        "mitre_matches": mitre[:20],
        "history":       [{"date": s["created_at"][:10], "latency": s.get("latency_s", 0)} for s in scans],
    }


@app.get("/api/target/{target:path}/wp-logs")
async def api_wp_logs(target: str) -> dict:
    """Aggregate WP plugin log events from all scans for this target."""
    from dashboard.app import extract_wp_logs
    scans = db.get_scans_for_target(target)
    all_logs: list = []
    for s in scans:
        parsed = extract_wp_logs(s.get("output", "") or "")
        for event in parsed.get("events", []):
            event["scan_date"] = s.get("created_at", "")[:10]
            all_logs.append(event)
    return {"logs": all_logs[:200], "scan_count": len(scans)}


# ═══════════════════════════════════════════════════════════════════════════════
# Latency probe
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/monitor/latency")
async def api_monitor_latency(target: str = Query(...)) -> dict:
    import urllib.request as _req
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    paths  = ["/", "/robots.txt", "/sitemap.xml", "/login", "/admin", "/wp-login.php"]
    results = []
    for path in paths:
        url = f"https://{domain}{path}"
        t0  = time.monotonic()
        try:
            r = _req.urlopen(_req.Request(url, headers={"User-Agent": "CF_AI/2.0"}), timeout=6)
            ms = round((time.monotonic() - t0) * 1000)
            results.append({"path": path, "status": r.status, "ms": ms})
        except Exception as exc:
            ms = round((time.monotonic() - t0) * 1000)
            results.append({"path": path, "status": 0, "ms": ms, "error": str(exc)[:80]})
    return {"target": domain, "probes": results}


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("CFAI_DASHBOARD_PORT", 8889))
    print(f"CF_AI FastAPI dashboard → http://0.0.0.0:{port}")
    print(f"  API docs             → http://0.0.0.0:{port}/api/docs")
    uvicorn.run("dashboard.api_fast:app", host="0.0.0.0", port=port, reload=False, workers=1)
