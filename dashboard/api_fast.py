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
import re
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
    elapsed = 0.0
    full_output = ""
    tool_count = 0

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
    except Exception as exc:
        job["error"] = str(exc)[:400]
        job["status"] = "error"
        _push({"k": "err", "d": str(exc)[:400]})
    finally:
        elapsed = round(time.monotonic() - start, 2)
        full_output = "".join(
            c["d"] for c in job["chunks"] if c.get("k") == "txt"
        )
        tool_count = sum(1 for c in job["chunks"] if c.get("k") == "tool")

    # Only record scans that completed successfully with actual output
    if job.get("status") not in ("error", "aborted") and full_output.strip():
        job["status"] = "done"
        scan_id = db.save_scan(
            target=target,
            agent_type=agent_type,
            model=model,
            status="ok",
            latency_s=elapsed,
            tool_count=tool_count,
            output=full_output,
        )
        job["scan_id"] = scan_id
    elif job.get("status") not in ("error", "aborted"):
        job["status"] = "done"  # completed but no output to log


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
    return templates.TemplateResponse(request=request, name="index.html", context=ctx)


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


_RISK_HIGH = re.compile(
    r'REFLECTED\s+XSS:|SQL\s+ERROR:|CODE\s+INJECTION\s+CONFIRMED:|CMD\s+INJECTION:'
    r'|SSTI\s+HIT|SSRF\s+HIT:|CREDS_FOUND|FOUND_DB_USER:|FOUND_ENV_USER:'
    r'|APP_PASS_CREATED|EXPOSED_FILE\s*\|.*\b20[0-9]\b'
    r'|WP-LOG[^|\n]*\|\s*HIGH|\|\s*(High|Critical)\s*\|', re.I)
_RISK_MED = re.compile(
    r'OPEN\s+REDIRECT:|HTML\s+INJECTION:|WP-USER-CONFIRMED|WP-USER\s*\|'
    r'|WP-LOG[^|\n]*\|\s*MEDIUM|\|\s*Medium\s*\|', re.I)
_RISK_LOW = re.compile(r'\|\s*(Low|Info)\s*\||\d+/tcp\s+open', re.I)

def _scan_risk(out: str) -> str:
    if _RISK_HIGH.search(out): return 'HIGH'
    if _RISK_MED.search(out):  return 'MEDIUM'
    if _RISK_LOW.search(out):  return 'LOW'
    return 'INFO'

@app.get("/api/scans/summary")
async def api_scans_summary(limit: int = Query(500, ge=1, le=2000)) -> list:
    """Lightweight scan list — pre-computed risk, no output text. Use for dashboard charts/KPIs."""
    scans = db.get_recent_scans(limit)
    return [
        {
            'id':         s['id'],
            'target':     s['target'],
            'agent_type': s['agent_type'],
            'created_at': s['created_at'],
            'status':     s['status'],
            'latency_s':  s['latency_s'],
            'tool_count': s['tool_count'],
            'risk':       _scan_risk(s.get('output') or ''),
        }
        for s in scans
    ]


@app.delete("/api/scans/clear", status_code=200)
async def api_scans_clear() -> dict:
    """Clear all scan history from the database."""
    import sqlite3
    from pathlib import Path as _Path
    with sqlite3.connect(db.DB_PATH) as con:
        con.execute("DELETE FROM scans")
        con.commit()
    return {"cleared": True}


@app.get("/api/login-events")
async def api_login_events(
    target: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
) -> dict:
    """Extract WordPress login events from scan outputs with geo enrichment."""
    import re as _re
    scans = db.get_recent_scans(500)
    events: List[Dict[str, Any]] = []

    # Patterns to extract login events from WP-LOG lines
    # WP-LOG | timestamp | user | event | ip | severity
    wp_log_re = _re.compile(
        r'^WP-LOG\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*'
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[^|\n]*?)\s*\|\s*(HIGH|MEDIUM|LOW|INFO)',
        _re.I | _re.MULTILINE,
    )
    login_keywords = _re.compile(r'logged?\s*in|login|sign.in|authentication|session\s*start', _re.I)
    failed_keywords = _re.compile(r'failed|invalid|incorrect|denied|blocked', _re.I)
    ip_re = _re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    for scan in scans:
        if target and target not in (scan.get('target') or ''):
            continue
        output = scan.get('output') or ''
        scan_target = scan.get('target', '')
        scan_date = scan.get('created_at', '')

        for m in wp_log_re.finditer(output):
            ts    = m.group(1).strip()
            user  = m.group(2).strip()
            event = m.group(3).strip()
            ip    = m.group(4).strip()
            sev   = m.group(5).strip()

            if not login_keywords.search(event):
                continue
            if user.lower() in {'system', 'cf_ai', 'cf_ai-mcp', 'cf_ai_mcp', 'scanner'}:
                continue

            status = 'failed' if failed_keywords.search(event) else 'success'
            geo = _geoip(ip) if ip_re.match(ip) else ''

            events.append({
                'timestamp': ts,
                'user': user,
                'event': event[:80],
                'ip': ip,
                'country': geo,
                'status': status,
                'severity': sev,
                'target': scan_target,
                'scan_date': scan_date,
            })

    events = events[:limit]
    return {'events': events, 'total': len(events)}


@app.get("/api/scan/{scan_id}")
async def api_scan(scan_id: int) -> dict:
    row = db.get_scan(scan_id)
    if not row:
        raise HTTPException(404, "Scan not found")
    return row


@app.delete("/api/scans/{scan_id}", status_code=200)
async def api_delete_scan(scan_id: int) -> dict:
    """Delete a single scan record by ID."""
    import sqlite3
    with sqlite3.connect(db.DB_PATH) as con:
        cur = con.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        con.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}


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


@app.delete("/api/incidents/{iid}", status_code=200)
async def api_incidents_delete(iid: int) -> dict:
    deleted = db.delete_incident(iid)
    if not deleted:
        raise HTTPException(404, "Incident not found")
    return {"deleted": iid}


# ═══════════════════════════════════════════════════════════════════════════════
# Security Signals
# ═══════════════════════════════════════════════════════════════════════════════

# Match only CONFIRMED findings from agent output — not test section headers or commands.
# Agents emit specific marker prefixes when they actually find something (see wstg_agents.py).
_HIGH_SIGNALS = re.compile(
    r'REFLECTED\s+XSS:'                          # INPV agent confirmed XSS
    r'|SQL\s+ERROR:'                              # INPV confirmed SQL injection
    r'|CODE\s+INJECTION\s+CONFIRMED:'             # INPV confirmed code injection
    r'|CMD\s+INJECTION:'                          # INPV confirmed command injection
    r'|SSTI\s+HIT'                                # INPV confirmed SSTI
    r'|SSRF\s+HIT:'                               # INPV confirmed SSRF
    r'|CREDS_FOUND'                               # APIT found valid credentials
    r'|FOUND_DB_USER:|FOUND_ENV_USER:'            # APIT found exposed credentials
    r'|EXPOSED_FILE\s*\|.*\b20[0-9]\b'           # APIT exposed file (HTTP 2xx)
    r'|APP_PASS_CREATED'                          # APIT auto-created application password
    r'|WP-LOG\s*\|[^|\n]+\|[^|\n]+\|[^|\n]+\|[^|\n]+\|\s*HIGH'  # WP log HIGH
    r'|\|\s*(High|Critical)\s*\|'                # Agent final report table rows
    r'|\bCVE-\d{4}-\d{4,}\b',                   # Any CVE reference found
    re.I,
)
_MED_SIGNALS = re.compile(
    r'OPEN\s+REDIRECT:'                           # CLNT confirmed open redirect
    r'|HTML\s+INJECTION:'                         # CLNT confirmed HTML injection
    r'|WP-USER-CONFIRMED'                         # APIT confirmed valid username
    r'|WP-USER\s*\|'                              # APIT enumerated WP user
    r'|WP-LOG\s*\|[^|\n]+\|[^|\n]+\|[^|\n]+\|[^|\n]+\|\s*MEDIUM'  # WP log MEDIUM
    r'|\|\s*Medium\s*\|'                          # Agent final report table rows
    r'|AUDIT_ENDPOINT\s*\|.*\b20[0-9]\b'         # APIT found exposed audit log
    r'|EXPOSED_FILE\s*\|.*\b(301|302)\b',        # APIT exposed file (redirect)
    re.I,
)
_LOW_SIGNALS = re.compile(
    r'WP-LOG\s*\|[^|\n]+\|[^|\n]+\|[^|\n]+\|[^|\n]+\|\s*LOW'  # WP log LOW
    r'|\|\s*(Low|Info)\s*\|'                     # Agent final report Info/Low rows
    r'|WP_SITE\s*\|'                             # WordPress site identified
    r'|WP_REST_ROOT:',                           # WordPress REST API confirmed
    re.I,
)

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
    coverage['tactic_order'] = [name for _, name in TACTICS]
    return coverage


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

@app.post("/api/logs/wp-live")
async def api_logs_wp_live(request: Request) -> dict:
    """Fetch real-time login events from WordPress via REST API + WSAL/Simple History plugins."""
    import base64 as _b64, urllib.request as _req
    body     = await request.json()
    url      = (body.get('url') or '').strip().rstrip('/')
    wp_user  = (body.get('wp_user') or '').strip()
    app_pass = (body.get('wp_app_pass') or '').strip()
    limit    = min(int(body.get('limit') or 50), 200)
    if not url:
        raise HTTPException(400, 'WordPress site URL required')
    if not url.startswith('http'):
        url = 'https://' + url
    auth_header = ('Basic ' + _b64.b64encode(f'{wp_user}:{app_pass}'.encode()).decode()
                   if wp_user and app_pass else None)

    def _wp_get(path, timeout=12):
        req = _req.Request(f'{url}{path}', headers={'User-Agent': 'CyberINK/2.0', 'Accept': 'application/json'})
        if auth_header:
            req.add_header('Authorization', auth_header)
        try:
            with _req.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode()), None
        except Exception as e:
            return None, str(e)

    events, source, note = [], 'none', ''
    for path in [f'/wp-json/wsal/v1/events?per_page={limit}&orderby=created_on&order=DESC',
                 f'/wp-json/wsal/v1/events?per_page={limit}']:
        wsal, _ = _wp_get(path)
        if not wsal:
            continue
        items = wsal if isinstance(wsal, list) else wsal.get('events') or wsal.get('data') or []
        for ev in items:
            msg = str(ev.get('message') or ev.get('alert_message') or ev.get('type') or '')
            if not msg:
                continue
            events.append({'timestamp': str(ev.get('created_on') or ev.get('date') or ''),
                           'user': str(ev.get('user_login') or ev.get('username') or '—'),
                           'event': msg[:120], 'ip': str(ev.get('client_ip') or ev.get('ip') or ''),
                           'severity': 'HIGH' if any(k in msg.lower() for k in ('fail','block','attack','brute','invalid')) else 'INFO',
                           'status': 'failed' if any(k in msg.lower() for k in ('fail','block','denied','invalid')) else 'success',
                           'source': 'wsal'})
        if events:
            source = 'wsal'
            break
    if not events:
        sh, _ = _wp_get(f'/wp-json/simple-history/v1/events?per_page={limit}')
        if sh and isinstance(sh, list):
            for ev in sh:
                msg = str(ev.get('message') or ev.get('text') or '')
                if not any(k in msg.lower() for k in ('login','logged','auth','fail','password')):
                    continue
                events.append({'timestamp': str(ev.get('date') or ''), 'ip': str(ev.get('ip') or ''),
                               'user': str(ev.get('via') or ev.get('initiator') or '—'), 'event': msg[:120],
                               'severity': 'HIGH' if 'fail' in msg.lower() else 'INFO',
                               'status': 'failed' if 'fail' in msg.lower() else 'success', 'source': 'simple_history'})
            if events:
                source = 'simple_history'
    if not events and auth_header:
        me, _ = _wp_get('/wp-json/wp/v2/users/me?context=edit')
        if me and me.get('id'):
            source = 'wp_rest'
            events.append({'timestamp': '', 'ip': '', 'user': me.get('slug') or wp_user,
                           'event': f"Authenticated — Role: {', '.join(me.get('roles', []))}",
                           'severity': 'INFO', 'status': 'success', 'source': 'wp_rest'})
            note = 'Install "WP Activity Log" (WSAL) plugin for full real-time login tracking.'
        else:
            note = 'Auth failed. Check username and Application Password (Users → Profile → Application Passwords).'
    if not auth_header and not events:
        root, _ = _wp_get('/wp-json/')
        note = ('WordPress REST API reachable — add credentials + WSAL plugin for login events.'
                if root and root.get('name') else 'Could not reach WordPress REST API. Check the URL.')
    if not events and not note:
        note = 'Install "WP Activity Log" or "Simple History" plugin for real-time login tracking.'
    return {'events': events[:limit], 'total': len(events), 'source': source, 'note': note}


@app.post("/api/logs/cpanel-live")
async def api_logs_cpanel_live(request: Request) -> dict:
    """Fetch real-time session/login data from cPanel via UAPI."""
    import base64 as _b64, ssl as _ssl, urllib.request as _req
    body     = await request.json()
    host     = (body.get('host') or '').strip().rstrip('/')
    cp_user  = (body.get('cp_user') or '').strip()
    cp_pass  = (body.get('cp_pass') or '').strip()
    cp_token = (body.get('cp_token') or '').strip()
    port     = int(body.get('port') or 2083)
    limit    = min(int(body.get('limit') or 50), 200)
    if not host or not cp_user:
        raise HTTPException(400, 'cPanel host and username required')
    base = host if host.startswith('http') else f'https://{host}:{port}'
    if cp_token:
        auth_header = f'cpanel {cp_user}:{cp_token}'
    elif cp_pass:
        auth_header = 'Basic ' + _b64.b64encode(f'{cp_user}:{cp_pass}'.encode()).decode()
    else:
        raise HTTPException(400, 'Password or API token required')
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    def _cp_get(path, timeout=12):
        req = _req.Request(f'{base}{path}', headers={'Authorization': auth_header, 'Accept': 'application/json'})
        try:
            with _req.urlopen(req, timeout=timeout, context=ctx) as r:
                return json.loads(r.read().decode()), None
        except Exception as e:
            return None, str(e)

    events, source, note = [], 'none', ''
    sess, err = _cp_get('/execute/Session/list')
    if sess and isinstance(sess, dict) and sess.get('data') is not None:
        source = 'cpanel_session'
        for s in (sess.get('data') or [])[:limit]:
            events.append({'timestamp': str(s.get('session_create') or ''), 'user': str(s.get('session_login') or cp_user),
                           'event': f"Active session — {s.get('session_type','cPanel')} — {str(s.get('user_agent',''))[:40]}",
                           'ip': str(s.get('remote_addr') or ''), 'severity': 'INFO', 'status': 'active', 'source': 'cpanel_session'})
    ll, _ = _cp_get('/execute/LastLogin/get_last_or_current_logged_in_ip')
    if ll and isinstance(ll, dict) and ll.get('data'):
        d2 = ll['data']
        ip = str(d2.get('ip') or d2.get('last_login_ip') or '')
        if ip:
            events.append({'timestamp': str(d2.get('unix_last_login') or ''), 'user': cp_user, 'ip': ip,
                           'event': 'Last recorded login IP', 'severity': 'INFO', 'status': 'success', 'source': 'cpanel_lastlogin'})
            source = source or 'cpanel_lastlogin'
    if not events:
        note = (f'Could not connect: {err}. Check host/port/credentials.' if err
                else 'Connected but no active sessions found.')
    return {'events': events[:limit], 'total': len(events), 'source': source, 'note': note}


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
# Vulnerability Intelligence  (NIST NVD · CISA KEV · EPSS · Exploit-DB)
# ═══════════════════════════════════════════════════════════════════════════════

from dashboard import vuln_intel as _vi


@app.get("/api/vuln-intel/cve/{cve_id}")
async def api_nvd_cve(cve_id: str) -> dict:
    """Look up a single CVE in NIST NVD v2."""
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id.upper()):
        raise HTTPException(400, "Invalid CVE ID format (expected CVE-YYYY-NNNNN)")
    return _vi.nvd_lookup(cve_id.upper())


@app.get("/api/vuln-intel/kev")
async def api_kev_list(cve: str = Query("")) -> dict:
    """
    Return CISA KEV data.
    ?cve=CVE-XXXX,CVE-YYYY  — look up specific IDs.
    No param                 — return stats + full list.
    """
    if cve:
        ids = [c.strip().upper() for c in cve.split(",") if c.strip()]
        return {"results": _vi.kev_lookup(ids)}
    stats = _vi.kev_stats()
    # Return full list (small enough, ~1000 entries)
    kev_map = _vi._load_kev()
    return {
        "total":   stats["total"],
        "entries": [{"cve_id": k, **v} for k, v in list(kev_map.items())[:200]],
    }


@app.get("/api/vuln-intel/epss")
async def api_epss(cves: str = Query(..., description="Comma-separated CVE IDs")) -> dict:
    """Return EPSS exploitation probability scores from FIRST.org."""
    ids = [c.strip().upper() for c in cves.split(",") if c.strip()]
    if not ids:
        raise HTTPException(400, "cves parameter required")
    return {"results": _vi.epss_lookup(ids)}


@app.get("/api/vuln-intel/correlate")
async def api_vuln_correlate(
    target: str = Query("", description="Optional target filter"),
    limit: int = Query(200, ge=1, le=500),
) -> dict:
    """
    Extract CVEs from scan outputs, enrich with NVD + KEV + EPSS + Exploit-DB,
    and return prioritised threat intelligence report.
    """
    scans = db.get_recent_scans(limit)
    if target:
        scans = [s for s in scans if target.lower() in (s.get("target") or "").lower()]
    result = _vi.correlate_scans(scans, max_cves=50)
    return result


@app.get("/api/vuln-intel/scan/{scan_id}")
async def api_vuln_for_scan(scan_id: int) -> dict:
    """Return CVE intel for a single scan record."""
    row = db.get_scan(scan_id)
    if not row:
        raise HTTPException(404, "Scan not found")
    cves = _vi.extract_cves(row.get("output", ""))
    enriched = _vi.correlate(cves[:20])
    return {"scan_id": scan_id, "target": row.get("target"), "cves": enriched}


# ─────────────────────────────────────────────────────────────────────────────
# PowerBI / Data export
# Exports scan + CVE intel as a structured JSON payload suitable for
# ingestion into Power BI via its REST API (Push Dataset) or as a flat
# JSON file that Power BI Desktop can import via "Get Data → JSON".
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/export/powerbi")
async def api_export_powerbi(
    limit: int = Query(500, ge=1, le=2000),
    include_intel: bool = Query(True),
) -> dict:
    """
    Export scan history + vulnerability intel in Power BI-compatible format.

    Schema follows Power BI Push Dataset conventions:
      tables:
        - scans   : scan records
        - cves    : enriched CVE intelligence
        - kev     : CISA KEV summary

    Import into Power BI Desktop via:
      Home → Get Data → JSON → paste the download URL
    """
    scans = db.get_recent_scans(limit)
    scan_rows = []
    for s in scans:
        scan_rows.append({
            "ScanId":      s.get("id"),
            "Target":      s.get("target", ""),
            "AgentType":   s.get("agent_type", ""),
            "Model":       s.get("model", ""),
            "Status":      s.get("status", ""),
            "Risk":        s.get("risk", "INFO"),
            "LatencyS":    s.get("latency_s", 0),
            "ToolCount":   s.get("tool_count", 0),
            "Date":        (s.get("created_at") or "")[:10],
            "DateTime":    (s.get("created_at") or "").replace(" ", "T"),
            "HasCritical": bool(re.search(r"\bcritical\b", s.get("output", ""), re.I)),
            "HasHigh":     bool(re.search(r"\bhigh\b", s.get("output", ""), re.I)),
        })

    cve_rows: list[dict] = []
    kev_summary: dict = {}
    if include_intel:
        intel = _vi.correlate_scans(scans, max_cves=100)
        for row in intel.get("cves", []):
            nvd = row.get("nvd") or {}
            cve_rows.append({
                "CveId":          row["cve_id"],
                "InKEV":          row["in_kev"],
                "EpssScore":      row.get("epss_score"),
                "EpssPercentile": row.get("epss_pct"),
                "CvssScore":      nvd.get("cvss_score"),
                "CvssSeverity":   nvd.get("severity", ""),
                "Published":      nvd.get("published", ""),
                "Description":    nvd.get("description", "")[:200],
                "AffectedTargets": ", ".join(row.get("affected_targets", [])),
                "ExploitDbUrl":   row.get("edb_url", ""),
                "KevProduct":     (row.get("kev") or {}).get("product", ""),
                "KevDueDate":     (row.get("kev") or {}).get("due_date", ""),
            })
        kev_summary = _vi.kev_stats()

    return {
        "schema_version": "1.0",
        "exported_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_name":   "CyberINK Security Intelligence",
        "tables": {
            "scans": scan_rows,
            "cves":  cve_rows,
            "kev_stats": [kev_summary] if kev_summary else [],
        },
        "powerbi_notes": (
            "Import via Power BI Desktop: Home > Get Data > JSON. "
            "Expand 'tables' record, then load scans and cves tables separately. "
            "Relate on Target / AffectedTargets fields."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("CFAI_DASHBOARD_PORT", 8889))
    print(f"CF_AI FastAPI dashboard → http://0.0.0.0:{port}")
    print(f"  API docs             → http://0.0.0.0:{port}/api/docs")
    uvicorn.run("dashboard.api_fast:app", host="0.0.0.0", port=port, reload=False, workers=1)
