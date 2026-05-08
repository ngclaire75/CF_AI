"""
CyberINK Vulnerability Intelligence Module
Integrates: NIST NVD API v2, CISA KEV, EPSS (FIRST.org), Exploit-DB (CSV)
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse as _up
import urllib.request as _req
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Cache paths ────────────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent.parent / "data"
_DATA_DIR.mkdir(exist_ok=True)
_KEV_CACHE    = _DATA_DIR / "cisa_kev_cache.json"
_EPSS_CACHE   = _DATA_DIR / "epss_cache.json"
_NVD_CACHE    = _DATA_DIR / "nvd_cache.json"
_EDB_CSV      = _DATA_DIR / "exploitdb_files_exploits.csv"

_KEV_TTL   = 6 * 3600    # re-fetch KEV every 6 hours
_EPSS_TTL  = 3600         # EPSS scores valid 1 hour
_NVD_TTL   = 3600         # NVD entries valid 1 hour

# ── Regex to extract CVE IDs from any text ────────────────────────────────────
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)


def extract_cves(text: str) -> list[str]:
    """Return deduplicated, upper-case CVE IDs found in text."""
    return list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(text or "")))


# ─────────────────────────────────────────────────────────────────────────────
# Generic helpers
# ─────────────────────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 10, headers: dict | None = None) -> dict | list | None:
    h = {"User-Agent": "CyberINK-VulnIntel/1.0", "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        req = _req.Request(url, headers=h)
        with _req.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        return {"_error": str(exc)[:200]}


def _load_cache(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text("utf-8"))
    except Exception:
        pass
    return {}


def _save_cache(path: Path, data: dict) -> None:
    try:
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# NIST NVD API v2
# ─────────────────────────────────────────────────────────────────────────────

def nvd_lookup(cve_id: str) -> dict:
    """
    Look up a single CVE from the NIST NVD API v2.
    Returns a dict with: id, description, cvss_score, cvss_severity,
    cvss_vector, published, modified, references, cpes.
    """
    cve_id = cve_id.upper().strip()
    cache = _load_cache(_NVD_CACHE)
    now = time.time()

    if cve_id in cache and now - cache[cve_id].get("_ts", 0) < _NVD_TTL:
        return cache[cve_id]

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={_up.quote(cve_id)}"
    # NVD rate limit: 5 req / 30s without API key; 50 req/30s with key
    api_key = _nvd_api_key()
    hdrs = {"apiKey": api_key} if api_key else {}
    raw = _http_get(url, timeout=12, headers=hdrs)

    result: dict = {"id": cve_id, "_ts": now}
    if raw and not raw.get("_error") and raw.get("vulnerabilities"):
        vuln = raw["vulnerabilities"][0].get("cve", {})
        # Description
        descs = vuln.get("descriptions", [])
        result["description"] = next(
            (d["value"] for d in descs if d.get("lang") == "en"), ""
        )
        # CVSS
        metrics = vuln.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                result["cvss_score"]    = m.get("baseScore")
                result["cvss_severity"] = m.get("baseSeverity") or m.get("baseScore", "")
                result["cvss_vector"]   = m.get("vectorString", "")
                break
        result["published"] = vuln.get("published", "")[:10]
        result["modified"]  = vuln.get("lastModified", "")[:10]
        result["references"] = [
            r.get("url", "") for r in vuln.get("references", [])[:5]
        ]
        result["cpes"] = [
            c.get("criteria", "")
            for c in (vuln.get("configurations") or [{}])[:3]
        ]
        result["_found"] = True
    else:
        result["_found"] = False
        result["_error"] = (raw or {}).get("_error", "NVD: no data returned")

    cache[cve_id] = result
    _save_cache(_NVD_CACHE, cache)
    return result


def _nvd_api_key() -> str:
    """Return NVD API key from env, or empty string."""
    import os
    return os.environ.get("NVD_API_KEY", "")


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV — Known Exploited Vulnerabilities catalogue
# ─────────────────────────────────────────────────────────────────────────────

def _load_kev() -> dict:
    """
    Returns dict mapping CVE-ID → KEV entry.
    Cached locally; refreshes every _KEV_TTL seconds.
    """
    cache = _load_cache(_KEV_CACHE)
    now = time.time()
    if cache.get("_ts") and now - cache["_ts"] < _KEV_TTL:
        return cache.get("_data", {})

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    raw = _http_get(url, timeout=15)
    mapping: dict = {}
    if raw and not raw.get("_error"):
        for entry in raw.get("vulnerabilities", []):
            cid = (entry.get("cveID") or "").upper()
            if cid:
                mapping[cid] = {
                    "vendor":        entry.get("vendorProject", ""),
                    "product":       entry.get("product", ""),
                    "name":          entry.get("vulnerabilityName", ""),
                    "date_added":    entry.get("dateAdded", ""),
                    "due_date":      entry.get("dueDate", ""),
                    "required_action": entry.get("requiredAction", ""),
                    "notes":         entry.get("notes", ""),
                }
    new_cache = {"_ts": now, "_data": mapping}
    _save_cache(_KEV_CACHE, new_cache)
    return mapping


def kev_lookup(cve_ids: list[str]) -> dict[str, dict]:
    """Return KEV entries for any CVE IDs in the CISA KEV list."""
    kev = _load_kev()
    return {c: kev[c] for c in cve_ids if c.upper() in kev}


def kev_stats() -> dict:
    """Return basic stats: total, last_updated."""
    kev = _load_kev()
    return {"total": len(kev), "cached": True}


# ─────────────────────────────────────────────────────────────────────────────
# EPSS — Exploit Prediction Scoring System (FIRST.org)
# ─────────────────────────────────────────────────────────────────────────────

def epss_lookup(cve_ids: list[str]) -> dict[str, dict]:
    """
    Return EPSS scores for a list of CVE IDs.
    Each entry: {"score": float, "percentile": float, "date": str}
    """
    if not cve_ids:
        return {}

    cve_ids = [c.upper() for c in cve_ids[:30]]  # API max 100, we cap at 30
    cache = _load_cache(_EPSS_CACHE)
    now = time.time()

    # Filter out what we already have and is fresh
    missing = [c for c in cve_ids if c not in cache or now - cache[c].get("_ts", 0) > _EPSS_TTL]

    if missing:
        param = ",".join(missing[:30])
        url = f"https://api.first.org/data/v1/epss?cve={_up.quote(param)}"
        raw = _http_get(url, timeout=10)
        if raw and not raw.get("_error"):
            for entry in raw.get("data", []):
                cid = (entry.get("cve") or "").upper()
                if cid:
                    cache[cid] = {
                        "score":      float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                        "date":       entry.get("date", ""),
                        "_ts":        now,
                    }
        _save_cache(_EPSS_CACHE, cache)

    return {c: {k: v for k, v in cache[c].items() if not k.startswith("_")}
            for c in cve_ids if c in cache}


# ─────────────────────────────────────────────────────────────────────────────
# Exploit-DB  (offline CSV lookup)
# ─────────────────────────────────────────────────────────────────────────────

_edb_index: dict | None = None  # cve_id → [edb_id, ...]

def _load_edb_index() -> dict:
    global _edb_index
    if _edb_index is not None:
        return _edb_index

    _edb_index = {}
    if not _EDB_CSV.exists():
        return _edb_index

    try:
        import csv
        with _EDB_CSV.open(newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_field = row.get("codes", "") or row.get("CVE", "") or ""
                for cve in _CVE_RE.findall(cve_field):
                    cid = cve.upper()
                    edb_id = row.get("id", "") or row.get("EDB-ID", "")
                    if edb_id:
                        _edb_index.setdefault(cid, []).append(edb_id)
    except Exception:
        pass
    return _edb_index


def edb_lookup(cve_ids: list[str]) -> dict[str, list[str]]:
    """Return Exploit-DB IDs for any CVEs found in the local CSV."""
    idx = _load_edb_index()
    result = {}
    for c in cve_ids:
        entries = idx.get(c.upper())
        if entries:
            result[c.upper()] = entries[:5]
    return result


def edb_search_url(cve_id: str) -> str:
    return f"https://www.exploit-db.com/search?cve={_up.quote(cve_id.upper())}"


# ─────────────────────────────────────────────────────────────────────────────
# Correlate — combine all sources for a list of CVEs
# ─────────────────────────────────────────────────────────────────────────────

def correlate(cve_ids: list[str]) -> list[dict]:
    """
    For each CVE ID, return enriched info from NVD + KEV + EPSS + EDB.
    Sorted by EPSS score desc (most exploitable first).
    """
    if not cve_ids:
        return []

    cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids))[:50]

    kev_data  = kev_lookup(cve_ids)
    epss_data = epss_lookup(cve_ids)
    edb_data  = edb_lookup(cve_ids)

    results = []
    for cid in cve_ids:
        row: dict = {
            "cve_id":        cid,
            "in_kev":        cid in kev_data,
            "kev":           kev_data.get(cid, {}),
            "epss_score":    epss_data.get(cid, {}).get("score"),
            "epss_pct":      epss_data.get(cid, {}).get("percentile"),
            "edb_ids":       edb_data.get(cid, []),
            "edb_url":       edb_search_url(cid) if cid in edb_data else "",
            "nvd":           {},
        }
        # NVD lookup (skip if batch is large to avoid rate limits)
        if len(cve_ids) <= 10:
            nvd = nvd_lookup(cid)
            if nvd.get("_found"):
                row["nvd"] = {
                    "description": nvd.get("description", "")[:300],
                    "cvss_score":  nvd.get("cvss_score"),
                    "severity":    nvd.get("cvss_severity", ""),
                    "vector":      nvd.get("cvss_vector", ""),
                    "published":   nvd.get("published", ""),
                    "refs":        nvd.get("references", [])[:3],
                }
        results.append(row)

    # Sort: KEV first, then by EPSS score desc
    results.sort(key=lambda r: (
        -int(r["in_kev"]),
        -(r["epss_score"] or 0),
        -(r["nvd"].get("cvss_score") or 0),
    ))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Correlate scans — extract CVEs from scan outputs and enrich
# ─────────────────────────────────────────────────────────────────────────────

def correlate_scans(scans: list[dict], max_cves: int = 30) -> dict:
    """
    Extract CVEs from scan outputs and return enriched vulnerability intel.
    Returns: {cves: [...], by_target: {target: [cve_ids]}, kev_count, epss_high}
    """
    by_target: dict[str, list] = {}
    all_cves: list[str] = []
    cve_to_targets: dict[str, list] = {}

    for s in scans:
        target = s.get("target", "")
        cves = extract_cves(s.get("output", ""))
        if cves:
            by_target[target] = list(dict.fromkeys(by_target.get(target, []) + cves))
            for c in cves:
                cve_to_targets.setdefault(c, [])
                if target not in cve_to_targets[c]:
                    cve_to_targets[c].append(target)
            all_cves.extend(cves)

    unique_cves = list(dict.fromkeys(all_cves))[:max_cves]
    enriched = correlate(unique_cves)

    # Attach affected targets to each enriched entry
    for row in enriched:
        row["affected_targets"] = cve_to_targets.get(row["cve_id"], [])

    kev_count  = sum(1 for r in enriched if r["in_kev"])
    epss_high  = sum(1 for r in enriched if (r["epss_score"] or 0) >= 0.5)

    return {
        "cves":        enriched,
        "by_target":   by_target,
        "total_cves":  len(unique_cves),
        "kev_count":   kev_count,
        "epss_high":   epss_high,
    }
