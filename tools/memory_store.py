"""
CF_AI — Smart Memory System.
Persistent long-term storage for agent research results, successful approaches,
target intelligence, and security findings across sessions.

Storage: JSON files in data/memory/ (gitignored like other data/).
Each memory entry has: id, type, tags, target, content, created, accessed, score.
"""
from __future__ import annotations
import json
import os
import re
import time
import uuid
from pathlib import Path
from sdk.agents import function_tool

_MEMORY_DIR = Path(__file__).parent.parent / 'data' / 'memory'
_MEMORY_DIR.mkdir(parents=True, exist_ok=True)

_MEMORY_TYPES = {
    'finding':     'Confirmed security vulnerability or weakness',
    'approach':    'Successful testing technique or bypass method',
    'target_info': 'Intelligence gathered about a specific target',
    'credential':  'Discovered credentials or authentication details (use carefully)',
    'tool_result': 'Successful tool execution output worth remembering',
    'pattern':     'Recurring vulnerability pattern across multiple targets',
    'note':        'General research note or observation',
}


def _index_path() -> Path:
    return _MEMORY_DIR / 'index.json'


def _load_index() -> list[dict]:
    p = _index_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return []


def _save_index(index: list[dict]) -> None:
    _index_path().write_text(json.dumps(index, indent=2), encoding='utf-8')


def _load_entry(entry_id: str) -> dict | None:
    p = _MEMORY_DIR / f'{entry_id}.json'
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return None


def _save_entry(entry: dict) -> None:
    p = _MEMORY_DIR / f'{entry["id"]}.json'
    p.write_text(json.dumps(entry, indent=2), encoding='utf-8')


# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def memory_save(content: str, memory_type: str = 'note', target: str = '',
                tags: str = '', title: str = '') -> str:
    """
    Save important findings, successful approaches, or target intelligence to long-term memory.
    Persists across sessions — agents can recall this in future engagements.

    Args:
        content:     The information to remember (vulnerability details, bypass technique, etc.)
        memory_type: Type — finding | approach | target_info | credential | tool_result | pattern | note
        target:      Target domain/IP this applies to (e.g. "example.com", or "" for general)
        tags:        Comma-separated tags (e.g. "sqli,authentication,critical")
        title:       Short descriptive title (auto-generated from content if empty)

    Returns: Memory entry ID and confirmation.
    """
    if not content or not content.strip():
        return json.dumps({'error': 'content cannot be empty'})

    if memory_type not in _MEMORY_TYPES:
        memory_type = 'note'

    # Auto-generate title from first sentence if not provided
    if not title:
        first_line = content.strip().split('\n')[0]
        title = first_line[:80] + ('...' if len(first_line) > 80 else '')

    entry_id = str(uuid.uuid4())[:8]
    ts       = int(time.time())
    tag_list = [t.strip().lower() for t in tags.split(',') if t.strip()]

    entry = {
        'id':      entry_id,
        'type':    memory_type,
        'title':   title,
        'target':  target.strip(),
        'tags':    tag_list,
        'content': content.strip(),
        'created': ts,
        'accessed': ts,
        'score':   1,
    }
    _save_entry(entry)

    # Update index
    index = _load_index()
    index.append({
        'id':      entry_id,
        'type':    memory_type,
        'title':   title,
        'target':  target.strip(),
        'tags':    tag_list,
        'created': ts,
        'score':   1,
    })
    _save_index(index)

    return json.dumps({
        'ok':      True,
        'id':      entry_id,
        'type':    memory_type,
        'title':   title,
        'message': f'Saved to memory (ID: {entry_id}). Use memory_recall to retrieve.',
    })


@function_tool
def memory_recall(query: str = '', target: str = '', memory_type: str = '',
                  tags: str = '', max_results: int = 10) -> str:
    """
    Recall relevant memories from long-term storage.
    Search by keyword, target domain, type, or tags.
    Use this at the START of each engagement to check for prior findings.

    Args:
        query:       Keyword search in title and content
        target:      Filter by target domain (e.g. "example.com")
        memory_type: Filter by type (finding|approach|target_info|credential|tool_result|pattern|note)
        tags:        Comma-separated tags to filter by
        max_results: Maximum entries to return (default 10)

    Returns: List of matching memory entries with full content.
    """
    index = _load_index()
    if not index:
        return json.dumps({'message': 'Memory store is empty — no prior research found.', 'results': []})

    query_lower = query.lower()
    tag_filter  = [t.strip().lower() for t in tags.split(',') if t.strip()]
    target_lower = target.lower()

    scored: list[tuple[int, dict]] = []
    for meta in index:
        score = meta.get('score', 1)

        # Type filter
        if memory_type and meta.get('type') != memory_type:
            continue

        # Target filter
        if target_lower and target_lower not in meta.get('target', '').lower():
            continue

        # Tag filter
        if tag_filter:
            if not any(t in meta.get('tags', []) for t in tag_filter):
                continue

        # Keyword search (title match scores higher)
        if query_lower:
            title_match   = query_lower in meta.get('title', '').lower()
            # Load full entry for content search only if title matches or it's a small query
            if not title_match:
                entry = _load_entry(meta['id'])
                if not entry or query_lower not in entry.get('content', '').lower():
                    continue
                score += 1
            else:
                score += 3

        scored.append((score, meta))

    # Sort by score desc, then by created desc
    scored.sort(key=lambda x: (x[0], x[1].get('created', 0)), reverse=True)

    results = []
    for _, meta in scored[:max_results]:
        entry = _load_entry(meta['id'])
        if entry:
            # Update access time and score
            entry['accessed'] = int(time.time())
            entry['score']    = entry.get('score', 1) + 1
            _save_entry(entry)
            results.append({
                'id':      entry['id'],
                'type':    entry['type'],
                'title':   entry['title'],
                'target':  entry.get('target', ''),
                'tags':    entry.get('tags', []),
                'created': entry['created'],
                'content': entry['content'],
            })

    return json.dumps({
        'query':        query or '(all)',
        'target_filter': target,
        'total_found':  len(scored),
        'results':      results,
    }, indent=2)


@function_tool
def memory_delete(entry_id: str) -> str:
    """
    Delete a memory entry by ID.

    Args:
        entry_id: Memory entry ID (8-character hex, returned by memory_save)
    """
    p = _MEMORY_DIR / f'{entry_id}.json'
    if not p.exists():
        return json.dumps({'error': f'Memory entry {entry_id} not found'})

    p.unlink()

    # Remove from index
    index = _load_index()
    index = [m for m in index if m.get('id') != entry_id]
    _save_index(index)

    return json.dumps({'ok': True, 'deleted': entry_id})


@function_tool
def memory_list(memory_type: str = '', target: str = '', limit: int = 20) -> str:
    """
    List all memory entries (index only — no full content).
    Useful for getting an overview of stored research before deciding what to recall.

    Args:
        memory_type: Filter by type (optional)
        target:      Filter by target domain (optional)
        limit:       Maximum entries to list (default 20)
    """
    index = _load_index()
    if not index:
        return json.dumps({'total': 0, 'entries': [], 'message': 'No memories stored yet.'})

    filtered = []
    for m in sorted(index, key=lambda x: x.get('created', 0), reverse=True):
        if memory_type and m.get('type') != memory_type:
            continue
        if target and target.lower() not in m.get('target', '').lower():
            continue
        filtered.append({
            'id':      m['id'],
            'type':    m['type'],
            'title':   m['title'],
            'target':  m.get('target', ''),
            'tags':    m.get('tags', []),
            'created': m.get('created', 0),
        })
        if len(filtered) >= limit:
            break

    return json.dumps({
        'total':   len(index),
        'showing': len(filtered),
        'entries': filtered,
    }, indent=2)


@function_tool
def memory_update(entry_id: str, content: str = '', tags: str = '',
                  title: str = '', score_boost: int = 0) -> str:
    """
    Update an existing memory entry — append new content, change tags, or boost relevance score.

    Args:
        entry_id:    Memory entry ID to update
        content:     New content to APPEND to existing (leave empty to not change content)
        tags:        New comma-separated tags to ADD (leave empty to not change)
        title:       New title (leave empty to not change)
        score_boost: Increase relevance score by this amount (useful for marking verified findings)
    """
    entry = _load_entry(entry_id)
    if not entry:
        return json.dumps({'error': f'Memory entry {entry_id} not found'})

    if content:
        entry['content'] += f'\n\n--- Update {time.strftime("%Y-%m-%d %H:%M")} ---\n{content.strip()}'
    if tags:
        new_tags = [t.strip().lower() for t in tags.split(',') if t.strip()]
        entry['tags'] = sorted(set(entry.get('tags', []) + new_tags))
    if title:
        entry['title'] = title
    if score_boost:
        entry['score'] = entry.get('score', 1) + score_boost

    entry['accessed'] = int(time.time())
    _save_entry(entry)

    # Update index
    index = _load_index()
    for m in index:
        if m.get('id') == entry_id:
            if title:
                m['title'] = title
            if tags:
                m['tags'] = entry['tags']
            if score_boost:
                m['score'] = entry['score']
            break
    _save_index(index)

    return json.dumps({'ok': True, 'id': entry_id, 'title': entry['title'],
                       'tags': entry['tags'], 'score': entry['score']})
