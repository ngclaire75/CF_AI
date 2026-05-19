"""
CF_AI — Knowledge Graph Integration (Graphiti-style, Neo4j backend).
Stores entities, relationships, and semantic context across security engagements.
Enables tracking attack paths, asset relationships, and vulnerability chains.

Neo4j Aura cloud: set NEO4J_CLIENT_ID + NEO4J_CLIENT_SECRET — URI is auto-discovered.
Direct connection:  set NEO4J_URI + NEO4J_USER + NEO4J_PASSWORD.
JSON fallback:      used automatically when Neo4j is not configured or unavailable.
"""
from __future__ import annotations
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from sdk.agents import function_tool

# ── Fallback JSON store (when Neo4j unavailable) ──────────────────────────────
_KG_DIR = Path(__file__).parent.parent / 'data' / 'knowledge_graph'
_KG_DIR.mkdir(parents=True, exist_ok=True)

_AURA_CACHE: dict = {}   # cache: {'uri': ..., 'user': ..., 'pw': ..., 'expires': int}


def _kg_path(filename: str) -> Path:
    return _KG_DIR / filename


def _load_json(filename: str, default):
    p = _kg_path(filename)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default


def _save_json(filename: str, data) -> None:
    _kg_path(filename).write_text(json.dumps(data, indent=2), encoding='utf-8')


# ── Neo4j Aura OAuth auto-discovery ──────────────────────────────────────────
def _curl_json(url: str, method: str = 'GET', data: str = '',
               headers: list[str] | None = None) -> dict | None:
    flags = ['-s', '-4', '-L', '--connect-timeout', '8', '--max-time', '15',
             '-w', '\n__STATUS__%{http_code}']
    if method == 'POST':
        flags += ['-X', 'POST', '--data', data or '']
    for h in (headers or []):
        flags += ['-H', h]
    flags.append(url)
    try:
        r = subprocess.run(['curl'] + flags, capture_output=True, text=True, timeout=20)
        body, _, st_str = r.stdout.rpartition('\n__STATUS__')
        if int(st_str.strip() or '0') not in (200, 201):
            return None
        return json.loads(body.strip())
    except Exception:
        return None


def _aura_resolve_connection() -> tuple[str, str, str]:
    """
    Use NEO4J_CLIENT_ID + NEO4J_CLIENT_SECRET to get an OAuth token from
    the Neo4j Aura API, then discover the first instance's connection URI.
    Returns (uri, user, password) or ('', '', '') on failure.
    Caches the result for 45 minutes to avoid repeated API calls.
    """
    global _AURA_CACHE
    client_id     = os.environ.get('NEO4J_CLIENT_ID', '').strip()
    client_secret = os.environ.get('NEO4J_CLIENT_SECRET', '').strip()
    if not client_id or not client_secret:
        return '', '', ''

    now = int(time.time())
    if _AURA_CACHE.get('expires', 0) > now:
        return _AURA_CACHE['uri'], _AURA_CACHE['user'], _AURA_CACHE['pw']

    # Step 1: get OAuth bearer token
    token_data = _curl_json(
        'https://api.neo4j.io/oauth/token',
        method='POST',
        data=f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}',
        headers=['Content-Type: application/x-www-form-urlencoded'],
    )
    if not token_data or not token_data.get('access_token'):
        return '', '', ''

    bearer = token_data['access_token']

    # Step 2: list Aura instances
    instances = _curl_json(
        'https://api.neo4j.io/v1/instances',
        headers=[f'Authorization: Bearer {bearer}', 'Content-Type: application/json'],
    )
    if not instances:
        return '', '', ''

    # Pick first running instance
    for inst in (instances.get('data') or []):
        if inst.get('status') in ('running', 'ready'):
            uri      = inst.get('connection_url', '')
            username = inst.get('username', 'neo4j')
            # Password is not returned by API — must be in NEO4J_PASSWORD env var
            pw = os.environ.get('NEO4J_PASSWORD', '').strip()
            if uri:
                _AURA_CACHE = {'uri': uri, 'user': username, 'pw': pw, 'expires': now + 2700}
                # Write discovered URI back to env so other code can see it
                os.environ['NEO4J_URI']  = uri
                os.environ['NEO4J_USER'] = username
                return uri, username, pw

    return '', '', ''


# ── Neo4j driver (optional) ───────────────────────────────────────────────────
def _get_neo4j_driver():
    uri  = os.environ.get('NEO4J_URI', '').strip()
    # Accept NEO4J_USERNAME (Aura default) or NEO4J_USER
    user = (os.environ.get('NEO4J_USERNAME') or os.environ.get('NEO4J_USER') or 'neo4j').strip()
    pw   = os.environ.get('NEO4J_PASSWORD', '').strip()
    db   = os.environ.get('NEO4J_DATABASE', 'neo4j').strip()

    # If URI not set, try Aura auto-discovery
    if not uri:
        uri, user, pw = _aura_resolve_connection()

    if not uri or not pw:
        return None
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, pw))
        driver.verify_connectivity()
        return driver
    except Exception:
        return None


def _neo4j_database() -> str:
    return os.environ.get('NEO4J_DATABASE', 'neo4j').strip()


def _neo4j_run(query: str, params: dict = None):
    driver = _get_neo4j_driver()
    if not driver:
        return None
    try:
        with driver.session(database=_neo4j_database()) as s:
            result = s.run(query, params or {})
            return [dict(r) for r in result]
    except Exception:
        return None
    finally:
        driver.close()


def _neo4j_available() -> bool:
    return _get_neo4j_driver() is not None


# ── Entity types ──────────────────────────────────────────────────────────────
_ENTITY_TYPES = {
    'domain':       'Domain or subdomain',
    'ip':           'IP address or CIDR range',
    'service':      'Network service or port',
    'technology':   'Software framework, CMS, or library',
    'vulnerability':'Security vulnerability or CVE',
    'credential':   'Credential or authentication material',
    'endpoint':     'URL path, API endpoint, or route',
    'finding':      'Security finding or observation',
    'actor':        'Threat actor or user identity',
    'asset':        'Server, container, or cloud resource',
}

_REL_TYPES = {
    'HOSTS':        'Server hosts a service or endpoint',
    'RUNS':         'Asset runs a technology',
    'HAS_VULN':     'Entity has a vulnerability',
    'CONNECTS_TO':  'Network connection or dependency',
    'AUTHENTICATES':'Credential authenticates to service',
    'EXPOSES':      'Service exposes an endpoint',
    'AFFECTS':      'Vulnerability affects technology',
    'LEADS_TO':     'Finding or vuln leads to another',
    'OWNED_BY':     'Asset or domain belongs to an org',
    'RELATED_TO':   'Generic relationship',
}


# ── JSON fallback helpers ─────────────────────────────────────────────────────
def _jload_entities() -> dict:
    return _load_json('entities.json', {})


def _jload_rels() -> list:
    return _load_json('relationships.json', [])


def _jsave_entities(entities: dict) -> None:
    _save_json('entities.json', entities)


def _jsave_rels(rels: list) -> None:
    _save_json('relationships.json', rels)


# ── Tools ─────────────────────────────────────────────────────────────────────

@function_tool
def kg_add_entity(name: str, entity_type: str, target: str = '',
                  properties: str = '', labels: str = '') -> str:
    """
    Add or update an entity node in the knowledge graph.
    Use to track domains, IPs, services, technologies, vulnerabilities, findings.

    Args:
        name:        Entity identifier (e.g. "example.com", "CVE-2021-44228", "/admin/login")
        entity_type: Type — domain|ip|service|technology|vulnerability|credential|endpoint|finding|actor|asset
        target:      Target domain this belongs to (for scoping, e.g. "example.com")
        properties:  JSON string of extra properties (e.g. '{"port": 443, "version": "1.18"}')
        labels:      Comma-separated labels (e.g. "critical,exposed,wordpress")

    Returns: Entity ID and status.
    """
    if not name or not name.strip():
        return json.dumps({'error': 'name is required'})

    if entity_type not in _ENTITY_TYPES:
        entity_type = 'asset'

    props = {}
    if properties:
        try:
            props = json.loads(properties)
        except Exception:
            props = {'raw': properties}

    label_list = [l.strip().lower() for l in labels.split(',') if l.strip()]
    ts = int(time.time())

    # Neo4j path
    if _neo4j_available():
        label_str = ':'.join(['Entity', entity_type.title()] + [l.title() for l in label_list[:3]])
        query = (
            f'MERGE (e:{label_str} {{name: $name}}) '
            'SET e += $props, e.entity_type = $etype, e.target = $target, '
            'e.updated = $ts, e.labels = $labels '
            'RETURN e.name as name, id(e) as neo_id'
        )
        result = _neo4j_run(query, {
            'name': name.strip(), 'props': props, 'etype': entity_type,
            'target': target.strip(), 'ts': ts, 'labels': label_list,
        })
        if result is not None:
            neo_id = result[0].get('neo_id', 'neo4j') if result else 'neo4j'
            return json.dumps({'ok': True, 'id': str(neo_id), 'name': name, 'type': entity_type, 'backend': 'neo4j'})

    # JSON fallback
    entities = _jload_entities()
    eid = name.strip().lower().replace(' ', '_')
    entities[eid] = {
        'id':          eid,
        'name':        name.strip(),
        'type':        entity_type,
        'target':      target.strip(),
        'properties':  props,
        'labels':      label_list,
        'created':     entities.get(eid, {}).get('created', ts),
        'updated':     ts,
    }
    _jsave_entities(entities)
    return json.dumps({'ok': True, 'id': eid, 'name': name, 'type': entity_type, 'backend': 'json'})


@function_tool
def kg_add_relationship(from_entity: str, relationship: str, to_entity: str,
                        target: str = '', properties: str = '') -> str:
    """
    Add a relationship (edge) between two entities in the knowledge graph.
    Use to model attack paths, dependencies, ownership, and vulnerability chains.

    Args:
        from_entity:  Source entity name (must exist or will be created as 'asset')
        relationship: Relationship type — HOSTS|RUNS|HAS_VULN|CONNECTS_TO|AUTHENTICATES|
                      EXPOSES|AFFECTS|LEADS_TO|OWNED_BY|RELATED_TO
        to_entity:    Target entity name
        target:       Target domain scope (e.g. "example.com")
        properties:   JSON string of edge properties (e.g. '{"confidence": "high", "cvss": 9.8}')

    Returns: Relationship ID and status.
    """
    if not from_entity or not to_entity:
        return json.dumps({'error': 'from_entity and to_entity are required'})

    if relationship not in _REL_TYPES:
        relationship = 'RELATED_TO'

    props = {}
    if properties:
        try:
            props = json.loads(properties)
        except Exception:
            props = {'raw': properties}

    ts = int(time.time())

    # Neo4j path
    if _neo4j_available():
        query = (
            'MERGE (a:Entity {name: $from_name}) '
            'MERGE (b:Entity {name: $to_name}) '
            f'MERGE (a)-[r:{relationship}]->(b) '
            'SET r += $props, r.target = $target, r.updated = $ts '
            'RETURN id(r) as rel_id'
        )
        result = _neo4j_run(query, {
            'from_name': from_entity.strip(), 'to_name': to_entity.strip(),
            'props': props, 'target': target.strip(), 'ts': ts,
        })
        if result is not None:
            rel_id = result[0].get('rel_id', 'neo4j') if result else 'neo4j'
            return json.dumps({'ok': True, 'id': str(rel_id), 'from': from_entity,
                               'rel': relationship, 'to': to_entity, 'backend': 'neo4j'})

    # JSON fallback
    rels = _jload_rels()
    rel_id = str(uuid.uuid4())[:8]
    rels.append({
        'id':           rel_id,
        'from':         from_entity.strip(),
        'relationship': relationship,
        'to':           to_entity.strip(),
        'target':       target.strip(),
        'properties':   props,
        'created':      ts,
    })
    _jsave_rels(rels)
    return json.dumps({'ok': True, 'id': rel_id, 'from': from_entity,
                       'rel': relationship, 'to': to_entity, 'backend': 'json'})


@function_tool
def kg_search(query: str = '', entity_type: str = '', target: str = '',
              max_results: int = 20) -> str:
    """
    Search the knowledge graph for entities matching a query, type, or target.
    Use to retrieve the attack surface map built during previous engagements.

    Args:
        query:       Keyword search in entity names and properties
        entity_type: Filter by type (domain|ip|service|technology|vulnerability|etc.)
        target:      Filter by target domain
        max_results: Maximum entities to return (default 20)

    Returns: List of matching entities with their relationships count.
    """
    # Neo4j path
    if _neo4j_available():
        where_clauses = []
        params: dict = {}
        if query:
            where_clauses.append('toLower(e.name) CONTAINS toLower($query)')
            params['query'] = query
        if entity_type:
            where_clauses.append('e.entity_type = $etype')
            params['etype'] = entity_type
        if target:
            where_clauses.append('e.target = $target')
            params['target'] = target

        where_str = ('WHERE ' + ' AND '.join(where_clauses)) if where_clauses else ''
        cypher = (
            f'MATCH (e:Entity) {where_str} '
            'OPTIONAL MATCH (e)-[r]->() '
            'RETURN e.name as name, e.entity_type as type, e.target as target, '
            'e.labels as labels, e.updated as updated, count(r) as out_degree '
            f'ORDER BY out_degree DESC LIMIT {max_results}'
        )
        result = _neo4j_run(cypher, params)
        if result is not None:
            return json.dumps({'backend': 'neo4j', 'query': query, 'results': result}, indent=2)

    # JSON fallback
    entities = _jload_entities()
    rels      = _jload_rels()
    q_lower   = query.lower()
    target_l  = target.lower()

    out_degree = {}
    for r in rels:
        out_degree[r.get('from', '')] = out_degree.get(r.get('from', ''), 0) + 1

    results = []
    for e in entities.values():
        if entity_type and e.get('type') != entity_type:
            continue
        if target_l and target_l not in e.get('target', '').lower():
            continue
        if q_lower and q_lower not in e.get('name', '').lower():
            props_str = json.dumps(e.get('properties', {})).lower()
            if q_lower not in props_str:
                continue
        results.append({
            'name':       e.get('name', ''),
            'type':       e.get('type', ''),
            'target':     e.get('target', ''),
            'labels':     e.get('labels', []),
            'properties': e.get('properties', {}),
            'updated':    e.get('updated', 0),
            'out_degree': out_degree.get(e.get('id', ''), 0),
        })

    results.sort(key=lambda x: x['out_degree'], reverse=True)
    return json.dumps({
        'backend':  'json',
        'query':    query or '(all)',
        'total':    len(results),
        'results':  results[:max_results],
    }, indent=2)


@function_tool
def kg_get_neighbors(entity_name: str, depth: int = 1, direction: str = 'both') -> str:
    """
    Get all entities connected to a given entity — maps the attack surface around a node.
    Use to trace attack paths from a vulnerability to impacted assets.

    Args:
        entity_name: Name of the starting entity
        depth:       Traversal depth (1=direct neighbors, 2=two hops, max 3)
        direction:   'out' (outgoing), 'in' (incoming), or 'both'

    Returns: Graph of connected entities and relationships.
    """
    depth = min(max(1, depth), 3)

    # Neo4j path
    if _neo4j_available():
        if direction == 'out':
            arrow = '-[r]->'
        elif direction == 'in':
            arrow = '<-[r]-'
        else:
            arrow = '-[r]-'
        cypher = (
            f'MATCH (e:Entity {{name: $name}}){arrow}(n:Entity) '
            'RETURN e.name as source, type(r) as relationship, '
            'n.name as target, n.entity_type as target_type, r as edge_props '
            f'LIMIT 50'
        )
        result = _neo4j_run(cypher, {'name': entity_name.strip()})
        if result is not None:
            return json.dumps({'backend': 'neo4j', 'entity': entity_name, 'edges': result}, indent=2)

    # JSON fallback
    rels = _jload_rels()
    entities = _jload_entities()
    name_lower = entity_name.strip().lower()

    edges = []
    for r in rels:
        from_l = r.get('from', '').lower()
        to_l   = r.get('to', '').lower()
        if direction in ('out', 'both') and from_l == name_lower:
            to_eid = r.get('to', '').lower().replace(' ', '_')
            edges.append({
                'source':       r.get('from', ''),
                'relationship': r.get('relationship', ''),
                'target':       r.get('to', ''),
                'target_type':  entities.get(to_eid, {}).get('type', 'unknown'),
                'properties':   r.get('properties', {}),
            })
        if direction in ('in', 'both') and to_l == name_lower:
            from_eid = r.get('from', '').lower().replace(' ', '_')
            edges.append({
                'source':       r.get('from', ''),
                'relationship': r.get('relationship', ''),
                'target':       r.get('to', ''),
                'target_type':  entities.get(from_eid, {}).get('type', 'unknown'),
                'properties':   r.get('properties', {}),
            })

    return json.dumps({
        'backend':  'json',
        'entity':   entity_name,
        'depth':    depth,
        'edges':    edges[:50],
        'count':    len(edges),
    }, indent=2)


@function_tool
def kg_attack_path(start_entity: str, end_entity: str = '') -> str:
    """
    Find or suggest attack paths between entities in the knowledge graph.
    With end_entity: traces path from start to end.
    Without end_entity: returns all paths from start entity (attack surface from this node).

    Args:
        start_entity: Starting node (e.g. "external_attacker" or a discovered vulnerability)
        end_entity:   Goal node (e.g. "admin_panel", "database", or leave empty for all paths)

    Returns: Attack path(s) with relationship chain.
    """
    # Neo4j shortest path
    if _neo4j_available() and end_entity:
        cypher = (
            'MATCH (a:Entity {name: $start}), (b:Entity {name: $end}), '
            'p = shortestPath((a)-[*1..5]-(b)) '
            'RETURN [n IN nodes(p) | n.name] as path, '
            '[r IN relationships(p) | type(r)] as rels, length(p) as length '
            'LIMIT 5'
        )
        result = _neo4j_run(cypher, {'start': start_entity.strip(), 'end': end_entity.strip()})
        if result is not None:
            return json.dumps({'backend': 'neo4j', 'start': start_entity, 'end': end_entity,
                               'paths': result}, indent=2)

    # JSON BFS fallback
    rels = _jload_rels()
    if not end_entity:
        # Return all direct connections as simple paths
        paths = []
        for r in rels:
            if r.get('from', '').lower() == start_entity.strip().lower():
                paths.append({
                    'path': [r.get('from'), r.get('to')],
                    'rels': [r.get('relationship')],
                    'length': 1,
                })
        return json.dumps({'backend': 'json', 'start': start_entity, 'paths': paths[:20]}, indent=2)

    # BFS
    from collections import deque
    graph: dict = {}
    for r in rels:
        f, t, rel = r.get('from', ''), r.get('to', ''), r.get('relationship', '')
        graph.setdefault(f.lower(), []).append((t, rel))
        graph.setdefault(t.lower(), []).append((f, rel))

    start_l = start_entity.strip().lower()
    end_l   = end_entity.strip().lower()
    queue   = deque([([start_entity], [])])
    visited: set = {start_l}
    found_paths = []

    while queue and len(found_paths) < 5:
        path, path_rels = queue.popleft()
        current = path[-1].lower()
        if len(path) > 6:
            continue
        for neighbor, rel in graph.get(current, []):
            if neighbor.lower() == end_l:
                found_paths.append({'path': path + [neighbor], 'rels': path_rels + [rel], 'length': len(path)})
            elif neighbor.lower() not in visited:
                visited.add(neighbor.lower())
                queue.append((path + [neighbor], path_rels + [rel]))

    return json.dumps({
        'backend': 'json',
        'start':   start_entity,
        'end':     end_entity,
        'paths':   found_paths,
    }, indent=2)


@function_tool
def kg_summary(target: str = '') -> str:
    """
    Get a summary of all entities and relationships in the knowledge graph.
    Optionally scoped to a specific target domain.

    Args:
        target: Filter by target domain (leave empty for all targets)

    Returns: Counts by entity type, relationship type, and top connected nodes.
    """
    if _neo4j_available():
        params = {}
        where  = 'WHERE e.target = $target ' if target else ''
        if target:
            params['target'] = target.strip()

        entity_counts = _neo4j_run(
            f'MATCH (e:Entity) {where}RETURN e.entity_type as type, count(*) as count ORDER BY count DESC',
            params
        ) or []
        rel_counts = _neo4j_run(
            'MATCH ()-[r]->() RETURN type(r) as type, count(*) as count ORDER BY count DESC'
        ) or []
        top_nodes = _neo4j_run(
            f'MATCH (e:Entity) {where}OPTIONAL MATCH (e)-[r]->() '
            'RETURN e.name as name, e.entity_type as type, count(r) as degree '
            'ORDER BY degree DESC LIMIT 10',
            params
        ) or []

        return json.dumps({
            'backend': 'neo4j', 'target': target or '(all)',
            'entity_counts': entity_counts,
            'relationship_counts': rel_counts,
            'top_nodes': top_nodes,
        }, indent=2)

    # JSON fallback
    entities  = _jload_entities()
    rels      = _jload_rels()
    target_l  = target.lower()

    filtered = [e for e in entities.values()
                if not target_l or target_l in e.get('target', '').lower()]

    type_counts: dict = {}
    for e in filtered:
        t = e.get('type', 'unknown')
        type_counts[t] = type_counts.get(t, 0) + 1

    rel_counts: dict = {}
    out_deg: dict = {}
    for r in rels:
        rt = r.get('relationship', 'RELATED_TO')
        rel_counts[rt] = rel_counts.get(rt, 0) + 1
        fn = r.get('from', '')
        out_deg[fn] = out_deg.get(fn, 0) + 1

    top_nodes = sorted(
        [{'name': e.get('name'), 'type': e.get('type'), 'degree': out_deg.get(e.get('name', ''), 0)}
         for e in filtered],
        key=lambda x: x['degree'], reverse=True
    )[:10]

    return json.dumps({
        'backend':            'json',
        'target':             target or '(all)',
        'total_entities':     len(filtered),
        'total_relationships': len(rels),
        'entity_counts':      [{'type': k, 'count': v} for k, v in
                               sorted(type_counts.items(), key=lambda x: -x[1])],
        'relationship_counts': [{'type': k, 'count': v} for k, v in
                                sorted(rel_counts.items(), key=lambda x: -x[1])],
        'top_nodes':          top_nodes,
    }, indent=2)
