"""CF_AI Security Dashboard — Flask web application."""
from __future__ import annotations
import ipaddress
import json as _json
import os
import re
import sys
import time as _time
import threading as _threading
import urllib.parse as _up_parse
import urllib.request as _up_req
import uuid as _uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, abort, request
import dashboard.db as db
from dashboard.remediations import REMEDIATIONS

db.init_db()

app = Flask(__name__, template_folder='templates')

# ── In-memory scan job store (Connect Your Website feature) ──────────────────
_scan_jobs: dict = {}

# ── IP geolocation (ip-api.com, free, no key required) ───────────────────────
_geo_cache: dict[str, str] = {}

def _geoip(ip_or_url: str) -> str:
    """Return 'Country (City)' for a real IP or hostname. Returns '' on failure."""
    raw = (ip_or_url or '').strip()
    if not raw or raw in ('-', '--', ''):
        return ''
    # Extract hostname from URL
    if raw.startswith('http'):
        raw = _up_parse.urlparse(raw).netloc or raw
    ip = raw.split(':')[0].strip()
    if not ip:
        return ''
    if ip in _geo_cache:
        return _geo_cache[ip]
    # Skip private/reserved IPs
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            _geo_cache[ip] = ''
            return ''
    except ValueError:
        pass  # hostname — proceed with lookup
    try:
        url = f'http://ip-api.com/json/{_up_parse.quote(ip)}?fields=status,country,city'
        req = _up_req.Request(url, headers={'User-Agent': 'CF_AI/1.0'})
        with _up_req.urlopen(req, timeout=5) as r:
            data = _json.loads(r.read().decode())
        if data.get('status') == 'success':
            country = data.get('country', '')
            city    = data.get('city', '')
            result  = f'{country} ({city})' if city else country
            _geo_cache[ip] = result
            return result
    except Exception:
        pass
    _geo_cache[ip] = ''
    return ''


def _build_cred_block(site_type: str, creds: dict, domain: str) -> str:
    """Return an agent instruction block for authenticated scanning."""
    if not site_type or site_type == 'none':
        return ''

    wp_user  = creds.get('wp_user', '')
    wp_pass  = creds.get('wp_pass', '')
    wp_app   = creds.get('wp_app_pass', '')
    cp_user  = creds.get('cpanel_user', '')
    ssh_host = creds.get('ssh_host', '') or domain
    ssh_user = creds.get('ssh_user', 'root')
    ssh_pass = creds.get('ssh_pass', '')
    ssh_port = creds.get('ssh_port', '22') or '22'
    ftp_host = creds.get('ftp_host', '') or domain
    ftp_user = creds.get('ftp_user', '')
    ftp_port = creds.get('ftp_port', '') or ('22' if site_type == 'sftp' else '21')

    hdr = (
        '\n\n══════════════ AUTHENTICATED SCAN ══════════════\n'
        'Credentials provided. You MUST use them for every check.\n'
        'NEVER print passwords in output — write [REDACTED] instead.\n'
        '════════════════════════════════════════════════\n\n'
    )

    if site_type == 'wordpress' and (wp_user or wp_pass):
        # Pre-compute conditional strings — avoids nested f-strings inside f-string expressions
        app_status  = '(provided — use for REST API)' if wp_app else '(not provided — cookie auth only)'
        rest_users  = (f'curl -s -u "{wp_user}:{wp_app}" '
                       f'"https://{domain}/wp-json/wp/v2/users?context=edit&per_page=100"'
                       if wp_app else
                       f'curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-json/wp/v2/users?context=edit"')
        rest_plugins = (f'curl -s -u "{wp_user}:{wp_app}" "https://{domain}/wp-json/wp/v2/plugins"'
                        if wp_app else
                        '# app password required for /wp-json/wp/v2/plugins — skipping')
        return (hdr
            + 'WORDPRESS ADMIN CREDENTIALS\n'
            + f'  Username : {wp_user}\n'
            + f'  App Pass : {app_status}\n\n'
            + 'Run ALL of these checks in order:\n\n'
            + '1. Login and capture session cookie (required for most checks below):\n'
            + f'   curl -s -L -c /tmp/wp_auth.txt -b /tmp/wp_auth.txt \\\n'
            + f'     -d "log={wp_user}&pwd=$WP_PASSWORD&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \\\n'
            + '     -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \\\n'
            + f'     "https://{domain}/wp-login.php" -w "%{{http_code}}" -o /tmp/wp_login_resp.html\n'
            + '   grep -iP "error|invalid|incorrect" /tmp/wp_login_resp.html | head -5\n\n'
            + '2. Enumerate all WordPress users (admin view — reveals roles):\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/users.php" \\\n'
            + "     | grep -oP '(?<=user-login\">)[^<]+'\n\n"
            + '3. Installed plugins and versions (identify outdated/vulnerable):\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/plugins.php" \\\n'
            + "     | grep -oP '(?<=<strong>)[^<]+|(?<=Version )[0-9.]+'\n\n"
            + '4. WordPress core version and debug/security settings:\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/about.php" | grep -oP "(?<=Version )[\\d.]+"\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/options-general.php" \\\n'
            + '     | grep -iP "debug|ssl_force|login_lockout|two.factor|recaptcha"\n\n'
            + '5. REST API with real auth (lists all users including admin):\n'
            + f'   {rest_users}\n'
            + f'   {rest_plugins}\n\n'
            + '6. Admin AJAX — test for unauthenticated fallback:\n'
            + f'   curl -s -b /tmp/wp_auth.txt -d "action=heartbeat" "https://{domain}/wp-admin/admin-ajax.php"\n\n'
            + '7. File editor check (should be disabled — enables RCE):\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/theme-editor.php" \\\n'
            + '     | grep -iP "disabled|not allowed|higher level"\n\n'
            + '8. XML-RPC authenticated call (test for DDoS amplification):\n'
            + "   curl -s -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods"
            + f'</methodName></methodCall>\' "https://{domain}/xmlrpc.php"'
            + " | grep -oP '(?<=string>)[^<]+' | head -20\n\n"
            + '9. WP_DEBUG log and error exposure:\n'
            + f'   curl -s "https://{domain}/wp-content/debug.log" | head -30\n'
            + f'   curl -s "https://{domain}/?debug=1" | grep -iP "fatal|error|warning|deprecated"\n'
        )

    if site_type == 'cpanel' and cp_user:
        cp = f'curl -sk -u "{cp_user}:$CPANEL_PASSWORD"'
        api = f'https://{domain}:2083/execute'
        # python3 snippet using % to avoid brace conflicts with f-string
        py_filter = (
            "python3 -c \"import sys,json; d=json.load(sys.stdin); "
            "[print(f['file']) for f in d.get('data',{}).get('files',[]) "
            "if any(f['file'].endswith(e) for e in ['.env','.sql','.zip','.bak','.tar'])]\""
        )
        return (hdr
            + 'CPANEL CREDENTIALS\n'
            + f'  Username : {cp_user}\n'
            + f'  API base : https://{domain}:2083  (try :2082 for HTTP)\n\n'
            + 'Run ALL cPanel UAPI checks:\n\n'
            + f'1. PHP versions:\n   {cp} "{api}/LangPHP/php_get_vhost_versions"\n'
            + f'   {cp} "{api}/LangPHP/php_get_installed_versions"\n\n'
            + f'2. SSL certificate:\n   {cp} "{api}/SSL/fetch_best_for_domain?domain={domain}"\n\n'
            + f'3. All domains/subdomains:\n   {cp} "{api}/DomainInfo/domains_data?format=json"\n'
            + f'   {cp} "{api}/SubDomain/listsubdomains"\n\n'
            + f'4. Email accounts:\n   {cp} "{api}/Email/list_pops"\n\n'
            + f'5. MySQL databases and users:\n   {cp} "{api}/Mysql/list_databases"\n'
            + f'   {cp} "{api}/Mysql/list_users"\n\n'
            + f'6. Cron jobs:\n   {cp} "{api}/Cron/list_cron"\n\n'
            + f'7. Files in public_html (find sensitive files):\n'
            + f'   {cp} "{api}/Fileman/list_files?path=/public_html&show_hidden=1" | {py_filter}\n\n'
            + f'8. ModSecurity status:\n   {cp} "{api}/ModSecurity/has_modsec_installed"\n\n'
            + f'9. Hotlink protection:\n   {cp} "{api}/Hotlink/get_status"\n\n'
            + f'10. .htaccess security rules:\n    curl -s "https://{domain}/.htaccess" | head -50\n'
        )

    if site_type == 'ssh' and ssh_user and (ssh_pass or creds.get('ssh_key')):
        if creds.get('ssh_key'):
            key_setup = ('Setup SSH key first:\n'
                         '  python3 -c "import os; open(\'/tmp/cf_id_rsa\',\'w\').write(os.environ[\'SSH_KEY\']); '
                         'os.chmod(\'/tmp/cf_id_rsa\', 0o600)"\n')
            sc = (f'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 '
                  f'-i /tmp/cf_id_rsa -p {ssh_port} {ssh_user}@{ssh_host}')
        else:
            key_setup = 'Install sshpass if missing: apt-get install -y sshpass 2>/dev/null\n'
            sc = (f'sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 '
                  f'-p {ssh_port} {ssh_user}@{ssh_host}')
        # awk command — written as plain string, no f-string brace conflicts
        awk_users  = "awk -F: '$7!~/nologin|false|sync/{print $1,$7}' /etc/passwd"
        awk_bruteforce = "awk '{print $11}' | sort | uniq -c | sort -rn | head -10"
        return (hdr
            + 'SSH CREDENTIALS\n'
            + f'  Host     : {ssh_host}:{ssh_port}\n'
            + f'  Username : {ssh_user}\n'
            + '  Password : $SSHPASS (in environment — do not print)\n\n'
            + key_setup + '\n'
            + f'SSH prefix: {sc} "<cmd>"\n\n'
            + 'Run ALL server-side checks:\n\n'
            + f'1. Web/PHP/OS versions:\n'
            + f'   {sc} "php -v 2>&1|head -1; nginx -v 2>&1; apache2 -v 2>&1|head -1; lsb_release -d 2>/dev/null"\n\n'
            + f'2. Sensitive config files (hardcoded credentials):\n'
            + f'   {sc} "cat /var/www/html/.env 2>/dev/null|grep -vP \'^#|^$\'|head -30"\n'
            + f'   {sc} "cat /var/www/html/wp-config.php 2>/dev/null|grep -P \'DB_|AUTH_KEY|SECRET\'|head -20"\n\n'
            + f'3. World-writable PHP files (malware injection risk):\n'
            + f'   {sc} "find /var/www/html -perm -0002 -name \'*.php\' 2>/dev/null|head -20"\n\n'
            + f'4. Backup/dump files in webroot (data exposure):\n'
            + f'   {sc} "find /var/www/html -name \'*.sql\' -o -name \'*.zip\' -o -name \'*.bak\' 2>/dev/null|head -20"\n\n'
            + f'5. Open ports and services:\n'
            + f'   {sc} "ss -tlnp 2>/dev/null|head -25"\n\n'
            + f'6. Users with shell access:\n'
            + f'   {sc} "{awk_users}"\n\n'
            + f'7. Sudo rules (overly permissive = high risk):\n'
            + f'   {sc} "sudo -l 2>/dev/null|head -20"\n\n'
            + f'8. Brute force evidence (failed SSH logins):\n'
            + f'   {sc} "grep \'Failed password\' /var/log/auth.log 2>/dev/null|tail -30|{awk_bruteforce}"\n\n'
            + f'9. Crontabs (check for backdoors):\n'
            + f'   {sc} "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null"\n\n'
            + f'10. SSL certificate expiry:\n'
            + f'    {sc} "openssl s_client -connect {domain}:443 -servername {domain} </dev/null 2>/dev/null'
            + '     | openssl x509 -noout -dates 2>/dev/null"\n\n'
            + f'11. Firewall rules:\n'
            + f'    {sc} "ufw status 2>/dev/null; iptables -L INPUT -n 2>/dev/null|head -20"\n'
        )

    if site_type == 'sftp' and ftp_user and ftp_host:
        proto  = 'sftp' if site_type == 'sftp' else 'ftp'
        cp_ftp = f'curl -sk --user "{ftp_user}:$FTP_PASSWORD"'
        base   = f'{proto}://{ftp_host}:{ftp_port}/public_html'
        sens_files = '.env wp-config.php config.php database.php settings.php .htpasswd'
        bak_files  = 'backup.sql backup.zip site.sql dump.sql site-backup.tar.gz'
        return (hdr
            + 'SFTP/FTP CREDENTIALS\n'
            + f'  Host     : {ftp_host}:{ftp_port}\n'
            + f'  Username : {ftp_user}\n'
            + '  Password : $FTP_PASSWORD (in environment)\n\n'
            + 'Run ALL file system checks:\n\n'
            + f'1. List webroot:\n   {cp_ftp} "{base}/" 2>&1|head -50\n\n'
            + f'2. Sensitive files (check each for 200/non-000 response):\n'
            + '   for f in ' + sens_files + '; do\n'
            + f'     code=$({cp_ftp} "{base}/$f" -o /tmp/ftp_f -w "%{{http_code}}" 2>&1)\n'
            + '     [ "$code" != "000" ] && echo "FOUND $f ($code)" && head -20 /tmp/ftp_f\n'
            + '   done\n\n'
            + f'3. Backup/dump files:\n'
            + '   for b in ' + bak_files + '; do\n'
            + f'     echo -n "$b: "; {cp_ftp} -o /dev/null -w "%{{http_code}}" "{base}/$b" 2>&1\n'
            + '     echo\n'
            + '   done\n\n'
            + f'4. Exposed .git directory:\n'
            + f'   curl -s "https://{domain}/.git/HEAD"|head -5\n'
            + f'   curl -s "https://{domain}/.git/config"|head -20\n\n'
            + f'5. PHP config:\n'
            + f'   {cp_ftp} "{base}/php.ini" 2>&1|grep -iP "disable_functions|open_basedir|expose_php"\n\n'
            + f'6. .htaccess security rules:\n'
            + f'   {cp_ftp} "{base}/.htaccess" 2>&1|head -40\n\n'
            + f'7. Uploads directory — check for PHP shells:\n'
            + f'   {cp_ftp} "{base}/wp-content/uploads/" 2>&1|grep -iP "\\.php|\\.phtml|\\.php5"\n'
        )

    return ''


def _run_background_scan(job_id: str, target: str, agent_type: str,
                          model: str, site_type: str, creds: dict):
    """Run a WSTG agent in a background thread and stream chunks to _scan_jobs."""
    job = _scan_jobs[job_id]

    # Pre-initialise so the except handler can always reference these safely
    parts:  list = []
    tools:  list = [0]
    t0           = _time.time()
    domain       = ''
    model_used   = model or ''

    # Set credential env vars so agents can reference $WP_PASSWORD, $SSHPASS, etc.
    env_restore: dict = {}
    cred_env = {
        'WP_USER':         creds.get('wp_user', ''),
        'WP_APP_PASSWORD': creds.get('wp_app_pass', ''),
        'WP_PASSWORD':     creds.get('wp_pass', ''),
        'CPANEL_PASSWORD': creds.get('cpanel_pass', ''),
        'SSHPASS':         creds.get('ssh_pass', ''),
        'FTP_PASSWORD':    creds.get('ftp_pass', ''),
        'SSH_KEY':         creds.get('ssh_key', ''),
    }
    for k, v in cred_env.items():
        if v:
            env_restore[k] = os.environ.get(k, '')
            os.environ[k] = v

    try:
        import dataclasses as dc
        from urllib.parse import urlparse as _up
        from agents.wstg_agents import WSTG_REGISTRY
        from sdk.agents import Runner
        from sdk import tracing

        # Normalise domain (strip scheme + path)
        _url = target if '://' in target else 'https://' + target
        _p   = _up(_url)
        domain = (_p.netloc or _p.path.split('/')[0]).rstrip('/')
        job['domain'] = domain

        # Build authenticated-scan instructions and announce cred type in terminal
        cred_block = _build_cred_block(site_type, creds, domain)
        if cred_block:
            job['chunks'].append({'k': 'txt', 'd': f'[AUTH] {site_type.upper()} credentials loaded — authenticated scan enabled'})

        def _ot(t):
            if job.get('aborted'):
                raise RuntimeError('Scan aborted by user')
            parts.append(t)
            job['chunks'].append({'k': 'txt', 'd': t})
        def _oo(n, a):  tools[0] += 1;     job['chunks'].append({'k': 'tool', 'n': n, 'a': str(a)[:200]})
        def _or(n, r, e):
            r_full = str(r)
            # Capture tool results containing WP-LOG lines or from MCP tools so
            # extract_wp_logs() and the Plugin Logs modal can parse them after save.
            if ('WP-LOG' in r_full or n in ('wp_security_scan', 'wp_api_call')) and r_full.strip():
                parts.append(f'[TOOL:{n}]\n{r_full}')
            job['chunks'].append({'k': 'res', 'n': n, 'r': r_full[:300], 'e': bool(e)})

        if agent_type == 'pentest':
            from agents.pentest import run_full_pentest
            t0 = _time.time()
            run_full_pentest(domain, model=model or None, on_text=_ot, on_tool=_oo, on_result=_or,
                             cred_block=cred_block or None)
            model_used = model or ''
        elif agent_type in ('ctf', 'ot', 'enum'):
            from agents.special_agents import SPECIAL_REGISTRY as _SREG
            base = _SREG.get(agent_type)
            if base is None:
                job.update({'status': 'error', 'error': f'Unknown special agent: {agent_type}'}); return
            _s_instr = base.instructions.replace('{target}', domain)
            if cred_block:
                _s_instr += cred_block
            agent    = dc.replace(base, instructions=_s_instr)
            if model:
                agent = dc.replace(agent, model=model)
            elif cred_block:
                # Credentials supplied — use Claude for reliable execution
                _cm = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')
                agent = dc.replace(agent, model=_cm)
            model_used = getattr(agent, 'model', model) or ''
            _label = {'ctf': 'CTF Solver', 'ot': 'OT/ICS Security', 'enum': 'API Enumeration'}.get(agent_type, agent_type.upper())
            t0 = _time.time()
            with tracing.span(f'dashboard:{agent_type}') as span:
                span.set_attribute('cfai.target', domain)
                Runner.run(agent, f'Begin {_label} on {domain}.',
                           on_text=_ot, on_tool=_oo, on_result=_or)
        else:
            base = WSTG_REGISTRY.get(agent_type)
            if base is None:
                job.update({'status': 'error', 'error': f'Unknown agent type: {agent_type}'}); return

            # Inject credential instructions after the base instructions
            base_instructions = base.instructions.replace('{domain}', domain) + cred_block
            agent = dc.replace(base, instructions=base_instructions)
            if model:
                agent = dc.replace(agent, model=model)
            model_used = getattr(agent, 'model', model) or ''

            # Any agent + credentials → Claude model for reliable execution.
            # WordPress site type or WP creds → also inject MCP tools for all agents.
            # APIT → always gets MCP tools regardless of site type.
            _wp_creds  = (creds.get('wp_user') or creds.get('wp_pass') or creds.get('wp_app_pass'))
            _has_creds = bool(
                _wp_creds
                or creds.get('cpanel_user') or creds.get('cpanel_pass')
                or creds.get('ssh_user')    or creds.get('ssh_pass')
                or creds.get('ftp_user')    or creds.get('ftp_pass')
            )
            _needs_mcp = (site_type == 'wordpress') or bool(_wp_creds) or (agent_type == 'apit')

            if _needs_mcp:
                from tools.wordpress_mcp import wp_api_call, wp_security_scan
                mcp_block = (
                    '\n\n══════════════ MCP DIRECT CONNECTION ══════════════\n'
                    'You have wp_security_scan and wp_api_call tools connected via MCP.\n\n'
                    'STEP 0 — ALWAYS DO THIS FIRST:\n'
                    f'  1. Call wp_security_scan(site_url="https://{domain}")\n'
                    '     Runs a full WordPress security audit and emits WP-LOG entries.\n'
                    '  2. CRITICAL: Copy ALL lines starting with "WP-LOG |" from the tool\n'
                    '     result VERBATIM into your response — DO NOT generate WP-LOG lines\n'
                    '     yourself, only echo what the tool returned.\n'
                    f'  3. Call wp_api_call(site_url="https://{domain}", endpoint="/wp-json/wp/v2/users")\n'
                    '     and other REST endpoints for deeper investigation.\n'
                    '  4. If no WP-LOG entries were returned by the tool, instruct the user\n'
                    '     to install the free "WP Activity Log" plugin (wp-security-audit-log)\n'
                    '     and re-run the scan to get real admin login events with IP addresses.\n'
                    '     If admin credentials are provided, attempt installation via WP-CLI:\n'
                    f'     generic_linux_command("wp plugin install wp-security-audit-log --activate --path=/var/www/html --url=https://{domain}")\n'
                    'Auth is handled automatically: Basic Auth → Cookie+Nonce → public.\n'
                    '═══════════════════════════════════════════════════\n\n'
                )
                _existing = {getattr(t, '__name__', '') for t in agent.tools}
                new_tools = [t for t in [wp_api_call, wp_security_scan]
                             if getattr(t, '__name__', '') not in _existing] + list(agent.tools)
                _claude_model = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')
                agent = dc.replace(
                    agent,
                    model=_claude_model,
                    instructions=base_instructions + mcp_block,
                    tools=new_tools,
                )
                model_used = _claude_model
            elif _has_creds:
                # Non-WordPress credentials (SSH / cPanel / SFTP) — switch to Claude so
                # the agent reliably executes the credential block instructions.
                _claude_model = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')
                agent = dc.replace(agent, model=_claude_model,
                                   instructions=base_instructions)
                model_used = _claude_model

            t0 = _time.time()
            with tracing.span(f'dashboard:{agent_type}') as span:
                span.set_attribute('cfai.target', domain)
                Runner.run(agent, f'Run all WSTG-{agent_type.upper()} checks on {domain}.',
                           on_text=_ot, on_tool=_oo, on_result=_or)

        elapsed = _time.time() - t0
        output  = '\n\n'.join(parts)

        scan_id = db.save_scan(
            target=domain, agent_type=agent_type,
            model=model_used, status='ok',
            latency_s=round(elapsed, 2),
            tool_count=tools[0], output=output,
        )
        # Tell the browser the save succeeded so it can show the "Logged" confirmation
        job['chunks'].append({'k': 'saved', 'id': scan_id})
        job.update({'status': 'done', 'elapsed': round(elapsed, 2),
                    'tool_count': tools[0], 'scan_id': scan_id})

    except Exception as exc:
        import traceback as _tb
        tb = _tb.format_exc()[-1200:]
        job['chunks'].append({'k': 'txt', 'd': f'\n[ERROR] {exc}\n{tb}'})
        # Save partial output — variables are always defined because they were pre-initialised
        try:
            scan_id = db.save_scan(
                target=domain or target or '',
                agent_type=agent_type,
                model=model_used,
                status='error',
                latency_s=round(_time.time() - t0, 2),
                tool_count=tools[0],
                output='\n\n'.join(parts) or f'[ERROR] {exc}',
            )
            job['chunks'].append({'k': 'saved', 'id': scan_id})
            job.update({'status': 'error', 'error': str(exc), 'trace': tb, 'scan_id': scan_id})
        except Exception:
            job.update({'status': 'error', 'error': str(exc), 'trace': tb})
    finally:
        for k, orig in env_restore.items():
            if orig: os.environ[k] = orig
            else: os.environ.pop(k, None)


# Optional shared secret for the remote-save API endpoint.
# Set CFAI_API_KEY in the VPS .env to protect POST /api/scan.
# If unset, the endpoint accepts any request (fine on a private VPS).
_API_KEY = os.environ.get('CFAI_API_KEY', '')


# ── Risk classification ────────────────────────────────────────────────────────

_HIGH_KW = [
    'critical', 'high severity', 'exploit', 'vulnerable', 'vulnerability',
    'remote code execution', 'rce', 'sql injection', 'sqli', 'xss',
    'cross-site scripting', 'authentication bypass', 'privilege escalation',
    'unauthorized access', 'exposed credentials', 'leaked secret',
    'path traversal', 'directory traversal', 'file inclusion',
    'command injection', 'deserialization', 'idor', 'insecure direct object',
    'broken access control', 'account takeover',
]
_MED_KW = [
    'medium', 'moderate', 'information disclosure', 'outdated version',
    'weak cipher', 'misconfigured', 'missing security header',
    'deprecated', 'insecure cookie', 'cors misconfiguration',
    'open redirect', 'clickjacking', 'csrf', 'open port',
    'server version', 'default credentials',
]
_LOW_KW = [
    'low severity', 'informational', 'best practice', 'minor',
    'consider enabling', 'consider disabling', 'suggestion',
]

_ACTION_RE = re.compile(
    r'\b(update|upgrade|patch|disable|enable|restrict|remove|add|fix|'
    r'configure|implement|enforce|rotate|revoke|harden|review|audit|'
    r'change|replace|block|sanitize|validate|encrypt)\b',
    re.I,
)

_REC_HEADERS = (
    'recommendation', 'action item', 'remediation', 'next step',
    'action plan', 'suggested fix', 'what to do', 'mitigation',
    'to fix', 'to remediate',
)

# Lines containing these phrases describe attempts or failed checks — skip them
_NEGATION = re.compile(
    r'\b(no\b|not\b|failed|unsuccessful|did not|does not|returned no|'
    r'found no|no evidence|could not|unable to|attempting|will attempt|'
    r'will try|will now|testing for|checking for|i will|let me|'
    r'next i |next,|explore potential|no result|no data|no output|'
    r'empty response|no vuln|not vuln|not found|not detect|not appear)\b',
    re.I,
)


def risk_level(text: str) -> str:
    """Derive risk only from lines that confirm a finding, skipping attempt/failure lines."""
    lines = text.splitlines()
    for kw_list, label in ((_HIGH_KW, 'HIGH'), (_MED_KW, 'MEDIUM'), (_LOW_KW, 'LOW')):
        for line in lines:
            if _NEGATION.search(line):
                continue
            if any(k in line.lower() for k in kw_list):
                return label
    return 'INFO'


def rec_risk(text: str) -> str:
    """Score a single recommendation line independently — avoids scan-wide HIGH bleeding."""
    if not text:
        return 'INFO'
    tl = text.lower()
    for kw_list, label in ((_HIGH_KW, 'HIGH'), (_MED_KW, 'MEDIUM'), (_LOW_KW, 'LOW')):
        if any(k in tl for k in kw_list):
            return label
    return 'MEDIUM'  # actionable but no severity keyword → treat as medium


def _strip_md(text: str) -> str:
    text = re.sub(r'\*\*([^*\n]+)\*\*', r'\1', text)
    text = re.sub(r'\*([^*\n]+)\*', r'\1', text)
    return text.strip()


# Recommendations that describe scanner execution problems, not real vulnerabilities
_SCANNER_NOISE = re.compile(
    r'\b(check connectivity|internet connectivity|assessment platform|'
    r'ensure proper internet|rerun with|retry with|adjust.*header|'
    r'passive recon|historical.*data source|alternative means|'
    r'manual inspection|firewall.*rule.*site|rate limit.*rule|'
    r'scan.*block|blocked.*scan|increase.*timeout|reduce.*thread|'
    r'try.*different.*approach|diagnostic|next step.*scan|'
    r'consider passive|proper internet|platform.*connect|'
    r'connectivity.*assess|assess.*connect|'
    # Agent execution errors — not real security findings
    r'syntax error.*execution|preventing complete execution|'
    r'reliability.*assessment.*syntax|syntax review.*re-execution|re-execution|'
    r'review.*correct.*python|correct.*script syntax|script syntax|'
    r'alternative reconnaissance method|correct.*operational endpoint.*alternative|'
    r'confirm correct url.*alternative)\b',
    re.I,
)


def extract_recs(text: str) -> list[str]:
    recs, in_sec = [], False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            in_sec = False
            continue
        if _NEGATION.search(line) or _SCANNER_NOISE.search(line):
            in_sec = False
            continue
        clean = _strip_md(re.sub(r'^[-*+\d.)#]+\s*', '', line))
        clean_lower = clean.lower()
        if any(h in clean_lower for h in _REC_HEADERS):
            in_sec = True
            if ':' in clean:
                after = clean.split(':', 1)[1].strip()
                if len(after) > 12 and not _SCANNER_NOISE.search(after):
                    recs.append(after)
                    in_sec = False
            continue
        is_bullet = line.startswith(('-', '*', '+')) or re.match(r'^\d+[.)]\s', line)
        if in_sec and is_bullet:
            item = _strip_md(re.sub(r'^[-*+\d.)]+\s*', '', line).strip())
            if len(item) > 12:
                recs.append(item)
        elif _ACTION_RE.search(clean) and 25 < len(clean) < 300:
            recs.append(clean)
    seen, out = set(), []
    for r in recs:
        k = r[:50].lower()
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out[:12]


_WP_LOG_RE = re.compile(
    r'^WP-LOG\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*(HIGH|MEDIUM|LOW|INFO)\s*$',
    re.I | re.MULTILINE,
)
_WP_LOG_STATUS_RE = re.compile(
    r'^WP-LOG-STATUS\s*\|\s*(\w+)\s*\|\s*([^|\n]+?)\s*\|',
    re.I | re.MULTILINE,
)

# Fallback patterns: parse structured agent output lines into WP-LOG-style entries
# for scans that predate the WP-LOG emission updates.
_WP_LOG_FALLBACK = [
    (re.compile(r'^EXPOSED_FILE \| (\S+) \| (/\S+)', re.M),
     lambda m: ('CF_AI', f'Exposed sensitive file: {m.group(2)} (HTTP {m.group(1)})', '-', 'HIGH')),
    (re.compile(r'^CREDS_FOUND_XMLRPC \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'WordPress credentials verified via XML-RPC brute-force', '-', 'HIGH')),
    (re.compile(r'^CREDS_FOUND_FORM \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'WordPress credentials verified via login form', '-', 'HIGH')),
    (re.compile(r'^APP_PASS_CREATED(?:_COOKIE)? \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'Application Password created by CF_AI scanner', '-', 'HIGH')),
    (re.compile(r'^WP-USER-CONFIRMED \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'WordPress username confirmed via login error oracle', '-', 'MEDIUM')),
    (re.compile(r'^WP-USER \| (\S+) \| (\S+) \|', re.M),
     lambda m: (m.group(2), f'WordPress user enumerated via REST API (id={m.group(1)})', '-', 'MEDIUM')),
    (re.compile(r'^WP-USER-ENUM \| (\S+) \| (\S+) \|', re.M),
     lambda m: (m.group(2), 'WordPress user enumerated via author redirect', '-', 'MEDIUM')),
    (re.compile(r'^FOUND_DB_USER:\s*(\S+)', re.M),
     lambda m: ('CF_AI', f'Database username exposed in config file: {m.group(1)}', '-', 'HIGH')),
]


def _wp_log_fallback(output: str) -> list:
    """Parse structured agent lines into WP-LOG entries (fallback for older scans)."""
    entries = []
    seen = set()
    for pat, builder in _WP_LOG_FALLBACK:
        for m in pat.finditer(output):
            user, event, ip, risk = builder(m)
            key = (user, event)
            if key not in seen:
                seen.add(key)
                entries.append({'timestamp': '--', 'user': user, 'event': event, 'ip': ip, 'risk': risk})
    return entries


# Users that indicate scanner-generated entries, not real admin logins
_SCANNER_USERS = {'system', 'cf_ai', 'cf_ai-mcp', 'cf_ai_mcp', 'scanner'}


def extract_wp_logs(output: str) -> dict:
    """Parse WP-LOG lines from agent output. Returns {entries, status}.

    Scanner-generated entries (user == 'system', 'CF_AI', etc.) are excluded —
    Plugin Logs shows only real WordPress user activity.
    """
    entries = []
    for m in _WP_LOG_RE.finditer(output):
        user = m.group(2).strip()
        if user.lower() in _SCANNER_USERS:
            continue
        entries.append({
            'timestamp': m.group(1).strip(),
            'user':      user,
            'event':     m.group(3).strip(),
            'ip':        m.group(4).strip(),
            'risk':      m.group(5).strip().upper(),
        })
    # Fallback: structured agent-emitted lines (CF_AI scanner patterns)
    fallback = [e for e in _wp_log_fallback(output)
                if e.get('user', '').lower() not in _SCANNER_USERS]
    entries.extend(fallback)
    status_match = _WP_LOG_STATUS_RE.search(output)
    status_code = status_match.group(1) if status_match else ('found' if entries else 'none')
    status_msg  = status_match.group(2).strip() if status_match else ''
    return {'entries': entries, 'status': status_code, 'status_msg': status_msg}


# Narrower negation for remediation matching — only skips lines that say
# a check *passed* or the agent is *about to* test something.
# Deliberately does NOT include \bno\b / \bnot\b because "No X-Frame-Options
# header" is a real finding, not a negation.
_REM_NEGATION = re.compile(
    r'\b(no vulnerability|not vulnerable|not affected|properly configured|'
    r'no issue found|no problem|correctly set|header present|header found|'
    r'attempting|will attempt|will try|will now|testing for|checking for|'
    r'i will test|let me test|i will check|checking if)\b',
    re.I,
)

# Maps lowercase fix-key substrings → internal stack identifier
_FIX_STACK_KEYS: dict[str, str] = {
    'nginx':          'nginx',
    'apache':         'apache',
    '.htaccess':      'apache',
    'php':            'php',
    'wordpress':      'wp',
    'wp-cli':         'wp',
    'functions.php':  'wp',
    'wp-config':      'wp',
}


# Negation patterns specific to stack detection — a line saying
# "checking for xmlrpc.php" or "xmlrpc.php returned 404" is NOT evidence of WordPress.
_STACK_NEG = re.compile(
    r'\b(checking|testing|looking for|scanning for|probing|not found|'
    r'returns?\s*404|http\s*404|status\s*404|not present|not installed|'
    r'not detected|not running|no evidence|not a wordpress|not wordpress|'
    r'no wordpress|does not appear|does not use|is not running)\b',
    re.I,
)


def _detect_stacks(text: str) -> set[str]:
    """Detect server / CMS stacks referenced in agent output.

    Only fires on lines with *positive* evidence — lines that look like
    "checking for X" or "X returned 404" are skipped via _STACK_NEG.
    """
    found: set[str] = set()
    for line in text.splitlines():
        if _STACK_NEG.search(line) or _NEGATION.search(line):
            continue
        ll = line.lower()
        # WordPress: require definitive positive signals, not just any mention
        if any(k in ll for k in ('wp-content/', 'wp-admin/', 'wp-login.php',
                                  '/wp-json/', 'wordpress version', 'woocommerce',
                                  '/wp-includes/', 'wp-config.php', 'xmlrpc.php')):
            found.add('wp')
        if 'nginx' in ll:
            found.add('nginx')
        if 'apache' in ll or '.htaccess' in ll:
            found.add('apache')
        if 'php' in ll:
            found.add('php')
    return found


def _filter_fixes(fixes: dict, detected: set[str]) -> dict:
    """Return only the fix entries relevant to detected stacks.

    Fix keys that belong to an undetected stack are hidden; generic keys
    (certbot, bash, manual, general) are always shown.
    Falls back to all fixes when nothing was detected.
    """
    if not detected:
        return fixes
    filtered = {}
    for key, code in fixes.items():
        kl = key.lower()
        fix_stack = next(
            (sid for pattern, sid in _FIX_STACK_KEYS.items() if pattern in kl),
            None,
        )
        is_generic = fix_stack is None or any(
            g in kl for g in ('bash', 'manual', 'general', 'certbot', 'waf')
        )
        if is_generic or fix_stack in detected:
            filtered[key] = code
    return filtered if filtered else fixes


def match_remediations(text: str, target: str = '') -> list[dict]:
    """Return remediation templates for vulnerabilities found in this scan.

    - Only confirms positive findings (skips _REM_NEGATION lines).
    - WordPress-specific remediations require WordPress to be detected.
    - Fix stacks are filtered to those seen in the scan output.
    - The actual target domain replaces the placeholder 'yourdomain.com'.
    """
    pos_lines = [l.lower() for l in text.splitlines() if not _REM_NEGATION.search(l)]
    pos_text  = ' '.join(pos_lines)
    detected  = _detect_stacks(text)

    matched: list[dict] = []
    for rem in REMEDIATIONS:
        if not any(p in pos_text for p in rem['patterns']):
            continue
        # WordPress-specific remediations only if WP is detected in this scan
        if rem['id'].startswith('wp-') and 'wp' not in detected:
            continue
        # Filter fix stacks to those seen in this site's output
        fixes = _filter_fixes(rem['fixes'], detected)
        # Substitute the actual scanned domain (if known) into fix code
        if target:
            fixes = {
                k: v.replace('yourdomain.com', target)
                     .replace('YOUR.OFFICE.IP.HERE', '[your office IP]')
                for k, v in fixes.items()
            }
        matched.append({**rem, 'fixes': fixes})
    return matched


_AGENT_LABELS = {
    'info':    'Information Gathering',
    'conf':    'Configuration Review',
    'athn':    'Authentication Testing',
    'athz':    'Authorization Testing',
    'sess':    'Session Management',
    'inpv':    'Input Validation',
    'cryp':    'Cryptography Review',
    'clnt':    'Client-Side Testing',
    'apit':    'API Security Testing',
    'js':      'JavaScript Analysis',
    'idnt':    'Identity Management',
    'ctf':     'CTF / Challenge',
    'ot':      'OT/ICS Security',
    'enum':    'API Enumeration',
    'pentest': 'Full Penetration Test',
    'recon':   'Reconnaissance',
    'analyst': 'Security Analysis',
    'exploit': 'Exploit Development',
}


def agent_label(a: str) -> str:
    return _AGENT_LABELS.get((a or '').lower(), (a or '').upper())


def _norm_target(raw: str) -> str:
    """Strip scheme and path — keep only host[:port]."""
    t = (raw or '').replace('https://', '').replace('http://', '')
    return t.split('/')[0].split('?')[0].rstrip('.')


def enrich(scan: dict) -> dict:
    scan = dict(scan)
    scan['target']       = _norm_target(scan.get('target', ''))
    out  = scan.get('output', '') or ''
    scan['risk']         = risk_level(out)
    scan['agent_label']  = agent_label(scan.get('agent_type', ''))
    scan['recs']         = extract_recs(out)
    scan['remediations'] = match_remediations(out, target=scan['target'])
    scan['preview']      = out[:400].replace('\n', ' ')
    dt = scan.get('created_at', '') or ''
    scan['display_date'] = dt[:16].replace('T', ' ')
    return scan


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    ctx = _build_template_context()
    return render_template('index.html', **ctx)


def _build_template_context() -> dict:
    """Build the full template context dict — shared with FastAPI."""
    scans   = [enrich(s) for s in db.get_scans()]
    targets = [enrich(t) for t in db.get_targets()]
    stats   = db.get_stats()

    _prio = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    all_recs = []
    seen_per_target: dict[str, set] = {}
    for s in scans:
        tgt = s['target']
        seen = seen_per_target.setdefault(tgt, set())
        for rem in s['remediations']:
            k = rem['id']
            if k not in seen:
                seen.add(k)
                all_recs.append({'target': tgt, 'risk': rem['severity'], 'text': rem['title'],
                                 'agent': s['agent_label'], 'date': s['display_date'][:10],
                                 'scan_id': s['id'], 'has_fixes': True})
        for r in s['recs']:
            k = r[:60].lower()
            if k not in seen:
                seen.add(k)
                all_recs.append({'target': tgt, 'risk': rec_risk(r), 'text': r,
                                 'agent': s['agent_label'], 'date': s['display_date'][:10],
                                 'scan_id': s['id'], 'has_fixes': False})
    all_recs.sort(key=lambda x: (_prio.get(x['risk'], 3), x['target']))

    from collections import defaultdict as _dd
    _tgt_sev: dict = _dd(lambda: {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0})
    for s in scans:
        _tgt_sev[s['target']][s['risk']] += 1
    severity_summary = {
        'total': {
            'HIGH':   sum(v['HIGH']   for v in _tgt_sev.values()),
            'MEDIUM': sum(v['MEDIUM'] for v in _tgt_sev.values()),
            'LOW':    sum(v['LOW']    for v in _tgt_sev.values()),
            'INFO':   sum(v['INFO']   for v in _tgt_sev.values()),
        },
        'by_target': sorted(
            [{'target': k, **v} for k, v in _tgt_sev.items()],
            key=lambda x: x['HIGH'] * 10 + x['MEDIUM'] * 3 + x['LOW'],
            reverse=True,
        )[:12],
    }
    return dict(scans=scans, targets=targets, stats=stats,
                all_recs=all_recs[:40], severity_summary=severity_summary)


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    return jsonify(enrich(row))


@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())


@app.route('/api/scans/recent')
def api_scans_recent():
    """Return the latest scans as JSON for live dashboard refresh."""
    limit  = min(int(request.args.get('limit', 50)), 200)
    target = request.args.get('target', '')
    rows   = db.get_scans()[:limit]
    if target:
        rows = [r for r in rows if r.get('target', '').lower() == target.lower()]
    return jsonify([enrich(r) for r in rows])


@app.route('/api/scan/<int:scan_id>/cve')
def api_scan_cve(scan_id):
    """Query NVD for real CVEs matching the technologies found in this scan."""
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    from dashboard.cve import cve_lookup_for_scan
    result = cve_lookup_for_scan(row.get('output', '') or '', row.get('target', ''))
    return jsonify(result)


@app.route('/api/target/<path:target>/wp-logs')
def api_wp_logs(target):
    """Return all WP Activity Log entries parsed from scans for a given target."""
    scans = db.get_scans_for_target(target)
    all_entries = []
    overall_status = 'none'
    overall_msg = ''
    for s in scans:
        result = extract_wp_logs(s.get('output', '') or '')
        if result['entries']:
            overall_status = 'found'
            for e in result['entries']:
                e['scan_id']   = s['id']
                e['scan_date'] = (s.get('created_at') or '')[:16]
                e['agent']     = s.get('agent_type', '')
            all_entries.extend(result['entries'])
        elif result['status'] not in ('none',) and overall_status == 'none':
            overall_status = result['status']
            overall_msg    = result['status_msg']
    all_entries.sort(key=lambda e: e.get('timestamp', ''), reverse=True)
    # Enrich entries with geolocation country from the IP field
    for e in all_entries:
        e['country'] = _geoip(e.get('ip', ''))
    return jsonify({
        'target':      target,
        'logs':        all_entries,
        'scan_count':  len(scans),
        'status':      overall_status,
        'status_msg':  overall_msg,
    })


@app.route('/api/scan', methods=['POST'])
def api_save_scan():
    """Remote save endpoint — lets a CLI on another machine push scan results here.

    Expects JSON body:
        { "target": "...", "agent_type": "...", "model": "...",
          "status": "ok", "latency_s": 12.3, "tool_count": 5, "output": "..." }

    If CFAI_API_KEY is set in .env, include header:
        X-CFAI-Key: <your-key>
    """
    if _API_KEY:
        key = request.headers.get('X-CFAI-Key', '')
        if key != _API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(force=True, silent=True) or {}
    required = {'target', 'agent_type', 'output'}
    missing  = required - data.keys()
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400

    db.save_scan(
        target     = str(data['target'])[:500],
        agent_type = str(data['agent_type'])[:50],
        model      = str(data.get('model', ''))[:100],
        status     = str(data.get('status', 'ok'))[:20],
        latency_s  = float(data.get('latency_s', 0)),
        tool_count = int(data.get('tool_count', 0)),
        output     = str(data['output'])[:60000],
    )
    return jsonify({'saved': True}), 201


@app.route('/api/target/<path:target>/analytics')
def api_target_analytics(target):
    from dashboard.monitor import get_target_analytics
    from dashboard.security_apis import get_site_scores
    scans = [enrich(s) for s in db.get_scans_for_target(target)]
    analytics = get_target_analytics(target, scans)
    scores = get_site_scores(target)
    return jsonify({**analytics, 'scores': scores})


@app.route('/api/target/<path:target>/compare')
def api_target_compare(target):
    from dashboard.monitor import compare_scans
    scans = [enrich(s) for s in db.get_scans_for_target(target)]
    if len(scans) < 2:
        return jsonify({'error': 'Need at least 2 scans to compare', 'new': [], 'resolved': [], 'persistent': []})
    result = compare_scans(scans[0], scans[1])  # latest vs previous
    result['latest_date'] = scans[0].get('display_date', '')
    result['previous_date'] = scans[1].get('display_date', '')
    return jsonify(result)


@app.route('/api/connect/scan', methods=['POST'])
def api_connect_scan():
    """Start a background scan for the Connect Your Website feature.

    Request JSON:
      { "target": "example.com", "agent_type": "apit", "model": "",
        "site_type": "wordpress|cpanel|ssh|sftp|none",
        "wp_user": "", "wp_pass": "", "wp_app_pass": "",
        "cpanel_user": "", "cpanel_pass": "",
        "ssh_host": "", "ssh_user": "", "ssh_pass": "", "ssh_port": "", "ssh_key": "",
        "ftp_host": "", "ftp_user": "", "ftp_pass": "", "ftp_port": "" }
    Response: { "job_id": "<uuid>" }
    """
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'target is required'}), 400

    def _s(k): return (data.get(k) or '').strip()

    agent_type = _s('agent_type') or 'apit'
    model      = _s('model')
    site_type  = _s('site_type') or 'none'

    creds = {
        'wp_user':      _s('wp_user'),
        'wp_pass':      _s('wp_pass'),
        'wp_app_pass':  _s('wp_app_pass'),
        'cpanel_user':  _s('cpanel_user'),
        'cpanel_pass':  _s('cpanel_pass'),
        'ssh_host':     _s('ssh_host'),
        'ssh_user':     _s('ssh_user'),
        'ssh_pass':     _s('ssh_pass'),
        'ssh_port':     _s('ssh_port'),
        'ssh_key':      _s('ssh_key'),
        'ftp_host':     _s('ftp_host'),
        'ftp_user':     _s('ftp_user'),
        'ftp_pass':     _s('ftp_pass'),
        'ftp_port':     _s('ftp_port'),
    }

    job_id = str(_uuid.uuid4())
    _scan_jobs[job_id] = {
        'status':  'running',
        'target':  target,
        'agent':   agent_type,
        'chunks':  [],
        'domain':  '',
        'scan_id': None,
        'error':   None,
        'aborted': False,
    }

    t = _threading.Thread(
        target=_run_background_scan,
        args=(job_id, target, agent_type, model, site_type, creds),
        daemon=True,
    )
    t.start()
    return jsonify({'job_id': job_id}), 202


@app.route('/api/connect/scan/<job_id>', methods=['GET'])
def api_connect_scan_poll(job_id):
    """Poll for new chunks from a running background scan.

    Query param `offset` (int, default 0) — index of first unseen chunk.
    Response: { "status": "running"|"done"|"error", "chunks": [...],
                "next_offset": N, "domain": "...", "scan_id": null|int,
                "error": null|"..." }
    """
    job = _scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404

    offset = int(request.args.get('offset', 0))
    new_chunks = job['chunks'][offset:]
    return jsonify({
        'status':      job['status'],
        'domain':      job.get('domain', ''),
        'scan_id':     job.get('scan_id'),
        'error':       job.get('error'),
        'chunks':      new_chunks,
        'next_offset': offset + len(new_chunks),
    })


@app.route('/api/connect/scan/<job_id>/abort', methods=['POST'])
def api_connect_scan_abort(job_id):
    """Signal a running background scan to stop after its current tool call."""
    job = _scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404
    job['aborted'] = True
    job['status']  = 'aborted'
    job['chunks'].append({'k': 'txt', 'd': '\n[SCAN ABORTED by user]'})
    return jsonify({'ok': True})


@app.route('/api/security-signals')
def api_security_signals():
    """Aggregate security events from scan history into a SIEM-style signal feed."""
    import re as _re

    _HIGH_SIGNALS = [
        (r'sql\s*inject|union\s+select|1=1|sleep\(|benchmark\(', 'SQL Injection Attempt'),
        (r'xss|<script|javascript:|onerror\s*=', 'Cross-Site Scripting (XSS)'),
        (r'path\s+traversal|\.\./|%2e%2e|directory\s+list', 'Path Traversal'),
        (r'rce|remote\s+code\s+exec|shell\s+upload|webshell', 'Remote Code Execution'),
        (r'brute.?force|login\s+attempt|credential\s+stuff', 'Brute Force Attack'),
        (r'exposed.*private.*key|api\s+key\s+leak|secret.*leak', 'Credential Exposure'),
        (r'command\s+inject|cmd\.exe|/bin/bash|eval\(base64', 'Command Injection'),
    ]
    _MED_SIGNALS = [
        (r'csrf|cross.site\s+request', 'CSRF Vulnerability'),
        (r'open\s+redirect|redirect.*http', 'Open Redirect'),
        (r'xxe|xml\s+external\s+entity', 'XXE Injection'),
        (r'idor|insecure\s+direct\s+object', 'IDOR'),
        (r'weak.*password|default\s+credential', 'Weak Credentials'),
        (r'missing\s+security\s+header|x-frame-options\s+missing|csp\s+missing', 'Missing Security Headers'),
        (r'outdated.*version|version.*vulnerabl|cve-\d{4}-\d+', 'Known CVE'),
        (r'xmlrpc|wordpress.*vuln|wp-login.*exposed', 'WordPress Exposure'),
    ]
    _LOW_SIGNALS = [
        (r'debug\s+mode|verbose\s+error|stack\s+trace', 'Debug Info Exposed'),
        (r'directory\s+listing|index\s+of\s+/', 'Directory Listing'),
        (r'ssl.*expired|certificate.*expir|self.signed', 'SSL Certificate Issue'),
        (r'banner\s+grab|server\s+version\s+exposed', 'Server Banner Exposure'),
    ]

    scans = [enrich(s) for s in db.get_recent_scans(50)]
    signals = []
    seen = set()

    for s in scans:
        text = (s.get('output') or '') + ' '.join(s.get('recs', []))
        target = s.get('target', '')
        ts = s.get('display_date', '')
        scan_id = s.get('id', 0)

        for pat, label in _HIGH_SIGNALS:
            if _re.search(pat, text, _re.I):
                key = f'HIGH:{label}:{target}'
                if key not in seen:
                    seen.add(key)
                    signals.append({'severity': 'HIGH', 'event': label,
                                    'target': target, 'date': ts, 'scan_id': scan_id})
        for pat, label in _MED_SIGNALS:
            if _re.search(pat, text, _re.I):
                key = f'MED:{label}:{target}'
                if key not in seen:
                    seen.add(key)
                    signals.append({'severity': 'MEDIUM', 'event': label,
                                    'target': target, 'date': ts, 'scan_id': scan_id})
        for pat, label in _LOW_SIGNALS:
            if _re.search(pat, text, _re.I):
                key = f'LOW:{label}:{target}'
                if key not in seen:
                    seen.add(key)
                    signals.append({'severity': 'LOW', 'event': label,
                                    'target': target, 'date': ts, 'scan_id': scan_id})

    _sev_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    signals.sort(key=lambda x: _sev_order.get(x['severity'], 3))

    counts = {k: sum(1 for s in signals if s['severity'] == k)
              for k in ('HIGH', 'MEDIUM', 'LOW', 'INFO')}
    counts['CRITICAL'] = sum(1 for sig in signals
                             if sig['severity'] == 'HIGH' and
                             any(kw in sig['event'].lower()
                                 for kw in ('injection', 'rce', 'exposure', 'traversal')))
    return jsonify({'signals': signals[:200], 'counts': counts})


@app.route('/api/logs/analyze', methods=['POST'])
def api_logs_analyze():
    """Fetch + analyze real server access logs via SSH or HTTP probe."""
    from tools.log_analyzer import analyze_from_ssh, analyze_from_probe, check_latency, check_error_rate

    data    = request.get_json(force=True, silent=True) or {}
    domain  = (data.get('domain') or '').strip().replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        return jsonify({'error': 'domain is required'}), 400

    ssh_host = (data.get('ssh_host') or domain).strip()
    ssh_user = (data.get('ssh_user') or 'root').strip()
    ssh_pass = (data.get('ssh_pass') or '').strip()
    ssh_port = int(data.get('ssh_port') or 22)

    if ssh_user and ssh_pass:
        result = analyze_from_ssh(ssh_host, ssh_user, ssh_pass, ssh_port)
    else:
        result = analyze_from_probe(domain)

    result['latency'] = check_latency(domain)
    return jsonify(result)


@app.route('/api/monitor/network', methods=['POST'])
def api_monitor_network():
    """Discover services + network topology via Nmap + SSH netstat."""
    import subprocess, json as _j, re as _re

    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get('domain') or '').strip().replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        return jsonify({'error': 'domain is required'}), 400

    ssh_host = (data.get('ssh_host') or domain).strip()
    ssh_user = (data.get('ssh_user') or '').strip()
    ssh_pass = (data.get('ssh_pass') or '').strip()
    ssh_port = int(data.get('ssh_port') or 22)

    # ── Nmap service scan (external) ──────────────────────────────────────────
    nodes = [{'id': domain, 'label': domain, 'type': 'target', 'group': 'target'}]
    edges = []
    services = []

    try:
        nmap_out = subprocess.run(
            ['nmap', '-Pn', '-sV', '--top-ports', '20', '--host-timeout', '30s',
             '--open', '-oG', '-', domain],
            capture_output=True, text=True, timeout=45,
        ).stdout
        for line in nmap_out.splitlines():
            m_ports = _re.findall(r'(\d+)/open/tcp//([^/]+)//([^/]*)', line)
            for port, proto, ver in m_ports:
                svc_id  = f'{proto.strip()}:{port}'
                svc_label = f'{proto.strip()} ({port})'
                services.append({'port': int(port), 'service': proto.strip(),
                                  'version': ver.strip()[:40], 'state': 'open'})
                nodes.append({'id': svc_id, 'label': svc_label, 'type': 'service', 'group': proto.strip()})
                edges.append({'from': domain, 'to': svc_id,
                               'label': f':{port}', 'arrows': 'to'})
    except Exception as e:
        services.append({'error': str(e)[:60]})

    # ── SSH netstat — active connections ─────────────────────────────────────
    connections = []
    traffic     = {}
    if ssh_user and ssh_pass:
        import os as _os
        ssh_base = ['sshpass', '-e', 'ssh', '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=10', '-p', str(ssh_port), f'{ssh_user}@{ssh_host}']
        run_env = _os.environ.copy()
        run_env['SSHPASS'] = ssh_pass

        try:
            ss_out = subprocess.run(
                ssh_base + ["ss -tuanp 2>/dev/null | head -40 || netstat -tunap 2>/dev/null | head -40"],
                capture_output=True, text=True, timeout=15, env=run_env,
            ).stdout
            for line in ss_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5 and parts[0] in ('tcp', 'udp', 'ESTAB', 'LISTEN', 'TIME-WAIT'):
                    connections.append({'proto': parts[0], 'local': parts[3] if len(parts) > 3 else '',
                                        'remote': parts[4] if len(parts) > 4 else '', 'state': parts[1] if len(parts) > 1 else ''})
        except Exception:
            pass

        try:
            dev_out = subprocess.run(
                ssh_base + ["cat /proc/net/dev 2>/dev/null | tail -n +3"],
                capture_output=True, text=True, timeout=10, env=run_env,
            ).stdout
            for line in dev_out.splitlines():
                if ':' not in line:
                    continue
                iface, rest = line.split(':', 1)
                nums = rest.split()
                if len(nums) >= 9:
                    traffic[iface.strip()] = {
                        'rx_bytes': int(nums[0]),
                        'tx_bytes': int(nums[8]),
                        'rx_mb': round(int(nums[0]) / 1048576, 2),
                        'tx_mb': round(int(nums[8]) / 1048576, 2),
                    }
        except Exception:
            pass

    # Add remote connection nodes
    remote_ips = set()
    for c in connections:
        remote = c.get('remote', '')
        if remote and remote not in ('*:*', '0.0.0.0:*', ':::*'):
            ip = remote.rsplit(':', 1)[0].strip('[]')
            if ip and ip not in ('0.0.0.0', '::', '127.0.0.1', '::1') and ip not in remote_ips:
                remote_ips.add(ip)
                geo = _geoip(ip)
                label = f'{ip}\n{geo}' if geo else ip
                nodes.append({'id': ip, 'label': label, 'type': 'remote', 'group': 'remote'})
                edges.append({'from': domain, 'to': ip, 'arrows': 'to'})

    return jsonify({
        'nodes': nodes, 'edges': edges,
        'services': services, 'connections': connections[:30],
        'traffic': traffic,
    })


@app.route('/api/monitor/latency')
def api_monitor_latency():
    """Quick HTTP latency probe for a domain."""
    from tools.log_analyzer import check_latency
    domain = (request.args.get('domain') or '').strip().replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        return jsonify({'error': 'domain required'}), 400
    return jsonify({'results': check_latency(domain)})


@app.route('/api/mitre/coverage')
def api_mitre_coverage():
    """MITRE ATT&CK coverage from all scan history."""
    from dashboard.mitre_rules import get_coverage, TACTICS
    scans   = db.get_recent_scans(100)
    result  = get_coverage(scans)
    result['tactic_order'] = [name for _, name in TACTICS]
    return jsonify(result)


@app.route('/api/incidents', methods=['GET'])
def api_incidents_get():
    status = request.args.get('status')
    return jsonify({'incidents': db.get_incidents(status=status),
                    'stats': db.get_incident_stats()})


@app.route('/api/incidents', methods=['POST'])
def api_incidents_create():
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title required'}), 400
    iid = db.create_incident(
        title=title,
        description=data.get('description', ''),
        severity=data.get('severity', 'MEDIUM'),
        target=data.get('target', ''),
        scan_id=data.get('scan_id'),
        mitre_tactic=data.get('mitre_tactic', ''),
        mitre_technique=data.get('mitre_technique', ''),
        rule_id=data.get('rule_id', ''),
    )
    return jsonify({'id': iid, 'created': True}), 201


@app.route('/api/incidents/<int:iid>', methods=['PATCH'])
def api_incidents_update(iid):
    data = request.get_json(force=True, silent=True) or {}
    ok   = db.update_incident(iid, **data)
    return jsonify({'updated': ok})


@app.route('/api/unified/overview')
def api_unified_overview():
    """Aggregate metrics for the unified observability dashboard."""
    from dashboard.mitre_rules import get_coverage
    scans      = db.get_recent_scans(50)
    coverage   = get_coverage(scans)

    # Build signal timeline (signals per day from recent scans)
    import re as _re
    from collections import defaultdict
    daily: dict = defaultdict(int)
    for s in scans:
        day = s.get('created_at', '')[:10]
        text = s.get('output', '')
        # Count high-severity pattern hits
        if _re.search(r'sql\s*inject|xss|rce|brute.force|exposed.*key|path.traversal', text, _re.I):
            daily[day] += 1

    # Slowest pages from latest scan per target
    slowest = sorted(
        [{'target': s['target'], 'latency': s.get('latency_s', 0),
          'agent': s.get('agent_type', '')}
         for s in scans],
        key=lambda x: x['latency'], reverse=True
    )[:10]

    # Error rate from scan statuses
    total = len(scans)
    errors = sum(1 for s in scans if s.get('status') != 'ok')
    error_rate = round(errors / max(total, 1) * 100, 1)

    # Recent high-severity signals
    from dashboard.mitre_rules import evaluate_rules
    recent_signals = []
    seen = set()
    for s in scans[:20]:
        for match in evaluate_rules(s.get('output', ''), s.get('target', '')):
            if match['severity'] in ('HIGH',) and match['id'] not in seen:
                seen.add(match['id'])
                recent_signals.append({**match, 'date': s.get('created_at', '')[:10]})

    return jsonify({
        'signal_timeline':  dict(sorted(daily.items())[-14:]),
        'slowest_pages':    slowest,
        'error_rate_pct':   error_rate,
        'total_scans':      total,
        'mitre_total':      coverage['total'],
        'mitre_severities': coverage['severities'],
        'recent_high_signals': recent_signals[:10],
        'incident_stats':   db.get_incident_stats(),
    })


@app.route('/api/stream/signals')
def api_stream_signals():
    """SSE endpoint — pushes a JSON signal-stats event every 15 s."""
    from flask import Response, stream_with_context

    def _event_stream():
        while True:
            try:
                stats = db.get_stats()
                inc   = db.get_incident_stats()
                recent = db.get_recent_scans(5)
                payload = _json.dumps({
                    'total_scans': stats['total_scans'],
                    'open_incidents': inc['open'],
                    'latest_target': recent[0]['target'] if recent else '',
                    'latest_status': recent[0]['status'] if recent else '',
                })
                yield f'data: {payload}\n\n'
            except Exception:
                yield 'data: {}\n\n'
            _time.sleep(15)

    return Response(stream_with_context(_event_stream()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache',
                             'X-Accel-Buffering': 'no'})


if __name__ == '__main__':
    port = int(os.environ.get('CFAI_DASHBOARD_PORT', 8889))
    print(f'CF_AI Dashboard running on http://0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
