"""CF_AI — Remediation template library.

Each entry maps detection patterns found in agent output to exact,
copy-paste-ready configuration fixes for common web server stacks.
Patterns are matched only on non-negated lines (see app.py _NEGATION filter).

Categories:
  Security Headers · SSL/TLS · WordPress · Server Configuration
  Application Security · PHP/File Upload · Infrastructure
  Email Security · API Security · Authentication · Injection
  Web Server Misconfig · Cryptography · Dependencies
  Network/Infrastructure · Client-side · CMS Extended
"""

REMEDIATIONS = [

    # ── Security Headers ──────────────────────────────────────────────────────

    {
        'id': 'missing-x-frame-options',
        'patterns': ['x-frame-options', 'clickjacking', 'iframe embed'],
        'title': 'Add X-Frame-Options header to prevent clickjacking',
        'severity': 'MEDIUM',
        'description': 'The X-Frame-Options header is missing. Without it, attackers can embed your site inside an invisible iframe and trick users into clicking on hidden elements.',
        'fixes': {
            'Nginx': 'add_header X-Frame-Options "SAMEORIGIN" always;',
            'Apache': 'Header always set X-Frame-Options "SAMEORIGIN"',
            '.htaccess': 'Header set X-Frame-Options "SAMEORIGIN"',
            'WordPress (functions.php)': "add_action('send_headers', function() {\n    header('X-Frame-Options: SAMEORIGIN');\n});",
        },
    },

    {
        'id': 'missing-csp',
        'patterns': ['content-security-policy', 'csp missing', 'no csp', 'csp not set', 'csp header'],
        'title': 'Add Content-Security-Policy header',
        'severity': 'MEDIUM',
        'description': 'No Content-Security-Policy header was found. This leaves the site open to cross-site scripting (XSS) and data injection attacks by allowing scripts from any source.',
        'fixes': {
            'Nginx': "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline';\" always;",
            'Apache': "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline';\"",
            '.htaccess': "Header set Content-Security-Policy \"default-src 'self';\"",
            'Strict CSP (report-only first)': "# Start with report-only mode to catch breakage before enforcing:\nadd_header Content-Security-Policy-Report-Only \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; report-uri /csp-report;\" always;",
        },
    },

    {
        'id': 'weak-csp',
        'patterns': ['unsafe-inline in csp', 'csp unsafe-inline', 'csp contains unsafe', 'csp bypass', 'weak csp', 'content-security-policy.*unsafe-inline'],
        'title': "Strengthen CSP — remove 'unsafe-inline' to block XSS",
        'severity': 'MEDIUM',
        'description': "Content-Security-Policy is set but contains 'unsafe-inline', which allows inline scripts and negates most XSS protection. Use nonces or hashes instead.",
        'fixes': {
            'Nginx (nonce-based)': "# 1. Generate a random nonce per request in your app\n# 2. Add the nonce to each <script> tag: <script nonce=\"{nonce}\">\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none';\" always;",
            'PHP — generate nonce': "<?php\n\$nonce = base64_encode(random_bytes(16));\nheader(\"Content-Security-Policy: script-src 'nonce-{\$nonce}'\");\n// Then in HTML: <script nonce=\"<?= \$nonce ?>\">",
            'WordPress (functions.php)': "// Use WP's built-in nonce for inline scripts:\nwp_add_inline_script('my-handle', 'var config = '.json_encode(\$data).';');",
        },
    },

    {
        'id': 'missing-hsts',
        'patterns': ['strict-transport-security', 'hsts missing', 'hsts not', 'no hsts'],
        'title': 'Enable HTTP Strict Transport Security (HSTS)',
        'severity': 'MEDIUM',
        'description': 'The HSTS header is missing. Without it, users connecting over HTTP are not automatically upgraded to HTTPS and can be intercepted by man-in-the-middle attacks.',
        'fixes': {
            'Nginx': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            'Apache': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            '.htaccess': 'Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            'Preload submission': '# After confirming HSTS works, submit to the preload list:\n# https://hstspreload.org\n# This makes all browsers enforce HTTPS before the first connection.',
        },
    },

    {
        'id': 'missing-xcto',
        'patterns': ['x-content-type-options', 'mime sniff', 'nosniff missing', 'content-type sniff'],
        'title': 'Add X-Content-Type-Options: nosniff header',
        'severity': 'LOW',
        'description': 'The X-Content-Type-Options header is missing. Browsers may try to guess the content type and execute files in unintended ways.',
        'fixes': {
            'Nginx': 'add_header X-Content-Type-Options "nosniff" always;',
            'Apache': 'Header always set X-Content-Type-Options "nosniff"',
            '.htaccess': 'Header set X-Content-Type-Options "nosniff"',
        },
    },

    {
        'id': 'missing-referrer-policy',
        'patterns': ['referrer-policy', 'referrer policy missing', 'no referrer-policy'],
        'title': 'Add Referrer-Policy header',
        'severity': 'LOW',
        'description': 'No Referrer-Policy header found. The browser may leak full URLs to third-party sites when users follow links.',
        'fixes': {
            'Nginx': 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'Apache': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            '.htaccess': 'Header set Referrer-Policy "strict-origin-when-cross-origin"',
        },
    },

    {
        'id': 'missing-permissions-policy',
        'patterns': ['permissions-policy', 'feature-policy', 'permissions policy missing', 'feature policy missing'],
        'title': 'Add Permissions-Policy header to restrict browser features',
        'severity': 'LOW',
        'description': 'No Permissions-Policy header found. Without it, third-party scripts can access sensitive browser APIs (camera, microphone, geolocation, payment) on your domain.',
        'fixes': {
            'Nginx': 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;',
            'Apache': 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"',
            '.htaccess': 'Header set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
        },
    },

    # ── SSL / TLS ─────────────────────────────────────────────────────────────

    {
        'id': 'weak-tls',
        'patterns': ['tlsv1.0', 'tlsv1.1', 'sslv3', 'weak cipher', 'weak tls', 'outdated ssl', 'old tls'],
        'title': 'Disable outdated TLS 1.0 and TLS 1.1 protocols',
        'severity': 'HIGH',
        'description': 'Old TLS versions (1.0, 1.1) are still enabled. These have known weaknesses and are deprecated. Only TLS 1.2 and 1.3 should be active.',
        'fixes': {
            'Nginx': 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers off;',
            'Apache': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\nSSLHonorCipherOrder off',
            'Verify after change': '# Test with: nmap --script ssl-enum-ciphers -p 443 yourdomain.com\n# Or: testssl.sh yourdomain.com',
        },
    },

    {
        'id': 'expired-cert',
        'patterns': ['expired certificate', 'certificate expired', 'cert expired', 'certificate has expired'],
        'title': 'Renew the SSL/TLS certificate immediately',
        'severity': 'HIGH',
        'description': 'The SSL certificate is expired. Visitors see a browser security warning and may leave. Encrypted connections may also be rejected.',
        'fixes': {
            "Certbot (Let's Encrypt)": 'sudo certbot renew --force-renewal\nsudo systemctl reload nginx   # or: sudo systemctl reload apache2',
            'Certbot (cron check)': '# Ensure auto-renewal cron is active:\nsudo certbot renew --dry-run',
            'Manual': '# 1. Log into your certificate provider or hosting panel\n# 2. Generate a new CSR and submit for renewal\n# 3. Download and install the new certificate files',
        },
    },

    {
        'id': 'self-signed-cert',
        'patterns': ['self-signed', 'self signed certificate', 'untrusted certificate', 'certificate not trusted'],
        'title': 'Replace self-signed certificate with a trusted one',
        'severity': 'HIGH',
        'description': "A self-signed certificate is in use. Browsers will show a security warning to all visitors. A free trusted certificate is available via Let's Encrypt.",
        'fixes': {
            "Certbot (Let's Encrypt — free)": 'sudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com -d www.yourdomain.com',
            'Certbot (Apache)': 'sudo apt install certbot python3-certbot-apache\nsudo certbot --apache -d yourdomain.com',
        },
    },

    {
        'id': 'cert-cn-mismatch',
        'patterns': ['certificate name mismatch', 'cn mismatch', 'hostname mismatch', 'ssl hostname', 'common name mismatch', 'certificate hostname'],
        'title': 'Fix SSL certificate hostname mismatch',
        'severity': 'HIGH',
        'description': 'The SSL certificate is issued for a different hostname than the one being accessed. This causes browser warnings and breaks secure connections.',
        'fixes': {
            "Certbot — issue cert for correct domain": 'sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com\n# Include ALL hostnames that access this server as -d arguments',
            'Check current cert names': 'openssl s_client -connect yourdomain.com:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -subj_hash -alt_name',
        },
    },

    # ── WordPress ─────────────────────────────────────────────────────────────

    {
        'id': 'wp-xmlrpc-exposed',
        'patterns': ['xmlrpc.php', 'xml-rpc enabled', 'xmlrpc exposed', 'xmlrpc accessible'],
        'title': 'Disable WordPress XML-RPC endpoint',
        'severity': 'MEDIUM',
        'description': 'The WordPress XML-RPC endpoint is publicly accessible. It can be abused for brute-force credential attacks and server-side request forgery (SSRF) if not needed.',
        'fixes': {
            'Nginx': 'location = /xmlrpc.php {\n    deny all;\n    return 403;\n}',
            '.htaccess': '<Files xmlrpc.php>\n  Order Deny,Allow\n  Deny from all\n</Files>',
            'WordPress (functions.php)': "add_filter('xmlrpc_enabled', '__return_false');",
            'WP-CLI': 'wp option add disallow_file_edit 1',
        },
    },

    {
        'id': 'wp-version-disclosed',
        'patterns': ['wordpress version disclosed', 'wp version exposed', 'readme.html', 'generator tag wordpress'],
        'title': 'Hide WordPress version number',
        'severity': 'LOW',
        'description': 'The WordPress version is publicly visible in readme.html or the page source. Attackers use this to target known vulnerabilities for that version.',
        'fixes': {
            'Bash (remove files)': 'rm /var/www/html/readme.html\nrm /var/www/html/license.txt',
            'WordPress (functions.php)': "remove_action('wp_head', 'wp_generator');\nfunction remove_wp_version_strings(\$src) {\n    global \$wp_version;\n    return str_replace('ver='.\$wp_version, '', \$src);\n}\nadd_filter('script_loader_src', 'remove_wp_version_strings');\nadd_filter('style_loader_src', 'remove_wp_version_strings');",
            'Nginx': 'location ~* ^/(readme|license|wp-config-sample)\\.(html|txt|php)$ {\n    deny all;\n    return 404;\n}',
        },
    },

    {
        'id': 'wp-login-no-ratelimit',
        'patterns': ['wp-login.php', 'login brute', 'brute force login', 'no rate limit on login', 'unlimited login'],
        'title': 'Add rate limiting to WordPress login page',
        'severity': 'HIGH',
        'description': 'The WordPress login page has no rate limiting or lockout after failed attempts. An attacker can try unlimited username/password combinations automatically.',
        'fixes': {
            'Nginx (rate limit)': '# In http block:\nlimit_req_zone $binary_remote_addr zone=wp_login:10m rate=5r/m;\n\n# In server block:\nlocation = /wp-login.php {\n    limit_req zone=wp_login burst=3 nodelay;\n    fastcgi_pass unix:/run/php/php-fpm.sock;\n    include fastcgi_params;\n}',
            'WP-CLI (install plugin)': 'wp plugin install limit-login-attempts-reloaded --activate --path=/var/www/html',
            'WP-CLI (install Wordfence)': 'wp plugin install wordfence --activate --path=/var/www/html',
        },
    },

    {
        'id': 'wp-admin-exposed',
        'patterns': ['wp-admin accessible', '/wp-admin/ open', 'admin panel exposed'],
        'title': 'Restrict access to WordPress admin panel by IP',
        'severity': 'MEDIUM',
        'description': 'The WordPress admin panel is publicly accessible from any IP. Restricting it to known IPs reduces brute-force attack surface significantly.',
        'fixes': {
            'Nginx': 'location /wp-admin/ {\n    allow YOUR.OFFICE.IP.HERE;\n    deny all;\n}',
            '.htaccess': '<Files wp-login.php>\n  Order Deny,Allow\n  Deny from all\n  Allow from YOUR.OFFICE.IP.HERE\n</Files>',
        },
    },

    {
        'id': 'wp-debug-mode',
        'patterns': ['wp_debug', 'wp debug enabled', 'wordpress debug mode', 'wp_debug true', 'debug.log exposed'],
        'title': 'Disable WordPress debug mode on production',
        'severity': 'HIGH',
        'description': 'WordPress debug mode is enabled on a production server. This exposes PHP errors, warnings, file paths, and potentially sensitive data to all visitors.',
        'fixes': {
            'wp-config.php': "// Set these in wp-config.php:\ndefine('WP_DEBUG', false);\ndefine('WP_DEBUG_LOG', false);\ndefine('WP_DEBUG_DISPLAY', false);\n@ini_set('display_errors', 0);",
            'Nginx — block debug.log': "location ~* /wp-content/debug\\.log$ {\n    deny all;\n    return 404;\n}",
        },
    },

    {
        'id': 'wp-file-editing',
        'patterns': ['file editing enabled', 'wp file editor', 'theme editor accessible', 'plugin editor accessible', 'disallow_file_edit'],
        'title': 'Disable WordPress theme/plugin file editor',
        'severity': 'MEDIUM',
        'description': 'The WordPress admin file editor is enabled. If an attacker gains admin access, they can immediately inject code into any theme or plugin file.',
        'fixes': {
            'wp-config.php': "// Prevent any code editing via the admin panel:\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('DISALLOW_FILE_MODS', true);  // Also blocks plugin/theme installs",
            'WP-CLI': "wp config set DISALLOW_FILE_EDIT true --raw --path=/var/www/html",
        },
    },

    {
        'id': 'wp-user-enum',
        'patterns': ['wordpress user enumeration', 'wp user enum', '/wp-json/wp/v2/users', 'wordpress users exposed', '?author=1'],
        'title': 'Block WordPress user enumeration',
        'severity': 'MEDIUM',
        'description': 'WordPress user accounts can be enumerated via the REST API or author archives. Attackers use this to get valid usernames before launching credential attacks.',
        'fixes': {
            'WordPress (functions.php)': "// Block author enumeration redirects:\nif (!is_admin() && isset(\$_GET['author'])) {\n    wp_redirect(home_url(), 301); exit;\n}\n// Block REST API user listing:\nadd_filter('rest_endpoints', function(\$endpoints) {\n    if (isset(\$endpoints['/wp/v2/users'])) unset(\$endpoints['/wp/v2/users']);\n    if (isset(\$endpoints['/wp/v2/users/(?P<id>[\\d]+)'])) unset(\$endpoints['/wp/v2/users/(?P<id>[\\d]+)']);\n    return \$endpoints;\n});",
            'Nginx': "# Block ?author= enumeration:\nif (\$query_string ~ \"author=\\d+\") {\n    return 403;\n}",
        },
    },

    {
        'id': 'wp-outdated-plugin',
        'patterns': ['outdated plugin', 'plugin update available', 'vulnerable plugin', 'plugin vulnerability', 'insecure plugin version', 'plugin cve'],
        'title': 'Update outdated / vulnerable WordPress plugins immediately',
        'severity': 'HIGH',
        'description': 'One or more WordPress plugins are outdated or have known security vulnerabilities. Unpatched plugins are the most common WordPress compromise vector.',
        'fixes': {
            'WP-CLI (update all)': 'wp plugin update --all --path=/var/www/html\nwp theme update --all --path=/var/www/html',
            'WP-CLI (check which are outdated)': 'wp plugin list --update=available --path=/var/www/html\nwp plugin list --status=inactive --path=/var/www/html',
            'Dashboard': '# WordPress Dashboard → Plugins → Update Available → Update All\n# Enable auto-updates per plugin with WP-CLI:\nwp plugin auto-updates enable --all --path=/var/www/html',
            'Remove unused plugins': '# Delete — do not just deactivate — unused plugins:\nwp plugin delete <plugin-slug> --path=/var/www/html',
        },
    },

    # ── Server Configuration ──────────────────────────────────────────────────

    {
        'id': 'server-version-disclosed',
        'patterns': ['server version', 'x-powered-by', 'server banner', 'version in header', 'php version disclosed'],
        'title': 'Hide server version and technology from response headers',
        'severity': 'LOW',
        'description': 'The web server is revealing its version and technology in response headers (Server, X-Powered-By). This helps attackers identify which CVEs apply to the server.',
        'fixes': {
            'Nginx': 'server_tokens off;',
            'Apache (httpd.conf)': 'ServerTokens Prod\nServerSignature Off',
            '.htaccess': 'Header unset X-Powered-By\nServerSignature Off',
            'PHP (php.ini)': 'expose_php = Off',
        },
    },

    {
        'id': 'directory-listing',
        'patterns': ['directory listing', 'directory index enabled', 'index of /', 'autoindex on'],
        'title': 'Disable directory listing',
        'severity': 'MEDIUM',
        'description': 'Directory listing is enabled. Anyone can browse your folder contents and discover source files, configuration files, or backup files.',
        'fixes': {
            'Nginx': 'autoindex off;   # Add inside server or location block',
            'Apache': 'Options -Indexes',
            '.htaccess': 'Options -Indexes',
        },
    },

    {
        'id': 'exposed-env-git',
        'patterns': ['.env exposed', '.git exposed', '/.env accessible', '/.git/head', 'git repository exposed'],
        'title': 'Block access to .env and .git files immediately',
        'severity': 'HIGH',
        'description': 'Environment files (.env) or Git repository files (.git) are publicly accessible. These can contain database passwords, API keys, and full source code.',
        'fixes': {
            'Nginx': 'location ~ /\\.(env|git|svn|htaccess|DS_Store) {\n    deny all;\n    return 404;\n}',
            'Apache': '<FilesMatch "^\\.">\n  Order allow,deny\n  Deny from all\n</FilesMatch>',
            '.htaccess': 'RedirectMatch 404 /\\.git\nRedirectMatch 404 /\\.env',
        },
    },

    {
        'id': 'http-trace-method',
        'patterns': ['trace method', 'http trace', 'trace enabled', 'xst attack', 'cross-site tracing'],
        'title': 'Disable HTTP TRACE method to prevent XST attacks',
        'severity': 'LOW',
        'description': 'The HTTP TRACE method is enabled. This can be used in Cross-Site Tracing (XST) attacks to steal cookies or auth headers when combined with XSS.',
        'fixes': {
            'Nginx': 'if ($request_method = TRACE) {\n    return 405;\n}',
            'Apache (httpd.conf)': 'TraceEnable off',
            '.htaccess': 'RewriteEngine On\nRewriteCond %{REQUEST_METHOD} ^TRACE\nRewriteRule .* - [F]',
        },
    },

    {
        'id': 'http-put-delete-methods',
        'patterns': ['put method enabled', 'delete method enabled', 'http put allowed', 'dav enabled', 'webdav exposed'],
        'title': 'Disable HTTP PUT/DELETE/WebDAV methods',
        'severity': 'HIGH',
        'description': 'HTTP PUT or DELETE methods are enabled. These can allow attackers to upload files, overwrite content, or delete pages from the server.',
        'fixes': {
            'Nginx': "if (\$request_method ~* '^(PUT|DELETE|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)') {\n    return 405;\n}",
            'Apache (httpd.conf)': '<LimitExcept GET POST HEAD>\n    Require all denied\n</LimitExcept>',
            '.htaccess': '<LimitExcept GET POST HEAD>\n  Order allow,deny\n  Deny from all\n</LimitExcept>',
        },
    },

    {
        'id': 'path-traversal',
        'patterns': ['path traversal', 'directory traversal', '../', 'dot dot slash', 'lfi confirmed', 'local file inclusion'],
        'title': 'Fix path traversal / local file inclusion vulnerability',
        'severity': 'HIGH',
        'description': 'A path traversal or local file inclusion vulnerability was detected. An attacker can read arbitrary files from the server, including /etc/passwd, .env, or SSL private keys.',
        'fixes': {
            'PHP — use realpath() validation': "// Whitelist allowed base directory:\n\$base = realpath('/var/www/html/uploads');\n\$file = realpath(\$base . '/' . \$_GET['file']);\n// Reject if resolved path doesn't start with the base:\nif (\$file === false || strpos(\$file, \$base) !== 0) {\n    http_response_code(403);\n    exit('Access denied');\n}\nreadfile(\$file);",
            'Nginx — block traversal sequences': "location ~* (\\.\\./|\\.\\.) {\n    return 400;\n}",
            'Apache': 'Options -FollowSymLinks\n# Also set in php.ini:\n# open_basedir = /var/www/html:/tmp',
        },
    },

    # ── Application Security ──────────────────────────────────────────────────

    {
        'id': 'insecure-cookies',
        'patterns': ['insecure cookie', 'cookie without secure', 'missing secure flag', 'missing httponly', 'cookie not secure', 'samesite missing'],
        'title': 'Set Secure, HttpOnly, and SameSite flags on session cookies',
        'severity': 'MEDIUM',
        'description': 'Session cookies are missing the Secure and/or HttpOnly flags. Without Secure, cookies can be sent over HTTP. Without HttpOnly, JavaScript can read them. Without SameSite, CSRF attacks are possible.',
        'fixes': {
            'Nginx': 'proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";',
            'Apache': 'Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"',
            'PHP (php.ini)': 'session.cookie_httponly = 1\nsession.cookie_secure = 1\nsession.cookie_samesite = "Strict"',
            'PHP (session_set_cookie_params)': "session_set_cookie_params([\n    'lifetime' => 0,\n    'path'     => '/',\n    'domain'   => '.yourdomain.com',\n    'secure'   => true,\n    'httponly' => true,\n    'samesite' => 'Strict',\n]);\nsession_start();",
            'WordPress (wp-config.php)': "@ini_set('session.cookie_httponly', true);\n@ini_set('session.cookie_secure', true);\n@ini_set('session.cookie_samesite', 'Strict');",
        },
    },

    {
        'id': 'csrf-missing',
        'patterns': ['csrf', 'cross-site request forgery', 'no csrf token', 'csrf token missing', 'csrf protection'],
        'title': 'Implement CSRF protection on all state-changing endpoints',
        'severity': 'HIGH',
        'description': 'The application lacks CSRF protection. An attacker can craft a malicious page that silently performs actions (transfers, password changes) on behalf of a logged-in user.',
        'fixes': {
            'PHP — synchronizer token': "// Generate and store token on form load:\nif (empty(\$_SESSION['csrf_token'])) {\n    \$_SESSION['csrf_token'] = bin2hex(random_bytes(32));\n}\n// In form HTML:\necho '<input type=\"hidden\" name=\"csrf_token\" value=\"' . \$_SESSION['csrf_token'] . '\">';\n// On submit — verify:\nif (!hash_equals(\$_SESSION['csrf_token'], \$_POST['csrf_token'] ?? '')) {\n    http_response_code(403); exit('CSRF check failed');\n}",
            'SameSite cookie (defence-in-depth)': "# Setting SameSite=Strict on session cookies prevents most CSRF:\nsession.cookie_samesite = Strict",
            'WordPress (nonces)': "// Use WordPress nonces for all admin actions:\nwp_nonce_field('my_action', '_wpnonce');\n// Verify:\ncheck_admin_referer('my_action');",
        },
    },

    {
        'id': 'cors-wildcard',
        'patterns': ['cors misconfiguration', 'cors wildcard', 'access-control-allow-origin: *', 'cors *'],
        'title': 'Fix CORS — replace wildcard with specific allowed origins',
        'severity': 'MEDIUM',
        'description': 'CORS is set to allow all origins (*). Any website can make authenticated requests to your API and read the response, enabling data theft.',
        'fixes': {
            'Nginx': "add_header Access-Control-Allow-Origin 'https://yourdomain.com' always;\nadd_header Access-Control-Allow-Credentials 'true' always;",
            'Apache': 'Header set Access-Control-Allow-Origin "https://yourdomain.com"',
            'PHP': "header('Access-Control-Allow-Origin: https://yourdomain.com');\nheader('Access-Control-Allow-Credentials: true');",
            'Dynamic origin validation (PHP)': "\$allowed = ['https://yourdomain.com', 'https://app.yourdomain.com'];\n\$origin = \$_SERVER['HTTP_ORIGIN'] ?? '';\nif (in_array(\$origin, \$allowed)) {\n    header('Access-Control-Allow-Origin: ' . \$origin);\n}",
        },
    },

    {
        'id': 'sql-injection-confirmed',
        'patterns': ['sql injection confirmed', 'sqli confirmed', 'sql injection found', 'sql injection successful', 'injectable', 'sqlmap'],
        'title': 'Fix confirmed SQL injection vulnerability',
        'severity': 'HIGH',
        'description': 'A SQL injection vulnerability was confirmed. An attacker can read, modify, or delete all data in the database, and potentially take over the server.',
        'fixes': {
            'PHP — parameterised queries (PDO)': "// SAFE — always use prepared statements:\n\$stmt = \$pdo->prepare('SELECT * FROM users WHERE id = ? AND active = ?');\n\$stmt->execute([\$_GET['id'], 1]);\n\$user = \$stmt->fetch(PDO::FETCH_ASSOC);",
            'PHP — PDO input type enforcement': "// For integer params, cast explicitly:\n\$id = (int) \$_GET['id'];   // 0 if not numeric\n\$stmt = \$pdo->prepare('SELECT * FROM users WHERE id = :id');\n\$stmt->bindValue(':id', \$id, PDO::PARAM_INT);\n\$stmt->execute();",
            'WordPress ($wpdb->prepare)': "\$result = \$wpdb->get_results(\n    \$wpdb->prepare(\n        'SELECT * FROM wp_users WHERE ID = %d',\n        (int) \$user_id\n    )\n);",
            'WAF rule (Nginx + ModSecurity)': 'sudo apt install libapache2-mod-security2\n# Enable OWASP Core Rule Set (CRS):\n# https://github.com/coreruleset/coreruleset',
        },
    },

    {
        'id': 'open-redirect',
        'patterns': ['open redirect', 'unvalidated redirect', 'redirect to external'],
        'title': 'Fix open redirect vulnerability',
        'severity': 'MEDIUM',
        'description': 'The application allows redirecting users to arbitrary external URLs. Attackers use this in phishing links that appear to come from your trusted domain.',
        'fixes': {
            'PHP — allowlist approach': "\$allowed_hosts = ['yourdomain.com', 'www.yourdomain.com'];\n\$url = parse_url(\$_GET['redirect'] ?? '/');\nif (!isset(\$url['host']) || !in_array(\$url['host'], \$allowed_hosts)) {\n    \$redirect = '/home';\n}\nheader('Location: ' . \$redirect);\nexit;",
            'General': '# 1. Validate all redirect targets against an allowlist\n# 2. Use relative paths instead of full URLs where possible\n# 3. If external redirects are needed, use an interstitial warning page',
        },
    },

    # ── PHP / File Upload ─────────────────────────────────────────────────────

    {
        'id': 'php-file-upload',
        'patterns': ['unrestricted file upload', 'arbitrary file upload', 'php file upload', 'file upload vulnerability', 'malicious file upload'],
        'title': 'Restrict file upload types and store outside web root',
        'severity': 'HIGH',
        'description': 'The application allows uploading files without proper type validation. An attacker can upload a PHP webshell and execute arbitrary code on the server.',
        'fixes': {
            'PHP — validate MIME + extension': "\$allowed_ext  = ['jpg','jpeg','png','gif','pdf','docx'];\n\$allowed_mime = ['image/jpeg','image/png','image/gif','application/pdf'];\n\$finfo   = new finfo(FILEINFO_MIME_TYPE);\n\$detected = \$finfo->file(\$_FILES['file']['tmp_name']);\n\$ext     = strtolower(pathinfo(\$_FILES['file']['name'], PATHINFO_EXTENSION));\nif (!in_array(\$ext, \$allowed_ext) || !in_array(\$detected, \$allowed_mime)) {\n    die('Invalid file type');\n}\n\$dest = '/var/uploads/' . bin2hex(random_bytes(8)) . '.' . \$ext;\nmove_uploaded_file(\$_FILES['file']['tmp_name'], \$dest);",
            'Nginx — block PHP in uploads': 'location ~* /uploads/.*\\.php$ {\n    deny all;\n    return 403;\n}',
            'WordPress (functions.php)': "add_filter('upload_mimes', function(\$mimes) {\n    unset(\$mimes['php'], \$mimes['phtml'], \$mimes['phar'], \$mimes['js']);\n    return \$mimes;\n});",
        },
    },

    {
        'id': 'php-code-execution',
        'patterns': ['remote code execution', 'rce confirmed', 'rce found', 'code execution', 'command injection', 'os command injection', 'eval injection'],
        'title': 'Fix remote code / OS command execution vulnerability',
        'severity': 'HIGH',
        'description': 'The scan found a remote code execution or command injection vulnerability. An attacker can execute arbitrary OS commands or PHP code with the permissions of the web server process.',
        'fixes': {
            'PHP — disable dangerous functions (php.ini)': 'disable_functions = exec, passthru, shell_exec, system, proc_open, popen, show_source, posix_kill, posix_mkfifo, posix_getpwuid, posix_setpgid, posix_setsid, posix_setuid, posix_setgid',
            'PHP — safe OS command pattern': "\$allowed = ['ls /var/log', 'df -h'];\nif (!in_array(\$cmd, \$allowed)) die('Forbidden');\n\$output = shell_exec(escapeshellcmd(\$cmd));",
            'WAF (ModSecurity)': '# Enable OWASP CRS rule set:\n# SecRuleEngine On\n# Include /etc/modsecurity/crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf',
        },
    },

    {
        'id': 'xss-reflected',
        'patterns': ['xss found', 'cross-site scripting', 'xss confirmed', 'reflected xss', 'stored xss', 'xss vulnerability', 'xss detected'],
        'title': 'Fix cross-site scripting (XSS) vulnerability',
        'severity': 'HIGH',
        'description': 'A cross-site scripting vulnerability was found. Attackers can inject malicious scripts into pages viewed by other users, stealing session cookies, credentials, or redirecting users to phishing sites.',
        'fixes': {
            'PHP — HTML encoding': "echo htmlspecialchars(\$userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');",
            'PHP — JSON output': "echo json_encode(\$data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);",
            'CSP nonce to block inline execution': "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none';\" always;",
            'WordPress': "// Sanitise user input on save:\n\$clean = sanitize_text_field(\$_POST['field']);\n// Escape on output:\necho esc_html(\$value);  // text\necho esc_attr(\$value);  // HTML attributes\necho esc_url(\$value);   // URLs",
        },
    },

    {
        'id': 'broken-access-control',
        'patterns': ['broken access control', 'idor', 'insecure direct object', 'unauthorized access', 'privilege escalation', 'access control bypass', 'unauthorised access'],
        'title': 'Fix broken access control / IDOR',
        'severity': 'HIGH',
        'description': "The application fails to properly enforce access controls. Users can access resources or actions they should not be authorised for, potentially exposing other users' data.",
        'fixes': {
            'PHP — always verify ownership': "\$stmt = \$pdo->prepare('SELECT * FROM orders WHERE id=? AND user_id=?');\n\$stmt->execute([\$_GET['id'], \$_SESSION['user_id']]);\n\$order = \$stmt->fetch();\nif (!\$order) { http_response_code(403); die('Forbidden'); }",
            'UUID instead of sequential IDs': '# Use UUIDs instead of integers for resource IDs:\n# INSERT INTO orders (id, ...) VALUES (UUID(), ...)\n# This prevents enumeration even if auth fails',
            'WordPress': "if (!current_user_can('edit_post', \$post_id)) {\n    wp_die('You do not have permission.');\n}",
        },
    },

    {
        'id': 'sensitive-data-exposed',
        'patterns': ['sensitive data exposed', 'data exposure', 'credential exposed', 'password in plaintext', 'api key exposed', 'secret exposed', 'token exposed', 'credential in response'],
        'title': 'Remove exposed credentials / sensitive data from responses',
        'severity': 'HIGH',
        'description': 'Sensitive data — such as passwords, API keys, or secrets — was found in HTTP responses, logs, or publicly accessible files. This data must be removed immediately and the exposed credentials rotated.',
        'fixes': {
            'Rotate immediately': '# STOP: Rotate ALL exposed credentials NOW — they are compromised.\n# Check git history: git log -p | grep -i "password\\|api_key\\|secret\\|token"\n# Purge from history: git filter-repo --invert-paths --path <file>',
            'PHP — environment variables': "// Never hardcode secrets:\n// WRONG: \$db_pass = 'MySecret123';\n// RIGHT: \$db_pass = getenv('DB_PASSWORD');\n// Store in /etc/environment or .env (block HTTP access)",
            'Nginx — block sensitive file types': 'location ~* \\.(env|log|bak|sql|conf|ini|key|pem|pfx|p12)$ {\n    deny all;\n    return 404;\n}',
        },
    },

    # ── Infrastructure ────────────────────────────────────────────────────────

    {
        'id': 'unpatched-cms',
        'patterns': ['outdated wordpress', 'wordpress outdated', 'wp version', 'wordpress version', 'cms version', 'outdated cms', 'outdated version', 'old version detected'],
        'title': 'Update WordPress / CMS to the latest version',
        'severity': 'HIGH',
        'description': 'An outdated version of WordPress or another CMS was detected. Older versions contain known, publicly exploited vulnerabilities. Updates should be applied immediately.',
        'fixes': {
            'WP-CLI (recommended)': 'wp core update --path=/var/www/html\nwp plugin update --all --path=/var/www/html\nwp theme update --all --path=/var/www/html\nwp core version --path=/var/www/html',
            'Enable auto-updates (wp-config.php)': 'define("WP_AUTO_UPDATE_CORE", "minor");',
            'Bash — backup before update': 'mysqldump -u root -p dbname > backup_$(date +%Y%m%d).sql\ntar -czf wp_backup_$(date +%Y%m%d).tar.gz /var/www/html',
        },
    },

    {
        'id': 'open-port-service',
        'patterns': ['open port', 'exposed port', 'port open', 'service exposed', 'ssh exposed', 'rdp exposed', 'ftp exposed', 'telnet exposed', 'database port open', 'mysql port', '3306 open', '5432 open', '27017 open'],
        'title': 'Close or restrict unnecessarily exposed network ports / services',
        'severity': 'MEDIUM',
        'description': 'One or more network ports are exposed to the internet that should be restricted. Database ports (MySQL, PostgreSQL, MongoDB) and management interfaces (SSH, RDP) should never be publicly accessible.',
        'fixes': {
            'UFW (Ubuntu Firewall)': '# Allow SSH only from your office IP:\nufw allow from YOUR.OFFICE.IP.HERE to any port 22\nufw deny 22\nufw allow from 127.0.0.1 to any port 3306\nufw enable',
            'iptables': 'iptables -A INPUT -p tcp --dport 3306 -s YOUR_APP_SERVER_IP -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -j DROP',
            'Nginx — restrict admin by IP': 'location /admin {\n    allow YOUR.OFFICE.IP.HERE;\n    deny all;\n}',
        },
    },

    # ── Email Security ────────────────────────────────────────────────────────

    {
        'id': 'missing-spf',
        'patterns': ['spf record', 'spf missing', 'no spf', 'sender policy framework', 'spf not configured', 'spf check failed'],
        'title': 'Add SPF DNS record to prevent email spoofing',
        'severity': 'MEDIUM',
        'description': 'No SPF record was found for this domain. Without SPF, anyone can send email that appears to come from your domain, enabling phishing attacks against your customers and partners.',
        'fixes': {
            'DNS TXT record': '# Add to your DNS zone (replace with your actual mail servers):\n# v=spf1 include:_spf.google.com include:sendgrid.net ip4:YOUR_SERVER_IP ~all\n\n# Common providers:\n# Google Workspace: v=spf1 include:_spf.google.com ~all\n# Microsoft 365:    v=spf1 include:spf.protection.outlook.com ~all\n# Generic VPS:      v=spf1 ip4:YOUR.VPS.IP.HERE ~all',
            'Verify with dig': 'dig TXT yourdomain.com | grep spf\n# Or use: https://mxtoolbox.com/spf.aspx',
        },
    },

    {
        'id': 'missing-dkim',
        'patterns': ['dkim missing', 'no dkim', 'dkim not configured', 'dkim record', 'domainkeys identified mail'],
        'title': 'Configure DKIM to cryptographically sign outgoing email',
        'severity': 'MEDIUM',
        'description': 'DKIM is not configured. DKIM adds a cryptographic signature to outgoing emails, allowing recipients to verify the email was not tampered with in transit.',
        'fixes': {
            'Generate DKIM key (Postfix)': 'sudo apt install opendkim opendkim-tools\nopendkim-genkey -t -s mail -d yourdomain.com\n# mail.private → private key for Postfix\n# mail.txt → DNS TXT record to publish',
            'DNS TXT record': '# Add to DNS (key generated by your mail provider):\nmail._domainkey.yourdomain.com IN TXT "v=DKIM1; k=rsa; p=<YOUR_PUBLIC_KEY>"',
            'Google Workspace': '# Google Admin Console → Apps → Google Workspace → Gmail → Authenticate email → Generate DKIM key → Publish to DNS',
        },
    },

    {
        'id': 'missing-dmarc',
        'patterns': ['dmarc missing', 'no dmarc', 'dmarc not configured', 'dmarc policy', 'dmarc record'],
        'title': 'Add DMARC policy to enforce SPF and DKIM',
        'severity': 'MEDIUM',
        'description': 'No DMARC record was found. Without DMARC, spoofed emails that fail SPF/DKIM checks are still delivered. DMARC tells mail servers what to do with failures and gives you visibility via reports.',
        'fixes': {
            'DNS TXT record (start with monitoring)': '# Start with p=none to monitor without blocking:\n_dmarc.yourdomain.com IN TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com; ruf=mailto:dmarc-failures@yourdomain.com; fo=1"\n\n# After reviewing reports, move to quarantine then reject:\n# p=quarantine  (failed → spam folder)\n# p=reject      (failed → bounced — most secure)',
            'Verify with dig': 'dig TXT _dmarc.yourdomain.com\n# Or: https://mxtoolbox.com/dmarc.aspx',
        },
    },

    # ── API Security ──────────────────────────────────────────────────────────

    {
        'id': 'graphql-introspection',
        'patterns': ['graphql introspection', 'graphql schema exposed', 'graphql __schema', '__typename', 'graphql endpoint'],
        'title': 'Disable GraphQL introspection in production',
        'severity': 'MEDIUM',
        'description': 'GraphQL introspection is enabled in production. This exposes your full API schema, all types, and all queries/mutations to any visitor, giving attackers a complete map of your API surface.',
        'fixes': {
            'Apollo Server (Node.js)': "const server = new ApolloServer({\n  introspection: process.env.NODE_ENV !== 'production',\n  schema,\n});",
            'Graphene (Python/Django)': "GRAPHENE = {\n    'SCHEMA': 'myapp.schema.schema',\n    'GRAPHIQL': False,  # disable GraphiQL\n}",
            'Nginx — block introspection': "location /graphql {\n    # Block introspection queries:\n    if (\$request_body ~* '__schema|__type') {\n        return 403;\n    }\n}",
        },
    },

    {
        'id': 'swagger-exposed',
        'patterns': ['swagger exposed', 'openapi exposed', 'swagger ui', 'api documentation exposed', '/swagger.json', '/openapi.json', '/api-docs', 'swagger spec'],
        'title': 'Restrict access to API documentation / Swagger UI',
        'severity': 'MEDIUM',
        'description': 'API documentation (Swagger/OpenAPI) is publicly accessible. This exposes all endpoints, parameters, authentication mechanisms, and data models to potential attackers.',
        'fixes': {
            'Nginx — require auth or restrict by IP': 'location ~* ^/(swagger|api-docs|openapi)\\.?(json|yaml|html)?$ {\n    allow YOUR.OFFICE.IP.HERE;\n    deny all;\n}',
            'Express.js (disable in production)': "if (process.env.NODE_ENV !== 'development') {\n    // Don't mount swagger-ui-express routes\n}",
            'Spring Boot (application.properties)': 'springdoc.api-docs.enabled=false\nspringdoc.swagger-ui.enabled=false',
        },
    },

    {
        'id': 'jwt-weak',
        'patterns': ['jwt weak', 'jwt secret', 'json web token', 'jwt none algorithm', 'jwt alg none', 'weak jwt', 'jwt forgery'],
        'title': 'Fix weak or misconfigured JWT authentication',
        'severity': 'HIGH',
        'description': 'JWT tokens are using a weak secret, the "none" algorithm, or another insecure configuration. An attacker can forge tokens and impersonate any user.',
        'fixes': {
            'Node.js (jsonwebtoken)': "// Use RS256 (asymmetric) instead of HS256 for production:\nconst token = jwt.sign(payload, privateKey, {\n    algorithm: 'RS256',\n    expiresIn: '15m',\n});\n// Verify — explicitly specify allowed algorithms:\njwt.verify(token, publicKey, { algorithms: ['RS256'] });",
            'Generate strong HS256 secret (Bash)': 'openssl rand -hex 64\n# Store in environment variable — never in source code',
            'Block alg:none attacks': "// Always specify algorithms on verify — never accept 'none':\njwt.verify(token, secret, { algorithms: ['HS256'] });  // explicit allowlist",
        },
    },

    {
        'id': 'api-no-rate-limit',
        'patterns': ['no rate limit', 'api rate limit', 'rate limiting missing', 'brute force api', 'unlimited requests'],
        'title': 'Add rate limiting to API endpoints',
        'severity': 'MEDIUM',
        'description': 'API endpoints have no rate limiting. An attacker can make unlimited requests for brute-force attacks, data scraping, or denial-of-service.',
        'fixes': {
            'Nginx (global rate limit)': '# In http block:\nlimit_req_zone $binary_remote_addr zone=api:20m rate=30r/m;\n\n# In server block:\nlocation /api/ {\n    limit_req zone=api burst=10 nodelay;\n    limit_req_status 429;\n}',
            'Express.js (express-rate-limit)': "import rateLimit from 'express-rate-limit';\napp.use('/api/', rateLimit({\n    windowMs: 15 * 60 * 1000,  // 15 minutes\n    max: 100,\n    standardHeaders: true,\n    legacyHeaders: false,\n}));",
            'PHP (token bucket — Redis)': "// Use Redis to count requests per IP:\n\$redis = new Redis(); \$redis->connect('127.0.0.1');\n\$key = 'rate:' . \$_SERVER['REMOTE_ADDR'];\n\$count = \$redis->incr(\$key);\nif (\$count === 1) \$redis->expire(\$key, 60);\nif (\$count > 30) { http_response_code(429); exit('Too many requests'); }",
        },
    },

    # ── Authentication ────────────────────────────────────────────────────────

    {
        'id': 'default-credentials',
        'patterns': ['default credentials', 'default password', 'default username', 'admin/admin', 'admin/password', 'default login'],
        'title': 'Change default credentials immediately',
        'severity': 'HIGH',
        'description': 'Default credentials (username/password) were found active on a system or application. Attackers routinely scan for and exploit default credentials within minutes of a deployment.',
        'fixes': {
            'WordPress — change admin password': 'wp user update admin --user_pass="$(openssl rand -base64 24)" --path=/var/www/html',
            'MySQL — change root password': "ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongRandomPassword!';\nFLUSH PRIVILEGES;",
            'General checklist': '# 1. Change ALL default passwords on all services\n# 2. Create unique service accounts — never use root/admin for apps\n# 3. Enable two-factor authentication on admin accounts\n# 4. Audit: grep for default passwords in config files',
        },
    },

    {
        'id': 'account-enumeration',
        'patterns': ['user enumeration', 'account enumeration', 'username enumeration', 'user exists', 'username not found', 'invalid username'],
        'title': 'Prevent username enumeration on login/registration forms',
        'severity': 'MEDIUM',
        'description': 'The application reveals whether a username/email is registered through different error messages or response times. Attackers use this to harvest valid usernames for credential stuffing.',
        'fixes': {
            'Generic fix': '# Always return the same error message regardless of whether the\n# username or password is wrong:\n# WRONG: "Username not found" / "Incorrect password"\n# RIGHT: "Invalid username or password"',
            'PHP example': "if (!\$user || !password_verify(\$password, \$user->hash)) {\n    // Same message, same timing regardless of which failed:\n    sleep(1);  // constant-time response\n    die('Invalid username or password');\n}",
            'WordPress (functions.php)': "add_filter('login_errors', function() {\n    return 'Invalid username or password.';\n});",
        },
    },

    {
        'id': 'no-mfa',
        'patterns': ['no mfa', 'no 2fa', 'two-factor missing', 'multi-factor not enabled', 'mfa not configured'],
        'title': 'Enable multi-factor authentication (MFA) for privileged accounts',
        'severity': 'HIGH',
        'description': 'Multi-factor authentication is not enabled on admin or privileged accounts. MFA stops account takeover even when credentials are compromised.',
        'fixes': {
            'WordPress (WP-CLI + plugin)': 'wp plugin install two-factor --activate --path=/var/www/html\n# Then enable per user via Profile → Two-Factor Authentication',
            'SSH — require MFA (Google Authenticator)': 'sudo apt install libpam-google-authenticator\ngoogle-authenticator  # Run as each user\n# In /etc/pam.d/sshd add: auth required pam_google_authenticator.so\n# In /etc/ssh/sshd_config: ChallengeResponseAuthentication yes',
            'General': '# Enable MFA on:\n# - WordPress admin accounts\n# - SSH logins\n# - Cloud console (AWS, GCP, Azure)\n# - Domain registrar and DNS provider\n# - Any account that can change DNS or SSL certificates',
        },
    },

    {
        'id': 'weak-password-policy',
        'patterns': ['weak password', 'password policy', 'short password', 'password complexity', 'no password requirements'],
        'title': 'Enforce strong password policy',
        'severity': 'MEDIUM',
        'description': 'The application has a weak or missing password policy. Users are setting easily guessable passwords, increasing risk of credential attacks.',
        'fixes': {
            'PHP — password validation': "function is_strong_password(\$pass): bool {\n    return strlen(\$pass) >= 12\n        && preg_match('/[A-Z]/', \$pass)\n        && preg_match('/[a-z]/', \$pass)\n        && preg_match('/[0-9]/', \$pass)\n        && preg_match('/[^A-Za-z0-9]/', \$pass);\n}",
            'WordPress (functions.php)': "add_filter('password_hint', function() {\n    return 'Minimum 12 characters, uppercase, lowercase, number, and symbol.';\n});\n// Use a plugin: wp plugin install force-strong-passwords --activate",
            'General guidance': '# Minimum 12 characters\n# No maximum length restriction\n# Check against HaveIBeenPwned breached password list\n# Use bcrypt (cost 12+), Argon2id, or scrypt — never MD5/SHA1',
        },
    },

    # ── Injection (Advanced) ──────────────────────────────────────────────────

    {
        'id': 'nosql-injection',
        'patterns': ['nosql injection', 'mongodb injection', 'nosqli', 'operator injection', '$where injection', 'nosql'],
        'title': 'Fix NoSQL injection vulnerability (MongoDB)',
        'severity': 'HIGH',
        'description': 'A NoSQL injection vulnerability was detected. An attacker can manipulate MongoDB queries by injecting operator expressions, bypassing authentication or extracting data.',
        'fixes': {
            'Node.js (Mongoose)': "// VULNERABLE:\nUser.findOne({ username: req.body.username, password: req.body.password });\n\n// SAFE — cast to string and validate type:\nconst username = String(req.body.username);\nconst password = String(req.body.password);\nif (typeof req.body.username !== 'string') throw new Error('Invalid input');\nUser.findOne({ username, password });",
            'PHP (MongoDB driver)': "// Always cast query parameters:\n\$filter = [\n    'username' => (string) \$_POST['username'],\n    'password' => (string) \$_POST['password'],\n];\n\$collection->findOne(\$filter);",
            'Mongoose — schema type enforcement': "const UserSchema = new Schema({\n    username: { type: String, required: true },\n    password: { type: String, required: true },\n});  // Schema types reject object/operator inputs automatically",
        },
    },

    {
        'id': 'ssti',
        'patterns': ['server-side template injection', 'ssti', 'template injection', 'jinja2 injection', 'twig injection', 'smarty injection'],
        'title': 'Fix server-side template injection (SSTI)',
        'severity': 'HIGH',
        'description': 'Server-side template injection was detected. An attacker can inject template expressions that execute arbitrary code on the server, leading to full server compromise.',
        'fixes': {
            'Python (Jinja2)': "# NEVER render user input as a template:\n# VULNERABLE: Template(user_input).render()\n# SAFE — pass as variable, not template:\nreturn render_template('page.html', user_text=user_input)",
            'PHP (Twig)': "// VULNERABLE: \$twig->createTemplate(\$userInput)->render();\n// SAFE — use sandboxed environment or never render user input as template:\n\$template = \$twig->load('safe_template.twig');\n\$template->render(['user_text' => \$userInput]);",
            'General': '# 1. Never pass user input directly to template rendering functions\n# 2. Use sandboxed template environments if dynamic templates are needed\n# 3. Input validation alone is NOT sufficient — template engines are Turing-complete',
        },
    },

    {
        'id': 'xxe',
        'patterns': ['xml external entity', 'xxe', 'xxe injection', 'entity injection', 'xml entity', 'external entity'],
        'title': 'Disable external entity processing to prevent XXE',
        'severity': 'HIGH',
        'description': 'XML External Entity (XXE) injection was detected. An attacker can read local files, perform SSRF attacks, or cause denial-of-service by including malicious external entities in XML input.',
        'fixes': {
            'PHP (libxml)': "// Disable external entity loading globally:\nlibxml_disable_entity_loader(true);\n\n// When loading XML:\n\$dom = new DOMDocument();\n\$dom->loadXML(\$xmlString, LIBXML_NONET | LIBXML_NOENT);",
            'Java (JAXP)': "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\ndbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\ndbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\ndbf.setXIncludeAware(false);\ndbf.setExpandEntityReferences(false);",
            'Python (lxml)': "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.fromstring(xml_bytes, parser)",
        },
    },

    {
        'id': 'ssrf',
        'patterns': ['ssrf', 'server-side request forgery', 'internal network access', 'cloud metadata', '169.254.169.254', 'ssrf confirmed'],
        'title': 'Fix server-side request forgery (SSRF)',
        'severity': 'HIGH',
        'description': 'Server-side request forgery was detected. An attacker can make the server send requests to internal services, cloud metadata endpoints (AWS/GCP/Azure), or other restricted resources.',
        'fixes': {
            'PHP — URL validation allowlist': "function is_allowed_url(string \$url): bool {\n    \$parsed = parse_url(\$url);\n    \$host = \$parsed['host'] ?? '';\n    \$allowed_domains = ['api.yourdomain.com', 'cdn.yourdomain.com'];\n    // Block internal IPs\n    if (filter_var(\$host, FILTER_VALIDATE_IP)) {\n        if (filter_var(\$host, FILTER_VALIDATE_IP,\n            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {\n            return false;  // Block 10.x, 172.16.x, 192.168.x, 169.254.x\n        }\n    }\n    return in_array(\$host, \$allowed_domains);\n}",
            'Block cloud metadata (iptables)': '# Block access to AWS/GCP/Azure metadata endpoints:\niptables -A OUTPUT -d 169.254.169.254 -j DROP\niptables -A OUTPUT -d 169.254.170.2 -j DROP  # ECS task metadata',
            'Nginx — prevent proxying to internal': "# If using proxy_pass with user-supplied URLs, validate the target:\n# Never pass raw user input to proxy_pass",
        },
    },

    # ── Cryptography ──────────────────────────────────────────────────────────

    {
        'id': 'weak-hash',
        'patterns': ['md5 hash', 'sha1 password', 'weak hashing', 'insecure hash', 'md5 password', 'unsalted hash', 'plain md5'],
        'title': 'Upgrade password hashing from MD5/SHA1 to bcrypt or Argon2',
        'severity': 'HIGH',
        'description': 'Passwords are hashed with MD5 or SHA1. These are fast, reversible hashes — an attacker who gets the database can crack all passwords in hours using GPU-accelerated tools.',
        'fixes': {
            'PHP — migrate to password_hash()': "// NEW registrations:\n\$hash = password_hash(\$password, PASSWORD_BCRYPT, ['cost' => 12]);\n// Or Argon2 (PHP 7.2+):\n\$hash = password_hash(\$password, PASSWORD_ARGON2ID);\n\n// VERIFY:\nif (password_verify(\$password, \$stored_hash)) {\n    // Transparently rehash if still MD5:\n    if (strpos(\$stored_hash, '\$2y\$') !== 0) {\n        \$new_hash = password_hash(\$password, PASSWORD_BCRYPT);\n        // UPDATE user SET password=\$new_hash WHERE id=\$id\n    }\n}",
            'Python (Django)': "# Set in settings.py:\nPASSWORD_HASHERS = [\n    'django.contrib.auth.hashers.Argon2PasswordHasher',\n    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',\n    'django.contrib.auth.hashers.PBKDF2PasswordHasher',  # legacy fallback\n]",
            'Node.js (bcrypt)': "import bcrypt from 'bcrypt';\n// Hash:\nconst hash = await bcrypt.hash(password, 12);\n// Verify:\nconst match = await bcrypt.compare(password, hash);",
        },
    },

    # ── Dependencies / Libraries ──────────────────────────────────────────────

    {
        'id': 'outdated-jquery',
        'patterns': ['outdated jquery', 'jquery version', 'jquery vulnerability', 'jquery xss', 'jquery prototype pollution'],
        'title': 'Update jQuery to remove known XSS and prototype pollution vulnerabilities',
        'severity': 'MEDIUM',
        'description': 'An outdated version of jQuery is in use with known security vulnerabilities including XSS (CVE-2019-11358) and prototype pollution (CVE-2020-11022, CVE-2020-11023).',
        'fixes': {
            'Update jQuery (npm)': 'npm update jquery\nnpm audit fix',
            'Update jQuery (CDN)': '<!-- Replace with current version from https://jquery.com/download/ -->\n<script src="https://code.jquery.com/jquery-3.7.1.min.js"\n  integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="\n  crossorigin="anonymous"></script>',
            'WordPress — update bundled jQuery': 'wp core update --path=/var/www/html\n# Or force jQuery version with Enqueue:\nwp_enqueue_script("jquery", "https://code.jquery.com/jquery-3.7.1.min.js", [], "3.7.1", true);',
        },
    },

    {
        'id': 'log4shell',
        'patterns': ['log4shell', 'log4j', 'cve-2021-44228', 'jndi injection', 'log4j rce'],
        'title': 'Patch Log4Shell (CVE-2021-44228) — critical RCE in Log4j',
        'severity': 'HIGH',
        'description': 'Log4Shell (CVE-2021-44228) was detected. This critical vulnerability in Apache Log4j allows unauthenticated remote code execution via JNDI injection in any logged string.',
        'fixes': {
            'Upgrade Log4j (Maven)': '<dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.17.1</version>  <!-- minimum safe version -->\n</dependency>',
            'Workaround (JVM flag)': '# Add JVM startup flag to disable JNDI lookups:\njava -Dlog4j2.formatMsgNoLookups=true -jar app.jar',
            'Verify with scanner': '# Check for vulnerable Log4j versions in your JARs:\nfind / -name "log4j*.jar" 2>/dev/null\n# Run: https://github.com/logpresso/CVE-2021-44228-Scanner',
        },
    },

    {
        'id': 'outdated-library',
        'patterns': ['outdated library', 'vulnerable library', 'dependency vulnerability', 'npm audit', 'composer audit', 'known vulnerability in', 'cve in library'],
        'title': 'Update vulnerable dependencies to patched versions',
        'severity': 'HIGH',
        'description': 'Outdated libraries with known security vulnerabilities were detected. Vulnerable dependencies are among the most commonly exploited attack vectors.',
        'fixes': {
            'Node.js / npm': 'npm audit\nnpm audit fix\nnpm audit fix --force  # for breaking changes\n# Review: npm audit --json | jq .vulnerabilities',
            'PHP / Composer': 'composer audit\ncomposer update --with-dependencies\n# For a specific package: composer require vendor/package:^2.0',
            'Python / pip': 'pip install safety\nsafety check\npip install --upgrade <package>',
            'Ruby / Bundler': 'bundle audit\nbundle update',
            'GitHub Dependabot': '# Add .github/dependabot.yml to auto-create PRs for security updates',
        },
    },

    # ── Network / Infrastructure ──────────────────────────────────────────────

    {
        'id': 'redis-exposed',
        'patterns': ['redis exposed', 'redis without auth', 'redis open', 'redis no password', 'unauthenticated redis', '6379 open'],
        'title': 'Secure Redis — require authentication and bind to localhost',
        'severity': 'HIGH',
        'description': 'Redis is accessible without authentication or is bound to a public interface. An attacker can read/write all cached data, execute OS commands (if running as root), or achieve RCE via cron or SSH key injection.',
        'fixes': {
            'redis.conf': '# Bind to localhost only:\nbind 127.0.0.1 ::1\n\n# Require a strong password:\nrequirepass YourStrongRedisPasswordHere\n\n# Disable dangerous commands:\nrename-command FLUSHALL ""\nrename-command CONFIG ""\nrename-command SLAVEOF ""',
            'UFW — block external access': 'ufw deny 6379\n# Or allow only from app server:\nufw allow from YOUR_APP_SERVER_IP to any port 6379',
        },
    },

    {
        'id': 'elasticsearch-exposed',
        'patterns': ['elasticsearch exposed', 'elasticsearch without auth', 'kibana exposed', 'elastic open', '9200 open', '9300 open'],
        'title': 'Secure Elasticsearch — enable authentication and bind to localhost',
        'severity': 'HIGH',
        'description': 'Elasticsearch is accessible without authentication. All indexed data is readable and writable by anyone. Entire databases have been ransomed via exposed Elasticsearch instances.',
        'fixes': {
            'elasticsearch.yml — bind to localhost': 'network.host: 127.0.0.1\nhttp.port: 9200\n\n# Enable X-Pack security (Elasticsearch 8+ includes this free):\nxpack.security.enabled: true',
            'Generate passwords': 'bin/elasticsearch-setup-passwords auto\n# Or interactive: bin/elasticsearch-setup-passwords interactive',
            'UFW — block external access': 'ufw deny 9200\nufw deny 9300',
        },
    },

    {
        'id': 'mongodb-exposed',
        'patterns': ['mongodb exposed', 'mongodb without auth', 'mongo open', 'no mongodb auth', '27017 open'],
        'title': 'Secure MongoDB — enable authentication and bind to localhost',
        'severity': 'HIGH',
        'description': 'MongoDB is accessible without authentication on a public interface. An attacker can read, modify, or delete all databases without any credentials.',
        'fixes': {
            'mongod.conf': "net:\n  bindIp: 127.0.0.1  # localhost only\n  port: 27017\nsecurity:\n  authorization: enabled",
            'Create admin user': "use admin\ndb.createUser({\n  user: 'admin',\n  pwd: 'StrongPasswordHere',\n  roles: [{ role: 'userAdminAnyDatabase', db: 'admin' }]\n})",
            'UFW — block external access': 'ufw deny 27017',
        },
    },

    {
        'id': 'cloud-metadata-endpoint',
        'patterns': ['169.254.169.254', 'cloud metadata', 'aws metadata', 'ec2 metadata', 'gcp metadata', 'azure metadata', 'imds endpoint'],
        'title': 'Block access to cloud metadata endpoint (SSRF mitigation)',
        'severity': 'HIGH',
        'description': 'The cloud instance metadata service (IMDS) endpoint 169.254.169.254 is reachable. Via SSRF, an attacker can steal IAM credentials, instance details, and user data that may contain secrets.',
        'fixes': {
            'IMDSv2 (AWS — enforce token-based access)': 'aws ec2 modify-instance-metadata-options \\\n    --instance-id YOUR_INSTANCE_ID \\\n    --http-tokens required \\\n    --http-put-response-hop-limit 1',
            'iptables — block SSRF to metadata': '# Prevent the web application process from reaching the metadata IP:\niptables -A OUTPUT -p tcp -d 169.254.169.254 -m owner --uid-owner www-data -j DROP\niptables -A OUTPUT -p tcp -d 169.254.170.2 -m owner --uid-owner www-data -j DROP',
            'PHP — SSRF prevention': "// Validate URLs before making server-side HTTP requests:\nif (strpos(\$url, '169.254') !== false || strpos(\$url, 'metadata') !== false) {\n    die('Blocked: metadata endpoint access denied');\n}",
        },
    },

    {
        'id': 'dns-zone-transfer',
        'patterns': ['dns zone transfer', 'axfr', 'zone transfer allowed', 'dns enumeration'],
        'title': 'Disable public DNS zone transfers',
        'severity': 'MEDIUM',
        'description': 'DNS zone transfers (AXFR) are allowed from any IP address. This exposes your complete DNS zone including all subdomains, internal server names, and IP addresses.',
        'fixes': {
            'BIND (named.conf)': 'zone "yourdomain.com" {\n    type master;\n    // Restrict zone transfers to authoritative secondaries only:\n    allow-transfer { YOUR_SECONDARY_DNS_IP; };\n    // Or deny entirely if no secondaries:\n    allow-transfer { none; };\n};',
            'Verify fix': 'dig @ns1.yourdomain.com yourdomain.com AXFR\n# Should return: Transfer failed (or permission denied)',
        },
    },

    # ── Client-side Security ──────────────────────────────────────────────────

    {
        'id': 'sri-missing',
        'patterns': ['subresource integrity', 'sri missing', 'cdn script no integrity', 'script without integrity'],
        'title': 'Add Subresource Integrity (SRI) to CDN-hosted scripts',
        'severity': 'LOW',
        'description': 'External scripts loaded from CDNs lack Subresource Integrity attributes. If the CDN is compromised, attackers can serve malicious JavaScript to all your visitors without detection.',
        'fixes': {
            'Generate SRI hash': "# Generate integrity hash for any file:\ncurl -s https://cdn.example.com/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A\n# Output → use as integrity attribute value",
            'HTML — add integrity attribute': '<script src="https://cdn.example.com/lib.min.js"\n    integrity="sha384-<HASH_FROM_ABOVE>"\n    crossorigin="anonymous"></script>',
            'SRI Hash Generator tool': '# Use https://www.srihash.org/ to generate integrity hashes automatically',
        },
    },

    {
        'id': 'prototype-pollution',
        'patterns': ['prototype pollution', '__proto__', 'constructor.prototype', 'prototype injection', 'object prototype'],
        'title': 'Fix JavaScript prototype pollution vulnerability',
        'severity': 'MEDIUM',
        'description': 'A prototype pollution vulnerability was detected. An attacker can inject properties into JavaScript object prototypes, leading to XSS, privilege escalation, or denial-of-service in server-side Node.js applications.',
        'fixes': {
            'Node.js — use Object.create(null) for merge targets': "// VULNERABLE:\nfunction merge(target, source) {\n    for (const key of Object.keys(source)) target[key] = source[key];\n}\n\n// SAFE — use null-prototype objects as merge targets:\nconst safe = Object.assign(Object.create(null), target);\n\n// Or validate keys:\nconst ALLOWED_KEYS = new Set(['name', 'email']);\nfor (const key of Object.keys(source)) {\n    if (ALLOWED_KEYS.has(key)) target[key] = source[key];\n}",
            'npm — update lodash': 'npm update lodash\n# CVE-2019-10744, CVE-2020-8203 — lodash < 4.17.19',
            'Freeze prototypes': '// Prevent prototype modification globally:\nObject.freeze(Object.prototype);\nObject.freeze(Array.prototype);\nObject.freeze(Function.prototype);',
        },
    },

    # ── Injection (Additional) ────────────────────────────────────────────────

    {
        'id': 'http-basic-auth-unencrypted',
        'patterns': ['basic auth over http', 'http basic authentication', 'basic authentication plaintext', 'basic auth not https'],
        'title': 'Move HTTP Basic Authentication to HTTPS only',
        'severity': 'HIGH',
        'description': 'HTTP Basic Authentication is being used over unencrypted HTTP. Credentials are base64-encoded (not encrypted) and can be intercepted by any network observer.',
        'fixes': {
            'Nginx — redirect HTTP to HTTPS then require auth': 'server {\n    listen 80;\n    server_name yourdomain.com;\n    return 301 https://$server_name$request_uri;\n}\nserver {\n    listen 443 ssl;\n    auth_basic "Protected Area";\n    auth_basic_user_file /etc/nginx/.htpasswd;\n}',
            'Generate .htpasswd': 'sudo htpasswd -c /etc/nginx/.htpasswd admin\n# Or: sudo apt install apache2-utils',
        },
    },

]
