"""CF_AI — Remediation template library.

Each entry maps detection patterns found in agent output to exact,
copy-paste-ready configuration fixes for common web server stacks.
Patterns are matched only on non-negated lines (see app.py _NEGATION filter).
"""

REMEDIATIONS = [

    # ── Security Headers ─────────────────────────────────────────────────────

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

    # ── SSL / TLS ────────────────────────────────────────────────────────────

    {
        'id': 'weak-tls',
        'patterns': ['tlsv1.0', 'tlsv1.1', 'sslv3', 'weak cipher', 'weak tls', 'outdated ssl', 'old tls'],
        'title': 'Disable outdated TLS 1.0 and TLS 1.1 protocols',
        'severity': 'HIGH',
        'description': 'Old TLS versions (1.0, 1.1) are still enabled. These have known weaknesses and are deprecated. Only TLS 1.2 and 1.3 should be active.',
        'fixes': {
            'Nginx': 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers off;',
            'Apache': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\nSSLHonorCipherOrder off',
        },
    },

    {
        'id': 'expired-cert',
        'patterns': ['expired certificate', 'certificate expired', 'cert expired', 'certificate has expired'],
        'title': 'Renew the SSL/TLS certificate immediately',
        'severity': 'HIGH',
        'description': 'The SSL certificate is expired. Visitors see a browser security warning and may leave. Encrypted connections may also be rejected.',
        'fixes': {
            'Certbot (Let\'s Encrypt)': 'sudo certbot renew --force-renewal\nsudo systemctl reload nginx   # or: sudo systemctl reload apache2',
            'Certbot (cron check)': '# Ensure auto-renewal cron is active:\nsudo certbot renew --dry-run',
            'Manual': '# 1. Log into your certificate provider or hosting panel\n# 2. Generate a new CSR and submit for renewal\n# 3. Download and install the new certificate files',
        },
    },

    {
        'id': 'self-signed-cert',
        'patterns': ['self-signed', 'self signed certificate', 'untrusted certificate', 'certificate not trusted'],
        'title': 'Replace self-signed certificate with a trusted one',
        'severity': 'HIGH',
        'description': 'A self-signed certificate is in use. Browsers will show a security warning to all visitors. A free trusted certificate is available via Let\'s Encrypt.',
        'fixes': {
            'Certbot (Let\'s Encrypt — free)': 'sudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com -d www.yourdomain.com',
            'Certbot (Apache)': 'sudo apt install certbot python3-certbot-apache\nsudo certbot --apache -d yourdomain.com',
        },
    },

    # ── WordPress ────────────────────────────────────────────────────────────

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
            'WordPress (functions.php)': "// Remove version from head\nremove_action('wp_head', 'wp_generator');\n\n// Remove version from scripts and styles\nfunction remove_wp_version_strings(\$src) {\n    global \$wp_version;\n    return str_replace('ver='.\$wp_version, '', \$src);\n}\nadd_filter('script_loader_src', 'remove_wp_version_strings');\nadd_filter('style_loader_src', 'remove_wp_version_strings');",
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

    # ── Server Configuration ─────────────────────────────────────────────────

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
            'Apache': '<FilesMatch "^\\.">  \n  Order allow,deny\n  Deny from all\n</FilesMatch>',
            '.htaccess': 'RedirectMatch 404 /\\.git\nRedirectMatch 404 /\\.env',
        },
    },

    # ── Application Security ─────────────────────────────────────────────────

    {
        'id': 'insecure-cookies',
        'patterns': ['insecure cookie', 'cookie without secure', 'missing secure flag', 'missing httponly', 'cookie not secure'],
        'title': 'Set Secure and HttpOnly flags on all session cookies',
        'severity': 'MEDIUM',
        'description': 'Session cookies are missing the Secure and/or HttpOnly flags. Without Secure, cookies can be sent over HTTP. Without HttpOnly, JavaScript can read them.',
        'fixes': {
            'Nginx': 'proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";',
            'Apache': 'Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"',
            'PHP (php.ini)': 'session.cookie_httponly = 1\nsession.cookie_secure = 1\nsession.cookie_samesite = "Strict"',
            'WordPress (wp-config.php)': "@ini_set('session.cookie_httponly', true);\n@ini_set('session.cookie_secure', true);\n@ini_set('session.cookie_samesite', 'Strict');",
        },
    },

    {
        'id': 'cors-wildcard',
        'patterns': ['cors misconfiguration', 'cors wildcard', 'access-control-allow-origin: *', 'cors *'],
        'title': 'Fix CORS — replace wildcard with specific allowed origins',
        'severity': 'MEDIUM',
        'description': 'CORS is set to allow all origins (*). Any website can make authenticated requests to your API and read the response, enabling data theft.',
        'fixes': {
            'Nginx': "# Replace the wildcard with your specific frontend domain\nadd_header Access-Control-Allow-Origin 'https://yourdomain.com' always;\nadd_header Access-Control-Allow-Credentials 'true' always;",
            'Apache': 'Header set Access-Control-Allow-Origin "https://yourdomain.com"',
            'PHP': "header('Access-Control-Allow-Origin: https://yourdomain.com');\nheader('Access-Control-Allow-Credentials: true');",
        },
    },

    {
        'id': 'sql-injection-confirmed',
        'patterns': ['sql injection confirmed', 'sqli confirmed', 'sql injection found', 'sql injection successful', 'injectable'],
        'title': 'Fix confirmed SQL injection vulnerability',
        'severity': 'HIGH',
        'description': 'A SQL injection vulnerability was confirmed. An attacker can read, modify, or delete all data in the database, and potentially take over the server.',
        'fixes': {
            'PHP — use prepared statements': "// VULNERABLE (do not use):\n// $q = \"SELECT * FROM users WHERE id = \" . $_GET['id'];\n\n// SAFE — parameterised query:\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$_GET['id']]);\n$user = $stmt->fetch();",
            'WordPress ($wpdb->prepare)': "// SAFE:\n\$result = \$wpdb->get_results(\n    \$wpdb->prepare(\n        'SELECT * FROM wp_users WHERE ID = %d',\n        \$user_id\n    )\n);",
            'WAF rule (Nginx + ModSecurity)': '# Install ModSecurity and enable the OWASP Core Rule Set\n# apt install libapache2-mod-security2\n# This adds a WAF layer while you fix the code',
        },
    },

    {
        'id': 'open-redirect',
        'patterns': ['open redirect', 'unvalidated redirect', 'redirect to external'],
        'title': 'Fix open redirect vulnerability',
        'severity': 'MEDIUM',
        'description': 'The application allows redirecting users to arbitrary external URLs. Attackers use this in phishing links that appear to come from your trusted domain.',
        'fixes': {
            'PHP — allowlist approach': "// Only allow redirects to your own domain\n\$allowed_hosts = ['yourdomain.com', 'www.yourdomain.com'];\n\$url = parse_url(\$_GET['redirect']);\nif (!in_array(\$url['host'] ?? '', \$allowed_hosts)) {\n    \$redirect = '/home';  // fallback to safe page\n}\nheader('Location: ' . \$redirect);\nexit;",
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
            'PHP — validate MIME + extension': "// Check both MIME type and extension — never trust $_FILES['type']\n\$allowed_ext = ['jpg','jpeg','png','gif','pdf','docx'];\n\$allowed_mime = ['image/jpeg','image/png','image/gif','application/pdf'];\n\$finfo = new finfo(FILEINFO_MIME_TYPE);\n\$detected = \$finfo->file(\$_FILES['file']['tmp_name']);\n\$ext = strtolower(pathinfo(\$_FILES['file']['name'], PATHINFO_EXTENSION));\nif (!in_array(\$ext, \$allowed_ext) || !in_array(\$detected, \$allowed_mime)) {\n    die('Invalid file type');\n}\n// Store OUTSIDE web root\n\$dest = '/var/uploads/' . uniqid() . '.' . \$ext;\nmove_uploaded_file(\$_FILES['file']['tmp_name'], \$dest);",
            'Nginx — block PHP in uploads': 'location ~* /uploads/.*\\.php$ {\n    deny all;\n    return 403;\n}',
            'WordPress (functions.php)': "add_filter('upload_mimes', function(\$mimes) {\n    unset(\$mimes['php'], \$mimes['phtml'], \$mimes['phar']);\n    return \$mimes;\n});",
        },
    },

    {
        'id': 'php-code-execution',
        'patterns': ['remote code execution', 'rce confirmed', 'rce found', 'code execution', 'command injection', 'os command injection', 'eval injection'],
        'title': 'Fix remote code / OS command execution vulnerability',
        'severity': 'HIGH',
        'description': 'The scan found a remote code execution or command injection vulnerability. An attacker can execute arbitrary OS commands or PHP code with the permissions of the web server process.',
        'fixes': {
            'PHP — avoid dangerous functions': "// Never pass user input to eval(), system(), exec(), passthru(), shell_exec()\n// If OS commands are truly needed, use an allowlist of commands:\n\$allowed = ['ls', 'df'];\nif (!in_array(\$cmd, \$allowed)) die('Forbidden');\n\$output = shell_exec(escapeshellcmd(\$cmd));",
            'PHP — disable dangerous functions (php.ini)': 'disable_functions = exec, passthru, shell_exec, system, proc_open, popen, show_source, posix_kill, posix_mkfifo, posix_getpwuid, posix_setpgid, posix_setsid, posix_setuid, posix_setgid',
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
            'PHP — output encoding': "// Always encode before echoing user-controlled data:\necho htmlspecialchars(\$userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');",
            'Content-Security-Policy header': "# A strict CSP prevents XSS even if the code is broken:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none';\" always;",
            'WordPress (functions.php)': "// Use wp_kses() to sanitise rich content:\n\$clean = wp_kses(\$dirty_html, [\n    'a'  => ['href'=>[],'title'=>[]],\n    'br' => [],\n    'em' => [],\n    'strong' => [],\n]);",
        },
    },

    {
        'id': 'broken-access-control',
        'patterns': ['broken access control', 'idor', 'insecure direct object', 'unauthorized access', 'privilege escalation', 'access control bypass', 'unauthorised access'],
        'title': 'Fix broken access control / IDOR',
        'severity': 'HIGH',
        'description': 'The application fails to properly enforce access controls. Users can access resources or actions they should not be authorised for, potentially exposing other users\' data.',
        'fixes': {
            'PHP — always verify ownership': "// Always check that the requested resource belongs to the current user:\n\$stmt = \$pdo->prepare('SELECT * FROM orders WHERE id=? AND user_id=?');\n\$stmt->execute([\$_GET['id'], \$_SESSION['user_id']]);\n\$order = \$stmt->fetch();\nif (!\$order) { http_response_code(403); die('Forbidden'); }",
            'General approach': '# 1. Never rely on client-supplied IDs alone — verify ownership server-side\n# 2. Use UUIDs instead of sequential integers to reduce enumeration\n# 3. Log and alert on access control failures',
            'WordPress': "// Verify capabilities before performing any privileged action:\nif (!current_user_can('edit_post', \$post_id)) {\n    wp_die(__('You do not have permission to edit this post.'));\n}",
        },
    },

    {
        'id': 'sensitive-data-exposed',
        'patterns': ['sensitive data exposed', 'data exposure', 'credential exposed', 'password in plaintext', 'api key exposed', 'secret exposed', 'token exposed', 'credential in response'],
        'title': 'Remove exposed credentials / sensitive data from responses',
        'severity': 'HIGH',
        'description': 'Sensitive data — such as passwords, API keys, or secrets — was found in HTTP responses, logs, or publicly accessible files. This data must be removed immediately and the exposed credentials rotated.',
        'fixes': {
            'Immediate actions': '# 1. Rotate ALL exposed credentials immediately (passwords, API keys, tokens)\n# 2. Check if secrets appear in git history: git log -p | grep -i "password\\|api_key\\|secret"\n# 3. Use: git filter-repo --invert-paths --path <sensitive-file>  to purge git history',
            'PHP — use environment variables': "// Never hardcode secrets in source code:\n// WRONG:  \$db_pass = 'MySecret123';\n// RIGHT:  \$db_pass = getenv('DB_PASSWORD');",
            'Nginx — block sensitive files': 'location ~* \\.(env|log|bak|sql|conf|ini|key|pem)$ {\n    deny all;\n    return 404;\n}',
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
            'WP-CLI (recommended)': 'wp core update --path=/var/www/html\nwp plugin update --all --path=/var/www/html\nwp theme update --all --path=/var/www/html',
            'WordPress Dashboard': '# Dashboard → Updates → Update All\n# Enable auto-updates for minor releases in wp-config.php:\ndefine("WP_AUTO_UPDATE_CORE", "minor");',
            'Bash — verify version after update': 'wp core version --path=/var/www/html',
        },
    },

    {
        'id': 'open-port-service',
        'patterns': ['open port', 'exposed port', 'port open', 'service exposed', 'ssh exposed', 'rdp exposed', 'ftp exposed', 'telnet exposed', 'database port open', 'mysql port', '3306 open', '5432 open', '27017 open'],
        'title': 'Close or restrict unnecessarily exposed network ports / services',
        'severity': 'MEDIUM',
        'description': 'One or more network ports are exposed to the internet that should be restricted. Database ports (MySQL, PostgreSQL, MongoDB) and management interfaces (SSH, RDP) should never be publicly accessible.',
        'fixes': {
            'iptables — block specific port': '# Block port 3306 (MySQL) from internet, allow only from your app server:\niptables -A INPUT -p tcp --dport 3306 -s YOUR_APP_SERVER_IP -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -j DROP',
            'UFW (Ubuntu Firewall)': '# Allow SSH only from your office IP:\nufw allow from YOUR.OFFICE.IP.HERE to any port 22\nufw deny 22\n# Allow MySQL only locally:\nufw allow from 127.0.0.1 to any port 3306',
            'Nginx — restrict admin by IP': 'location /admin {\n    allow YOUR.OFFICE.IP.HERE;\n    deny all;\n}',
        },
    },

]
