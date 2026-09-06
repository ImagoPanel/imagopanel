<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once __DIR__ . '/DataStore.php';
require_once __DIR__ . '/RootAuditLog.php';
require_once __DIR__ . '/session.php';

function domainToolBase64Encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function domainToolBase64Decode(string $value): ?string
{
    if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1) return null;
    $padding = strlen($value) % 4;
    if ($padding !== 0) $value .= str_repeat('=', 4 - $padding);
    $decoded = base64_decode(strtr($value, '-_', '+/'), true);
    return $decoded === false ? null : $decoded;
}

function domainToolCookieName(?string $tool = null): string
{
    if ($tool === null || $tool === '') return DOMAIN_TOOL_SESSION_NAME;
    domainToolPermissionKey($tool);
    return DOMAIN_TOOL_SESSION_NAME . '_' . strtoupper($tool);
}

function domainToolSetCookie(array $payload, int $expiresAt, ?string $tool = null): void
{
    $payload['expiresAt'] = $expiresAt;
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) throw new RuntimeException('Cannot create tool session');
    $encoded = domainToolBase64Encode($json);
    $signature = domainToolBase64Encode(hash_hmac('sha256', $encoded, DOMAIN_TOOL_AUTH_SECRET, true));
    setcookie(domainToolCookieName($tool), $encoded . '.' . $signature, [
        'expires' => $expiresAt,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function domainToolClearCookie(?string $tool = null): void
{
    setcookie(domainToolCookieName($tool), '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    unset($_COOKIE[domainToolCookieName($tool)]);
}

function domainToolReadCookie(?string $tool = null): ?array
{
    $token = (string) ($_COOKIE[domainToolCookieName($tool)] ?? '');
    $parts = explode('.', $token, 2);
    if (count($parts) !== 2 || strlen($token) > 8192) return null;
    $signature = domainToolBase64Decode($parts[1]);
    if ($signature === null || !hash_equals(hash_hmac('sha256', $parts[0], DOMAIN_TOOL_AUTH_SECRET, true), $signature)) return null;
    $json = domainToolBase64Decode($parts[0]);
    $payload = $json === null ? null : json_decode($json, true);
    if (!is_array($payload) || (int) ($payload['expiresAt'] ?? 0) <= time()) return null;
    return $payload;
}

function domainToolRequestHost(): string
{
    $host = mb_strtolower(trim((string) ($_SERVER['HTTP_HOST'] ?? '')));
    if (substr_count($host, ':') === 1) $host = explode(':', $host, 2)[0];
    return rtrim($host, '.');
}

function domainToolFindDomain(DataStore $store, string $host): ?array
{
    $candidates = [$host];
    if (strpos($host, 'www.') === 0) $candidates[] = substr($host, 4);
    foreach ($store->listDocuments() as $document) {
        if (empty($document['profile']['active'])) continue;
        foreach ($document['resources']['domains'] ?? [] as $index => $domain) {
            if (!is_array($domain) || empty($domain['active'])) continue;
            $name = mb_strtolower(trim((string) ($domain['domain'] ?? '')));
            if (in_array($name, $candidates, true)) {
                return ['document' => $document, 'domain' => $domain, 'index' => (int) $index];
            }
        }
    }
    return null;
}

function domainToolPermissionKey(string $tool): string
{
    $map = ['phpmyadmin' => 'phpmyadmin', 'filemanager' => 'filemanager', 'fileeditor' => 'fileeditor'];
    if (!isset($map[$tool])) throw new InvalidArgumentException('Unknown domain tool');
    return $map[$tool];
}

function domainToolAccessTimes(array $access): array
{
    $start = strtotime((string) ($access['startsAt'] ?? '')) ?: 0;
    $end = strtotime((string) ($access['expiresAt'] ?? '')) ?: 0;
    return [$start, $end];
}

function domainToolAccessError(array $access, string $tool, string $ip): ?string
{
    if (empty($access['active'])) return 'Доступ отключён владельцем домена.';
    $ips = is_array($access['ips'] ?? null) ? $access['ips'] : [];
    if (!in_array($ip, $ips, true)) return 'Доступ с этого IP запрещён.';
    $permissions = is_array($access['permissions'] ?? null) ? $access['permissions'] : [];
    if (empty($permissions[domainToolPermissionKey($tool)])) return 'Этот инструмент не разрешён для доступа.';
    [$start, $end] = domainToolAccessTimes($access);
    if ($start <= 0 || $end <= $start) return 'Срок доступа настроен неправильно.';
    if (time() < $start) return 'Время доступа ещё не наступило.';
    if (time() >= $end) return 'Время доступа истекло. Обратитесь к владельцу домена.';
    return null;
}

function domainToolDocumentRoot(array $document, array $domain): string
{
    $prefix = (string) ($document['profile']['prefix'] ?? '');
    $relative = trim(str_replace('\\', '/', (string) ($domain['path'] ?? '')), '/');
    if (preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) !== 1 || $relative === '' || in_array('..', explode('/', $relative), true)) {
        throw new RuntimeException('Invalid domain directory');
    }
    $root = rtrim(str_replace('\\', '/', USER_WEB_ROOT_DIRECTORY), '/') . '/' . $prefix;
    $path = $root . '/' . $relative;
    if (!WIN) {
        $realRoot = realpath($root);
        $realPath = realpath($path);
        if ($realRoot === false || $realPath === false || strpos(str_replace('\\', '/', $realPath), rtrim(str_replace('\\', '/', $realRoot), '/') . '/') !== 0) {
            throw new RuntimeException('Domain directory not found');
        }
        $path = $realPath;
    }
    if (basename(str_replace('\\', '/', $path)) !== trim(USER_PUBLIC_HTML_DIRECTORY, '/')) throw new RuntimeException('Invalid public_html directory');
    return $path;
}

function domainToolDatabase(array $document, array $domain): ?array
{
    $domainName = mb_strtolower((string) ($domain['domain'] ?? ''));
    foreach ($document['resources']['databases'] ?? [] as $database) {
        if (is_array($database) && !empty($database['active']) && mb_strtolower((string) ($database['domain'] ?? '')) === $domainName) return $database;
    }
    return null;
}

function domainToolPanelDatabaseContext(DataStore $store, array $selection): ?array
{
    $prefix = (string) ($selection['prefix'] ?? '');
    $databaseId = (int) ($selection['databaseId'] ?? 0);
    if ($databaseId <= 0 || preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) !== 1) return null;

    $document = $store->load($prefix);
    if (!is_array($document) || empty($document['profile']['active'])) return null;
    foreach ($document['resources']['databases'] ?? [] as $database) {
        if (!is_array($database) || empty($database['active']) || (int) ($database['id'] ?? 0) !== $databaseId) continue;
        return [
            'document' => $document,
            'domain' => ['domain' => (string) ($database['domain'] ?? domainToolRequestHost())],
            'database' => $database,
            'tool' => 'phpmyadmin',
            'panelDatabase' => true,
        ];
    }
    return null;
}

function domainToolPhpMyAdminDatabaseUrl(array $context): string
{
    $database = is_array($context['database'] ?? null) ? $context['database'] : [];
    $databaseName = trim((string) ($database['name'] ?? ''));
    if ($databaseName === '') return '/phpmyadmin/';
    return '/phpmyadmin/index.php?route=/database/structure&db=' . rawurlencode($databaseName);
}

function domainToolPanelLaunchDirectory(): string
{
    return rtrim(DOMAIN_TOOL_STATE_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . 'panel-tool-launches';
}

function domainToolPhpMyAdminAdapterStateDirectory(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'domain-tool-state';
}

function domainToolSyncPhpMyAdminAdapterSettings(): void
{
    $directory = domainToolPhpMyAdminAdapterStateDirectory();
    if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
        throw new RuntimeException('Cannot prepare phpMyAdmin access settings');
    }
    $trustedIps = [];
    foreach (DOMAIN_TOOL_TRUSTED_IPS as $trustedIp) {
        $trustedIp = trim((string) $trustedIp);
        if ($trustedIp !== '' && filter_var($trustedIp, FILTER_VALIDATE_IP) !== false) {
            $trustedIps[] = $trustedIp;
        }
    }
    $payload = json_encode([
        'version' => 1,
        'trustedIps' => array_values(array_unique($trustedIps)),
        'trustedProxyIps' => array_values(ROOT_TRUSTED_PROXY_IPS),
        'dataDirectory' => DATA_DIRECTORY,
        'sessionIdleSeconds' => DOMAIN_TOOL_SESSION_IDLE_SECONDS,
        'mysqlHost' => MYSQL_CLIENT_CONNECTION_HOST,
        'mysqlPort' => MYSQL_CLIENT_CONNECTION_PORT,
    ], JSON_UNESCAPED_SLASHES);
    if (!is_string($payload)) throw new RuntimeException('Cannot prepare phpMyAdmin access settings');

    $path = $directory . DIRECTORY_SEPARATOR . 'phpmyadmin-adapter.json';
    $current = is_file($path) && !is_link($path) ? file_get_contents($path) : false;
    if (is_string($current) && hash_equals($current, $payload)) return;
    $temporary = tempnam($directory, '.pma-settings-');
    if ($temporary === false) throw new RuntimeException('Cannot prepare phpMyAdmin access settings');
    try {
        if (file_put_contents($temporary, $payload, LOCK_EX) === false) {
            throw new RuntimeException('Cannot prepare phpMyAdmin access settings');
        }
        @chmod($temporary, 0600);
        if (!@rename($temporary, $path)) {
            @unlink($path);
            if (!@rename($temporary, $path)) throw new RuntimeException('Cannot prepare phpMyAdmin access settings');
        }
    } finally {
        if (is_file($temporary)) @unlink($temporary);
    }
}

function domainToolCreatePanelLaunch(array $selection, int $ttlSeconds): string
{
    domainToolSyncPhpMyAdminAdapterSettings();
    $directory = (string) ($selection['tool'] ?? '') === 'phpmyadmin'
        ? domainToolPhpMyAdminAdapterStateDirectory() . DIRECTORY_SEPARATOR . 'panel-tool-launches'
        : domainToolPanelLaunchDirectory();
    if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
        throw new RuntimeException('Cannot prepare tool launch');
    }
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $expiredPath) {
        if (!is_file($expiredPath) || is_link($expiredPath)) continue;
        $expired = json_decode((string) file_get_contents($expiredPath), true);
        if (!is_array($expired) || (int) ($expired['expiresAt'] ?? 0) <= time()) @unlink($expiredPath);
    }
    $token = domainToolBase64Encode(random_bytes(32));
    $payload = json_encode(array_merge($selection, [
        'host' => domainToolRequestHost(),
        'clientIp' => panelClientIp(),
        'expiresAt' => time() + $ttlSeconds,
    ]), JSON_UNESCAPED_SLASHES);
    $path = $directory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    if (!is_string($payload) || file_put_contents($path, $payload, LOCK_EX) === false) {
        throw new RuntimeException('Cannot create tool launch');
    }
    @chmod($path, 0600);
    return $token;
}

function domainToolConsumePanelLaunch(string $token): ?array
{
    if (preg_match('/^[A-Za-z0-9_-]{40,64}$/D', $token) !== 1) return null;
    $path = domainToolPanelLaunchDirectory() . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    if (!is_file($path) || is_link($path)) return null;
    $claimedPath = $path . '.used-' . bin2hex(random_bytes(8));
    if (!@rename($path, $claimedPath)) return null;
    $json = file_get_contents($claimedPath);
    @unlink($claimedPath);
    $payload = is_string($json) ? json_decode($json, true) : null;
    if (!is_array($payload)
        || (int) ($payload['expiresAt'] ?? 0) <= time()
        || !hash_equals((string) ($payload['host'] ?? ''), domainToolRequestHost())) {
        return null;
    }
    return $payload;
}

function domainToolCreateDatabaseLaunch(string $prefix, int $databaseId): string
{
    if (preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) !== 1 || $databaseId <= 0) {
        throw new InvalidArgumentException('Invalid database launch');
    }
    return domainToolCreatePanelLaunch([
        'kind' => 'database',
        'tool' => 'phpmyadmin',
        'prefix' => $prefix,
        'databaseId' => $databaseId,
    ], PHPMYADMIN_DATABASE_LAUNCH_TTL_SECONDS);
}

function domainToolCreateDomainLaunch(string $tool, string $prefix, int $domainId, string $accessId = '', int $accessLimit = PHP_INT_MAX): string
{
    if (!in_array($tool, ['phpmyadmin', 'filemanager', 'fileeditor'], true)
        || preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) !== 1
        || $domainId <= 0
        || ($accessId !== '' && preg_match('/^[a-f0-9]{16,64}$/D', $accessId) !== 1)) {
        throw new InvalidArgumentException('Invalid domain tool launch');
    }
    return domainToolCreatePanelLaunch([
        'kind' => 'domain',
        'tool' => $tool,
        'prefix' => $prefix,
        'domainId' => $domainId,
        'accessId' => $accessId,
        'accessLimit' => $accessLimit,
    ], DOMAIN_TOOL_PANEL_LAUNCH_TTL_SECONDS);
}

function domainToolPanelDomainContext(DataStore $store, array $selection, string $tool): ?array
{
    $prefix = (string) ($selection['prefix'] ?? '');
    $domainId = (int) ($selection['domainId'] ?? 0);
    if (!in_array($tool, ['phpmyadmin', 'filemanager', 'fileeditor'], true)
        || $domainId <= 0
        || preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) !== 1
        || !hash_equals($tool, (string) ($selection['tool'] ?? ''))) {
        return null;
    }
    $document = $store->load($prefix);
    if (!is_array($document) || empty($document['profile']['active'])) return null;
    foreach ($document['resources']['domains'] ?? [] as $domain) {
        if (!is_array($domain) || empty($domain['active']) || (int) ($domain['id'] ?? 0) !== $domainId) continue;
        $accessId = (string) ($selection['accessId'] ?? '');
        if ($accessId !== '') {
            $matchedAccess = null;
            foreach ($domain['toolAccesses'] ?? [] as $access) {
                if (is_array($access) && hash_equals((string) ($access['id'] ?? ''), $accessId)) {
                    $matchedAccess = $access;
                    break;
                }
            }
            if (!is_array($matchedAccess) || domainToolAccessError($matchedAccess, $tool, panelClientIp()) !== null) return null;
        }
        $context = [
            'document' => $document,
            'domain' => $domain,
            'database' => domainToolDatabase($document, $domain),
            'tool' => $tool,
            'panelDomain' => true,
        ];
        $context['documentRoot'] = domainToolDocumentRoot($document, $domain);
        $stateSuffix = (string) $document['profile']['prefix'] . DIRECTORY_SEPARATOR . (string) $domain['domain'];
        $context['stateDirectory'] = rtrim(DOMAIN_TOOL_STATE_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $stateSuffix;
        if (!is_dir($context['stateDirectory']) && !mkdir($context['stateDirectory'], 0750, true) && !is_dir($context['stateDirectory'])) {
            return null;
        }
        if ($tool === 'phpmyadmin' && $context['database'] === null) return null;
        return $context;
    }
    return null;
}

function domainToolLog(string $action, array $context, bool $ok, ?string $error = null, array $extra = []): void
{
    try {
        $log = new RootAuditLog(DOMAIN_TOOL_LOG_DIRECTORY, DOMAIN_TOOL_LOG_RETENTION_DAYS, DOMAIN_TOOL_LOG_ENTRY_MAX_BYTES);
        $meta = [
            'user_prefix' => (string) ($context['document']['profile']['prefix'] ?? ''),
            'user_email' => (string) ($context['document']['profile']['email'] ?? ''),
            'client_ip' => panelClientIp(),
        ];
        $params = array_merge([
            'tool' => (string) ($context['tool'] ?? ''),
            'domain' => (string) ($context['domain']['domain'] ?? ''),
            'method' => (string) ($_SERVER['REQUEST_METHOD'] ?? ''),
            'uri' => (string) ($_SERVER['REQUEST_URI'] ?? ''),
        ], $extra);
        $started = $log->start($action, $params, $meta);
        $response = ['ok' => $ok, 'data' => $ok ? ['authorized' => true] : null, 'error' => $error];
        $log->finish($started, $response, $error === null ? null : ['message' => $error]);
    } catch (Throwable $ignored) {
        // An audit failure must not expose data or block access that has already been validated.
    }
}

function domainToolBeginRequestLog(array $context, array $extra = []): void
{
    try {
        $log = new RootAuditLog(DOMAIN_TOOL_LOG_DIRECTORY, DOMAIN_TOOL_LOG_RETENTION_DAYS, DOMAIN_TOOL_LOG_ENTRY_MAX_BYTES);
        $started = $log->start('tool_request', array_merge([
            'tool' => (string) ($context['tool'] ?? ''),
            'domain' => (string) ($context['domain']['domain'] ?? ''),
            'method' => (string) ($_SERVER['REQUEST_METHOD'] ?? ''),
            'uri' => (string) ($_SERVER['REQUEST_URI'] ?? ''),
        ], $extra), [
            'user_prefix' => (string) ($context['document']['profile']['prefix'] ?? ''),
            'user_email' => (string) ($context['document']['profile']['email'] ?? ''),
            'client_ip' => panelClientIp(),
        ]);
        register_shutdown_function(static function () use ($log, $started): void {
            try {
                $fatal = error_get_last();
                $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
                $status = http_response_code();
                $error = is_array($fatal) && in_array((int) ($fatal['type'] ?? 0), $fatalTypes, true)
                    ? ['message' => (string) ($fatal['message'] ?? 'Fatal tool error'), 'file' => (string) ($fatal['file'] ?? ''), 'line' => (int) ($fatal['line'] ?? 0)]
                    : ($status >= 400 ? ['message' => 'HTTP ' . $status] : null);
                $log->finish($started, ['ok' => $error === null, 'data' => ['httpStatus' => $status], 'error' => $error['message'] ?? null], $error);
            } catch (Throwable $ignored) {
                // Auditing must not append text to HTML/JSON and corrupt the tool response.
            }
        });
    } catch (Throwable $ignored) {
        // An audit failure must not block a tool request that has already been validated.
    }
}

function domainToolPage(string $title, string $message, bool $login, string $domain, string $tool): void
{
    http_response_code($login ? 401 : 403);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $safeMessage = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    $safeDomain = htmlspecialchars($domain, ENT_QUOTES, 'UTF-8');
    $safeTool = htmlspecialchars($tool, ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>' . $safeTitle . '</title><link rel="stylesheet" href="/panel/assets/vendor/bootstrap/css/bootstrap.min.css">'
        . '<link rel="stylesheet" href="/panel/assets/vendor/bootstrap-icons/font/bootstrap-icons.css"></head>'
        . '<body class="bg-light"><main class="container py-5"><div class="card border-0 shadow-sm mx-auto" style="max-width:520px"><div class="card-body p-4 p-md-5">'
        . '<div class="d-flex align-items-center gap-3 mb-4"><span class="btn btn-primary disabled"><i class="bi bi-shield-lock"></i></span><div><h1 class="h4 mb-0">' . $safeTitle . '</h1><small class="text-secondary">' . $safeDomain . ' · ' . $safeTool . '</small></div></div>'
        . ($safeMessage !== '' ? '<div class="alert alert-warning">' . $safeMessage . '</div>' : '');
    if ($login) {
        echo '<form method="post" autocomplete="on"><input type="hidden" name="imagopanel_tool_login" value="1">'
            . '<div class="mb-3"><label class="form-label">Логин</label><input class="form-control" name="imagopanel_login" autocomplete="username" required maxlength="128"></div>'
            . '<div class="mb-4"><label class="form-label">Пароль</label><input class="form-control" type="password" name="imagopanel_password" autocomplete="current-password" required maxlength="256"></div>'
            . '<button class="btn btn-primary w-100" type="submit"><i class="bi bi-box-arrow-in-right me-2"></i>Войти</button></form>';
    }
    echo '</div></div></main></body></html>';
    exit;
}

function domainToolAuthorize(string $tool): array
{
    domainToolPermissionKey($tool);
    $store = new DataStore(DATA_DIRECTORY);

    if ($tool === 'phpmyadmin') {
        $launchToken = trim((string) ($_GET['imagopanel_database_launch'] ?? ''));
        if ($launchToken !== '') {
            $launch = domainToolConsumePanelLaunch($launchToken);
            $panelContext = is_array($launch) ? domainToolPanelDatabaseContext($store, $launch) : null;
            if ($launch === null
                || (string) ($launch['kind'] ?? '') !== 'database'
                || (string) ($launch['tool'] ?? '') !== 'phpmyadmin'
                || $panelContext === null) {
                domainToolPage('Доступ запрещён', 'Ссылка для открытия базы недействительна или устарела.', false, domainToolRequestHost(), $tool);
            }
            domainToolSetCookie([
                'mode' => 'panel_database',
                'prefix' => (string) $launch['prefix'],
                'databaseId' => (int) $launch['databaseId'],
                'host' => (string) $launch['host'],
                'accessLimit' => PHP_INT_MAX,
            ], time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS, 'phpmyadmin');
            header('Location: ' . domainToolPhpMyAdminDatabaseUrl($panelContext));
            exit;
        }

        if (trim((string) ($_GET['imagopanel_domain_launch'] ?? '')) === '') {
            $selection = domainToolReadCookie('phpmyadmin');
            $panelContext = is_array($selection)
                && (string) ($selection['mode'] ?? '') === 'panel_database'
                && hash_equals((string) ($selection['host'] ?? ''), domainToolRequestHost())
                ? domainToolPanelDatabaseContext($store, $selection)
                : null;
            if ($panelContext !== null) {
                domainToolSetCookie($selection, time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS, 'phpmyadmin');
                domainToolBeginRequestLog($panelContext, ['mode' => 'panel_database', 'databaseId' => (int) $selection['databaseId']]);
                $GLOBALS['IMAGO_DOMAIN_TOOL_CONTEXT'] = $panelContext;
                return $panelContext;
            }
        }
    }

    if (in_array($tool, ['phpmyadmin', 'filemanager', 'fileeditor'], true)) {
        $launchToken = trim((string) ($_GET['imagopanel_domain_launch'] ?? ''));
        if ($launchToken !== '') {
            $launch = domainToolConsumePanelLaunch($launchToken);
            $panelContext = is_array($launch) ? domainToolPanelDomainContext($store, $launch, $tool) : null;
            if ($launch === null
                || (string) ($launch['kind'] ?? '') !== 'domain'
                || $panelContext === null) {
                domainToolPage('Доступ запрещён', 'Ссылка для открытия папки недействительна или устарела.', false, domainToolRequestHost(), $tool);
            }
            domainToolSetCookie([
                'mode' => (string) ($launch['accessId'] ?? '') !== '' ? 'tool_portal' : 'panel_domain',
                'prefix' => (string) $launch['prefix'],
                'domainId' => (int) $launch['domainId'],
                'accessId' => (string) ($launch['accessId'] ?? ''),
                'tool' => $tool,
                'host' => (string) $launch['host'],
                'accessLimit' => (int) ($launch['accessLimit'] ?? PHP_INT_MAX),
            ], min((int) ($launch['accessLimit'] ?? PHP_INT_MAX), time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS), $tool);
            header('Location: ' . ($tool === 'phpmyadmin' ? domainToolPhpMyAdminDatabaseUrl($panelContext) : '/' . $tool . '/'));
            exit;
        }

        $selection = domainToolReadCookie($tool);
        $panelContext = is_array($selection)
            && in_array((string) ($selection['mode'] ?? ''), ['panel_domain', 'tool_portal'], true)
            && hash_equals((string) ($selection['host'] ?? ''), domainToolRequestHost())
            ? domainToolPanelDomainContext($store, $selection, $tool)
            : null;
        if ($panelContext !== null) {
            domainToolSetCookie($selection, min((int) ($selection['accessLimit'] ?? PHP_INT_MAX), time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS), $tool);
            domainToolBeginRequestLog($panelContext, ['mode' => (string) $selection['mode'], 'domainId' => (int) $selection['domainId'], 'accessId' => (string) ($selection['accessId'] ?? '')]);
            $GLOBALS['IMAGO_DOMAIN_TOOL_CONTEXT'] = $panelContext;
            return $panelContext;
        }
    }

    $host = domainToolRequestHost();
    $found = domainToolFindDomain($store, $host);
    if ($found === null) domainToolPage('Доступ запрещён', 'Инструмент недоступен для этого домена.', false, $host, $tool);
    $context = $found + ['tool' => $tool];
    $ip = panelClientIp();
    $trustedIp = filter_var($ip, FILTER_VALIDATE_IP) !== false && in_array($ip, DOMAIN_TOOL_TRUSTED_IPS, true);

    if (isset($_GET['imagopanel_tool_logout'])) {
        domainToolClearCookie();
        header('Location: ' . strtok((string) ($_SERVER['REQUEST_URI'] ?? '/'), '?'));
        exit;
    }

    $cookie = domainToolReadCookie();
    if (is_array($cookie)
        && hash_equals((string) ($cookie['domain'] ?? ''), (string) ($found['domain']['domain'] ?? ''))
        && hash_equals((string) ($cookie['prefix'] ?? ''), (string) ($found['document']['profile']['prefix'] ?? ''))) {
        $mode = (string) ($cookie['mode'] ?? '');
        $allowed = false;
        $error = 'Сессия доступа больше не действует.';
        if ($mode === 'owner' && $trustedIp) {
            $credential = hash_hmac('sha256', (string) ($found['document']['profile']['passwordHash'] ?? ''), DOMAIN_TOOL_AUTH_SECRET);
            $allowed = is_string($cookie['credential'] ?? null) && hash_equals($credential, (string) $cookie['credential']);
        } elseif ($mode === 'temporary') {
            foreach ($found['domain']['toolAccesses'] ?? [] as $access) {
                if (!is_array($access) || !hash_equals((string) ($access['id'] ?? ''), (string) ($cookie['accessId'] ?? ''))) continue;
                $error = domainToolAccessError($access, $tool, $ip) ?? '';
                $allowed = $error === '';
                break;
            }
        }
        if ($allowed) {
            $context['documentRoot'] = domainToolDocumentRoot($found['document'], $found['domain']);
            $context['database'] = domainToolDatabase($found['document'], $found['domain']);
            $stateSuffix = (string) $found['document']['profile']['prefix'] . DIRECTORY_SEPARATOR . (string) $found['domain']['domain'];
            $context['stateDirectory'] = rtrim(DOMAIN_TOOL_STATE_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $stateSuffix;
            if (!is_dir($context['stateDirectory']) && !mkdir($context['stateDirectory'], 0750, true) && !is_dir($context['stateDirectory'])) {
                domainToolPage('Доступ временно недоступен', 'Не удалось подготовить служебную папку инструмента.', false, $host, $tool);
            }
            if ($tool === 'phpmyadmin' && $context['database'] === null) {
                domainToolLog('tool_request', $context, false, 'No database linked to domain');
                domainToolPage('База недоступна', 'К этому домену не привязана активная база данных.', false, $host, $tool);
            }
            domainToolSetCookie($cookie, min((int) ($cookie['accessLimit'] ?? PHP_INT_MAX), time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS));
            domainToolBeginRequestLog($context, ['mode' => $mode, 'accessId' => (string) ($cookie['accessId'] ?? '')]);
            $GLOBALS['IMAGO_DOMAIN_TOOL_CONTEXT'] = $context;
            return $context;
        }
        domainToolClearCookie();
        domainToolLog('tool_request', $context, false, $error, ['mode' => $mode]);
    }

    $loginSubmitted = isset($_POST['imagopanel_tool_login']);
    if ($loginSubmitted) {
        $login = trim((string) ($_POST['imagopanel_login'] ?? ''));
        $password = (string) ($_POST['imagopanel_password'] ?? '');
        if ($trustedIp
            && hash_equals(mb_strtolower((string) ($found['document']['profile']['email'] ?? '')), mb_strtolower($login))
            && password_verify($password, (string) ($found['document']['profile']['passwordHash'] ?? ''))) {
            $limit = time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS;
            domainToolSetCookie(['mode' => 'owner', 'prefix' => (string) $found['document']['profile']['prefix'], 'domain' => (string) $found['domain']['domain'], 'tool' => '*', 'accessId' => '', 'accessLimit' => PHP_INT_MAX, 'credential' => hash_hmac('sha256', (string) $found['document']['profile']['passwordHash'], DOMAIN_TOOL_AUTH_SECRET)], $limit);
            domainToolLog('tool_login', $context, true, null, ['mode' => 'owner', 'login' => $login]);
            header('Location: ' . (string) ($_SERVER['REQUEST_URI'] ?? '/'));
            exit;
        }

        $matched = null;
        foreach ($found['domain']['toolAccesses'] ?? [] as $access) {
            if (is_array($access) && hash_equals((string) ($access['login'] ?? ''), $login)) {
                $matched = $access;
                break;
            }
        }
        $error = 'Неверный логин или пароль.';
        if (is_array($matched) && hash_equals((string) ($matched['password'] ?? ''), $password)) {
            $error = domainToolAccessError($matched, $tool, $ip) ?? '';
            if ($error === '') {
                [, $accessLimit] = domainToolAccessTimes($matched);
                domainToolSetCookie(['mode' => 'temporary', 'prefix' => (string) $found['document']['profile']['prefix'], 'domain' => (string) $found['domain']['domain'], 'tool' => '*', 'accessId' => (string) $matched['id'], 'accessLimit' => $accessLimit], min($accessLimit, time() + DOMAIN_TOOL_SESSION_IDLE_SECONDS));
                domainToolLog('tool_login', $context, true, null, ['mode' => 'temporary', 'accessId' => (string) $matched['id'], 'login' => $login]);
                header('Location: ' . (string) ($_SERVER['REQUEST_URI'] ?? '/'));
                exit;
            }
        }
        domainToolLog('tool_login', $context, false, $error, ['login' => $login]);
        domainToolPage('Вход в инструмент', $error, true, $host, $tool);
    }

    $ipKnown = $trustedIp;
    foreach ($found['domain']['toolAccesses'] ?? [] as $access) {
        if (is_array($access) && in_array($ip, is_array($access['ips'] ?? null) ? $access['ips'] : [], true)) {
            $ipKnown = true;
            break;
        }
    }
    if (!$ipKnown) {
        domainToolLog('tool_login', $context, false, 'IP access denied');
        domainToolPage('Доступ запрещён', 'Доступ с этого IP запрещён.', false, $host, $tool);
    }
    domainToolPage('Вход в инструмент', '', true, $host, $tool);
}
