<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/Size.php';
require_once __DIR__ . '/lib/session.php';
require_once __DIR__ . '/lib/DataStore.php';
require_once __DIR__ . '/lib/PanelMailer.php';
require_once __DIR__ . '/lib/DnsService.php';
require_once __DIR__ . '/lib/DomainToolAccess.php';

try {
    domainToolSyncPhpMyAdminAdapterSettings();
} catch (Throwable $ignored) {
    // phpMyAdmin will fail closed if its isolated adapter settings cannot be refreshed.
}

function completePanelLogin(array $pending): void
{
    $auth = is_array($pending['auth'] ?? null) ? $pending['auth'] : [];
    $credential = (string) ($pending['credential'] ?? '');
    $remember = !empty($pending['remember']);
    session_regenerate_id(true);
    $_SESSION['auth'] = $auth;
    $_SESSION['last_activity'] = time();
    unset($_SESSION['pending_2fa'], $_SESSION['tool_portal']);
    if ($remember && $credential !== '') panelSetRememberCookie($auth, $credential);
    else panelForgetRememberCookie();
}

function panelToolPortalSelection(array $document, array $domain, array $access): array
{
    return [
        'prefix' => (string) ($document['profile']['prefix'] ?? ''),
        'domainId' => (int) ($domain['id'] ?? 0),
        'accessId' => (string) ($access['id'] ?? ''),
    ];
}

function panelToolPortalTools(DataStore $store, array $selection): array
{
    $tools = [];
    foreach (['phpmyadmin', 'filemanager', 'fileeditor'] as $tool) {
        $candidate = $selection + ['tool' => $tool];
        try {
            $tools[$tool] = domainToolPanelDomainContext($store, $candidate, $tool) !== null;
        } catch (Throwable $exception) {
            $tools[$tool] = false;
        }
    }
    return $tools;
}

function panelToolPortalFromSession(DataStore $store): ?array
{
    $saved = is_array($_SESSION['tool_portal'] ?? null) ? $_SESSION['tool_portal'] : null;
    if ($saved === null || (int) ($saved['expiresAt'] ?? 0) <= time()) {
        unset($_SESSION['tool_portal']);
        return null;
    }
    $prefix = (string) ($saved['prefix'] ?? '');
    $document = $store->load($prefix);
    if (!is_array($document) || empty($document['profile']['active'])) {
        unset($_SESSION['tool_portal']);
        return null;
    }
    foreach ($document['resources']['domains'] ?? [] as $domain) {
        if (!is_array($domain) || empty($domain['active']) || (int) ($domain['id'] ?? 0) !== (int) ($saved['domainId'] ?? 0)) continue;
        foreach ($domain['toolAccesses'] ?? [] as $access) {
            if (!is_array($access) || !hash_equals((string) ($access['id'] ?? ''), (string) ($saved['accessId'] ?? ''))) continue;
            $fingerprint = hash_hmac('sha256', (string) ($access['password'] ?? ''), DOMAIN_TOOL_AUTH_SECRET);
            if (!hash_equals($fingerprint, (string) ($saved['credential'] ?? ''))) break;
            $selection = panelToolPortalSelection($document, $domain, $access);
            $tools = panelToolPortalTools($store, $selection);
            if (!in_array(true, $tools, true)) break;
            $_SESSION['last_activity'] = time();
            return [
                'name' => (string) ($access['name'] ?? ''),
                'login' => (string) ($access['login'] ?? ''),
                'domain' => (string) ($domain['domain'] ?? ''),
                'prefix' => $prefix,
                'domainId' => (int) ($domain['id'] ?? 0),
                'accessId' => (string) ($access['id'] ?? ''),
                'accessLimit' => strtotime((string) ($access['expiresAt'] ?? '')) ?: 0,
                'expiresAt' => (string) ($access['expiresAt'] ?? ''),
                'tools' => $tools,
            ];
        }
    }
    unset($_SESSION['tool_portal']);
    return null;
}

function panelFindToolPortalLogin(DataStore $store, string $login, string $password): array
{
    $credentialsMatched = false;
    $loginFound = false;
    $firstMatch = [];
    foreach ($store->listDocuments() as $document) {
        if (empty($document['profile']['active'])) continue;
        foreach ($document['resources']['domains'] ?? [] as $domain) {
            if (!is_array($domain) || empty($domain['active'])) continue;
            foreach ($domain['toolAccesses'] ?? [] as $access) {
                if (!is_array($access) || !hash_equals((string) ($access['login'] ?? ''), $login)) continue;
                $loginFound = true;
                if ($firstMatch === []) $firstMatch = ['document' => $document, 'domain' => $domain, 'access' => $access];
                if (!hash_equals((string) ($access['password'] ?? ''), $password)) continue;
                $credentialsMatched = true;
                $selection = panelToolPortalSelection($document, $domain, $access);
                $tools = panelToolPortalTools($store, $selection);
                if (!in_array(true, $tools, true)) continue;
                return ['matched' => true, 'document' => $document, 'domain' => $domain, 'access' => $access, 'tools' => $tools];
            }
        }
    }
    return array_merge(['matched' => $credentialsMatched, 'loginFound' => $loginFound], $firstMatch);
}

function maskedLoginEmail(string $email): string
{
    $parts = explode('@', $email, 2);
    if (count($parts) !== 2) return $email;
    $local = $parts[0];
    $visible = mb_substr($local, 0, min(2, mb_strlen($local)));
    return $visible . str_repeat('*', max(3, mb_strlen($local) - mb_strlen($visible))) . '@' . $parts[1];
}

startPanelSession();
$store = new DataStore(DATA_DIRECTORY);

if (panelSessionExpired()) {
    clearPanelSession();
}

$loginError = '';
$action = isset($_POST['_action']) ? (string) $_POST['_action'] : '';
$pendingTwoFactor = is_array($_SESSION['pending_2fa'] ?? null) ? $_SESSION['pending_2fa'] : null;

if ($pendingTwoFactor !== null && (int) ($pendingTwoFactor['expiresAt'] ?? 0) <= time()) {
    unset($_SESSION['pending_2fa']);
    $pendingTwoFactor = null;
    $loginError = 'twoFactorExpired';
}

if (isset($_GET['verify_login']) && $pendingTwoFactor !== null) {
    $token = (string) $_GET['verify_login'];
    $expected = (string) ($pendingTwoFactor['tokenHash'] ?? '');
    if ($token !== '' && $expected !== '' && hash_equals($expected, hash_hmac('sha256', $token, REMEMBER_LOGIN_SECRET))) {
        completePanelLogin($pendingTwoFactor);
        header('Location: ./');
        exit;
    }
    $loginError = 'twoFactorInvalid';
}

if ($action === 'logout') {
    if (panelCsrfValid(isset($_POST['_csrf']) ? (string) $_POST['_csrf'] : null)) {
        clearPanelSession();
        panelForgetRememberCookie();
        domainToolClearCookie();
        foreach (['phpmyadmin', 'filemanager', 'fileeditor'] as $toolCookie) domainToolClearCookie($toolCookie);
    }
    header('Location: ./');
    exit;
}

if ($action === 'cancel2fa') {
    if (panelCsrfValid(isset($_POST['_csrf']) ? (string) $_POST['_csrf'] : null)) {
        unset($_SESSION['pending_2fa']);
    }
    header('Location: ./');
    exit;
}

if ($action === 'verify2fa' && $pendingTwoFactor !== null) {
    $code = preg_replace('/\D+/', '', (string) ($_POST['code'] ?? ''));
    $csrfValid = panelCsrfValid(isset($_POST['_csrf']) ? (string) $_POST['_csrf'] : null);
    $attempts = (int) ($pendingTwoFactor['attempts'] ?? 0);
    $validCode = $code !== '' && hash_equals((string) ($pendingTwoFactor['codeHash'] ?? ''), hash_hmac('sha256', $code, REMEMBER_LOGIN_SECRET));
    if ($csrfValid && $attempts < USER_LOGIN_2FA_MAX_ATTEMPTS && $validCode) {
        completePanelLogin($pendingTwoFactor);
        header('Location: ./');
        exit;
    }
    $attempts++;
    if ($attempts >= USER_LOGIN_2FA_MAX_ATTEMPTS) {
        unset($_SESSION['pending_2fa']);
        $pendingTwoFactor = null;
        $loginError = 'twoFactorExpired';
    } else {
        $_SESSION['pending_2fa']['attempts'] = $attempts;
        $pendingTwoFactor['attempts'] = $attempts;
        $loginError = 'twoFactorInvalid';
    }
}

$toolPortal = panelToolPortalFromSession($store);
if ($action === 'launchTemporaryTool' && $toolPortal !== null) {
    $tool = trim((string) ($_POST['tool'] ?? ''));
    $csrfValid = panelCsrfValid(isset($_POST['_csrf']) ? (string) $_POST['_csrf'] : null);
    if ($csrfValid && !empty($toolPortal['tools'][$tool]) && in_array($tool, ['phpmyadmin', 'filemanager', 'fileeditor'], true)) {
        $token = domainToolCreateDomainLaunch(
            $tool,
            (string) $toolPortal['prefix'],
            (int) $toolPortal['domainId'],
            (string) $toolPortal['accessId'],
            (int) $toolPortal['accessLimit']
        );
        header('Location: /' . $tool . '/?imagopanel_domain_launch=' . rawurlencode($token));
        exit;
    }
    $loginError = 'toolAccessUnavailable';
}

if ($action === 'login') {
    $identifier = trim((string) ($_POST['identifier'] ?? ($_POST['email'] ?? '')));
    $email = mb_strtolower($identifier);
    $password = (string) ($_POST['password'] ?? '');
    $rememberLogin = isset($_POST['remember']) && (string) $_POST['remember'] === '1';
    $authenticated = null;
    $authenticatedPasswordHash = null;

    $csrfValid = panelCsrfValid(isset($_POST['_csrf']) ? (string) $_POST['_csrf'] : null);
    if ($csrfValid && hash_equals(mb_strtolower(ROOT_EMAIL), $email)) {
        if (panelRootIpAllowed() && password_verify($password, ROOT_PASSWORD_HASH)) {
            $authenticated = ['role' => 'root', 'email' => ROOT_EMAIL, 'name' => 'Root', 'user_id' => null, 'prefix' => 'root'];
            $authenticatedPasswordHash = ROOT_PASSWORD_HASH;
        }
    } elseif ($csrfValid) {
        $document = $store->findByEmail($email);
        $profile = $document['profile'] ?? null;
        if (is_array($profile) && !empty($profile['active'])
            && panelUserIpAllowed($profile)
            && password_verify($password, (string) ($profile['passwordHash'] ?? ''))) {
            $authenticated = [
                'role' => 'user',
                'email' => (string) $profile['email'],
                'name' => (string) $profile['name'],
                'user_id' => (int) $profile['id'],
                'prefix' => (string) $profile['prefix'],
            ];
            $authenticatedPasswordHash = (string) $profile['passwordHash'];
        }
    }

    if ($authenticated !== null && $authenticated['role'] === 'user' && USER_LOGIN_2FA_ENABLED) {
        $code = (string) random_int(100000, 999999);
        $token = bin2hex(random_bytes(32));
        session_regenerate_id(true);
        $_SESSION['pending_2fa'] = [
            'auth' => $authenticated,
            'credential' => (string) $authenticatedPasswordHash,
            'remember' => $rememberLogin,
            'codeHash' => hash_hmac('sha256', $code, REMEMBER_LOGIN_SECRET),
            'tokenHash' => hash_hmac('sha256', $token, REMEMBER_LOGIN_SECRET),
            'expiresAt' => time() + USER_LOGIN_2FA_TTL_SECONDS,
            'attempts' => 0,
        ];
        try {
            panelSendLoginCode((string) $authenticated['email'], $code, $token);
            header('Location: ./');
            exit;
        } catch (Throwable $exception) {
            unset($_SESSION['pending_2fa']);
            $loginError = 'twoFactorSendFailed';
        }
    } elseif ($authenticated !== null) {
        completePanelLogin(['auth' => $authenticated, 'credential' => (string) $authenticatedPasswordHash, 'remember' => $rememberLogin]);
        header('Location: ./');
        exit;
    }

    if ($authenticated === null && $csrfValid && $identifier !== '' && $password !== '') {
        $temporary = panelFindToolPortalLogin($store, $identifier, $password);
        if (!empty($temporary['document']) && !empty($temporary['domain']) && !empty($temporary['access'])) {
            if (empty($temporary['matched']) || empty($temporary['tools']) || !in_array(true, $temporary['tools'], true)) {
                domainToolLog('tool_portal_login', ['document' => $temporary['document'], 'domain' => $temporary['domain'], 'tool' => 'portal'], false, 'Temporary access conditions rejected', ['accessId' => (string) ($temporary['access']['id'] ?? ''), 'login' => $identifier]);
            }
        }
        if (!empty($temporary['matched']) && !empty($temporary['document']) && !empty($temporary['domain']) && !empty($temporary['access']) && !empty($temporary['tools']) && in_array(true, $temporary['tools'], true)) {
            $access = $temporary['access'];
            $domain = $temporary['domain'];
            $document = $temporary['document'];
            session_regenerate_id(true);
            unset($_SESSION['auth'], $_SESSION['pending_2fa']);
            $_SESSION['tool_portal'] = [
                'prefix' => (string) $document['profile']['prefix'],
                'domainId' => (int) $domain['id'],
                'accessId' => (string) $access['id'],
                'credential' => hash_hmac('sha256', (string) $access['password'], DOMAIN_TOOL_AUTH_SECRET),
                'expiresAt' => strtotime((string) $access['expiresAt']) ?: 0,
            ];
            $_SESSION['last_activity'] = time();
            panelForgetRememberCookie();
            domainToolLog('tool_portal_login', ['document' => $document, 'domain' => $domain, 'tool' => 'portal'], true, null, ['accessId' => (string) $access['id'], 'login' => $identifier]);
            header('Location: ./');
            exit;
        }
        if (!empty($temporary['matched'])) $loginError = 'toolAccessUnavailable';
    }

    if ($loginError === '') $loginError = 'invalidCredentials';
}

$auth = panelAuth();
if ($auth !== null) {
    $_SESSION['last_activity'] = time();
}
$toolPortal = $auth === null ? panelToolPortalFromSession($store) : null;

$clientTariffs = [];
foreach (USER_TARIFFS as $key => $tariff) {
    if (!is_array($tariff)) continue;
    $tariff = tariffSizesInBytes($tariff, (string) $key);
    $clientTariffs[] = [
        'key' => (string) $key,
        'name' => (string) ($tariff['name'] ?? $key),
        'domain' => max(0, (int) ($tariff['domain'] ?? 0)),
        'db' => max(0, (int) ($tariff['db'] ?? 0)),
        'mailbydomain' => max(0, (int) ($tariff['mailbydomain'] ?? 0)),
        'wwwsize' => max(0, (float) ($tariff['wwwsize'] ?? 0)),
        'mailsize' => max(0, (float) ($tariff['mailsize'] ?? 0)),
        'dbsize' => max(0, (float) ($tariff['dbsize'] ?? 0)),
    ];
}
$quotaRuntimeActive = SYSTEM_QUOTAS_ENABLED && UNIX_ACCOUNTS_ENABLED && !WIN
    && UNIX_ID_BINARY !== '' && is_executable(UNIX_ID_BINARY)
    && SYSTEM_SETQUOTA_BINARY !== '' && is_executable(SYSTEM_SETQUOTA_BINARY)
    && is_dir(SYSTEM_QUOTA_MOUNTPOINT);
$systemWarnings = [];
if (SYSTEM_QUOTAS_ENABLED && !$quotaRuntimeActive) {
    $systemWarnings[] = !UNIX_ACCOUNTS_ENABLED
        ? 'System quotas отключены: включите UNIX_ACCOUNTS_ENABLED в config.php.'
        : 'System quotas недоступны в системе и не применяются.';
}

$clientConfig = [
    'panelName' => PANEL_NAME,
    'assetVersion' => ASSET_VERSION,
    'defaultLanguage' => DEFAULT_LANGUAGE,
    'refreshMinutes' => STATS_REFRESH_MINUTES,
    'importMaxRows' => IMPORT_MAX_ROWS,
    'importMailQuotaMb' => IMPORT_MAIL_DEFAULT_QUOTA_MB,
    'mailboxQuotaOptionsMb' => array_values(MAILBOX_QUOTA_OPTIONS_MB),
    'mailboxDefaultQuotaMb' => IMPORT_MAIL_DEFAULT_QUOTA_MB,
    'isAuthenticated' => $auth !== null,
    'role' => $auth['role'] ?? null,
    'email' => $auth['email'] ?? null,
    'name' => $auth['name'] ?? null,
    'userId' => $auth['user_id'] ?? null,
    'prefix' => $auth['prefix'] ?? null,
    'clientIp' => panelClientIp(),
    'domainToolAccessHours' => DOMAIN_TOOL_ACCESS_HOURS,
    'loginError' => $loginError,
    'twoFactorPending' => is_array($_SESSION['pending_2fa'] ?? null),
    'twoFactorEmail' => is_array($_SESSION['pending_2fa'] ?? null)
        ? maskedLoginEmail((string) ($_SESSION['pending_2fa']['auth']['email'] ?? ''))
        : '',
    'toolPortal' => $toolPortal,
    'tariffs' => $clientTariffs,
    'defaultTariff' => DEFAULT_USER_TARIFF,
    'tariffLimitsEnabled' => TARIFF_LIMITS_ENABLED,
    'unixAccountsEnabled' => UNIX_ACCOUNTS_ENABLED,
    'systemQuotasActive' => $quotaRuntimeActive,
    'systemWarnings' => ($auth['role'] ?? '') === 'root' ? $systemWarnings : [],
    'csrfToken' => panelCsrfToken(),
    'userWebRootDirectory' => USER_WEB_ROOT_DIRECTORY,
    'publicHtmlDirectory' => USER_PUBLIC_HTML_DIRECTORY,
    'mailStorageDirectory' => MAIL_STORAGE_DIRECTORY,
    'mysqlConnectionHost' => MYSQL_CLIENT_CONNECTION_HOST,
    'mysqlConnectionPort' => MYSQL_CLIENT_CONNECTION_PORT,
    'mysqlUserMaxLength' => MYSQL_CLIENT_USER_MAX_LENGTH,
    'showDatabasePasswords' => SHOW_DATABASE_PASSWORDS,
    'showMailPasswords' => SHOW_MAIL_PASSWORDS,
    'showUserPasswordsToAdmin' => ($auth['role'] ?? '') === 'root' && SHOW_USER_PASSWORDS_TO_ADMIN,
    'userPasswordPolicy' => [
        'minLength' => max(1, (int) (USER_PASSWORD_POLICY['min_length'] ?? 8)),
        'requireUppercase' => !empty(USER_PASSWORD_POLICY['require_uppercase']),
        'requireLowercase' => !empty(USER_PASSWORD_POLICY['require_lowercase']),
        'requireNumber' => !empty(USER_PASSWORD_POLICY['require_number']),
        'requireSpecial' => !empty(USER_PASSWORD_POLICY['require_special']),
        'specialCharacters' => (string) (USER_PASSWORD_POLICY['special_characters'] ?? '+-_)(?%#!,.'),
    ],
    'mailMigrationEnabled' => MAIL_MIGRATION_ENABLED,
    'mailMigrationPollIntervalMs' => MAIL_MIGRATION_POLL_INTERVAL_MS,
    'mailMigrationAllowedPorts' => array_values(array_map('intval', MAIL_MIGRATION_ALLOWED_PORTS)),
    'mailConnection' => [
        'imapHost' => MAIL_CLIENT_IMAP_HOST,
        'imapPort' => MAIL_CLIENT_IMAP_PORT,
        'pop3Host' => MAIL_CLIENT_POP3_HOST,
        'pop3Port' => MAIL_CLIENT_POP3_PORT,
        'smtpHost' => MAIL_CLIENT_SMTP_HOST,
        'smtpPort' => MAIL_CLIENT_SMTP_PORT,
        'webmailUrl' => MAIL_CLIENT_WEBMAIL_URL,
        'domainWebmailTemplate' => MAIL_CLIENT_DOMAIN_WEBMAIL_TEMPLATE,
        'appleProfilePath' => '/mail/apple.mobileconfig',
        'applePop3ProfilePath' => '/mail/apple-pop3.mobileconfig',
        'appleImapProfilePath' => '/mail/apple-imap.mobileconfig',
    ],
    'domainLogFiles' => [USER_APACHE_ACCESS_LOG_FILE, USER_APACHE_ERROR_LOG_FILE, USER_PHP_ERROR_LOG_FILE],
    'domainLogLinesPerPage' => DOMAIN_LOG_LINES_PER_PAGE,
    'dnsVerifyRequestTimeoutMs' => (DNS_VERIFY_TOTAL_TIMEOUT_SECONDS + 5) * 1000,
    'dnsProviders' => DnsService::publicProviders(),
    'dnsDefaultProvider' => DNS_API_DEFAULT_PROVIDER,
    'dnsDefaultTtl' => DNS_API_DEFAULT_TTL,
    'showDnsProviderCredentials' => SHOW_DNS_PROVIDER_CREDENTIALS,
    'phpVersions' => array_map(static function (array $version): array {
        return [
            'id' => (string) ($version['id'] ?? ''),
            'label' => (string) ($version['label'] ?? ''),
            'default' => (string) ($version['id'] ?? '') === APACHE_DEFAULT_PHP_VERSION,
        ];
    }, APACHE_PHP_VERSIONS),
    'dnsRecords' => [
        [
            'label' => 'DKIM',
            'type' => 'TXT',
            'name' => DNS_DKIM_SELECTOR . '._domainkey.{domain}',
            'value' => DNS_DKIM_VALUE,
        ],
        [
            'label' => 'SPF',
            'type' => 'TXT',
            'name' => '{domain}',
            'value' => DNS_SPF_VALUE,
        ],
        [
            'label' => 'DMARC',
            'type' => 'TXT',
            'name' => '_dmarc.{domain}',
            'value' => DNS_DMARC_VALUE,
        ],
    ],
];
?>
<!doctype html>
<html lang="<?= htmlspecialchars(DEFAULT_LANGUAGE, ENT_QUOTES, 'UTF-8') ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <meta name="robots" content="noindex,nofollow">
    <title><?= htmlspecialchars(PANEL_NAME, ENT_QUOTES, 'UTF-8') ?></title>
    <link rel="stylesheet" href="assets/vendor/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="assets/vendor/bootstrap-icons/font/bootstrap-icons.css">
    <link rel="stylesheet" href="assets/vendor/datatables/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" href="assets/css/app.css?v=<?= rawurlencode(ASSET_VERSION) ?>">
</head>
<body>
    <div id="app-loader" class="app-loader" role="status" aria-live="polite">
        <div class="loader-mark"><span></span><span></span><span></span></div>
        <strong><?= htmlspecialchars(PANEL_NAME, ENT_QUOTES, 'UTF-8') ?></strong>
        <small translate="loadingPanel"></small>
    </div>
    <div id="language-loader" class="language-loader" role="status" aria-live="polite" aria-hidden="true">
        <div class="spinner-border" aria-hidden="true"></div>
        <strong translate="languagePicker.loading"></strong>
    </div>
    <div id="app"></div>

    <script>window.IMAGO_CONFIG = <?= json_encode($clientConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;</script>
    <script src="assets/vendor/jquery/jquery-3.7.1.min.js"></script>
    <script src="assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="assets/vendor/datatables/dataTables.min.js"></script>
    <script src="assets/vendor/datatables/dataTables.bootstrap5.min.js"></script>
    <script src="assets/js/templates.js?v=<?= rawurlencode(ASSET_VERSION) ?>"></script>
    <script src="assets/js/app.js?v=<?= rawurlencode(ASSET_VERSION) ?>"></script>
</body>
</html>
