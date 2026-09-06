<?php
declare(strict_types=1);

// The CLI process does not receive HTTP_HOST automatically, so the environment is passed as an argument.
if (isset($argv) && is_array($argv) && in_array('--task', $argv, true)) {
    $_SERVER['HTTP_HOST'] = 'task.lv';
} elseif (isset($argv) && is_array($argv) && in_array('--prod', $argv, true)) {
    $_SERVER['HTTP_HOST'] = '';
}

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/RootAuditLog.php';
require_once dirname(__DIR__) . '/lib/MailMigrationStore.php';
require_once dirname(__DIR__) . '/lib/MailMigrationRuntime.php';
require_once dirname(__DIR__) . '/lib/OpenDkimManager.php';
require_once dirname(__DIR__) . '/lib/ServerDiagnostics.php';

$rootAuditLog = null;
$rootAuditContext = null;

const ROOT_ALLOWED_ACTIONS = [
    'user_create', 'user_update', 'user_toggle', 'user_delete',
    'domain_create', 'domain_update', 'domain_permissions', 'domain_permissions_all', 'domains_toggle', 'domains_delete', 'domain_project_cleanup',
    'database_create', 'database_update', 'databases_toggle', 'databases_delete',
    'mail_domain_create', 'create_mailbox', 'mailbox_update', 'mail_toggle', 'mail_delete', 'mailbox_password',
    'mail_migration_test', 'mail_migration_start',
    'apache_vhosts_rebuild', 'apache_vhosts_remove', 'apache_vhosts_refresh_all', 'apache_vhost_check', 'opendkim_check', 'opendkim_prepare',
    'server_diagnostics',
];

function rootResponse(bool $ok, $data = null, ?string $error = null, ?array $auditError = null): void
{
    global $rootAuditLog, $rootAuditContext;
    $payload = ['ok' => $ok, 'data' => $data, 'error' => $error];
    if ($rootAuditLog instanceof RootAuditLog && is_array($rootAuditContext)) {
        try {
            $rootAuditLog->finish($rootAuditContext, $payload, $auditError);
        } catch (Throwable $logException) {
            fwrite(STDERR, ($error === null ? '' : PHP_EOL) . 'Cannot finish root audit log: ' . $logException->getMessage());
        }
        $rootAuditContext = null;
    }
    $encoded = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    fwrite(STDOUT, $encoded === false ? '{"ok":false,"data":null,"error":"Cannot encode response"}' : $encoded);
    exit($ok ? 0 : 1);
}

function rootFail(string $message, ?Throwable $exception = null): void
{
    $safe = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $message) ?? '');
    if ($safe === '') $safe = 'Root operation failed';
    fwrite(STDERR, $safe);
    rootResponse(false, null, $safe, [
        'type' => $exception !== null ? get_class($exception) : 'RootError',
        'code' => $exception !== null ? $exception->getCode() : 0,
        'message' => $safe,
    ]);
}

function validPrefix(string $prefix): bool
{
    return strpos($prefix, 'usr_') !== 0 && preg_match('/^[a-z][a-z0-9_]{1,31}$/', $prefix) === 1;
}

function requirePrefix(array $params): string
{
    $prefix = mb_strtolower(trim((string) ($params['prefix'] ?? '')));
    if (!validPrefix($prefix)) throw new RuntimeException('Invalid user prefix');
    return $prefix;
}

function validDomain(string $domain): bool
{
    return strlen($domain) <= 253 && preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $domain) === 1;
}

function requireDomain(array $params): string
{
    $domain = mb_strtolower(trim((string) ($params['domain'] ?? '')));
    if (!validDomain($domain)) throw new RuntimeException('Invalid domain');
    return $domain;
}

function apachePhpVersion(string $selected): array
{
    $selected = trim($selected);
    if ($selected === '') $selected = APACHE_DEFAULT_PHP_VERSION;
    foreach (APACHE_PHP_VERSIONS as $version) {
        if (is_array($version) && hash_equals((string) ($version['id'] ?? ''), $selected)) return $version;
    }
    throw new RuntimeException('Invalid PHP version');
}

function requirePhpVersion(array $params): string
{
    $selected = trim((string) ($params['phpVersion'] ?? APACHE_DEFAULT_PHP_VERSION));
    $version = apachePhpVersion($selected);
    return (string) $version['id'];
}

function validMailboxAddress(string $address): bool
{
    if (strlen($address) > 254 || filter_var($address, FILTER_VALIDATE_EMAIL) === false) return false;
    $parts = explode('@', $address, 2);
    return count($parts) === 2 && preg_match('/^[a-z0-9][a-z0-9._+-]{0,63}$/i', $parts[0]) === 1 && validDomain($parts[1]);
}

function requireMailbox(array $params, string $key = 'email'): string
{
    $address = mb_strtolower(trim((string) ($params[$key] ?? '')));
    if (!validMailboxAddress($address)) throw new RuntimeException('Invalid mail address');
    return $address;
}

function expectedUserRoot(string $prefix): string
{
    return rtrim(str_replace('\\', '/', USER_WEB_ROOT_DIRECTORY), '/') . '/' . $prefix;
}

function requireUserRoot(array $params, string $prefix): string
{
    $path = rtrim(str_replace('\\', '/', trim((string) ($params['root_path'] ?? expectedUserRoot($prefix)))), '/');
    if ($path !== expectedUserRoot($prefix)) throw new RuntimeException('Invalid user root path');
    return $path;
}

function safeRelativePath(string $relativePath): string
{
    $relativePath = trim(str_replace('\\', '/', $relativePath), '/');
    if ($relativePath === '' || preg_match('/[\x00\r\n"]/', $relativePath) === 1) throw new RuntimeException('Invalid domain relative path');
    foreach (explode('/', $relativePath) as $part) {
        if ($part === '' || $part === '.' || $part === '..') throw new RuntimeException('Invalid domain relative path');
    }
    return $relativePath;
}

function safeUserPath(string $prefix, string $relativePath): string
{
    return expectedUserRoot($prefix) . '/' . safeRelativePath($relativePath);
}

function assertPathInside(string $path, string $base): void
{
    $path = rtrim(str_replace('\\', '/', $path), '/');
    $base = rtrim(str_replace('\\', '/', $base), '/');
    if ($path === '' || $base === '' || $path === $base || strpos($path, $base . '/') !== 0) throw new RuntimeException('Unsafe filesystem path');
}

function runProcess(array $command, string $stdin = '', ?int $timeoutSeconds = null): array
{
    if ($command === [] || trim((string) $command[0]) === '') throw new RuntimeException('System command is not configured');
    $binary = (string) $command[0];
    if ($binary[0] !== '/' || !is_file($binary) || !is_executable($binary)) throw new RuntimeException('System binary is not executable: ' . $binary);
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), null, ['bypass_shell' => true]);
    if (!is_resource($process)) throw new RuntimeException('Cannot start system command');
    if ($stdin !== '') fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = '';
    $stderr = '';
    $started = microtime(true);
    $timeoutSeconds = $timeoutSeconds === null ? ROOT_COMMAND_TIMEOUT_SECONDS : max(1, $timeoutSeconds);
    $exitCode = -1;
    $timedOut = false;
    while (true) {
        $stdout .= (string) stream_get_contents($pipes[1]);
        $stderr .= (string) stream_get_contents($pipes[2]);
        $status = proc_get_status($process);
        if (!$status['running']) {
            $exitCode = (int) $status['exitcode'];
            break;
        }
        if (microtime(true) - $started >= $timeoutSeconds) {
            $timedOut = true;
            proc_terminate($process);
            usleep(100000);
            $status = proc_get_status($process);
            if ($status['running']) proc_terminate($process, 9);
            break;
        }
        usleep(20000);
    }
    $stdout .= (string) stream_get_contents($pipes[1]);
    $stderr .= (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $closedCode = proc_close($process);
    if ($exitCode < 0 && $closedCode >= 0) $exitCode = $closedCode;
    if ($timedOut) throw new RuntimeException('System command timed out');
    return [$exitCode, trim(substr($stdout, 0, ROOT_RESPONSE_MAX_BYTES)), trim(substr($stderr, 0, ROOT_RESPONSE_MAX_BYTES))];
}

function commandOrFail(array $command, string $stdin = '', string $fallback = 'System command failed'): string
{
    [$exitCode, $stdout, $stderr] = runProcess($command, $stdin);
    if ($exitCode !== 0) throw new RuntimeException($stderr !== '' ? $stderr : ($stdout !== '' ? $stdout : $fallback));
    return $stdout;
}

function openDkimManager(): OpenDkimManager
{
    return OpenDkimManager::fromConfig(static function (): void {
        if (OPENDKIM_SYSTEMCTL_BINARY === '' || !is_executable(OPENDKIM_SYSTEMCTL_BINARY)) {
            throw new RuntimeException('OpenDKIM systemctl command is not available');
        }
        if (!in_array(OPENDKIM_SYSTEMCTL_ACTION, ['reload', 'restart'], true)) {
            throw new RuntimeException('Invalid OPENDKIM_SYSTEMCTL_ACTION');
        }
        commandOrFail(
            [OPENDKIM_SYSTEMCTL_BINARY, OPENDKIM_SYSTEMCTL_ACTION, OPENDKIM_SERVICE_NAME],
            '',
            'Cannot apply OpenDKIM configuration'
        );
    });
}

function withRootLock(string $scope, callable $callback)
{
    $scope = preg_replace('/[^a-z0-9_.-]+/i', '_', $scope) ?? 'operation';
    if (!is_dir(ROOT_LOCK_DIRECTORY) && !mkdir(ROOT_LOCK_DIRECTORY, 0750, true) && !is_dir(ROOT_LOCK_DIRECTORY)) throw new RuntimeException('Cannot create root lock directory');
    @chmod(ROOT_LOCK_DIRECTORY, 0750);
    $path = rtrim(ROOT_LOCK_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $scope . '.lock';
    $handle = fopen($path, 'c+');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        if (is_resource($handle)) fclose($handle);
        throw new RuntimeException('Cannot lock root operation');
    }
    try {
        return $callback();
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function loadUserDocument(string $prefix): array
{
    $path = rtrim(DATA_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $prefix . '.json';
    if (!is_file($path)) throw new RuntimeException('User JSON not found');
    $json = file_get_contents($path);
    $document = $json === false ? null : json_decode($json, true);
    if (!is_array($document) || !is_array($document['profile'] ?? null) || !is_array($document['resources'] ?? null)) throw new RuntimeException('Invalid user JSON');
    if (mb_strtolower((string) ($document['profile']['prefix'] ?? '')) !== $prefix) throw new RuntimeException('User JSON prefix mismatch');
    return $document;
}

function findResource(array $document, string $type, int $id): array
{
    foreach ($document['resources'][$type] ?? [] as $row) {
        if (is_array($row) && (int) ($row['id'] ?? 0) === $id) return $row;
    }
    throw new RuntimeException('Resource not found in user JSON');
}

function documentOwnsDomain(array $document, string $domain): bool
{
    foreach ($document['resources']['domains'] ?? [] as $row) {
        if (is_array($row) && mb_strtolower((string) ($row['domain'] ?? '')) === $domain) return true;
    }
    return false;
}

function requireOwnedDomain(string $prefix, string $domain, bool $allowPending = false): array
{
    $document = loadUserDocument($prefix);
    if (!$allowPending && !documentOwnsDomain($document, $domain)) throw new RuntimeException('Domain does not belong to user');
    return $document;
}

function filesystemIdentity($identity)
{
    if ($identity === null || is_int($identity)) return $identity;

    $identity = trim((string)$identity);
    if ($identity !== '' && preg_match('/^\d+$/D', $identity) === 1) return (int)$identity;

    return $identity;
}

function unixAccountExists(string $prefix): bool
{
    if (WIN || UNIX_ID_BINARY === '' || !is_executable(UNIX_ID_BINARY)) return false;
    [$exitCode] = runProcess([UNIX_ID_BINARY, '-u', $prefix]);
    return $exitCode === 0;
}

function ensureUnixAccount(string $prefix, string $rootPath): array
{
    if (!UNIX_ACCOUNTS_ENABLED) return ['enabled' => false, 'created' => false];
    foreach ([UNIX_ID_BINARY, UNIX_USERADD_BINARY] as $binary) {
        if ($binary === '' || !is_executable($binary)) throw new RuntimeException('UNIX account command is not available');
    }
    $created = false;
    if (!unixAccountExists($prefix)) {
        commandOrFail([
            UNIX_USERADD_BINARY,
            '--home-dir', $rootPath,
            '--shell', UNIX_NOLOGIN_SHELL,
            '--user-group',
            '--no-create-home',
            '--', $prefix,
        ], '', 'Cannot create UNIX account');
        $created = true;
    }
    return ['enabled' => true, 'created' => $created, 'user' => $prefix];
}

function configuredFilesystemOwner(string $prefix): string
{
    return UNIX_ACCOUNTS_ENABLED ? $prefix : (string) USER_WEB_OWNER;
}

function applyConfiguredSystemQuota(string $prefix, float $bytes): array
{
    if (!SYSTEM_QUOTAS_ENABLED) return ['requested' => false, 'active' => false];
    if (!UNIX_ACCOUNTS_ENABLED || SYSTEM_SETQUOTA_BINARY === '' || !is_executable(SYSTEM_SETQUOTA_BINARY) || !is_dir(SYSTEM_QUOTA_MOUNTPOINT)) {
        return ['requested' => true, 'active' => false, 'warning' => 'System quotas are unavailable and were not applied'];
    }
    $blocks = $bytes > 0 ? (int) ceil($bytes / 1024) : 0;
    [$exitCode, $stdout, $stderr] = runProcess([
        SYSTEM_SETQUOTA_BINARY,
        '-u', $prefix,
        (string) $blocks,
        (string) $blocks,
        '0', '0',
        SYSTEM_QUOTA_MOUNTPOINT,
    ]);
    if ($exitCode !== 0) {
        return ['requested' => true, 'active' => false, 'warning' => trim($stderr !== '' ? $stderr : ($stdout !== '' ? $stdout : 'Filesystem quotas are unavailable'))];
    }
    return ['requested' => true, 'active' => true, 'blocks' => $blocks, 'mountpoint' => SYSTEM_QUOTA_MOUNTPOINT];
}

function ensureDirectory(string $path, int $mode, $owner = null, $group = null): void
{
    if (is_link($path)) throw new RuntimeException('Directory path cannot be a symlink');
    if (!is_dir($path) && !@mkdir($path, $mode, true) && !is_dir($path)) throw new RuntimeException('Cannot create directory: ' . $path);
    if (!@chmod($path, $mode)) throw new RuntimeException('Cannot set directory mode: ' . $path);

    $owner = filesystemIdentity($owner);
    $group = filesystemIdentity($group);

    if ($owner !== null && !@chown($path, $owner)) throw new RuntimeException('Cannot set directory owner: ' . $path);
    if ($group !== null && !@chgrp($path, $group)) throw new RuntimeException('Cannot set directory group: ' . $path);
}

function projectLogDirectory(string $prefix, string $documentRoot): string
{
    $publicDirectory = trim(USER_PUBLIC_HTML_DIRECTORY, '/');
    $logDirectory = trim(USER_PHP_LOG_DIRECTORY, '/');
    if ($publicDirectory === '' || basename($documentRoot) !== $publicDirectory) throw new RuntimeException('Invalid public_html path');
    if ($logDirectory === '' || preg_match('/^[a-zA-Z0-9._-]+$/', $logDirectory) !== 1) throw new RuntimeException('Invalid PHP log directory');
    $path = dirname($documentRoot) . '/' . $logDirectory;
    assertPathInside($path, expectedUserRoot($prefix));
    return $path;
}

function projectPhpErrorLog(string $prefix, string $documentRoot): string
{
    return projectLogFile($prefix, $documentRoot, USER_PHP_ERROR_LOG_FILE);
}

function projectLogFile(string $prefix, string $documentRoot, string $file): string
{
    $file = trim($file);
    if ($file === '' || preg_match('/^[a-zA-Z0-9._-]+$/', $file) !== 1) throw new RuntimeException('Invalid project log file');
    return projectLogDirectory($prefix, $documentRoot) . '/' . $file;
}

function ensureUserProjectPath(string $prefix, string $relativePath): string
{
    $relativePath = safeRelativePath($relativePath);
    $root = expectedUserRoot($prefix);
    if (UNIX_ACCOUNTS_ENABLED) ensureUnixAccount($prefix, $root);
    $owner = configuredFilesystemOwner($prefix);
    ensureDirectory($root, USER_ROOT_DIRECTORY_MODE, $owner, USER_WEB_GROUP);
    $current = $root;
    $parts = explode('/', $relativePath);
    foreach ($parts as $index => $part) {
        $current .= '/' . $part;
        $mode = $index === count($parts) - 1 ? USER_PUBLIC_DIRECTORY_MODE : USER_ROOT_DIRECTORY_MODE;
        ensureDirectory($current, $mode, $owner, USER_WEB_GROUP);
    }
    ensureDirectory(projectLogDirectory($prefix, $current), USER_PHP_LOG_DIRECTORY_MODE, $owner, USER_WEB_GROUP);
    return $current;
}

function setProjectOwnershipRecursive(string $prefix, string $relativePath): array
{
    $relativePath = safeRelativePath($relativePath);
    if (basename($relativePath) !== trim(USER_PUBLIC_HTML_DIRECTORY, '/')) {
        throw new RuntimeException('Domain path must end with public_html');
    }
    $path = safeUserPath($prefix, $relativePath);
    assertPathInside($path, expectedUserRoot($prefix));
    if (is_link($path) || !is_dir($path)) throw new RuntimeException('Domain public_html directory not found');

    $owner = (string) filesystemIdentity(configuredFilesystemOwner($prefix));
    $group = (string) filesystemIdentity(USER_WEB_GROUP);
    foreach ([$owner, $group] as $identity) {
        if ($identity === '' || preg_match('/^(?:[a-z_][a-z0-9_.-]*|[0-9]+)$/i', $identity) !== 1) {
            throw new RuntimeException('Invalid Apache filesystem identity');
        }
    }
    if (FILESYSTEM_CHOWN_BINARY === '' || FILESYSTEM_CHOWN_BINARY[0] !== '/') {
        throw new RuntimeException('chown binary is not configured');
    }

    commandOrFail([
        FILESYSTEM_CHOWN_BINARY,
        '-R',
        '--no-dereference',
        $owner . ':' . $group,
        '--',
        $path,
    ], '', 'Cannot set domain directory ownership');

    return ['path' => $path, 'owner' => $owner, 'group' => $group, 'recursive' => true];
}

function repairDomainPermissions(array $params): array
{
    $prefix = requirePrefix($params);
    $document = loadUserDocument($prefix);
    $domain = findResource($document, 'domains', (int) ($params['id'] ?? 0));
    $ownership = setProjectOwnershipRecursive($prefix, (string) ($domain['path'] ?? ''));
    return $ownership + ['prefix' => $prefix, 'domain' => (string) ($domain['domain'] ?? '')];
}

function appendDomainPermissionsIssue(array &$summary, string $prefix, string $domain, string $path, string $error): void
{
    $summary['issuesTotal']++;
    if (count($summary['issues']) >= 100) return;
    $summary['issues'][] = [
        'prefix' => $prefix,
        'domain' => $domain,
        'path' => $path,
        'error' => $error,
    ];
}

function repairAllDomainPermissions(bool $apply): array
{
    $summary = [
        'users' => 0,
        'domains' => 0,
        'paths' => 0,
        'updated' => 0,
        'duplicatePaths' => 0,
        'issuesTotal' => 0,
        'issues' => [],
        'simulated' => !$apply,
    ];
    $seen = [];

    foreach (apacheUserPrefixes() as $prefix) {
        $summary['users']++;
        try {
            $document = loadUserDocument($prefix);
        } catch (Throwable $exception) {
            appendDomainPermissionsIssue($summary, $prefix, '', '', $exception->getMessage());
            continue;
        }

        foreach ($document['resources']['domains'] ?? [] as $domain) {
            if (!is_array($domain)) continue;
            $summary['domains']++;
            $domainName = mb_strtolower(trim((string) ($domain['domain'] ?? '')));
            $configuredPath = trim((string) ($domain['path'] ?? ''));
            try {
                $path = safeRelativePath($configuredPath);
                if (basename($path) !== trim(USER_PUBLIC_HTML_DIRECTORY, '/')) {
                    throw new RuntimeException('Domain path must end with public_html');
                }
                $key = $prefix . "\0" . $path;
                if (isset($seen[$key])) {
                    $summary['duplicatePaths']++;
                    continue;
                }
                $seen[$key] = true;
                $summary['paths']++;

                if ($apply) {
                    setProjectOwnershipRecursive($prefix, $path);
                } else {
                    $absolutePath = safeUserPath($prefix, $path);
                    assertPathInside($absolutePath, expectedUserRoot($prefix));
                }
                $summary['updated']++;
            } catch (Throwable $exception) {
                appendDomainPermissionsIssue($summary, $prefix, $domainName, $configuredPath, $exception->getMessage());
            }
        }
    }

    return $summary;
}

function deleteTree(string $path, string $base): void
{
    assertPathInside($path, $base);
    if (is_link($path) || is_file($path)) {
        if (!unlink($path)) throw new RuntimeException('Cannot remove filesystem entry');
        return;
    }
    if (!is_dir($path)) return;
    $entries = scandir($path);
    if ($entries === false) throw new RuntimeException('Cannot read directory for removal');
    foreach ($entries as $entry) {
        if ($entry !== '.' && $entry !== '..') deleteTree($path . DIRECTORY_SEPARATOR . $entry, $base);
    }
    if (!rmdir($path)) throw new RuntimeException('Cannot remove directory');
}

function ensureConfiguredUserRoot(string $prefix, string $rootPath): array
{
    $account = UNIX_ACCOUNTS_ENABLED ? ensureUnixAccount($prefix, $rootPath) : ['enabled' => false, 'created' => false];
    $owner = configuredFilesystemOwner($prefix);
    ensureDirectory($rootPath, USER_ROOT_DIRECTORY_MODE, $owner, USER_WEB_GROUP);
    return ['rootPath' => $rootPath, 'owner' => $owner, 'group' => USER_WEB_GROUP, 'unixAccount' => $account];
}

function mysqlPdo(): PDO
{
    $dsn = 'mysql:host=' . MYSQL_ADMIN_HOST . ';port=' . MYSQL_ADMIN_PORT . ';charset=utf8mb4';
    return new PDO($dsn, MYSQL_ADMIN_USER, MYSQL_ADMIN_PASSWORD, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
}

function mysqlIdentifier(string $identifier): string
{
    if (preg_match('/^[a-z][a-z0-9_]{1,63}$/', $identifier) !== 1) throw new RuntimeException('Invalid MySQL identifier');
    return '`' . $identifier . '`';
}

function mysqlAccountName(string $database): string
{
    $name = $database;
    if (strlen($name) > MYSQL_CLIENT_USER_MAX_LENGTH) {
        $suffix = '_' . substr(hash('sha256', $name), 0, 8);
        $name = substr($name, 0, MYSQL_CLIENT_USER_MAX_LENGTH - strlen($suffix)) . $suffix;
    }
    if (strlen($name) > MYSQL_CLIENT_USER_MAX_LENGTH || preg_match('/^[a-z][a-z0-9_]{1,31}$/', $name) !== 1) throw new RuntimeException('Invalid MySQL user name');
    return $name;
}

function mysqlAccountSql(PDO $pdo, string $database): string
{
    return $pdo->quote(mysqlAccountName($database)) . '@' . $pdo->quote(MYSQL_CLIENT_USER_HOST);
}

function mysqlUserExists(PDO $pdo, string $database): bool
{
    $statement = $pdo->prepare('SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = ?');
    $statement->execute([mysqlAccountName($database), MYSQL_CLIENT_USER_HOST]);
    return (int) $statement->fetchColumn() > 0;
}

function requireDatabasePassword(array $params): string
{
    $password = (string) ($params['password'] ?? ($params['record']['password'] ?? ''));
    if (strlen($password) < 8
        || strlen($password) > 128
        || preg_match('/[A-Z]/', $password) !== 1
        || preg_match('/[a-z]/', $password) !== 1
        || preg_match('/[0-9]/', $password) !== 1
        || preg_match('/[+\-_)(?%#!,.]/', $password) !== 1) {
        throw new RuntimeException('Invalid database password');
    }
    return $password;
}

function ensureMysqlUser(PDO $pdo, string $database, string $password): array
{
    $exists = mysqlUserExists($pdo, $database);
    $account = mysqlAccountSql($pdo, $database);
    if (!$exists) {
        $pdo->exec('CREATE USER ' . $account . ' IDENTIFIED BY ' . $pdo->quote($password));
    } else {
        $pdo->exec('ALTER USER ' . $account . ' IDENTIFIED BY ' . $pdo->quote($password));
    }
    return ['user' => mysqlAccountName($database), 'created' => !$exists];
}

function requireDatabaseName(string $prefix, array $params): string
{
    $name = mb_strtolower(trim((string) ($params['name'] ?? ($params['record']['name'] ?? ''))));
    if (preg_match('/^' . preg_quote($prefix, '/') . '_[a-z0-9_]{1,48}$/', $name) !== 1 || strlen($name) > 64) throw new RuntimeException('Database name must start with user prefix');
    return $name;
}

function grantDatabase(PDO $pdo, string $database): void
{
    if (!mysqlUserExists($pdo, $database)) throw new RuntimeException('MySQL user does not exist');
    $pdo->exec('GRANT ALL PRIVILEGES ON ' . mysqlIdentifier($database) . '.* TO ' . mysqlAccountSql($pdo, $database));
}

function revokeDatabase(PDO $pdo, string $database): void
{
    if (!mysqlUserExists($pdo, $database)) return;
    try {
        $pdo->exec('REVOKE ALL PRIVILEGES ON ' . mysqlIdentifier($database) . '.* FROM ' . mysqlAccountSql($pdo, $database));
    } catch (PDOException $exception) {
        if (stripos($exception->getMessage(), 'no such grant') === false) throw $exception;
    }
}

function dropDatabaseUser(PDO $pdo, string $database): void
{
    if (mysqlUserExists($pdo, $database)) $pdo->exec('DROP USER ' . mysqlAccountSql($pdo, $database));
}

function legacyMysqlAccountName(string $prefix): string
{
    $name = $prefix . MYSQL_CLIENT_USER_SUFFIX;
    if (strlen($name) > 32 || preg_match('/^[a-z][a-z0-9_]{1,31}$/', $name) !== 1) throw new RuntimeException('Invalid legacy MySQL user name');
    return $name;
}

function legacyMysqlAccountSql(PDO $pdo, string $prefix): string
{
    return $pdo->quote(legacyMysqlAccountName($prefix)) . '@' . $pdo->quote(MYSQL_CLIENT_USER_HOST);
}

function legacyMysqlUserExists(PDO $pdo, string $prefix): bool
{
    $statement = $pdo->prepare('SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = ?');
    $statement->execute([legacyMysqlAccountName($prefix), MYSQL_CLIENT_USER_HOST]);
    return (int) $statement->fetchColumn() > 0;
}

function revokeLegacyDatabase(PDO $pdo, string $prefix, string $database): void
{
    if (!legacyMysqlUserExists($pdo, $prefix)) return;
    try {
        $pdo->exec('REVOKE ALL PRIVILEGES ON ' . mysqlIdentifier($database) . '.* FROM ' . legacyMysqlAccountSql($pdo, $prefix));
    } catch (PDOException $exception) {
        if (stripos($exception->getMessage(), 'no such grant') === false) throw $exception;
    }
}

function createDatabase(array $params): array
{
    $prefix = requirePrefix($params);
    loadUserDocument($prefix);
    $database = requireDatabaseName($prefix, $params);
    $password = requireDatabasePassword($params);
    $pdo = mysqlPdo();
    $pdo->exec('CREATE DATABASE IF NOT EXISTS ' . mysqlIdentifier($database) . ' CHARACTER SET ' . mysqlIdentifier(MYSQL_DATABASE_CHARSET) . ' COLLATE ' . mysqlIdentifier(MYSQL_DATABASE_COLLATION));
    $user = ensureMysqlUser($pdo, $database, $password);
    grantDatabase($pdo, $database);
    revokeLegacyDatabase($pdo, $prefix, $database);
    return ['database' => $database, 'user' => $user['user'], 'created' => true];
}

function updateDatabase(array $params): array
{
    $prefix = requirePrefix($params);
    $database = requireDatabaseName($prefix, $params);
    $old = findResource(loadUserDocument($prefix), 'databases', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($old['name'] ?? '')) !== $database) throw new RuntimeException('Database rename is not supported');
    $password = requireDatabasePassword($params);
    $pdo = mysqlPdo();
    $statement = $pdo->prepare('SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?');
    $statement->execute([$database]);
    if ((int) $statement->fetchColumn() === 0) throw new RuntimeException('Database does not exist');
    $user = ensureMysqlUser($pdo, $database, $password);
    grantDatabase($pdo, $database);
    revokeLegacyDatabase($pdo, $prefix, $database);
    return ['database' => $database, 'user' => $user['user'], 'updated' => true];
}

function toggleDatabase(array $params): array
{
    $prefix = requirePrefix($params);
    $record = is_array($params['record'] ?? null) ? $params['record'] : [];
    $database = requireDatabaseName($prefix, ['record' => $record]);
    $stored = findResource(loadUserDocument($prefix), 'databases', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($stored['name'] ?? '')) !== $database) throw new RuntimeException('Database does not belong to user resource');
    $enable = empty($record['active']);
    $pdo = mysqlPdo();
    if ($enable) {
        ensureMysqlUser($pdo, $database, requireDatabasePassword(['record' => $record]));
        grantDatabase($pdo, $database);
        revokeLegacyDatabase($pdo, $prefix, $database);
    } else {
        revokeDatabase($pdo, $database);
        revokeLegacyDatabase($pdo, $prefix, $database);
    }
    return ['database' => $database, 'active' => $enable];
}

function deleteDatabase(array $params): array
{
    $prefix = requirePrefix($params);
    $record = is_array($params['record'] ?? null) ? $params['record'] : [];
    $database = requireDatabaseName($prefix, ['record' => $record]);
    $stored = findResource(loadUserDocument($prefix), 'databases', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($stored['name'] ?? '')) !== $database) throw new RuntimeException('Database does not belong to user resource');
    $pdo = mysqlPdo();
    $pdo->exec('DROP DATABASE IF EXISTS ' . mysqlIdentifier($database));
    dropDatabaseUser($pdo, $database);
    return ['database' => $database, 'deleted' => true];
}

function postfixPdo(): PDO
{
    $dsn = 'mysql:host=' . POSTFIXADMIN_DB_HOST . ';port=' . POSTFIXADMIN_DB_PORT . ';dbname=' . POSTFIXADMIN_DB_NAME . ';charset=utf8mb4';
    return new PDO($dsn, POSTFIXADMIN_DB_USER, POSTFIXADMIN_DB_PASSWORD, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
}

function postfixTable(string $table): string
{
    if (preg_match('/^[a-zA-Z0-9_]+$/', $table) !== 1) throw new RuntimeException('Invalid PostfixAdmin table name');
    return '`' . $table . '`';
}

function postfixColumns(PDO $pdo, string $table): array
{
    static $cache = [];
    $key = POSTFIXADMIN_DB_NAME . '.' . $table;
    if (isset($cache[$key])) return $cache[$key];
    $statement = $pdo->prepare('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?');
    $statement->execute([POSTFIXADMIN_DB_NAME, $table]);
    $columns = [];
    foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $column) $columns[(string) $column] = true;
    if ($columns === []) throw new RuntimeException('PostfixAdmin table not found: ' . $table);
    $cache[$key] = $columns;
    return $columns;
}

function postfixUpsert(PDO $pdo, string $table, array $keys, array $values): void
{
    $columns = postfixColumns($pdo, $table);
    foreach ($keys as $key => $value) if (!isset($columns[$key])) throw new RuntimeException('Required PostfixAdmin column not found: ' . $key);
    $filtered = [];
    foreach ($values as $column => $value) if (isset($columns[$column])) $filtered[$column] = $value;
    $where = implode(' AND ', array_map(static function (string $column): string { return '`' . $column . '` = ?'; }, array_keys($keys)));
    $check = $pdo->prepare('SELECT COUNT(*) FROM ' . postfixTable($table) . ' WHERE ' . $where);
    $check->execute(array_values($keys));
    if ((int) $check->fetchColumn() > 0) {
        $updates = array_diff_key($filtered, $keys);
        unset($updates['created']);
        if ($updates === []) return;
        $set = implode(', ', array_map(static function (string $column): string { return '`' . $column . '` = ?'; }, array_keys($updates)));
        $statement = $pdo->prepare('UPDATE ' . postfixTable($table) . ' SET ' . $set . ' WHERE ' . $where);
        $statement->execute(array_merge(array_values($updates), array_values($keys)));
        return;
    }
    $insert = $keys + $filtered;
    $names = implode(', ', array_map(static function (string $column): string { return '`' . $column . '`'; }, array_keys($insert)));
    $placeholders = implode(', ', array_fill(0, count($insert), '?'));
    $statement = $pdo->prepare('INSERT INTO ' . postfixTable($table) . ' (' . $names . ') VALUES (' . $placeholders . ')');
    $statement->execute(array_values($insert));
}

function postfixDelete(PDO $pdo, string $table, array $keys): void
{
    $columns = postfixColumns($pdo, $table);
    foreach (array_keys($keys) as $column) if (!isset($columns[$column])) throw new RuntimeException('Required PostfixAdmin column not found: ' . $column);
    $where = implode(' AND ', array_map(static function (string $column): string { return '`' . $column . '` = ?'; }, array_keys($keys)));
    $statement = $pdo->prepare('DELETE FROM ' . postfixTable($table) . ' WHERE ' . $where);
    $statement->execute(array_values($keys));
}

function ensureMailDomain(PDO $pdo, string $domain, bool $active = true, float $quotaBytes = 0): void
{
    $now = gmdate('Y-m-d H:i:s');
    $quota = (int) max(0, ceil($quotaBytes / max(1, POSTFIXADMIN_QUOTA_DIVISOR)));
    postfixUpsert($pdo, POSTFIXADMIN_DOMAIN_TABLE, ['domain' => $domain], ['description' => 'Managed by ImagoPanel', 'aliases' => POSTFIXADMIN_DOMAIN_ALIAS_LIMIT, 'mailboxes' => POSTFIXADMIN_DOMAIN_MAILBOX_LIMIT, 'maxquota' => $quota, 'quota' => $quota, 'transport' => '', 'backupmx' => 0, 'active' => $active ? 1 : 0, 'created' => $now, 'modified' => $now]);
}

function createMailDomain(array $params): array
{
    $prefix = requirePrefix($params);
    $domain = requireDomain($params);
    $document = requireOwnedDomain($prefix, $domain, !empty($params['pending_domain']));
    $quota = (float) ($document['profile']['mailQuotaBytes'] ?? 0);
    $forwardTo = mailboxForwarding($params, 'info@' . $domain);
    if (count($forwardTo) > 1) throw new RuntimeException('Only one whole-domain forwarding address is allowed');
    if ($forwardTo !== [] && substr($forwardTo[0], strrpos($forwardTo[0], '@') + 1) === $domain) {
        throw new RuntimeException('Whole-domain forwarding cannot point to the same domain');
    }
    $pdo = postfixPdo();
    $pdo->beginTransaction();
    try {
        ensureMailDomain($pdo, $domain, true, $quota);
        if ($forwardTo !== []) {
            $source = '@' . $domain;
            $columns = postfixColumns($pdo, POSTFIXADMIN_ALIAS_TABLE);
            if (!isset($columns['address'], $columns['goto'])) throw new RuntimeException('Required PostfixAdmin alias columns not found');
            $statement = $pdo->prepare('SELECT `goto` FROM ' . postfixTable(POSTFIXADMIN_ALIAS_TABLE) . ' WHERE `address` = ? LIMIT 1');
            $statement->execute([$source]);
            $stored = $statement->fetchColumn();
            if ($stored !== false && mb_strtolower(trim((string) $stored)) !== $forwardTo[0]) {
                throw new RuntimeException('Catch-all already exists for domain: ' . $domain);
            }
            $now = gmdate('Y-m-d H:i:s');
            postfixUpsert($pdo, POSTFIXADMIN_ALIAS_TABLE, ['address' => $source], ['goto' => $forwardTo[0], 'domain' => $domain, 'active' => 1, 'created' => $now, 'modified' => $now]);
        }
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $exception;
    }
    return ['domain' => $domain, 'forwardTo' => $forwardTo, 'created' => true];
}

/**
 * Generate or update a compatible hash manually:
 *   doveadm pw -s SHA512-CRYPT -p 'NEW_PASSWORD'
 * The plaintext password exists only in process memory and is never written to responses or logs.
 */
function postfixPasswordHash(string $password): string
{
    if ($password === '' || preg_match('/[\x00\r\n]/', $password) === 1) throw new RuntimeException('Invalid mailbox password');
    if (strtoupper(POSTFIXADMIN_PASSWORD_SCHEME) !== 'SHA512-CRYPT') throw new RuntimeException('Unsupported PostfixAdmin password scheme');
    $salt = rtrim(strtr(base64_encode(random_bytes(12)), '+/', '._'), '=');
    $hash = crypt($password, '$6$rounds=5000$' . $salt . '$');
    if (!is_string($hash) || strpos($hash, '$6$') !== 0) throw new RuntimeException('Cannot create mailbox password hash');
    return '{SHA512-CRYPT}' . $hash;
}

function mailboxParts(string $address): array
{
    if (!validMailboxAddress($address)) throw new RuntimeException('Invalid mail address');
    return explode('@', $address, 2);
}

function mailboxForwarding(array $params, string $address): array
{
    $input = $params['forwardTo'] ?? [];
    if (!is_array($input)) $input = preg_split('/[\s,;]+/u', trim((string) $input), -1, PREG_SPLIT_NO_EMPTY);
    $recipients = [];
    foreach ($input ?: [] as $candidate) {
        $recipient = mb_strtolower(trim((string) $candidate));
        if ($recipient === '') continue;
        if (!validMailboxAddress($recipient)) throw new RuntimeException('Invalid forwarding address: ' . $recipient);
        if ($recipient !== $address) $recipients[$recipient] = true;
    }
    return array_keys($recipients);
}

function mailboxAliases(array $params, string $address): array
{
    [, $domain] = mailboxParts($address);
    $input = $params['aliases'] ?? [];
    if (!is_array($input)) $input = preg_split('/[\s,;]+/u', trim((string) $input), -1, PREG_SPLIT_NO_EMPTY);
    $aliases = [];
    foreach ($input ?: [] as $candidate) {
        $alias = mb_strtolower(trim((string) $candidate));
        if ($alias === '') continue;
        if (strpos($alias, '@') === false) $alias .= '@' . $domain;
        if (!validMailboxAddress($alias) || substr($alias, strrpos($alias, '@') + 1) !== $domain) throw new RuntimeException('Invalid mailbox alias: ' . $alias);
        if ($alias !== $address) $aliases[$alias] = true;
    }
    return array_keys($aliases);
}

function managedMailboxAliasSources(string $address, array $aliases, bool $catchAll): array
{
    [, $domain] = mailboxParts($address);
    $managed = [$address => true];
    foreach ($aliases as $alias) $managed[(string) $alias] = true;
    if ($catchAll) $managed['@' . $domain] = true;
    return array_keys($managed);
}

function deleteManagedMailboxAliases(PDO $pdo, string $address, array $aliases, bool $catchAll): void
{
    foreach (managedMailboxAliasSources($address, $aliases, $catchAll) as $source) {
        postfixDelete($pdo, POSTFIXADMIN_ALIAS_TABLE, ['address' => $source]);
    }
}

function upsertMailboxRouting(PDO $pdo, string $address, array $aliases, array $forwardTo, bool $catchAll, bool $active): void
{
    [, $domain] = mailboxParts($address);
    $now = gmdate('Y-m-d H:i:s');
    $targets = array_merge([$address], $forwardTo);
    postfixUpsert($pdo, POSTFIXADMIN_ALIAS_TABLE, ['address' => $address], ['goto' => implode(',', $targets), 'domain' => $domain, 'active' => $active ? 1 : 0, 'created' => $now, 'modified' => $now]);
    foreach ($aliases as $alias) {
        postfixUpsert($pdo, POSTFIXADMIN_ALIAS_TABLE, ['address' => $alias], ['goto' => $address, 'domain' => $domain, 'active' => $active ? 1 : 0, 'created' => $now, 'modified' => $now]);
    }
    if ($catchAll) {
        postfixUpsert($pdo, POSTFIXADMIN_ALIAS_TABLE, ['address' => '@' . $domain], ['goto' => $address, 'domain' => $domain, 'active' => $active ? 1 : 0, 'created' => $now, 'modified' => $now]);
    }
}

function assertMailboxAliasSourcesAvailable(PDO $pdo, string $address, array $aliases, bool $catchAll, array $replaceable = []): void
{
    $columns = postfixColumns($pdo, POSTFIXADMIN_ALIAS_TABLE);
    if (!isset($columns['address'], $columns['goto'])) throw new RuntimeException('Required PostfixAdmin alias columns not found');
    $statement = $pdo->prepare('SELECT `goto` FROM ' . postfixTable(POSTFIXADMIN_ALIAS_TABLE) . ' WHERE `address` = ? LIMIT 1');
    foreach (managedMailboxAliasSources($address, $aliases, $catchAll) as $source) {
        $statement->execute([$source]);
        $storedTargets = $statement->fetchColumn();
        if ($storedTargets === false || in_array($source, $replaceable, true)) continue;
        $targets = preg_split('/\s*,\s*/', mb_strtolower((string) $storedTargets), -1, PREG_SPLIT_NO_EMPTY);
        if (!in_array($address, $targets ?: [], true)) throw new RuntimeException('Mailbox alias already exists: ' . $source);
    }
}

function mailboxPath(string $address): string
{
    [$local, $domain] = mailboxParts($address);
    return rtrim(MAIL_STORAGE_DIRECTORY, '/') . '/' . $domain . '/' . $local;
}

function ensureMaildir(string $address): string
{
    $path = mailboxPath($address);
    assertPathInside($path, MAIL_STORAGE_DIRECTORY);
    ensureDirectory(dirname($path), MAIL_STORAGE_MAILBOX_MODE, MAIL_STORAGE_OWNER, MAIL_STORAGE_GROUP);
    ensureDirectory($path, MAIL_STORAGE_MAILBOX_MODE, MAIL_STORAGE_OWNER, MAIL_STORAGE_GROUP);
    foreach (['cur', 'new', 'tmp'] as $folder) ensureDirectory($path . '/' . $folder, MAIL_STORAGE_MAILBOX_MODE, MAIL_STORAGE_OWNER, MAIL_STORAGE_GROUP);
    return $path;
}

function mailboxStoredPassword(PDO $pdo, string $address): ?string
{
    $columns = postfixColumns($pdo, POSTFIXADMIN_MAILBOX_TABLE);
    if (!isset($columns['username'], $columns['password'])) throw new RuntimeException('Required mailbox columns not found');
    $statement = $pdo->prepare('SELECT `password` FROM ' . postfixTable(POSTFIXADMIN_MAILBOX_TABLE) . ' WHERE `username` = ? LIMIT 1');
    $statement->execute([$address]);
    $value = $statement->fetchColumn();
    return $value === false ? null : (string) $value;
}

function upsertMailbox(PDO $pdo, string $address, float $quotaBytes, float $domainQuotaBytes, bool $active, ?string $passwordHash): void
{
    [$local, $domain] = mailboxParts($address);
    $now = gmdate('Y-m-d H:i:s');
    ensureMailDomain($pdo, $domain, true, $domainQuotaBytes);
    $values = ['name' => $local, 'maildir' => $domain . '/' . $local . '/', 'quota' => (int) max(0, ceil($quotaBytes / max(1, POSTFIXADMIN_QUOTA_DIVISOR))), 'local_part' => $local, 'domain' => $domain, 'active' => $active ? 1 : 0, 'created' => $now, 'modified' => $now];
    if ($passwordHash !== null) $values['password'] = $passwordHash;
    postfixUpsert($pdo, POSTFIXADMIN_MAILBOX_TABLE, ['username' => $address], $values);
}

function createMailbox(array $params): array
{
    $prefix = requirePrefix($params);
    $address = requireMailbox($params);
    $domain = requireDomain($params);
    if (substr($address, strrpos($address, '@') + 1) !== $domain) throw new RuntimeException('Mailbox domain mismatch');
    $document = requireOwnedDomain($prefix, $domain, !empty($params['pending_domain']));
    $password = (string) ($params['password'] ?? '');
    $aliases = mailboxAliases($params, $address);
    $forwardTo = mailboxForwarding($params, $address);
    $catchAll = !empty($params['catchAll']);
    $quota = max(1048576, (float) ($params['quotaBytes'] ?? IMPORT_MAIL_DEFAULT_QUOTA_MB * 1048576));
    $domainQuota = max($quota, (float) ($document['profile']['mailQuotaBytes'] ?? $quota));
    $pdo = postfixPdo();
    $pdo->beginTransaction();
    try {
        assertMailboxAliasSourcesAvailable($pdo, $address, $aliases, $catchAll);
        upsertMailbox($pdo, $address, $quota, $domainQuota, true, postfixPasswordHash($password));
        upsertMailboxRouting($pdo, $address, $aliases, $forwardTo, $catchAll, true);
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $exception;
    }
    return ['email' => $address, 'aliases' => $aliases, 'forwardTo' => $forwardTo, 'catchAll' => $catchAll, 'maildir' => ensureMaildir($address), 'created' => true];
}

function updateMailbox(array $params): array
{
    $prefix = requirePrefix($params);
    assertNoActiveMailMigration($prefix, (int) ($params['id'] ?? 0));
    $address = requireMailbox($params);
    $old = findResource(loadUserDocument($prefix), 'mail', (int) ($params['id'] ?? 0));
    $oldAddress = mb_strtolower((string) ($old['address'] ?? ''));
    if (!validMailboxAddress($oldAddress)) throw new RuntimeException('Invalid old mail address');
    $oldAliases = mailboxAliases($old, $oldAddress);
    $oldCatchAll = !empty($old['catchAll']);
    $aliases = mailboxAliases($params, $address);
    $forwardTo = mailboxForwarding($params, $address);
    $catchAll = !empty($params['catchAll']);
    $domain = substr($address, strrpos($address, '@') + 1);
    $document = requireOwnedDomain($prefix, $domain);
    $quota = max(1048576, (float) ($params['quotaBytes'] ?? ($old['quotaBytes'] ?? IMPORT_MAIL_DEFAULT_QUOTA_MB * 1048576)));
    $domainQuota = max($quota, (float) ($document['profile']['mailQuotaBytes'] ?? $quota));
    $pdo = postfixPdo();
    $password = (string) ($params['password'] ?? '');
    $hash = $password !== '' ? postfixPasswordHash($password) : mailboxStoredPassword($pdo, $oldAddress);
    if ($hash === null) throw new RuntimeException('Existing mailbox password not found');
    $oldPath = mailboxPath($oldAddress);
    $newPath = mailboxPath($address);
    $moved = false;
    if ($oldPath !== $newPath && is_dir($oldPath)) {
        ensureDirectory(dirname($newPath), MAIL_STORAGE_MAILBOX_MODE, MAIL_STORAGE_OWNER, MAIL_STORAGE_GROUP);
        if (file_exists($newPath) || !rename($oldPath, $newPath)) throw new RuntimeException('Cannot move mailbox directory');
        $moved = true;
    }
    $pdo->beginTransaction();
    try {
        $oldManagedSources = managedMailboxAliasSources($oldAddress, $oldAliases, $oldCatchAll);
        assertMailboxAliasSourcesAvailable($pdo, $address, $aliases, $catchAll, $oldManagedSources);
        deleteManagedMailboxAliases($pdo, $oldAddress, $oldAliases, $oldCatchAll);
        if ($oldAddress !== $address) {
            postfixDelete($pdo, POSTFIXADMIN_MAILBOX_TABLE, ['username' => $oldAddress]);
        }
        upsertMailbox($pdo, $address, $quota, $domainQuota, !array_key_exists('active', $params) || !empty($params['active']), $hash);
        upsertMailboxRouting($pdo, $address, $aliases, $forwardTo, $catchAll, !array_key_exists('active', $params) || !empty($params['active']));
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        if ($moved && !file_exists($oldPath)) @rename($newPath, $oldPath);
        throw $exception;
    }
    ensureMaildir($address);
    return ['email' => $address, 'aliases' => $aliases, 'forwardTo' => $forwardTo, 'catchAll' => $catchAll, 'updated' => true];
}

function toggleMailbox(array $params): array
{
    $prefix = requirePrefix($params);
    assertNoActiveMailMigration($prefix, (int) ($params['id'] ?? 0));
    $record = is_array($params['record'] ?? null) ? $params['record'] : [];
    $address = requireMailbox(['email' => $record['address'] ?? '']);
    $stored = findResource(loadUserDocument($prefix), 'mail', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($stored['address'] ?? '')) !== $address) throw new RuntimeException('Mailbox does not belong to user resource');
    $active = empty($record['active']);
    $aliases = mailboxAliases($stored, $address);
    $catchAll = !empty($stored['catchAll']);
    $pdo = postfixPdo();
    $pdo->beginTransaction();
    try {
        $mailboxColumns = postfixColumns($pdo, POSTFIXADMIN_MAILBOX_TABLE);
        if (isset($mailboxColumns['active'], $mailboxColumns['username'])) {
            $statement = $pdo->prepare('UPDATE ' . postfixTable(POSTFIXADMIN_MAILBOX_TABLE) . ' SET `active` = ? WHERE `username` = ?');
            $statement->execute([$active ? 1 : 0, $address]);
        }
        $aliasColumns = postfixColumns($pdo, POSTFIXADMIN_ALIAS_TABLE);
        if (isset($aliasColumns['active'], $aliasColumns['address'])) {
            $statement = $pdo->prepare('UPDATE ' . postfixTable(POSTFIXADMIN_ALIAS_TABLE) . ' SET `active` = ? WHERE `address` = ?');
            foreach (managedMailboxAliasSources($address, $aliases, $catchAll) as $source) $statement->execute([$active ? 1 : 0, $source]);
        }
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $exception;
    }
    return ['email' => $address, 'active' => $active];
}

function deleteMailbox(array $params): array
{
    $prefix = requirePrefix($params);
    assertNoActiveMailMigration($prefix, (int) ($params['id'] ?? 0));
    $record = is_array($params['record'] ?? null) ? $params['record'] : [];
    $address = requireMailbox(['email' => $record['address'] ?? '']);
    $stored = findResource(loadUserDocument($prefix), 'mail', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($stored['address'] ?? '')) !== $address) throw new RuntimeException('Mailbox does not belong to user resource');
    $pdo = postfixPdo();
    $aliases = mailboxAliases($stored, $address);
    $catchAll = !empty($stored['catchAll']);
    $pdo->beginTransaction();
    try {
        deleteManagedMailboxAliases($pdo, $address, $aliases, $catchAll);
        postfixDelete($pdo, POSTFIXADMIN_MAILBOX_TABLE, ['username' => $address]);
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $exception;
    }
    $path = mailboxPath($address);
    if (file_exists($path)) deleteTree($path, MAIL_STORAGE_DIRECTORY);
    return ['email' => $address, 'deleted' => true];
}

function changeMailboxPassword(array $params): array
{
    $prefix = requirePrefix($params);
    $address = requireMailbox($params);
    $found = false;
    $mailboxId = 0;
    foreach (loadUserDocument($prefix)['resources']['mail'] ?? [] as $row) {
        if (mb_strtolower((string) ($row['address'] ?? '')) === $address) {
            $found = true;
            $mailboxId = (int) ($row['id'] ?? 0);
            break;
        }
    }
    if (!$found) throw new RuntimeException('Mailbox does not belong to user');
    assertNoActiveMailMigration($prefix, $mailboxId);
    $hash = postfixPasswordHash((string) ($params['password'] ?? ''));
    $pdo = postfixPdo();
    $columns = postfixColumns($pdo, POSTFIXADMIN_MAILBOX_TABLE);
    if (!isset($columns['username'], $columns['password'])) throw new RuntimeException('Required mailbox columns not found');
    $statement = $pdo->prepare('UPDATE ' . postfixTable(POSTFIXADMIN_MAILBOX_TABLE) . ' SET `password` = ? WHERE `username` = ?');
    $statement->execute([$hash, $address]);
    if ($statement->rowCount() === 0 && mailboxStoredPassword($pdo, $address) === null) throw new RuntimeException('Mailbox not found in PostfixAdmin');
    return ['email' => $address, 'passwordChanged' => true];
}

function mailMigrationStore(): MailMigrationStore
{
    return MailMigrationStore::configured();
}

function assertNoActiveMailMigration(string $prefix, int $mailboxId): void
{
    if (!MAIL_MIGRATION_ENABLED || $mailboxId <= 0) return;
    if (mailMigrationStore()->hasActive($prefix, $mailboxId)) {
        throw new RuntimeException('An active mail migration is currently running');
    }
}

function mailMigrationMailbox(array $params): array
{
    $prefix = requirePrefix($params);
    $mailboxId = (int) ($params['mailbox_id'] ?? 0);
    if ($mailboxId <= 0) throw new InvalidArgumentException('Invalid destination mailbox');
    $mailbox = findResource(loadUserDocument($prefix), 'mail', $mailboxId);
    $address = requireMailbox(['email' => $mailbox['address'] ?? '']);
    $password = (string) ($mailbox['password'] ?? '');
    if ($password === '' || preg_match('/[\x00\r\n]/', $password) === 1) {
        throw new RuntimeException('Set and save the destination mailbox password before importing old mail');
    }
    return ['prefix' => $prefix, 'mailbox_id' => $mailboxId, 'address' => $address, 'password' => $password];
}

function mailMigrationAnalyzeOutput(string $output): array
{
    $progress = mailMigrationProgressFromLog([
        'status' => 'ready', 'folders_total' => 0, 'folders_done' => 0,
        'messages_total' => 0, 'messages_done' => 0, 'bytes_total' => 0,
        'bytes_done' => 0, 'skipped_count' => 0, 'errors_count' => 0,
    ], $output);
    return [
        'status' => 'ready',
        'folders' => (int) ($progress['folders_total'] ?? 0),
        'messages' => (int) ($progress['messages_total'] ?? 0),
        'bytes' => (float) ($progress['bytes_total'] ?? 0),
        'destinationAvailable' => true,
    ];
}

function testMailMigration(array $params): array
{
    $source = MailMigrationRuntime::validateSource($params);
    $destination = mailMigrationMailbox($params);
    if (!PROD) {
        return ['available' => false, 'status' => 'failed', 'error' => 'imapsync connection tests run only on TASK/PROD Linux'];
    }
    MailMigrationRuntime::assertDependencies();
    MailMigrationRuntime::ensureDirectories();
    $id = bin2hex(random_bytes(16));
    [$sourceFile, $destinationFile] = MailMigrationRuntime::writeCredentials($id, $source['source_password'], $destination['password']);
    try {
        $job = $source + ['id' => $id, 'destination_email' => $destination['address']];
        [$exitCode, $stdout, $stderr] = runProcess(
            MailMigrationRuntime::command($job, $sourceFile, $destinationFile, true),
            '',
            MAIL_MIGRATION_TEST_TIMEOUT_SECONDS
        );
        $output = trim($stdout . PHP_EOL . $stderr);
        if ($exitCode !== 0) throw new RuntimeException(MailMigrationRuntime::friendlyError($output));
        return ['available' => true] + mailMigrationAnalyzeOutput($output);
    } finally {
        MailMigrationRuntime::removeCredentials($id);
        MailMigrationRuntime::removeTemporaryDirectory($id);
    }
}

function startMailMigration(array $params): array
{
    if (!PROD) throw new RuntimeException('Background mail migration is available only on TASK/PROD Linux');
    $source = MailMigrationRuntime::validateSource($params);
    $destination = mailMigrationMailbox($params);
    MailMigrationRuntime::assertBackgroundDependencies();
    MailMigrationRuntime::ensureDirectories();
    $store = mailMigrationStore();
    if ($store->hasActive($destination['prefix'], $destination['mailbox_id'])) {
        throw new RuntimeException('An active mail migration is already running for this mailbox');
    }
    $id = bin2hex(random_bytes(16));
    $job = $store->create([
        'id' => $id,
        'user_prefix' => $destination['prefix'],
        'mailbox_id' => $destination['mailbox_id'],
        'destination_email' => $destination['address'],
        'source_host' => $source['source_host'],
        'source_port' => $source['source_port'],
        'source_security' => $source['source_security'],
        'source_login' => $source['source_login'],
        'status' => 'pending',
        'log_file' => $id . '.log',
        'report_file' => $id . '.json',
    ]);
    try {
        MailMigrationRuntime::writeCredentials($id, $source['source_password'], $destination['password']);
        $command = [
            MAIL_MIGRATION_SYSTEMD_RUN_BINARY,
            '--quiet',
            '--unit=imagopanel-mail-migration-' . $id,
            MAIL_MIGRATION_PHP_BINARY,
            dirname(__DIR__) . '/root/mail_migration_worker.php',
            '--prod',
            '--job=' . $id,
        ];
        [$exitCode, $stdout, $stderr] = runProcess($command, '', 20);
        if ($exitCode !== 0) throw new RuntimeException('Cannot start background mail import. Check systemd-run configuration.');
    } catch (Throwable $exception) {
        MailMigrationRuntime::removeCredentials($id);
        $store->update($id, [
            'status' => 'failed', 'errors_count' => 1, 'error_message' => $exception->getMessage(),
            'finished_at' => gmdate('Y-m-d H:i:s'),
        ]);
        throw $exception;
    }
    return $store->publicRow($job);
}

function provisionDomain(array $params, bool $update = false): array
{
    $prefix = requirePrefix($params);
    $domain = requireDomain($params);
    $document = loadUserDocument($prefix);
    $phpVersion = requirePhpVersion($params);
    $previousDomain = null;
    if ($update) {
        $stored = findResource($document, 'domains', (int) ($params['id'] ?? 0));
        $storedDomain = mb_strtolower(trim((string) ($stored['domain'] ?? '')));
        if (validDomain($storedDomain)) $previousDomain = $storedDomain;
    }
    $projectPath = ensureUserProjectPath($prefix, (string) ($params['path'] ?? ''));
    $ownership = setProjectOwnershipRecursive($prefix, (string) ($params['path'] ?? ''));
    $dkim = openDkimManager()->activate($domain, $previousDomain);
    return [
        'domain' => $domain,
        'path' => $projectPath,
        'ownership' => $ownership,
        'phpVersion' => $phpVersion,
        'ssl' => !empty($params['ssl']),
        'certificateDeferredUntilVhost' => !empty($params['ssl']),
        'dkim' => $dkim,
    ];
}

function toggleDomain(array $params): array
{
    $prefix = requirePrefix($params);
    $record = is_array($params['record'] ?? null) ? $params['record'] : [];
    $domain = requireDomain($record);
    $stored = findResource(loadUserDocument($prefix), 'domains', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($stored['domain'] ?? '')) !== $domain) throw new RuntimeException('Domain does not belong to user resource');
    if (empty($record['active'])) return provisionDomain($record + ['prefix' => $prefix], true) + ['active' => true];
    $dkim = openDkimManager()->remove($domain);
    return ['domain' => $domain, 'active' => false, 'filesystemPreserved' => true, 'dkim' => $dkim];
}

function deleteDomain(array $params): array
{
    $prefix = requirePrefix($params);
    $record = is_array($params['record'] ?? null) ? $params['record'] : [];
    $domain = requireDomain($record);
    $stored = findResource(loadUserDocument($prefix), 'domains', (int) ($params['id'] ?? 0));
    if (mb_strtolower((string) ($stored['domain'] ?? '')) !== $domain) throw new RuntimeException('Domain does not belong to user resource');
    $dkim = openDkimManager()->remove($domain);
    return ['domain' => $domain, 'deleted' => true, 'filesystemPreserved' => true, 'certificatePreserved' => true, 'dkim' => $dkim];
}

function cleanupUnusedDomainProject(array $params): array
{
    $prefix = requirePrefix($params);
    $relativePath = safeRelativePath((string) ($params['path'] ?? ''));
    $publicDirectory = trim(USER_PUBLIC_HTML_DIRECTORY, '/');
    if ($publicDirectory === '' || basename($relativePath) !== $publicDirectory) {
        throw new RuntimeException('Domain path must end with public_html');
    }

    $projectRelativePath = trim(str_replace('\\', '/', dirname($relativePath)), '/');
    if ($projectRelativePath === '' || $projectRelativePath === '.') {
        throw new RuntimeException('Cannot remove the user root directory');
    }

    $document = loadUserDocument($prefix);
    $projectPrefix = $projectRelativePath . '/';
    foreach ($document['resources']['domains'] ?? [] as $domain) {
        if (!is_array($domain)) continue;
        $otherPath = safeRelativePath((string) ($domain['path'] ?? ''));
        if ($otherPath === $relativePath || strpos($otherPath, $projectPrefix) === 0) {
            return [
                'path' => $projectRelativePath,
                'deleted' => false,
                'preserved' => true,
                'reason' => 'used_by_another_domain',
            ];
        }
    }

    $projectPath = safeUserPath($prefix, $projectRelativePath);
    assertPathInside($projectPath, expectedUserRoot($prefix));
    if (!file_exists($projectPath) && !is_link($projectPath)) {
        return ['path' => $projectRelativePath, 'deleted' => false, 'preserved' => false, 'reason' => 'not_found'];
    }
    deleteTree($projectPath, expectedUserRoot($prefix));
    return ['path' => $projectRelativePath, 'deleted' => true, 'preserved' => false];
}

function dnsAddresses(string $domain): array
{
    $values = gethostbynamel($domain);
    return $values === false ? [] : array_values(array_unique(array_filter($values, static function ($value): bool { return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false; })));
}

function assertHostingDns(string $domain): void
{
    if (!CERTBOT_REQUIRE_HOSTING_DNS) return;
    $hostingIps = array_values(array_filter(STATS_HOSTING_PUBLIC_IPS, static function ($ip): bool { return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false; }));
    if ($hostingIps === []) throw new RuntimeException('Hosting public IPs are not configured');
    if (array_intersect(dnsAddresses($domain), $hostingIps) === []) throw new RuntimeException('Domain does not point to this hosting: ' . $domain);
}

function ensureCertificate(string $prefix, string $domain, string $webRoot, bool $includeWww): array
{
    assertHostingDns($domain);
    if ($includeWww) assertHostingDns('www.' . $domain);
    $webRoot = rtrim($webRoot, '/') . '/';
    $owner = configuredFilesystemOwner($prefix);
    ensureDirectory($webRoot . '.well-known', 0755, $owner, USER_WEB_GROUP);
    ensureDirectory($webRoot . '.well-known/acme-challenge', 0755, $owner, USER_WEB_GROUP);

    if (CERTBOT_DRY_RUN_FIRST) certbotOrFail(certbotCommand($domain, $webRoot, $includeWww, true), 'dry-run');
    certbotOrFail(certbotCommand($domain, $webRoot, $includeWww, false), 'production');
    $certificate = str_replace('{domain}', $domain, APACHE_SSL_CERTIFICATE_TEMPLATE);
    $key = str_replace('{domain}', $domain, APACHE_SSL_KEY_TEMPLATE);
    if (!is_file($certificate) || !is_readable($certificate) || !is_file($key) || !is_readable($key)) throw new RuntimeException('SSL certificate files not found after Certbot');
    return ['certificate' => $certificate, 'key' => $key, 'www' => $includeWww, 'dryRun' => CERTBOT_DRY_RUN_FIRST];
}

function certbotCommand(string $domain, string $webRoot, bool $includeWww, bool $dryRun): array
{
    $command = [
        CERTBOT_BINARY,
        'certonly',
        '--webroot',
        '--non-interactive',
        '--agree-tos',
        '--email',
        CERTBOT_EMAIL,
        '--cert-name',
        $domain,
        '--expand',
        '-w',
        $webRoot,
        '-d',
        $domain,
    ];
    if ($includeWww) { $command[] = '-d'; $command[] = 'www.' . $domain; }
    if ($dryRun) $command[] = '--dry-run';
    return $command;
}

function certbotOrFail(array $command, string $stage): void
{
    [$exitCode, $stdout, $stderr] = runProcess($command);
    if ($exitCode === 0) return;
    $details = trim($stdout . ($stdout !== '' && $stderr !== '' ? PHP_EOL : '') . $stderr);
    if ($details === '') $details = 'Certbot returned exit code ' . $exitCode;
    throw new RuntimeException('Certbot ' . $stage . ' failed: ' . $details);
}

function certificateCoversDomains(string $certificate, array $domains): bool
{
    if (!is_file($certificate) || !is_readable($certificate)) return false;
    [$exitCode, $stdout] = runProcess([CERTBOT_OPENSSL_BINARY, 'x509', '-in', $certificate, '-noout', '-text'], '', 10);
    if ($exitCode !== 0) return false;
    foreach ($domains as $domain) {
        if (preg_match('/DNS:\s*' . preg_quote((string) $domain, '/') . '(?:\s*,|\s|$)/i', $stdout) !== 1) return false;
    }
    return true;
}

function apacheDocumentRootBlock(string $documentRoot): array
{
    return ['    DocumentRoot "' . $documentRoot . '"'];
}

function apacheLogBlock(string $prefix, string $documentRoot): array
{
    $errorLog = projectLogFile($prefix, $documentRoot, USER_APACHE_ERROR_LOG_FILE);
    $accessLog = projectLogFile($prefix, $documentRoot, USER_APACHE_ACCESS_LOG_FILE);
    return [
        '    ErrorLog "' . $errorLog . '"',
        '    CustomLog "' . $accessLog . '" combined',
    ];
}

function apachePhpBlock(string $selected, string $errorLog): array
{
    $version = apachePhpVersion($selected);
    if ($errorLog === '' || $errorLog[0] !== '/' || preg_match('/[\x00\r\n"]/', $errorLog) === 1) throw new RuntimeException('Invalid PHP error log path');
    $lines = [
        '    # PHP: ' . (string) $version['id'],
        '    ProxyFCGISetEnvIf "true" PHP_ADMIN_VALUE "log_errors=On\\nerror_log=' . $errorLog . '"',
    ];
    $include = trim((string) ($version['include'] ?? ''));
    if ($include !== '') {
        if ($include[0] !== '/' || preg_match('/[^a-zA-Z0-9_\.\/-]/', $include) === 1) throw new RuntimeException('Invalid PHP include path');
        $lines[] = '    Include ' . $include;
        return $lines;
    }

    $fallback = $version['fallback'] ?? [];
    if (is_string($fallback)) $fallback = preg_split('/\r?\n/', $fallback);
    if (!is_array($fallback) || $fallback === []) throw new RuntimeException('PHP fallback configuration is empty');
    foreach ($fallback as $directive) {
        if (!is_string($directive) || $directive === '' || preg_match('/[\x00\r\n]/', $directive) === 1) {
            throw new RuntimeException('Invalid PHP fallback directive');
        }
        $lines[] = '    ' . rtrim($directive);
    }
    return $lines;
}

function apacheWwwRedirect(string $domain, string $scheme): array
{
    return ['    <IfModule mod_rewrite.c>', '        RewriteEngine On', '        RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/', '        RewriteCond %{HTTP_HOST} ^www\\.' . preg_quote($domain, '/') . '$ [NC]', '        RewriteRule ^ ' . $scheme . '://' . $domain . '%{REQUEST_URI} [R=301,L,NE]', '    </IfModule>'];
}

function apacheSslBlock(string $certificate, string $key): array
{
    foreach ([$certificate, $key, APACHE_SSL_OPTIONS_FILE] as $path) {
        if ($path === '' || $path[0] !== '/' || preg_match('/[\x00\r\n"]/', $path) === 1) throw new RuntimeException('Invalid Apache SSL path');
    }

    return [
        '    <IfFile "' . $certificate . '">',
        '        SSLEngine on',
        '        Include "' . APACHE_SSL_OPTIONS_FILE . '"',
        '        SSLCertificateFile "' . $certificate . '"',
        '        SSLCertificateKeyFile "' . $key . '"',
        '    </IfFile>',
    ];
}

function renderVirtualHosts(array $document, string $prefix): array
{
    $profile = is_array($document['profile'] ?? null) ? $document['profile'] : [];
    $domains = is_array($document['resources']['domains'] ?? null) ? $document['resources']['domains'] : [];
    $lines = ['# Generated by ImagoPanel. Manual changes will be overwritten.', '# User prefix: ' . $prefix, ''];
    $count = 0;
    if (empty($profile['active'])) return [implode(PHP_EOL, $lines) . PHP_EOL, 0];
    foreach ($domains as $row) {
        if (!is_array($row) || empty($row['active'])) continue;
        $domain = mb_strtolower(trim((string) ($row['domain'] ?? '')));
        if (!validDomain($domain)) throw new RuntimeException('Invalid domain in JSON: ' . $domain);
        $documentRoot = safeUserPath($prefix, (string) ($row['path'] ?? ''));
        $phpErrorLog = projectPhpErrorLog($prefix, $documentRoot);
        if (PROD && !is_dir($documentRoot)) throw new RuntimeException('Domain document root not found: ' . $documentRoot);
        $sslRequested = !empty($row['ssl']);
        $certificate = str_replace('{domain}', $domain, APACHE_SSL_CERTIFICATE_TEMPLATE);
        $key = str_replace('{domain}', $domain, APACHE_SSL_KEY_TEMPLATE);
        $certificateAvailable = is_file($certificate) && is_readable($certificate) && is_file($key) && is_readable($key);
        $phpVersion = (string) ($row['phpVersion'] ?? APACHE_DEFAULT_PHP_VERSION);
        apachePhpVersion($phpVersion);
        $redirectHttp = $sslRequested && !empty($row['redirectHttp']) && $certificateAvailable;
        $redirectWww = !empty($row['redirectWww']);
        $lines[] = '<VirtualHost *:80>';
        $lines[] = '    ServerName ' . $domain;
        if ($redirectWww) $lines[] = '    ServerAlias www.' . $domain;
        $lines = array_merge($lines, apacheLogBlock($prefix, $documentRoot));
        $lines = array_merge($lines, apacheDocumentRootBlock($documentRoot));
        $lines = array_merge($lines, apachePhpBlock($phpVersion, $phpErrorLog));
        if ($redirectHttp) {
            $lines[] = '    <IfModule mod_rewrite.c>';
            $lines[] = '        RewriteEngine On';
            $lines[] = '        RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/';
            $lines[] = '        RewriteRule ^ https://' . $domain . '%{REQUEST_URI} [R=301,L,NE]';
            $lines[] = '    </IfModule>';
        } else {
            if ($redirectWww) $lines = array_merge($lines, apacheWwwRedirect($domain, 'http'));
        }
        $lines[] = '</VirtualHost>';
        $lines[] = '';
        if ($sslRequested) {
            $lines[] = '<VirtualHost *:443>';
            $lines[] = '    ServerName ' . $domain;
            if ($redirectWww) $lines[] = '    ServerAlias www.' . $domain;
            $lines = array_merge($lines, apacheLogBlock($prefix, $documentRoot));
            $lines = array_merge($lines, apacheDocumentRootBlock($documentRoot));
            $lines = array_merge($lines, apachePhpBlock($phpVersion, $phpErrorLog));
            $lines = array_merge($lines, apacheSslBlock($certificate, $key));
            if ($redirectWww) $lines = array_merge($lines, apacheWwwRedirect($domain, 'https'));
            $lines[] = '    Protocols h2 http/1.1';
            $lines[] = '</VirtualHost>';
            $lines[] = '';
        }
        $count++;
    }
    return [implode(PHP_EOL, $lines) . PHP_EOL, $count];
}

function previewApacheVhosts(string $prefix): array
{
    return renderVirtualHosts(loadUserDocument($prefix), $prefix);
}

function checkApacheConfiguration(): void
{
    $result = apacheConfigurationStatus();
    if (empty($result['ok'])) throw new RuntimeException((string) ($result['output'] ?? 'Apache configuration test failed'));
}

function reloadApache(): void
{
    commandOrFail([APACHE_SYSTEMCTL_BINARY, 'reload', APACHE_SERVICE_NAME], '', 'Apache reload failed');
}

function apacheConfigurationStatus(): array
{
    [$exitCode, $stdout, $stderr] = runProcess([APACHE_HTTPD_BINARY, '-t']);
    $output = trim($stdout . ($stdout !== '' && $stderr !== '' ? PHP_EOL : '') . $stderr);
    if ($output === '') $output = $exitCode === 0 ? 'Syntax OK' : 'Apache configuration test failed';
    return ['ok' => $exitCode === 0, 'exitCode' => $exitCode, 'output' => $output];
}

function apacheIssueContext(string $file, int $line): array
{
    $normalizedFile = str_replace('\\', '/', trim($file, " \t\n\r\0\x0B\"'"));
    $vhostDirectory = rtrim(str_replace('\\', '/', APACHE_VHOST_DIRECTORY), '/');
    $context = ['domainId' => 0, 'domain' => '', 'prefix' => '', 'file' => $normalizedFile, 'line' => max(0, $line)];
    if ($normalizedFile === '' || strpos($normalizedFile, $vhostDirectory . '/') !== 0 || substr($normalizedFile, -5) !== '.conf') return $context;

    $prefix = basename($normalizedFile, '.conf');
    if (!validPrefix($prefix)) return $context;
    $context['prefix'] = $prefix;
    $fileLines = is_file($normalizedFile) ? file($normalizedFile, FILE_IGNORE_NEW_LINES) : false;
    if (is_array($fileLines) && $fileLines !== []) {
        $index = min(max(0, $line - 1), count($fileLines) - 1);
        for (; $index >= 0; $index--) {
            $candidate = trim((string) $fileLines[$index]);
            if (preg_match('/^ServerName\s+([^\s#]+)$/i', $candidate, $match) === 1) {
                $context['domain'] = mb_strtolower(rtrim((string) $match[1], '.'));
                break;
            }
            if ($candidate === '<VirtualHost *:80>' || $candidate === '<VirtualHost *:443>') break;
        }
    }

    if ($context['domain'] !== '') {
        try {
            $document = loadUserDocument($prefix);
            foreach ($document['resources']['domains'] ?? [] as $row) {
                if (is_array($row) && mb_strtolower((string) ($row['domain'] ?? '')) === $context['domain']) {
                    $context['domainId'] = (int) ($row['id'] ?? 0);
                    break;
                }
            }
        } catch (Throwable $exception) {
        }
    }
    return $context;
}

function apacheConfigurationIssues(string $output): array
{
    $issues = [];
    $seen = [];
    $outputLines = preg_split('/\r?\n/', trim($output)) ?: [];
    foreach ($outputLines as $index => $outputLine) {
        $locations = [];
        if (preg_match_all('/line\s+(\d+)\s+of\s+([^\s:]+\.conf)/i', $outputLine, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) $locations[] = ['file' => (string) $match[2], 'line' => (int) $match[1]];
        }
        if (preg_match_all('/([^\s:]+\.conf):(\d+)/i', $outputLine, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) $locations[] = ['file' => (string) $match[1], 'line' => (int) $match[2]];
        }
        foreach ($locations as $location) {
            $context = apacheIssueContext($location['file'], $location['line']);
            $reason = trim($outputLine);
            if (isset($outputLines[$index + 1]) && trim((string) $outputLines[$index + 1]) !== '') {
                $reason .= PHP_EOL . trim((string) $outputLines[$index + 1]);
            }
            $key = implode('|', [$context['file'], (string) $context['line'], $context['domain'], $reason]);
            if (isset($seen[$key])) continue;
            $seen[$key] = true;
            $issues[] = $context + ['reason' => $reason];
        }
    }
    if ($issues === []) {
        $issues[] = ['domainId' => 0, 'domain' => '', 'prefix' => '', 'file' => '', 'line' => 0, 'reason' => trim($output) !== '' ? trim($output) : 'Apache configuration test failed'];
    }
    return $issues;
}

function apacheUserPrefixes(): array
{
    $prefixes = [];
    foreach (glob(rtrim(DATA_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . '*.json') ?: [] as $path) {
        $prefix = basename($path, '.json');
        if (validPrefix($prefix)) $prefixes[] = $prefix;
    }
    sort($prefixes, SORT_STRING);
    return $prefixes;
}

function apacheGenerationIssue(string $prefix, string $reason): array
{
    $issue = ['domainId' => 0, 'domain' => '', 'prefix' => $prefix, 'file' => '', 'line' => 0, 'reason' => $reason];
    try {
        $document = loadUserDocument($prefix);
        $active = [];
        foreach ($document['resources']['domains'] ?? [] as $row) {
            if (!is_array($row) || empty($row['active'])) continue;
            $active[] = $row;
            $domain = mb_strtolower(trim((string) ($row['domain'] ?? '')));
            $path = trim((string) ($row['path'] ?? ''));
            if (($domain !== '' && stripos($reason, $domain) !== false) || ($path !== '' && strpos($reason, $path) !== false)) {
                $issue['domainId'] = (int) ($row['id'] ?? 0);
                $issue['domain'] = $domain;
                return $issue;
            }
        }
        if (count($active) === 1) {
            $issue['domainId'] = (int) ($active[0]['id'] ?? 0);
            $issue['domain'] = mb_strtolower(trim((string) ($active[0]['domain'] ?? '')));
        }
    } catch (Throwable $exception) {
    }
    return $issue;
}

function restoreApacheVhostBatch(array $staged): bool
{
    $restored = true;
    foreach (array_reverse($staged) as $item) {
        $target = (string) ($item['target'] ?? '');
        $backup = (string) ($item['backup'] ?? '');
        if (!empty($item['installed']) && $target !== '' && is_file($target) && !@unlink($target)) $restored = false;
        if ($backup !== '' && is_file($backup) && $target !== '' && !@rename($backup, $target)) $restored = false;
        $temporary = (string) ($item['temporary'] ?? '');
        if ($temporary !== '' && is_file($temporary) && !@unlink($temporary)) $restored = false;
    }
    return $restored;
}

function cleanupApacheVhostBatch(array $staged): void
{
    foreach ($staged as $item) {
        foreach (['backup', 'temporary'] as $key) {
            $path = (string) ($item[$key] ?? '');
            if ($path !== '' && is_file($path)) @unlink($path);
        }
    }
}

function refreshAllApacheVhosts(bool $continueAfterInvalidCurrent = false): array
{
    return withRootLock('apache_global', static function () use ($continueAfterInvalidCurrent): array {
        $initial = apacheConfigurationStatus();
        if (empty($initial['ok']) && !$continueAfterInvalidCurrent) {
            return [
                'ok' => false, 'phase' => 'current', 'initialCheck' => false, 'configTest' => false,
                'reloaded' => false, 'users' => 0, 'domains' => 0,
                'issues' => apacheConfigurationIssues((string) $initial['output']), 'output' => (string) $initial['output'],
            ];
        }

        $candidates = [];
        $domainCount = 0;
        foreach (apacheUserPrefixes() as $prefix) {
            try {
                ensureVhostProjectLogDirectories($prefix);
                [$content, $count] = previewApacheVhosts($prefix);
            } catch (Throwable $exception) {
                return [
                    'ok' => false, 'phase' => 'generation', 'initialCheck' => !empty($initial['ok']), 'configTest' => false,
                    'reloaded' => false, 'users' => count($candidates), 'domains' => $domainCount,
                    'issues' => [apacheGenerationIssue($prefix, $exception->getMessage())], 'output' => $exception->getMessage(),
                ];
            }
            $candidates[] = ['prefix' => $prefix, 'content' => $content, 'domains' => $count];
            $domainCount += $count;
        }

        $staged = [];
        try {
            foreach ($candidates as $candidate) {
                $prefix = (string) $candidate['prefix'];
                $target = rtrim(APACHE_VHOST_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $prefix . '.conf';
                $temporary = tempnam(APACHE_VHOST_DIRECTORY, '.' . $prefix . '.candidate.');
                if ($temporary === false) throw new RuntimeException('Cannot create temporary vhost file for ' . $prefix);
                $item = ['target' => $target, 'temporary' => $temporary, 'backup' => '', 'installed' => false];
                $staged[] = $item;
                $position = count($staged) - 1;
                if (file_put_contents($temporary, (string) $candidate['content'], LOCK_EX) === false || !chmod($temporary, 0644)) {
                    throw new RuntimeException('Cannot write vhost file for ' . $prefix);
                }
                if (is_file($target)) {
                    $backup = tempnam(APACHE_VHOST_DIRECTORY, '.' . $prefix . '.backup.');
                    if ($backup === false || !unlink($backup) || !rename($target, $backup)) throw new RuntimeException('Cannot back up vhost file for ' . $prefix);
                    $staged[$position]['backup'] = $backup;
                }
                if (!rename($temporary, $target)) throw new RuntimeException('Cannot replace vhost file for ' . $prefix);
                $staged[$position]['temporary'] = '';
                $staged[$position]['installed'] = true;
            }

            $generated = apacheConfigurationStatus();
            if (empty($generated['ok'])) {
                $issues = apacheConfigurationIssues((string) $generated['output']);
                $filesRestored = restoreApacheVhostBatch($staged);
                $rollback = apacheConfigurationStatus();
                return [
                    'ok' => false, 'phase' => 'generated', 'initialCheck' => !empty($initial['ok']), 'configTest' => false,
                    'rollbackOk' => $filesRestored && !empty($rollback['ok']), 'reloaded' => false, 'users' => count($candidates), 'domains' => $domainCount,
                    'issues' => $issues, 'output' => (string) $generated['output'],
                ];
            }

            try {
                reloadApache();
            } catch (Throwable $exception) {
                $filesRestored = restoreApacheVhostBatch($staged);
                $rollback = apacheConfigurationStatus();
                return [
                    'ok' => false, 'phase' => 'reload', 'initialCheck' => !empty($initial['ok']), 'configTest' => true,
                    'rollbackOk' => $filesRestored && !empty($rollback['ok']), 'reloaded' => false, 'users' => count($candidates), 'domains' => $domainCount,
                    'issues' => [['domainId' => 0, 'domain' => '', 'prefix' => '', 'file' => '', 'line' => 0, 'reason' => $exception->getMessage()]],
                    'output' => $exception->getMessage(),
                ];
            }

            cleanupApacheVhostBatch($staged);
            return [
                'ok' => true, 'phase' => 'complete', 'initialCheck' => !empty($initial['ok']), 'configTest' => true,
                'reloaded' => true, 'users' => count($candidates), 'domains' => $domainCount,
                'issues' => [], 'output' => 'Syntax OK',
            ];
        } catch (Throwable $exception) {
            restoreApacheVhostBatch($staged);
            throw $exception;
        }
    });
}

function ensureVhostProjectLogDirectories(string $prefix): void
{
    ensureDirectory(DOMAIN_TOOL_LOG_DIRECTORY, 0770, USER_WEB_OWNER, USER_WEB_GROUP);
    ensureDirectory(DOMAIN_TOOL_STATE_DIRECTORY, 0770, USER_WEB_OWNER, USER_WEB_GROUP);
    $document = loadUserDocument($prefix);
    foreach ($document['resources']['domains'] ?? [] as $row) {
        if (!is_array($row) || empty($row['active'])) continue;
        $documentRoot = safeUserPath($prefix, (string) ($row['path'] ?? ''));
        if (!is_dir($documentRoot)) throw new RuntimeException('Domain document root not found: ' . $documentRoot);
        ensureDirectory(projectLogDirectory($prefix, $documentRoot), USER_PHP_LOG_DIRECTORY_MODE, configuredFilesystemOwner($prefix), USER_WEB_GROUP);
    }
}

function installApacheVhostContent(string $prefix, string $content, int $domainCount): array
{
    if (!is_dir(APACHE_VHOST_DIRECTORY)) throw new RuntimeException('Apache vhost directory not found');
    $target = rtrim(APACHE_VHOST_DIRECTORY, '/') . '/' . $prefix . '.conf';
    $temporary = tempnam(APACHE_VHOST_DIRECTORY, '.' . $prefix . '.');
    if ($temporary === false) throw new RuntimeException('Cannot create temporary vhost file');
    $backup = null;
    $installed = false;
    try {
        if (file_put_contents($temporary, $content, LOCK_EX) === false || !chmod($temporary, 0644)) throw new RuntimeException('Cannot write vhost file');
        if (is_file($target)) {
            $backup = tempnam(APACHE_VHOST_DIRECTORY, '.' . $prefix . '.backup.');
            if ($backup === false || !unlink($backup) || !rename($target, $backup)) throw new RuntimeException('Cannot back up current vhost file');
        }
        if (!rename($temporary, $target)) throw new RuntimeException('Cannot replace vhost file');
        $installed = true;
        checkApacheConfiguration();
        reloadApache();
        if ($backup !== null && is_file($backup)) unlink($backup);
    } catch (Throwable $exception) {
        if ($installed && is_file($target)) @unlink($target);
        if ($backup !== null && is_file($backup)) @rename($backup, $target);
        throw $exception;
    } finally {
        if (is_file($temporary)) @unlink($temporary);
    }
    return ['file' => $target, 'domains' => $domainCount, 'configTest' => true, 'reloaded' => true];
}

function rebuildApacheVhostsUnlocked(string $prefix): array
{
    ensureVhostProjectLogDirectories($prefix);

    // Publish the HTTP and HTTPS vhosts first, validate the configuration, and then reload Apache.
    // SSL directives inside the HTTPS vhost are activated by IfFile only after the certificate exists.
    [$content, $domainCount] = previewApacheVhosts($prefix);
    $result = installApacheVhostContent($prefix, $content, $domainCount);

    $issued = [];
    $document = loadUserDocument($prefix);
    foreach ($document['resources']['domains'] ?? [] as $row) {
        if (!is_array($row) || empty($row['active']) || empty($row['ssl'])) continue;
        $domain = requireDomain($row);
        $documentRoot = safeUserPath($prefix, (string) ($row['path'] ?? ''));
        $includeWww = !empty($row['redirectWww']);
        $requiredDomains = [$domain];
        if ($includeWww) $requiredDomains[] = 'www.' . $domain;
        $certificate = str_replace('{domain}', $domain, APACHE_SSL_CERTIFICATE_TEMPLATE);
        $key = str_replace('{domain}', $domain, APACHE_SSL_KEY_TEMPLATE);
        if (certificateCoversDomains($certificate, $requiredDomains) && is_file($key) && is_readable($key)) continue;
        $issued[$domain] = ensureCertificate($prefix, $domain, $documentRoot, $includeWww);
    }

    if ($issued !== []) {
        [$content, $domainCount] = previewApacheVhosts($prefix);
        $result = installApacheVhostContent($prefix, $content, $domainCount);
    }
    $result['certificates'] = $issued;
    return $result;
}

function rebuildApacheVhosts(string $prefix): array
{
    return withRootLock('apache_global', static function () use ($prefix): array {
        return rebuildApacheVhostsUnlocked($prefix);
    });
}

function removeApacheVhostsUnlocked(string $prefix): array
{
    $target = rtrim(APACHE_VHOST_DIRECTORY, '/') . '/' . $prefix . '.conf';
    if (!is_file($target)) return ['file' => $target, 'removed' => false, 'configTest' => true, 'reloaded' => false];
    $backup = tempnam(APACHE_VHOST_DIRECTORY, '.' . $prefix . '.removed.');
    if ($backup === false || !unlink($backup) || !rename($target, $backup)) throw new RuntimeException('Cannot stage vhost removal');
    try {
        checkApacheConfiguration();
        reloadApache();
        unlink($backup);
    } catch (Throwable $exception) {
        @rename($backup, $target);
        throw $exception;
    }
    return ['file' => $target, 'removed' => true, 'configTest' => true, 'reloaded' => true];
}

function removeApacheVhosts(string $prefix): array
{
    return withRootLock('apache_global', static function () use ($prefix): array {
        return removeApacheVhostsUnlocked($prefix);
    });
}

function apacheVhostCheck(array $params): array
{
    $domain = requireDomain($params);
    $hostingIps = array_values(array_filter(STATS_HOSTING_PUBLIC_IPS, static function ($ip): bool {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }));
    if ($hostingIps === []) throw new RuntimeException('Hosting public IPs are not configured');

    $deadline = microtime(true) + DNS_VERIFY_TOTAL_TIMEOUT_SECONDS;
    $rootDns = authoritativeIpv4Status($domain, $hostingIps, $deadline);
    $wwwDns = authoritativeIpv4Status('www.' . $domain, $hostingIps, $deadline);
    $found = [];
    foreach (glob(rtrim(APACHE_VHOST_DIRECTORY, '/') . '/*.conf') ?: [] as $file) {
        $content = file_get_contents($file);
        if ($content !== false && preg_match('/^\s*Server(?:Name|Alias)\s+' . preg_quote($domain, '/') . '\s*$/mi', $content) === 1) $found[] = basename($file);
    }
    return [
        'domain' => $domain,
        'domainValid' => true,
        'rootPoints' => !empty($rootDns['valid']),
        'wwwPoints' => !empty($wwwDns['valid']),
        'sslReady' => !empty($rootDns['valid']) && !empty($wwwDns['valid']),
        'rootAddresses' => $rootDns['addresses'],
        'wwwAddresses' => $wwwDns['addresses'],
        'rootCname' => $rootDns['cname'],
        'wwwCname' => $wwwDns['cname'],
        'hostingIps' => $hostingIps,
        'nameServers' => array_values(array_unique(array_merge($rootDns['nameServers'], $wwwDns['nameServers']))),
        'exists' => $found !== [],
        'files' => $found,
        'cacheUsed' => false,
        'checkedAt' => gmdate('c'),
    ];
}

function parseDigTxtValues(string $stdout): array
{
    $values = [];
    foreach (preg_split('/\R/', trim($stdout)) ?: [] as $line) {
        $line = trim($line);
        if ($line === '') continue;
        preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $line, $matches);
        if (!empty($matches[1])) {
            $value = '';
            foreach ($matches[1] as $part) $value .= stripcslashes((string) $part);
        } else {
            $value = trim($line, '"');
        }
        if ($value !== '') $values[] = $value;
    }
    return array_values(array_unique($values));
}

function authoritativeNameServers(string $domain, float $deadline): array
{
    $labels = explode('.', $domain);
    for ($offset = 0; $offset < count($labels) - 1; $offset++) {
        $remaining = (int) ceil($deadline - microtime(true));
        if ($remaining <= 0) break;
        $zone = implode('.', array_slice($labels, $offset));
        [$code, $stdout] = runProcess([
            DNS_DIG_BINARY,
            '+short',
            '+time=' . DNS_DIG_TIMEOUT_SECONDS,
            '+tries=' . DNS_DIG_TRIES,
            $zone,
            'NS',
        ], '', min(DNS_DIG_PROCESS_TIMEOUT_SECONDS, $remaining));
        if ($code !== 0) continue;

        $servers = [];
        foreach (preg_split('/\R/', $stdout) ?: [] as $line) {
            $server = mb_strtolower(rtrim(trim((string) $line), '.'));
            if (preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i', $server) === 1) $servers[$server] = true;
        }
        if ($servers !== []) return array_slice(array_keys($servers), 0, DNS_AUTHORITATIVE_SERVER_LIMIT);
    }
    throw new RuntimeException('Cannot find authoritative DNS servers for ' . $domain);
}

function authoritativeDnsValues(array $nameServers, string $name, string $type, float $deadline): array
{
    $responses = [];
    foreach ($nameServers as $nameServer) {
        $remaining = (int) ceil($deadline - microtime(true));
        if ($remaining <= 0) break;
        [$code, $stdout] = runProcess([
            DNS_DIG_BINARY,
            '+short',
            '+norecurse',
            '+time=' . DNS_DIG_TIMEOUT_SECONDS,
            '+tries=' . DNS_DIG_TRIES,
            '@' . $nameServer,
            $name,
            $type,
        ], '', min(DNS_DIG_PROCESS_TIMEOUT_SECONDS, $remaining));
        if ($code !== 0) continue;
        $recordType = strtoupper($type);
        if ($recordType === 'TXT') {
            $responses[$nameServer] = parseDigTxtValues($stdout);
        } elseif (in_array($recordType, ['A', 'AAAA'], true)) {
            $responses[$nameServer] = array_values(array_filter(preg_split('/\R/', trim($stdout)) ?: [], static function ($value): bool {
                return filter_var(trim((string) $value), FILTER_VALIDATE_IP) !== false;
            }));
        } else {
            $responses[$nameServer] = array_values(array_filter(array_map(static function ($value): string {
                return mb_strtolower(rtrim(trim((string) $value), '.'));
            }, preg_split('/\R/', trim($stdout)) ?: [])));
        }
    }
    if ($responses === []) throw new RuntimeException('Authoritative DNS servers did not answer for ' . $name);
    return $responses;
}

function authoritativeIpv4Status(string $name, array $hostingIps, float $deadline, int $depth = 0): array
{
    if ($depth > 4 || microtime(true) >= $deadline) {
        return ['valid' => false, 'addresses' => [], 'cname' => '', 'nameServers' => []];
    }
    $nameServers = authoritativeNameServers($name, $deadline);
    $responses = authoritativeDnsValues($nameServers, $name, 'A', $deadline);
    $addresses = dnsResponseValues($responses);
    if ($addresses !== []) {
        $valid = true;
        foreach ($responses as $values) {
            if ($values === []) {
                $valid = false;
                break;
            }
            foreach ($values as $address) {
                if (!in_array($address, $hostingIps, true)) {
                    $valid = false;
                    break 2;
                }
            }
        }
        return ['valid' => $valid, 'addresses' => $addresses, 'cname' => '', 'nameServers' => $nameServers];
    }

    $cnameResponses = authoritativeDnsValues($nameServers, $name, 'CNAME', $deadline);
    $targets = dnsResponseValues($cnameResponses);
    if (count($targets) !== 1) {
        return ['valid' => false, 'addresses' => [], 'cname' => '', 'nameServers' => $nameServers];
    }
    $target = (string) $targets[0];
    $resolved = authoritativeIpv4Status($target, $hostingIps, $deadline, $depth + 1);
    $resolved['cname'] = $target;
    $resolved['nameServers'] = array_values(array_unique(array_merge($nameServers, $resolved['nameServers'])));
    return $resolved;
}

function dnsResponseValues(array $responses): array
{
    $values = [];
    foreach ($responses as $response) {
        foreach ($response as $value) $values[(string) $value] = true;
    }
    return array_keys($values);
}

function normalizedTxt(string $value): string
{
    return preg_replace('/\s+/', '', trim($value)) ?? '';
}

function txtMatches(array $values, string $expected): bool
{
    $needle = normalizedTxt($expected);
    foreach ($values as $value) if (hash_equals($needle, normalizedTxt((string) $value))) return true;
    return false;
}

function recommendedDnsValues(string $relativeName, string $type, string $domain): array
{
    $relativeName = mb_strtolower(rtrim(trim($relativeName), '.'));
    $type = strtoupper(trim($type));
    foreach (DNS_API_RECOMMENDED_RECORDS as $record) {
        if (!is_array($record)) continue;
        $configuredName = mb_strtolower(rtrim(trim((string) ($record['name'] ?? '')), '.'));
        if ($configuredName !== $relativeName || strtoupper((string) ($record['type'] ?? '')) !== $type) continue;
        $values = is_array($record['values'] ?? null) ? $record['values'] : [$record['values'] ?? ''];
        return array_values(array_filter(array_map(static function ($value) use ($domain): string {
            return trim(str_ireplace('{domain}', $domain, (string) $value));
        }, $values), static function (string $value): bool { return $value !== ''; }));
    }
    return [];
}

function normalizedMx(string $value): string
{
    $value = mb_strtolower(trim(preg_replace('/\s+/', ' ', $value) ?? $value));
    $parts = explode(' ', $value, 2);
    if (count($parts) !== 2 || preg_match('/^\d+$/D', $parts[0]) !== 1) return rtrim($value, '.');
    return (string) ((int) $parts[0]) . ' ' . rtrim($parts[1], '.');
}

function dnsResponsesMatch(array $responses, array $expected, callable $normalizer): bool
{
    $expected = array_values(array_unique(array_map($normalizer, $expected)));
    if ($expected === [] || $responses === []) return false;
    foreach ($responses as $values) {
        $actual = array_values(array_unique(array_map($normalizer, $values)));
        if ($actual === [] || array_diff($expected, $actual) !== [] || array_diff($actual, $expected) !== []) return false;
    }
    return true;
}

function opendkimCheck(array $params): array
{
    $domain = requireDomain($params);
    $dkimValue = openDkimManager()->dnsValue($domain, true);
    $deadline = microtime(true) + DNS_VERIFY_TOTAL_TIMEOUT_SECONDS;
    $nameServers = authoritativeNameServers($domain, $deadline);
    $mailAValues = recommendedDnsValues('mail', 'A', $domain);
    $mxValues = recommendedDnsValues('@', 'MX', $domain);
    if ($mailAValues === [] || $mxValues === []) throw new RuntimeException('Recommended mail A and MX records are not configured');

    $mailAResponses = authoritativeDnsValues($nameServers, 'mail.' . $domain, 'A', $deadline);
    $mxResponses = authoritativeDnsValues($nameServers, $domain, 'MX', $deadline);
    $result = [
        'mail_a' => [
            'name' => 'mail.' . $domain,
            'value' => implode(', ', $mailAValues),
            'actual' => dnsResponseValues($mailAResponses),
            'valid' => dnsResponsesMatch($mailAResponses, $mailAValues, static function ($value): string { return trim((string) $value); }),
            'authoritativeResponses' => $mailAResponses,
        ],
        'mx' => [
            'name' => $domain,
            'value' => implode(', ', $mxValues),
            'actual' => dnsResponseValues($mxResponses),
            'valid' => dnsResponsesMatch($mxResponses, $mxValues, static function ($value): string { return normalizedMx((string) $value); }),
            'authoritativeResponses' => $mxResponses,
        ],
    ];
    $required = ['dkim' => ['name' => DNS_DKIM_SELECTOR . '._domainkey.' . $domain, 'value' => $dkimValue], 'spf' => ['name' => $domain, 'value' => DNS_SPF_VALUE], 'dmarc' => ['name' => '_dmarc.' . $domain, 'value' => str_replace('{domain}', $domain, DNS_DMARC_VALUE)]];
    foreach ($required as $type => $record) {
        $responses = authoritativeDnsValues($nameServers, $record['name'], 'TXT', $deadline);
        $valid = true;
        foreach ($responses as $values) {
            if (!txtMatches($values, $record['value'])) $valid = false;
        }
        $result[$type] = $record + [
            'actual' => dnsResponseValues($responses),
            'valid' => $valid,
            'authoritativeResponses' => $responses,
        ];
    }
    [$code, $stdout] = runProcess([APACHE_SYSTEMCTL_BINARY, 'is-active', OPENDKIM_SERVICE_NAME], '', 3);
    return [
        'domain' => $domain,
        'exists' => $code === 0 && trim($stdout) === 'active',
        'records' => $result,
        'nameServers' => $nameServers,
        'cacheUsed' => false,
        'checkedAt' => gmdate('c'),
    ];
}

function setUserServicesActive(array $document, string $prefix, bool $enable): void
{
    $mysql = mysqlPdo();
    foreach ($document['resources']['databases'] ?? [] as $database) {
        if (!is_array($database)) continue;
        $name = requireDatabaseName($prefix, ['name' => $database['name'] ?? '']);
        if ($enable && !empty($database['active'])) {
            ensureMysqlUser($mysql, $name, requireDatabasePassword(['record' => $database]));
            grantDatabase($mysql, $name);
            revokeLegacyDatabase($mysql, $prefix, $name);
        } else {
            revokeDatabase($mysql, $name);
            revokeLegacyDatabase($mysql, $prefix, $name);
        }
    }
    $postfix = postfixPdo();
    foreach ($document['resources']['mail'] ?? [] as $mailbox) {
        if (!is_array($mailbox) || !validMailboxAddress((string) ($mailbox['address'] ?? ''))) continue;
        $address = mb_strtolower((string) $mailbox['address']);
        $active = $enable && !empty($mailbox['active']);
        foreach ([[POSTFIXADMIN_MAILBOX_TABLE, 'username'], [POSTFIXADMIN_ALIAS_TABLE, 'address']] as $target) {
            $columns = postfixColumns($postfix, $target[0]);
            if (isset($columns['active'], $columns[$target[1]])) {
                $statement = $postfix->prepare('UPDATE ' . postfixTable($target[0]) . ' SET `active` = ? WHERE `' . $target[1] . '` = ?');
                $statement->execute([$active ? 1 : 0, $address]);
            }
        }
    }
    $domains = [];
    foreach ($document['resources']['domains'] ?? [] as $domain) {
        $name = mb_strtolower((string) ($domain['domain'] ?? ''));
        if (validDomain($name)) $domains[$name] = $enable && !empty($domain['active']);
    }
    foreach ($domains as $domain => $active) {
        $columns = postfixColumns($postfix, POSTFIXADMIN_DOMAIN_TABLE);
        if (isset($columns['active'], $columns['domain'])) {
            $statement = $postfix->prepare('UPDATE ' . postfixTable(POSTFIXADMIN_DOMAIN_TABLE) . ' SET `active` = ? WHERE `domain` = ?');
            $statement->execute([$active ? 1 : 0, $domain]);
        }
    }
}

function createUser(array $params): array
{
    $prefix = requirePrefix($params);
    $rootPath = requireUserRoot($params, $prefix);
    $filesystemResult = ensureConfiguredUserRoot($prefix, $rootPath);
    $quota = applyConfiguredSystemQuota($prefix, max(0, (float) ($params['system_quota_bytes'] ?? 0)));
    return ['prefix' => $prefix, 'rootPath' => $rootPath, 'filesystem' => $filesystemResult, 'quota' => $quota];
}

function updateUser(array $params): array
{
    $prefix = requirePrefix($params);
    $rootPath = requireUserRoot($params, $prefix);
    loadUserDocument($prefix);
    $filesystemResult = ensureConfiguredUserRoot($prefix, $rootPath);
    $owner = (string) filesystemIdentity(configuredFilesystemOwner($prefix));
    $group = (string) filesystemIdentity(USER_WEB_GROUP);
    if (FILESYSTEM_CHOWN_BINARY !== '' && is_executable(FILESYSTEM_CHOWN_BINARY)) {
        commandOrFail([FILESYSTEM_CHOWN_BINARY, '-R', '--no-dereference', $owner . ':' . $group, '--', $rootPath], '', 'Cannot update user directory ownership');
    }
    $quota = applyConfiguredSystemQuota($prefix, max(0, (float) ($params['system_quota_bytes'] ?? 0)));
    return ['prefix' => $prefix, 'rootPath' => $rootPath, 'filesystem' => $filesystemResult, 'quota' => $quota];
}

function toggleUser(array $params): array
{
    $prefix = requirePrefix($params);
    $document = loadUserDocument($prefix);
    $enable = empty($document['profile']['active']);
    setUserServicesActive($document, $prefix, $enable);
    return ['prefix' => $prefix, 'active' => $enable];
}

function deletePostfixDomain(PDO $pdo, string $domain): void
{
    postfixDelete($pdo, POSTFIXADMIN_ALIAS_TABLE, ['domain' => $domain]);
    postfixDelete($pdo, POSTFIXADMIN_MAILBOX_TABLE, ['domain' => $domain]);
    postfixDelete($pdo, POSTFIXADMIN_DOMAIN_TABLE, ['domain' => $domain]);
}

function deleteUser(array $params): array
{
    $prefix = requirePrefix($params);
    $document = loadUserDocument($prefix);
    $domains = [];
    foreach ($document['resources']['domains'] ?? [] as $domain) {
        $name = mb_strtolower((string) ($domain['domain'] ?? ''));
        if (validDomain($name)) $domains[$name] = true;
    }
    openDkimManager()->removeDomains(array_keys($domains));
    removeApacheVhosts($prefix);
    $mysql = mysqlPdo();
    foreach ($document['resources']['databases'] ?? [] as $database) {
        if (!is_array($database)) continue;
        $name = requireDatabaseName($prefix, ['name' => $database['name'] ?? '']);
        $mysql->exec('DROP DATABASE IF EXISTS ' . mysqlIdentifier($name));
        dropDatabaseUser($mysql, $name);
    }
    if (legacyMysqlUserExists($mysql, $prefix)) $mysql->exec('DROP USER ' . legacyMysqlAccountSql($mysql, $prefix));
    $postfix = postfixPdo();
    $postfix->beginTransaction();
    try {
        foreach (array_keys($domains) as $domain) deletePostfixDomain($postfix, $domain);
        $postfix->commit();
    } catch (Throwable $exception) {
        if ($postfix->inTransaction()) $postfix->rollBack();
        throw $exception;
    }
    foreach (array_keys($domains) as $domain) {
        $mailPath = rtrim(MAIL_STORAGE_DIRECTORY, '/') . '/' . $domain;
        if (file_exists($mailPath)) deleteTree($mailPath, MAIL_STORAGE_DIRECTORY);
    }
    $rootPath = expectedUserRoot($prefix);
    if (file_exists($rootPath)) deleteTree($rootPath, USER_WEB_ROOT_DIRECTORY);
    if (!empty($document['profile']['unixAccountManaged']) && unixAccountExists($prefix)) {
        if (UNIX_USERDEL_BINARY === '' || !is_executable(UNIX_USERDEL_BINARY)) throw new RuntimeException('UNIX userdel command is not available');
        commandOrFail([UNIX_USERDEL_BINARY, '--', $prefix], '', 'Cannot delete UNIX account');
    }
    return ['prefix' => $prefix, 'deleted' => true];
}

function validateLocalAction(string $action, array $params): array
{
    if ($action === 'server_diagnostics') return ServerDiagnostics::fromConfig()->inspect();
    $summary = ['accepted' => true, 'action' => $action, 'localStub' => true, 'environment' => WIN ? 'WIN' : 'TASK'];
    if (strpos($action, 'user_') === 0) {
        $prefix = requirePrefix($params);
        $summary['prefix'] = $prefix;
        if (in_array($action, ['user_update', 'user_toggle', 'user_delete'], true)) loadUserDocument($prefix);
        if (in_array($action, ['user_create', 'user_update'], true)) {
            requireUserRoot($params, $prefix);
            if ($action === 'user_create' && (string) ($params['password'] ?? '') === '') throw new RuntimeException('User password is required');
        }
        return $summary;
    }
    if ($action === 'apache_vhosts_rebuild') {
        $prefix = requirePrefix($params);
        [$preview, $count] = previewApacheVhosts($prefix);
        return $summary + ['prefix' => $prefix, 'domains' => $count, 'preview' => $preview];
    }
    if ($action === 'apache_vhosts_refresh_all') {
        $users = 0;
        $domains = 0;
        foreach (apacheUserPrefixes() as $prefix) {
            [, $count] = previewApacheVhosts($prefix);
            $users++;
            $domains += $count;
        }
        return $summary + [
            'ok' => true, 'phase' => 'complete', 'initialCheck' => true, 'configTest' => true,
            'reloaded' => false, 'users' => $users, 'domains' => $domains, 'issues' => [],
            'output' => 'Syntax OK (local simulation)',
        ];
    }
    if ($action === 'apache_vhosts_remove') return $summary + ['prefix' => requirePrefix($params)];
    if ($action === 'apache_vhost_check') {
        $domain = requireDomain($params);
        $hostingIps = array_values(array_filter(STATS_HOSTING_PUBLIC_IPS, static function ($ip): bool {
            return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        }));
        $rootAddresses = dnsAddresses($domain);
        $wwwAddresses = dnsAddresses('www.' . $domain);
        $rootPoints = $rootAddresses !== [] && array_diff($rootAddresses, $hostingIps) === [];
        $wwwPoints = $wwwAddresses !== [] && array_diff($wwwAddresses, $hostingIps) === [];
        return $summary + [
            'domain' => $domain,
            'domainValid' => true,
            'rootPoints' => $rootPoints,
            'wwwPoints' => $wwwPoints,
            'sslReady' => $rootPoints && $wwwPoints,
            'rootAddresses' => $rootAddresses,
            'wwwAddresses' => $wwwAddresses,
            'rootCname' => '',
            'wwwCname' => '',
            'hostingIps' => $hostingIps,
            'nameServers' => [],
            'exists' => false,
            'files' => [],
            'cacheUsed' => true,
            'checkedAt' => gmdate('c'),
        ];
    }
    if ($action === 'opendkim_check') {
        $domain = requireDomain($params);
        $mailAValues = recommendedDnsValues('mail', 'A', $domain);
        $mxValues = recommendedDnsValues('@', 'MX', $domain);
        return $summary + [
            'domain' => $domain,
            'records' => [
                'mail_a' => ['name' => 'mail.' . $domain, 'value' => implode(', ', $mailAValues), 'actual' => [], 'valid' => false],
                'mx' => ['name' => $domain, 'value' => implode(', ', $mxValues), 'actual' => [], 'valid' => false],
                'dkim' => ['name' => DNS_DKIM_SELECTOR . '._domainkey.' . $domain, 'value' => DNS_DKIM_VALUE, 'actual' => [], 'valid' => false],
                'spf' => ['name' => $domain, 'value' => DNS_SPF_VALUE, 'actual' => [], 'valid' => false],
                'dmarc' => ['name' => '_dmarc.' . $domain, 'value' => str_replace('{domain}', $domain, DNS_DMARC_VALUE), 'actual' => [], 'valid' => false],
            ],
            'nameServers' => [],
            'cacheUsed' => false,
            'checkedAt' => gmdate('c'),
        ];
    }
    if ($action === 'opendkim_prepare') {
        $domain = requireDomain($params);
        return $summary + [
            'domain' => $domain,
            'selector' => DNS_DKIM_SELECTOR,
            'dnsValue' => DNS_DKIM_VALUE,
            'temporary' => OPENDKIM_MANAGEMENT_MODE === OpenDkimManager::MODE_PER_DOMAIN,
        ];
    }
    if ($action === 'domain_permissions') {
        $prefix = requirePrefix($params);
        $domain = findResource(loadUserDocument($prefix), 'domains', (int) ($params['id'] ?? 0));
        $path = safeRelativePath((string) ($domain['path'] ?? ''));
        return $summary + [
            'prefix' => $prefix,
            'domain' => (string) ($domain['domain'] ?? ''),
            'path' => safeUserPath($prefix, $path),
            'owner' => configuredFilesystemOwner($prefix),
            'group' => USER_WEB_GROUP,
            'recursive' => true,
        ];
    }
    if ($action === 'domain_permissions_all') {
        return $summary + repairAllDomainPermissions(false);
    }
    if (in_array($action, ['domain_create', 'domain_update'], true)) {
        $prefix = requirePrefix($params);
        $domain = requireDomain($params);
        $document = loadUserDocument($prefix);
        if ($action === 'domain_update') findResource($document, 'domains', (int) ($params['id'] ?? 0));
        $path = safeRelativePath((string) ($params['path'] ?? ''));
        $result = $summary + [
            'prefix' => $prefix,
            'domain' => $domain,
            'path' => $path,
            'phpVersion' => requirePhpVersion($params),
        ];
        if (!empty($params['ssl'])) {
            $webRoot = rtrim(safeUserPath($prefix, $path), '/') . '/';
            $includeWww = !empty($params['redirectWww']);
            $result['certbotPreview'] = [
                'dryRun' => certbotCommand($domain, $webRoot, $includeWww, true),
                'production' => certbotCommand($domain, $webRoot, $includeWww, false),
            ];
        }
        return $result;
    }
    if (in_array($action, ['domains_toggle', 'domains_delete'], true)) {
        $record = is_array($params['record'] ?? null) ? $params['record'] : [];
        $prefix = requirePrefix($params);
        $domain = requireDomain($record);
        $stored = findResource(loadUserDocument($prefix), 'domains', (int) ($params['id'] ?? 0));
        if (mb_strtolower((string) ($stored['domain'] ?? '')) !== $domain) throw new RuntimeException('Domain does not belong to user resource');
        if ($action === 'domains_toggle' && empty($record['active'])) safeRelativePath((string) ($record['path'] ?? ''));
        return $summary + ['prefix' => $prefix, 'domain' => $domain];
    }
    if ($action === 'domain_project_cleanup') {
        $prefix = requirePrefix($params);
        $relativePath = safeRelativePath((string) ($params['path'] ?? ''));
        if (basename($relativePath) !== trim(USER_PUBLIC_HTML_DIRECTORY, '/')) throw new RuntimeException('Domain path must end with public_html');
        $projectRelativePath = trim(str_replace('\\', '/', dirname($relativePath)), '/');
        if ($projectRelativePath === '' || $projectRelativePath === '.') throw new RuntimeException('Cannot remove the user root directory');
        foreach (loadUserDocument($prefix)['resources']['domains'] ?? [] as $domain) {
            if (!is_array($domain)) continue;
            $otherPath = safeRelativePath((string) ($domain['path'] ?? ''));
            if ($otherPath === $relativePath || strpos($otherPath, $projectRelativePath . '/') === 0) {
                return $summary + ['prefix' => $prefix, 'path' => $projectRelativePath, 'deleted' => false, 'preserved' => true];
            }
        }
        return $summary + ['prefix' => $prefix, 'path' => $projectRelativePath, 'deleted' => true, 'preserved' => false];
    }
    if (in_array($action, ['database_create', 'database_update'], true)) {
        $prefix = requirePrefix($params);
        $database = requireDatabaseName($prefix, $params);
        requireDatabasePassword($params);
        $document = loadUserDocument($prefix);
        if ($action === 'database_update') {
            $stored = findResource($document, 'databases', (int) ($params['id'] ?? 0));
            if (mb_strtolower((string) ($stored['name'] ?? '')) !== $database) throw new RuntimeException('Database rename is not supported');
        }
        return $summary + ['prefix' => $prefix, 'database' => $database, 'user' => mysqlAccountName($database)];
    }
    if (in_array($action, ['databases_toggle', 'databases_delete'], true)) {
        $prefix = requirePrefix($params);
        $database = requireDatabaseName($prefix, ['record' => $params['record'] ?? []]);
        $stored = findResource(loadUserDocument($prefix), 'databases', (int) ($params['id'] ?? 0));
        if (mb_strtolower((string) ($stored['name'] ?? '')) !== $database) throw new RuntimeException('Database does not belong to user resource');
        return $summary + ['prefix' => $prefix, 'database' => $database];
    }
    if ($action === 'mail_domain_create') {
        $prefix = requirePrefix($params);
        $domain = requireDomain($params);
        requireOwnedDomain($prefix, $domain, !empty($params['pending_domain']));
        $forwardTo = mailboxForwarding($params, 'info@' . $domain);
        if (count($forwardTo) > 1) throw new RuntimeException('Only one whole-domain forwarding address is allowed');
        if ($forwardTo !== [] && substr($forwardTo[0], strrpos($forwardTo[0], '@') + 1) === $domain) throw new RuntimeException('Whole-domain forwarding cannot point to the same domain');
        return $summary + ['prefix' => $prefix, 'domain' => $domain, 'forwardTo' => $forwardTo];
    }
    if (in_array($action, ['create_mailbox', 'mailbox_update', 'mailbox_password'], true)) {
        $address = requireMailbox($params);
        $prefix = requirePrefix($params);
        if (in_array($action, ['create_mailbox', 'mailbox_update'], true)) {
            mailboxAliases($params, $address);
            mailboxForwarding($params, $address);
        }
        if (in_array($action, ['create_mailbox', 'mailbox_password'], true) && (string) ($params['password'] ?? '') === '') throw new RuntimeException('Mailbox password is required');
        if ($action === 'create_mailbox') {
            $domain = requireDomain($params);
            if (substr($address, strrpos($address, '@') + 1) !== $domain) throw new RuntimeException('Mailbox domain mismatch');
            requireOwnedDomain($prefix, $domain, !empty($params['pending_domain']));
        } elseif ($action === 'mailbox_update') {
            findResource(loadUserDocument($prefix), 'mail', (int) ($params['id'] ?? 0));
            requireOwnedDomain($prefix, substr($address, strrpos($address, '@') + 1));
        } else {
            $owned = false;
            foreach (loadUserDocument($prefix)['resources']['mail'] ?? [] as $row) if (mb_strtolower((string) ($row['address'] ?? '')) === $address) $owned = true;
            if (!$owned) throw new RuntimeException('Mailbox does not belong to user');
        }
        return $summary + ['prefix' => $prefix, 'email' => $address];
    }
    if (in_array($action, ['mail_toggle', 'mail_delete'], true)) {
        $record = is_array($params['record'] ?? null) ? $params['record'] : [];
        $prefix = requirePrefix($params);
        $address = requireMailbox(['email' => $record['address'] ?? '']);
        $stored = findResource(loadUserDocument($prefix), 'mail', (int) ($params['id'] ?? 0));
        if (mb_strtolower((string) ($stored['address'] ?? '')) !== $address) throw new RuntimeException('Mailbox does not belong to user resource');
        return $summary + ['prefix' => $prefix, 'email' => $address];
    }
    if (in_array($action, ['mail_migration_test', 'mail_migration_start'], true)) {
        $source = MailMigrationRuntime::validateSource($params);
        $destination = mailMigrationMailbox($params);
        if ($action === 'mail_migration_start') throw new RuntimeException('Background mail migration is available only on TASK/PROD Linux');
        return $summary + [
            'available' => false,
            'status' => 'failed',
            'sourceHost' => $source['source_host'],
            'destination' => $destination['address'],
            'error' => 'imapsync connection tests run only on TASK/PROD Linux',
        ];
    }
    throw new RuntimeException('Unknown root action');
}

function executeProdAction(string $action, array $params)
{
    if ($action === 'server_diagnostics') return ServerDiagnostics::fromConfig()->inspect();
    if ($action === 'user_create') return createUser($params);
    if ($action === 'user_update') return updateUser($params);
    if ($action === 'user_toggle') return toggleUser($params);
    if ($action === 'user_delete') return deleteUser($params);
    if ($action === 'domain_create') return provisionDomain($params, false);
    if ($action === 'domain_update') return provisionDomain($params, true);
    if ($action === 'domain_permissions') return repairDomainPermissions($params);
    if ($action === 'domain_permissions_all') return repairAllDomainPermissions(true);
    if ($action === 'domains_toggle') return toggleDomain($params);
    if ($action === 'domains_delete') return deleteDomain($params);
    if ($action === 'domain_project_cleanup') return cleanupUnusedDomainProject($params);
    if ($action === 'database_create') return createDatabase($params);
    if ($action === 'database_update') return updateDatabase($params);
    if ($action === 'databases_toggle') return toggleDatabase($params);
    if ($action === 'databases_delete') return deleteDatabase($params);
    if ($action === 'mail_domain_create') return createMailDomain($params);
    if ($action === 'create_mailbox') return createMailbox($params);
    if ($action === 'mailbox_update') return updateMailbox($params);
    if ($action === 'mail_toggle') return toggleMailbox($params);
    if ($action === 'mail_delete') return deleteMailbox($params);
    if ($action === 'mailbox_password') return changeMailboxPassword($params);
    if ($action === 'mail_migration_test') return testMailMigration($params);
    if ($action === 'mail_migration_start') return startMailMigration($params);
    if ($action === 'apache_vhosts_rebuild') return rebuildApacheVhosts(requirePrefix($params));
    if ($action === 'apache_vhosts_remove') return removeApacheVhosts(requirePrefix($params));
    if ($action === 'apache_vhosts_refresh_all') return refreshAllApacheVhosts(!empty($params['continue_after_invalid_current']));
    if ($action === 'apache_vhost_check') return apacheVhostCheck($params);
    if ($action === 'opendkim_check') return opendkimCheck($params);
    if ($action === 'opendkim_prepare') return openDkimManager()->prepare(requireDomain($params));
    throw new RuntimeException('Unknown root action');
}

if (PHP_SAPI !== 'cli') rootFail('CLI access only');
$json = stream_get_contents(STDIN, ROOT_RESPONSE_MAX_BYTES + 1);
if (strlen((string) $json) > ROOT_RESPONSE_MAX_BYTES) rootFail('Root request is too large');
$request = json_decode((string) $json, true);
if (!is_array($request)) rootFail('Invalid JSON');
$action = trim((string) ($request['action'] ?? ''));
$params = is_array($request['params'] ?? null) ? $request['params'] : [];
$meta = is_array($request['meta'] ?? null) ? $request['meta'] : [];
if (!in_array($action, ROOT_ALLOWED_ACTIONS, true)) rootFail('Unknown root action');

try {
    if (ROOT_LOG_ENABLED && ($meta['actor_role'] ?? '') === 'user') {
        $rootAuditLog = new RootAuditLog(ROOT_LOG_DIRECTORY, ROOT_LOG_RETENTION_DAYS, ROOT_LOG_ENTRY_MAX_BYTES);
        $rootAuditContext = $rootAuditLog->start($action, $params, $meta);
    }
    if (!PROD) rootResponse(true, validateLocalAction($action, $params));
    if ($action === 'server_diagnostics') rootResponse(true, executeProdAction($action, $params));
    $prefix = isset($params['prefix']) ? mb_strtolower(trim((string) $params['prefix'])) : '';
    $scope = $prefix !== '' && validPrefix($prefix) ? 'user_' . $prefix : 'global_' . $action;
    $result = withRootLock($scope, static function () use ($action, $params) { return executeProdAction($action, $params); });
    rootResponse(true, $result);
} catch (Throwable $exception) {
    rootFail($exception->getMessage(), $exception);
}
