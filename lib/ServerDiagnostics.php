<?php
declare(strict_types=1);

/**
 * Read-only comparison of ImagoPanel configuration with the current host.
 *
 * The diagnostics intentionally never return configured credentials. Commands
 * are executed without a shell and only use fixed arguments assembled here.
 */
final class ServerDiagnostics
{
    /** @var callable */
    private $runner;

    /** @var int */
    private $timeoutSeconds;

    /** @var array<int,array<string,mixed>> */
    private $checks = [];

    public function __construct(?callable $runner = null, int $timeoutSeconds = 8)
    {
        $this->runner = $runner ?? [$this, 'runCommand'];
        $this->timeoutSeconds = max(1, $timeoutSeconds);
    }

    public static function fromConfig(): self
    {
        $timeout = defined('SERVER_DIAGNOSTICS_TIMEOUT_SECONDS')
            ? (int) constant('SERVER_DIAGNOSTICS_TIMEOUT_SECONDS')
            : 8;
        return new self(null, $timeout);
    }

    /** @return array<string,mixed> */
    public function inspect(): array
    {
        $this->checks = [];
        $this->checkConfiguration();
        $this->checkPhpRuntime();
        $this->checkExecutables();
        $this->checkServices();
        $this->checkDatabases();
        $this->checkApachePhpVersions();
        $this->checkPaths();
        $this->checkOpenDkim();
        $this->checkDnsProviders();

        $summary = ['ok' => 0, 'warning' => 0, 'error' => 0, 'total' => count($this->checks)];
        foreach ($this->checks as $check) {
            $status = (string) ($check['status'] ?? 'warning');
            if (isset($summary[$status])) $summary[$status]++;
        }

        return [
            'checkedAt' => gmdate('c'),
            'environment' => defined('WIN') && WIN ? 'Windows' : (defined('TASK') && TASK ? 'TASK' : 'PROD'),
            'summary' => $summary,
            'checks' => $this->checks,
        ];
    }

    private function checkConfiguration(): void
    {
        $required = [
            'PANEL_NAME', 'PANEL_TIMEZONE', 'IMAGOPANEL_INSTALL_DIRECTORY', 'DATA_DIRECTORY', 'STATUS_DIRECTORY',
            'ROOT_SCRIPT_PATH', 'ROOT_PHP_BINARY', 'APACHE_DEFAULT_PHP_VERSION',
            'APACHE_PHP_VERSIONS', 'MYSQL_ADMIN_HOST', 'MYSQL_ADMIN_PORT',
            'POSTFIXADMIN_DB_HOST', 'POSTFIXADMIN_DB_NAME', 'USER_WEB_ROOT_DIRECTORY',
        ];
        $missing = [];
        foreach ($required as $name) {
            if (!defined($name)) $missing[] = $name;
        }
        $this->add(
            'Configuration',
            'required_constants',
            'Required configuration values',
            $missing === [] ? 'ok' : 'error',
            $missing === [] ? 'All required diagnostics inputs are defined.' : 'Required constants are missing.',
            $missing === [] ? [] : ['missing' => implode(', ', $missing)]
        );

        $secretNames = [
            'ROOT_PASSWORD_HASH', 'REMEMBER_LOGIN_SECRET', 'DOMAIN_TOOL_AUTH_SECRET',
            'DOMAIN_TOOL_PHPMYADMIN_BLOWFISH_SECRET', 'MYSQL_ADMIN_PASSWORD',
            'POSTFIXADMIN_DB_PASSWORD',
        ];
        $invalid = [];
        foreach ($secretNames as $name) {
            if (!defined($name) || $this->looksLikePlaceholder(constant($name))) $invalid[] = $name;
        }
        $this->add(
            'Configuration',
            'private_values',
            'Private configuration values',
            $invalid === [] ? 'ok' : 'error',
            $invalid === [] ? 'Required private values are configured; their contents are hidden.' : 'One or more private values are missing or still use placeholders.',
            $invalid === [] ? [] : ['invalid' => implode(', ', $invalid)]
        );

        $configPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'config.php';
        $this->checkFilePermissions('Configuration', 'config_permissions', 'Private config.php permissions', $configPath, true);
        $this->checkFilePermissions('Configuration', 'root_script_permissions', 'Privileged helper permissions', defined('ROOT_SCRIPT_PATH') ? (string) ROOT_SCRIPT_PATH : '', false);
    }

    private function checkPhpRuntime(): void
    {
        $status = PHP_MAJOR_VERSION === 7 && PHP_MINOR_VERSION === 4 ? 'ok' : 'error';
        $this->add(
            'PHP',
            'runtime_version',
            'Root PHP CLI runtime',
            $status,
            $status === 'ok' ? 'PHP 7.4 compatibility runtime is active.' : 'The privileged helper is not running on PHP 7.4.',
            ['version' => PHP_VERSION, 'sapi' => PHP_SAPI]
        );

        $required = defined('SERVER_DIAGNOSTICS_REQUIRED_PHP_EXTENSIONS') && is_array(SERVER_DIAGNOSTICS_REQUIRED_PHP_EXTENSIONS)
            ? SERVER_DIAGNOSTICS_REQUIRED_PHP_EXTENSIONS
            : ['curl', 'json', 'mbstring', 'openssl', 'PDO', 'pdo_mysql'];
        foreach ($required as $extension) {
            $name = trim((string) $extension);
            if ($name === '') continue;
            $loaded = extension_loaded($name);
            $this->add(
                'PHP',
                'extension_' . preg_replace('/[^a-z0-9]+/i', '_', strtolower($name)),
                'PHP extension: ' . $name,
                $loaded ? 'ok' : 'error',
                $loaded ? 'Extension is loaded.' : 'Required extension is not loaded.'
            );
        }
    }

    private function checkExecutables(): void
    {
        $entries = [
            ['Apache httpd', 'APACHE_HTTPD_BINARY', true, ['-v'], '2.4.37'],
            ['systemctl', 'APACHE_SYSTEMCTL_BINARY', !(defined('WIN') && WIN), ['--version'], '239'],
            ['PHP CLI', 'ROOT_PHP_BINARY', true, ['-v'], '7.4.0'],
            ['sudo', 'ROOT_SUDO_BINARY', !(defined('WIN') && WIN), ['--version'], '1.8.29'],
            ['DNS dig', 'DNS_DIG_BINARY', !(defined('WIN') && WIN), ['-v'], ''],
            ['OpenSSL', 'CERTBOT_OPENSSL_BINARY', !(defined('WIN') && WIN), ['version'], '1.1.1'],
            ['Certbot', 'CERTBOT_BINARY', false, ['--version'], '1.0.0'],
            ['chown', 'FILESYSTEM_CHOWN_BINARY', !(defined('WIN') && WIN), ['--version'], '8.30'],
        ];
        if (defined('MAIL_MIGRATION_ENABLED') && MAIL_MIGRATION_ENABLED) {
            $entries[] = ['imapsync', 'MAIL_MIGRATION_IMAPSYNC_BINARY', true, ['--version'], '2.229'];
            $entries[] = ['systemd-run', 'MAIL_MIGRATION_SYSTEMD_RUN_BINARY', true, ['--version'], '239'];
        }
        if (defined('UNIX_ACCOUNTS_ENABLED') && UNIX_ACCOUNTS_ENABLED) {
            $entries[] = ['useradd', 'UNIX_USERADD_BINARY', true, ['--version'], ''];
            $entries[] = ['userdel', 'UNIX_USERDEL_BINARY', true, ['--version'], ''];
            $entries[] = ['id', 'UNIX_ID_BINARY', true, ['--version'], ''];
        }
        if (defined('SYSTEM_QUOTAS_ENABLED') && SYSTEM_QUOTAS_ENABLED) {
            $entries[] = ['setquota', 'SYSTEM_SETQUOTA_BINARY', true, ['--version'], ''];
        }

        foreach ($entries as $entry) {
            [$label, $constantName, $required, $arguments, $minimum] = $entry;
            $path = defined($constantName) ? trim((string) constant($constantName)) : '';
            $this->checkExecutable($label, $constantName, $path, (bool) $required, $arguments, (string) $minimum);
        }
    }

    private function checkServices(): void
    {
        $systemctl = defined('APACHE_SYSTEMCTL_BINARY') ? trim((string) APACHE_SYSTEMCTL_BINARY) : '';
        $services = defined('SERVER_DIAGNOSTICS_SERVICE_NAMES') && is_array(SERVER_DIAGNOSTICS_SERVICE_NAMES)
            ? SERVER_DIAGNOSTICS_SERVICE_NAMES
            : [];
        if ($services === []) {
            $this->add('Services', 'service_names', 'Configured service names', 'warning', 'No service names are configured for diagnostics.');
            return;
        }
        if ($systemctl === '' || !is_executable($systemctl)) {
            $this->add('Services', 'systemctl_services', 'Service state checks', 'error', 'The configured systemctl binary is not executable.');
            return;
        }
        foreach ($services as $key => $serviceName) {
            $name = trim((string) $serviceName);
            if ($name === '') {
                $this->add('Services', 'service_' . $key, ucfirst((string) $key), 'warning', 'Service check is disabled because its configured name is empty.');
                continue;
            }
            $result = $this->call([$systemctl, 'is-active', $name]);
            $active = (int) $result['exitCode'] === 0 && trim((string) $result['stdout']) === 'active';
            $this->add(
                'Services',
                'service_' . preg_replace('/[^a-z0-9]+/i', '_', (string) $key),
                ucfirst((string) $key) . ' service',
                $active ? 'ok' : 'error',
                $active ? 'Configured service is active.' : 'Configured service is not active or was not found.',
                ['service' => $name, 'state' => $this->cleanOutput((string) ($result['stdout'] ?: $result['stderr'] ?: 'unknown'))]
            );
        }
    }

    private function checkDatabases(): void
    {
        $this->checkDatabaseConnection(
            'mysql_admin',
            'MariaDB/MySQL administrative connection',
            defined('MYSQL_ADMIN_HOST') ? (string) MYSQL_ADMIN_HOST : '',
            defined('MYSQL_ADMIN_PORT') ? (int) MYSQL_ADMIN_PORT : 3306,
            '',
            defined('MYSQL_ADMIN_USER') ? (string) MYSQL_ADMIN_USER : '',
            defined('MYSQL_ADMIN_PASSWORD') ? (string) MYSQL_ADMIN_PASSWORD : ''
        );
        $this->checkDatabaseConnection(
            'postfix_database',
            'PostfixAdmin database connection',
            defined('POSTFIXADMIN_DB_HOST') ? (string) POSTFIXADMIN_DB_HOST : '',
            defined('POSTFIXADMIN_DB_PORT') ? (int) POSTFIXADMIN_DB_PORT : 3306,
            defined('POSTFIXADMIN_DB_NAME') ? (string) POSTFIXADMIN_DB_NAME : '',
            defined('POSTFIXADMIN_DB_USER') ? (string) POSTFIXADMIN_DB_USER : '',
            defined('POSTFIXADMIN_DB_PASSWORD') ? (string) POSTFIXADMIN_DB_PASSWORD : ''
        );
    }

    private function checkApachePhpVersions(): void
    {
        $versions = defined('APACHE_PHP_VERSIONS') && is_array(APACHE_PHP_VERSIONS) ? APACHE_PHP_VERSIONS : [];
        $defaultId = defined('APACHE_DEFAULT_PHP_VERSION') ? (string) APACHE_DEFAULT_PHP_VERSION : '';
        if ($versions === []) {
            $this->add('Apache / PHP-FPM', 'php_versions', 'Configured PHP-FPM versions', 'error', 'APACHE_PHP_VERSIONS is empty.');
            return;
        }
        $seen = [];
        foreach ($versions as $index => $version) {
            if (!is_array($version)) {
                $this->add('Apache / PHP-FPM', 'php_version_' . $index, 'PHP-FPM entry #' . ($index + 1), 'error', 'Configuration entry is not an array.');
                continue;
            }
            $id = trim((string) ($version['id'] ?? ''));
            $label = trim((string) ($version['label'] ?? $id));
            $include = trim((string) ($version['include'] ?? ''));
            $fallback = is_array($version['fallback'] ?? null) ? $version['fallback'] : [];
            if ($id === '' || isset($seen[$id])) {
                $this->add('Apache / PHP-FPM', 'php_version_' . $index, $label ?: 'PHP-FPM entry', 'error', $id === '' ? 'Version ID is empty.' : 'Version ID is duplicated.');
                continue;
            }
            $seen[$id] = true;
            $isDefault = hash_equals($defaultId, $id);
            $source = '';
            $socket = '';
            $status = 'ok';
            $summary = 'Apache include exists and the PHP-FPM socket is available.';
            if ($include !== '' && is_file($include) && is_readable($include)) {
                $source = (string) file_get_contents($include);
            } elseif ($fallback !== []) {
                $source = implode("\n", array_map('strval', $fallback));
                $status = 'warning';
                $summary = $include === '' ? 'Using the configured fallback block.' : 'Apache include is missing; the configured fallback block will be used.';
            } else {
                $status = 'error';
                $summary = 'Neither a readable Apache include nor a fallback block is available.';
            }
            if ($source !== '' && preg_match('/proxy:unix:([^|"\s]+)\|fcgi:/i', $source, $match) === 1) {
                $socket = trim($match[1]);
                if (!file_exists($socket)) {
                    $status = $isDefault ? 'error' : 'warning';
                    $summary = 'The configured PHP-FPM socket is missing.';
                }
            } elseif ($source !== '') {
                $status = $isDefault ? 'error' : 'warning';
                $summary = 'No PHP-FPM socket could be identified in the configured handler.';
            }
            $this->add(
                'Apache / PHP-FPM',
                'php_version_' . preg_replace('/[^a-z0-9]+/i', '_', $id),
                ($label !== '' ? $label : 'PHP ' . $id) . ($isDefault ? ' (default)' : ''),
                $status,
                $summary,
                ['include' => $include !== '' ? $include : '(fallback only)', 'socket' => $socket !== '' ? $socket : '(not detected)']
            );
        }
        if (!isset($seen[$defaultId])) {
            $this->add('Apache / PHP-FPM', 'php_default', 'Default PHP version', 'error', 'APACHE_DEFAULT_PHP_VERSION does not exist in APACHE_PHP_VERSIONS.', ['configuredId' => $defaultId]);
        }

        $httpd = defined('APACHE_HTTPD_BINARY') ? trim((string) APACHE_HTTPD_BINARY) : '';
        if ($httpd !== '' && is_executable($httpd)) {
            $result = $this->call([$httpd, '-t']);
            $ok = (int) $result['exitCode'] === 0;
            $output = $this->cleanOutput((string) ($result['stderr'] ?: $result['stdout']));
            $hasWarnings = $ok && preg_match('/(?:\bwarning\b|\[[^\]]*:warn\])/i', $output) === 1;
            $this->add(
                'Apache / PHP-FPM',
                'apache_syntax',
                'Apache configuration syntax',
                !$ok ? 'error' : ($hasWarnings ? 'warning' : 'ok'),
                !$ok ? 'httpd -t reported a configuration error.' : ($hasWarnings ? 'Apache syntax is valid, but httpd reported warnings.' : 'httpd -t completed successfully.'),
                ['output' => $output]
            );
        }
    }

    private function checkPaths(): void
    {
        $paths = [
            ['ImagoPanel installation root', 'IMAGOPANEL_INSTALL_DIRECTORY', true, true],
            ['Control data', 'DATA_DIRECTORY', true, true],
            ['Collected status data', 'STATUS_DIRECTORY', true, true],
            ['Apache vhost directory', 'APACHE_VHOST_DIRECTORY', !(defined('WIN') && WIN), true],
            ['User web root', 'USER_WEB_ROOT_DIRECTORY', !(defined('WIN') && WIN), true],
            ['Root lock directory', 'ROOT_LOCK_DIRECTORY', true, true],
            ['Root audit log directory', 'ROOT_LOG_DIRECTORY', defined('ROOT_LOG_ENABLED') && ROOT_LOG_ENABLED, true],
            ['Domain-tool logs', 'DOMAIN_TOOL_LOG_DIRECTORY', true, true],
            ['Domain-tool state', 'DOMAIN_TOOL_STATE_DIRECTORY', true, true],
            ['phpMyAdmin directory', 'DOMAIN_TOOL_PHPMYADMIN_DIRECTORY', true, false],
            ['File Manager directory', 'DOMAIN_TOOL_FILEMANAGER_DIRECTORY', true, false],
            ['File Editor directory', 'DOMAIN_TOOL_FILEEDITOR_DIRECTORY', true, false],
        ];
        if (defined('MAIL_MIGRATION_ENABLED') && MAIL_MIGRATION_ENABLED) {
            foreach (['MAIL_MIGRATION_RUNTIME_DIRECTORY', 'MAIL_MIGRATION_JOB_DIRECTORY', 'MAIL_MIGRATION_CREDENTIAL_DIRECTORY', 'MAIL_MIGRATION_TEMP_DIRECTORY', 'MAIL_MIGRATION_LOG_DIRECTORY', 'MAIL_MIGRATION_REPORT_DIRECTORY'] as $name) {
                $paths[] = [ucwords(strtolower(str_replace('_', ' ', $name))), $name, true, true];
            }
        }
        foreach ($paths as $entry) {
            [$label, $constantName, $required, $needsWrite] = $entry;
            $path = defined($constantName) ? trim((string) constant($constantName)) : '';
            $this->checkDirectory((string) $label, (string) $constantName, $path, (bool) $required, (bool) $needsWrite);
        }

        $sslOptions = defined('APACHE_SSL_OPTIONS_FILE') ? trim((string) APACHE_SSL_OPTIONS_FILE) : '';
        if ($sslOptions !== '') {
            $exists = is_file($sslOptions) && is_readable($sslOptions);
            $this->add('Paths and permissions', 'ssl_options', 'Apache SSL options file', $exists ? 'ok' : 'warning', $exists ? 'Configured SSL options file is readable.' : 'Configured SSL options file is missing or unreadable.', ['path' => $sslOptions]);
        }
    }

    private function checkOpenDkim(): void
    {
        $mode = defined('OPENDKIM_MANAGEMENT_MODE') ? trim((string) OPENDKIM_MANAGEMENT_MODE) : '';
        $validModes = ['shared_key_all_domains', 'shared_key_managed_domains', 'per_domain_keys'];
        $this->add(
            'OpenDKIM',
            'opendkim_mode',
            'OpenDKIM management mode',
            in_array($mode, $validModes, true) ? 'ok' : 'error',
            in_array($mode, $validModes, true) ? 'Management mode is supported.' : 'Configured management mode is invalid.',
            ['mode' => $mode]
        );
        $requiredFiles = [];
        if ($mode === 'shared_key_managed_domains') {
            $requiredFiles['SigningDomains'] = defined('OPENDKIM_SIGNING_DOMAINS_FILE') ? (string) OPENDKIM_SIGNING_DOMAINS_FILE : '';
        } elseif ($mode === 'per_domain_keys') {
            $requiredFiles['KeyTable'] = defined('OPENDKIM_KEY_TABLE_FILE') ? (string) OPENDKIM_KEY_TABLE_FILE : '';
            $requiredFiles['SigningTable'] = defined('OPENDKIM_SIGNING_TABLE_FILE') ? (string) OPENDKIM_SIGNING_TABLE_FILE : '';
        }
        foreach ($requiredFiles as $label => $path) {
            $exists = $path !== '' && is_file($path) && is_readable($path);
            $this->add('OpenDKIM', 'opendkim_' . strtolower($label), 'OpenDKIM ' . $label, $exists ? 'ok' : 'error', $exists ? 'Configured table is readable.' : 'Configured table is missing or unreadable.', ['path' => $path]);
        }
        if ($mode === 'per_domain_keys') {
            $path = defined('OPENDKIM_KEYS_DIRECTORY') ? (string) OPENDKIM_KEYS_DIRECTORY : '';
            $this->checkDirectory('OpenDKIM key directory', 'OPENDKIM_KEYS_DIRECTORY', $path, true, true, 'OpenDKIM');
        }
    }

    private function checkDnsProviders(): void
    {
        $providers = [
            ['Hetzner', 'DNS_HETZNER_API_URL', ['DNS_HETZNER_API_TOKEN'], 'DNS_HETZNER_ALLOWED_API_HOSTS'],
            ['Joker.com', 'DNS_JOKER_API_URL', ['DNS_JOKER_API_TOKEN'], 'DNS_JOKER_ALLOWED_API_HOSTS'],
            ['REG.RU', 'DNS_REGRU_API_URL', ['DNS_REGRU_API_USERNAME', 'DNS_REGRU_API_PASSWORD'], 'DNS_REGRU_ALLOWED_API_HOSTS'],
            ['Namecheap', 'DNS_NAMECHEAP_API_URL', ['DNS_NAMECHEAP_API_USERNAME', 'DNS_NAMECHEAP_API_KEY', 'DNS_NAMECHEAP_CLIENT_IP'], 'DNS_NAMECHEAP_ALLOWED_API_HOSTS'],
            ['Internet.bs', 'DNS_INTERNETBS_API_URL', ['DNS_INTERNETBS_API_KEY', 'DNS_INTERNETBS_API_PASSWORD'], 'DNS_INTERNETBS_ALLOWED_API_HOSTS'],
        ];
        foreach ($providers as $provider) {
            [$label, $urlName, $credentialNames, $hostsName] = $provider;
            $url = defined($urlName) ? trim((string) constant($urlName)) : '';
            $host = strtolower((string) parse_url($url, PHP_URL_HOST));
            $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
            $allowedHosts = defined($hostsName) && is_array(constant($hostsName)) ? array_map('strtolower', constant($hostsName)) : [];
            $urlValid = $scheme === 'https' && $host !== '' && in_array($host, $allowedHosts, true);
            $credentialsConfigured = true;
            foreach ($credentialNames as $name) {
                if (!defined($name) || $this->looksLikePlaceholder(constant($name))) $credentialsConfigured = false;
            }
            $status = $urlValid ? ($credentialsConfigured ? 'ok' : 'warning') : 'error';
            $summary = !$urlValid
                ? 'The configured API URL is not an allowed HTTPS endpoint.'
                : ($credentialsConfigured ? 'API endpoint and global credentials are configured.' : 'API endpoint is valid; global credentials are not configured. Per-user connections may still be used.');
            $this->add('DNS providers', 'dns_' . preg_replace('/[^a-z0-9]+/i', '_', strtolower($label)), $label, $status, $summary, ['endpointHost' => $host !== '' ? $host : '(missing)', 'credentials' => $credentialsConfigured ? 'configured' : 'not configured']);
        }
    }

    private function checkExecutable(string $label, string $id, string $path, bool $required, array $arguments, string $minimum): void
    {
        $exists = $path !== '' && is_file($path) && is_executable($path);
        if (!$exists) {
            $status = $required ? 'error' : 'warning';
            $this->add('Executables', strtolower($id), $label, $status, $required ? 'Configured executable is missing or not executable.' : 'Optional executable is not available.', ['path' => $path !== '' ? $path : '(not configured)']);
            return;
        }
        $result = $arguments === [] ? ['exitCode' => 0, 'stdout' => '', 'stderr' => ''] : $this->call(array_merge([$path], $arguments));
        $output = $this->cleanOutput((string) ($result['stdout'] ?: $result['stderr']));
        $status = (int) $result['exitCode'] === 0 ? 'ok' : 'warning';
        $summary = $status === 'ok' ? 'Configured executable is available.' : 'Executable exists but its version check returned a non-zero status.';
        if ($status === 'ok' && $minimum !== '') {
            $version = $this->extractVersion($output);
            if ($version !== '' && version_compare($version, $minimum, '<')) {
                $status = 'error';
                $summary = 'Installed version is below the documented minimum.';
            }
        }
        $details = ['path' => $path];
        if ($minimum !== '') $details['minimum'] = $minimum;
        if ($output !== '') $details['versionOutput'] = $output;
        $this->add('Executables', strtolower($id), $label, $status, $summary, $details);
    }

    private function checkDatabaseConnection(string $id, string $label, string $host, int $port, string $database, string $user, string $password): void
    {
        if ($host === '' || $user === '' || $this->looksLikePlaceholder($password)) {
            $this->add('Databases', $id, $label, 'error', 'Connection settings are incomplete or still use placeholders.');
            return;
        }
        $dsn = 'mysql:host=' . $host . ';port=' . max(1, $port) . ($database !== '' ? ';dbname=' . $database : '') . ';charset=utf8mb4';
        try {
            $pdo = new PDO($dsn, $user, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => $this->timeoutSeconds,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            $version = (string) $pdo->query('SELECT VERSION()')->fetchColumn();
            $this->add('Databases', $id, $label, 'ok', 'Read-only connection test succeeded.', ['serverVersion' => $this->cleanOutput($version), 'database' => $database !== '' ? $database : '(server connection)']);
        } catch (Throwable $exception) {
            $this->add('Databases', $id, $label, 'error', 'Read-only connection test failed.', ['error' => $this->cleanOutput($exception->getMessage())]);
        }
    }

    private function checkDirectory(string $label, string $id, string $path, bool $required, bool $needsWrite, string $category = 'Paths and permissions'): void
    {
        if ($path === '' || !is_dir($path)) {
            $this->add($category, strtolower($id), $label, $required ? 'error' : 'warning', $required ? 'Configured directory is missing.' : 'Optional directory is not configured or does not exist.', ['path' => $path !== '' ? $path : '(not configured)']);
            return;
        }
        $readable = is_readable($path);
        $writable = !$needsWrite || is_writable($path);
        $status = $readable && $writable ? 'ok' : 'error';
        $summary = $status === 'ok' ? 'Configured directory is available with the required access.' : 'Configured directory does not provide the required access.';
        $details = ['path' => $path, 'readable' => $readable ? 'yes' : 'no', 'writable' => is_writable($path) ? 'yes' : 'no'];
        $permissions = $this->permissionString($path);
        if ($permissions !== '') $details['permissions'] = $permissions;
        $this->add($category, strtolower($id), $label, $status, $summary, $details);
    }

    private function checkFilePermissions(string $category, string $id, string $label, string $path, bool $warnWorldReadable): void
    {
        if ($path === '' || !is_file($path)) {
            $this->add($category, $id, $label, 'error', 'Configured file is missing.', ['path' => $path !== '' ? $path : '(not configured)']);
            return;
        }
        $mode = fileperms($path);
        $worldWritable = is_int($mode) && ($mode & 0002) !== 0;
        $worldReadable = is_int($mode) && ($mode & 0004) !== 0;
        $status = $worldWritable ? 'error' : ($warnWorldReadable && $worldReadable ? 'warning' : 'ok');
        $summary = $worldWritable
            ? 'File is writable by other users.'
            : ($warnWorldReadable && $worldReadable ? 'Private configuration is readable by other users.' : 'File permissions do not allow writes by other users.');
        $this->add($category, $id, $label, $status, $summary, ['path' => $path, 'permissions' => $this->permissionString($path)]);
    }

    /** @return array<string,mixed> */
    private function call(array $command): array
    {
        try {
            $result = call_user_func($this->runner, $command, $this->timeoutSeconds);
            return is_array($result) ? $result + ['exitCode' => -1, 'stdout' => '', 'stderr' => ''] : ['exitCode' => -1, 'stdout' => '', 'stderr' => 'Invalid command result'];
        } catch (Throwable $exception) {
            return ['exitCode' => -1, 'stdout' => '', 'stderr' => $exception->getMessage()];
        }
    }

    /** @return array<string,mixed> */
    private function runCommand(array $command, int $timeoutSeconds): array
    {
        if ($command === [] || trim((string) $command[0]) === '') return ['exitCode' => -1, 'stdout' => '', 'stderr' => 'Command is not configured'];
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), null, ['bypass_shell' => true]);
        if (!is_resource($process)) return ['exitCode' => -1, 'stdout' => '', 'stderr' => 'Cannot start command'];
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = '';
        $stderr = '';
        $started = microtime(true);
        $exitCode = -1;
        while (true) {
            $stdout .= (string) stream_get_contents($pipes[1]);
            $stderr .= (string) stream_get_contents($pipes[2]);
            $state = proc_get_status($process);
            if (!$state['running']) {
                $exitCode = (int) $state['exitcode'];
                break;
            }
            if (microtime(true) - $started >= $timeoutSeconds) {
                proc_terminate($process);
                $stderr .= "\nCommand timed out";
                break;
            }
            usleep(20000);
        }
        $stdout .= (string) stream_get_contents($pipes[1]);
        $stderr .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $closed = proc_close($process);
        if ($exitCode < 0 && $closed >= 0) $exitCode = $closed;
        return [
            'exitCode' => $exitCode,
            'stdout' => substr($stdout, 0, 4096),
            'stderr' => substr($stderr, 0, 4096),
        ];
    }

    private function looksLikePlaceholder($value): bool
    {
        $text = trim((string) $value);
        if ($text === '') return true;
        return preg_match('/(?:change[_ -]?me|example\.(?:com|org|net)|placeholder|your[_ -]|replace[_ -]?me)/i', $text) === 1;
    }

    private function extractVersion(string $output): string
    {
        return preg_match('/(?<!\d)(\d+(?:\.\d+){0,3})(?!\d)/', $output, $match) === 1 ? $match[1] : '';
    }

    private function permissionString(string $path): string
    {
        $mode = @fileperms($path);
        return is_int($mode) ? sprintf('%04o', $mode & 07777) : '';
    }

    private function cleanOutput(string $value): string
    {
        $value = preg_replace('/(?i)(password|passwd|api[-_ ]?key|access[-_ ]?token|secret)(\s*[=:]\s*)[^\s,;]+/', '$1$2[redacted]', $value) ?? '';
        $value = preg_replace('#([a-z][a-z0-9+.-]*://)[^/@\s]+:[^/@\s]+@#i', '$1[redacted]@', $value) ?? '';
        $value = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]+/', ' ', $value) ?? '');
        return mb_substr($value, 0, 1500);
    }

    /** @param array<string,string> $details */
    private function add(string $category, string $id, string $label, string $status, string $summary, array $details = []): void
    {
        if (!in_array($status, ['ok', 'warning', 'error'], true)) $status = 'warning';
        $safeDetails = [];
        foreach ($details as $key => $value) {
            $safeDetails[(string) $key] = $this->cleanOutput((string) $value);
        }
        $this->checks[] = [
            'category' => $category,
            'id' => $id,
            'label' => $label,
            'status' => $status,
            'summary' => $this->cleanOutput($summary),
            'actionCode' => $status === 'ok' ? '' : $this->actionCode($category, $id),
            'details' => $safeDetails,
        ];
    }

    private function actionCode(string $category, string $id): string
    {
        if (strpos($id, 'mail_migration_') === 0 && substr($id, -10) === '_directory') return 'mailMigrationDirectory';
        if (in_array($id, ['config_permissions', 'root_script_permissions'], true)) return 'filePermissions';
        if ($id === 'apache_syntax') return 'apache';
        if ($id === 'ssl_options') return 'file';
        if ($category === 'Configuration') return 'configuration';
        if ($category === 'PHP') return 'php';
        if ($category === 'Executables') return 'executable';
        if ($category === 'Services') return 'service';
        if ($category === 'Databases') return 'database';
        if ($category === 'Apache / PHP-FPM') return 'phpFpm';
        if ($category === 'Paths and permissions') return 'directory';
        if ($category === 'OpenDKIM') return 'openDkim';
        if ($category === 'DNS providers') return 'dnsProvider';
        return 'review';
    }
}
