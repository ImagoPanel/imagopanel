<?php
/**
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026 SIA TASK.LV
 *
 * Standalone ImagoPanel access adapter for the bundled phpMyAdmin distribution.
 * This file is original integration code and intentionally has no dependency on
 * ImagoPanel's AGPL application code.
 */
declare(strict_types=1);

final class ImagoPanelPhpMyAdminAccessAdapter
{
    private const COOKIE_NAME = 'IMAGOPANELPMAACCESS';
    private const MAX_JSON_BYTES = 16777216;

    /** @var string */
    private $rootDirectory;
    /** @var string */
    private $dataDirectory;
    /** @var string */
    private $stateDirectory;
    /** @var array<string,mixed> */
    private $settings;

    public function __construct(?string $rootDirectory = null)
    {
        $root = $rootDirectory === null ? dirname(__DIR__, 2) : $rootDirectory;
        $resolved = realpath($root);
        if ($resolved === false || !is_dir($resolved)) {
            throw new RuntimeException('Access storage is unavailable.');
        }

        $this->rootDirectory = rtrim($resolved, '/\\');
        $this->stateDirectory = $this->rootDirectory . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'domain-tool-state';
        $this->settings = $this->loadSettings();
        $configuredDataDirectory = (string) ($this->settings['dataDirectory'] ?? ($this->rootDirectory . DIRECTORY_SEPARATOR . 'data'));
        $resolvedDataDirectory = realpath($configuredDataDirectory);
        if ($resolvedDataDirectory === false || !is_dir($resolvedDataDirectory)) {
            throw new RuntimeException('User data storage is unavailable.');
        }
        $this->dataDirectory = rtrim($resolvedDataDirectory, '/\\');
    }

    /** @return array<string,mixed> */
    public static function authorizeRequest(): array
    {
        try {
            return (new self())->authorize();
        } catch (Throwable $error) {
            error_log('ImagoPanel phpMyAdmin access adapter: ' . get_class($error) . ': ' . $error->getMessage());
            self::renderAccessPage('Access denied', 'The database access context is unavailable.', false, '');
        }
    }

    /** @return array<string,mixed> */
    public function authorize(): array
    {
        $host = $this->requestHost();
        $ip = $this->clientIp();
        if ($host === '' || $ip === '') {
            self::renderAccessPage('Access denied', 'The request cannot be validated.', false, $host);
        }

        $databaseLaunch = trim((string) ($_GET['imagopanel_database_launch'] ?? ''));
        $domainLaunch = trim((string) ($_GET['imagopanel_domain_launch'] ?? ''));
        $launchToken = $databaseLaunch !== '' ? $databaseLaunch : $domainLaunch;
        if ($launchToken !== '') {
            $launch = $this->consumeLaunch($launchToken, $host, $ip);
            $selection = is_array($launch) ? $this->selectionFromLaunch($launch) : null;
            $context = is_array($selection) ? $this->resolveSelection($selection, $host, $ip) : null;
            if ($context === null) {
                self::renderAccessPage('Access denied', 'The access link is invalid or has expired.', false, $host);
            }
            $this->createSession($selection, $host, $ip);
            header('Location: ' . self::databaseUrl($context));
            exit;
        }

        $selection = $this->readSession($host, $ip);
        if (is_array($selection)) {
            $context = $this->resolveSelection($selection, $host, $ip);
            if ($context !== null) {
                $this->refreshSession($selection, $host, $ip);
                return $context;
            }
            $this->clearSession();
        }

        $domainMatch = $this->findDomainByHost($host);
        if ($domainMatch === null) {
            self::renderAccessPage('Access denied', 'No active domain is available for this host.', false, $host);
        }

        if ((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'
            && (string) ($_POST['imagopanel_tool_login'] ?? '') === '1') {
            $selection = $this->authenticateDirectLogin(
                $domainMatch,
                trim((string) ($_POST['imagopanel_login'] ?? '')),
                (string) ($_POST['imagopanel_password'] ?? ''),
                $ip
            );
            $context = is_array($selection) ? $this->resolveSelection($selection, $host, $ip) : null;
            if ($context !== null) {
                $this->createSession($selection, $host, $ip);
                header('Location: ' . self::databaseUrl($context));
                exit;
            }
            self::renderAccessPage('Database access', 'Invalid credentials or access conditions.', true, $host);
        }

        if (!$this->ipMayAttemptLogin($domainMatch, $ip)) {
            self::renderAccessPage('Access denied', 'Access from this IP address is not allowed.', false, $host);
        }
        self::renderAccessPage('Database access', '', true, $host);
    }

    /** @return array<string,mixed>|null */
    public function consumeLaunch(string $token, string $host, string $ip): ?array
    {
        if (preg_match('/^[A-Za-z0-9_-]{40,64}$/D', $token) !== 1) {
            return null;
        }
        $directory = $this->stateDirectory . DIRECTORY_SEPARATOR . 'panel-tool-launches';
        $path = $directory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
        if (!$this->isSafeFile($path)) {
            return null;
        }
        $claimed = $path . '.used-' . bin2hex(random_bytes(8));
        if (!@rename($path, $claimed)) {
            return null;
        }
        try {
            $payload = $this->readJson($claimed);
        } finally {
            @unlink($claimed);
        }
        if (!is_array($payload)
            || (int) ($payload['expiresAt'] ?? 0) <= time()
            || !hash_equals((string) ($payload['host'] ?? ''), $host)
            || !hash_equals((string) ($payload['clientIp'] ?? ''), $ip)
            || (string) ($payload['tool'] ?? '') !== 'phpmyadmin') {
            return null;
        }
        return $payload;
    }

    /** @param array<string,mixed> $selection @return array<string,mixed>|null */
    public function resolveSelection(array $selection, string $host, string $ip): ?array
    {
        if (!hash_equals((string) ($selection['host'] ?? ''), $host)
            || !hash_equals((string) ($selection['clientIp'] ?? ''), $ip)
            || (int) ($selection['accessLimit'] ?? 0) <= time()) {
            return null;
        }

        $prefix = (string) ($selection['prefix'] ?? '');
        $document = $this->loadDocument($prefix);
        if ($document === null || empty($document['profile']['active'])) {
            return null;
        }

        $mode = (string) ($selection['mode'] ?? '');
        if ($mode === 'panel_database') {
            $database = $this->findDatabaseById($document, (int) ($selection['databaseId'] ?? 0));
            return $database === null ? null : $this->context($document, null, $database);
        }

        $domain = $this->findDomainById($document, (int) ($selection['domainId'] ?? 0));
        if ($domain === null) {
            return null;
        }

        if ($mode === 'temporary') {
            $access = $this->findAccess($domain, (string) ($selection['accessId'] ?? ''));
            if ($access === null || $this->accessError($access, $ip) !== null) {
                return null;
            }
        } elseif ($mode === 'owner') {
            $currentHash = (string) ($document['profile']['passwordHash'] ?? '');
            if (!$this->isTrustedIp($ip)
                || $currentHash === ''
                || !hash_equals((string) ($selection['credentialFingerprint'] ?? ''), hash('sha256', $currentHash))) {
                return null;
            }
        } elseif ($mode !== 'panel_domain') {
            return null;
        }

        $database = $this->databaseForDomain($document, $domain);
        return $database === null ? null : $this->context($document, $domain, $database);
    }

    public function blowfishSecret(): string
    {
        $path = $this->stateDirectory . DIRECTORY_SEPARATOR . 'phpmyadmin-blowfish.secret';
        if ($this->isSafeFile($path)) {
            $secret = trim((string) file_get_contents($path));
            if (strlen($secret) >= 32 && strlen($secret) <= 128) {
                return $secret;
            }
        }
        $this->ensureDirectory($this->stateDirectory);
        $secret = $this->base64UrlEncode(random_bytes(48));
        $this->writePrivateFile($path, $secret . "\n");
        return $secret;
    }

    /** @param array<string,mixed> $context */
    public static function databaseUrl(array $context): string
    {
        $database = is_array($context['database'] ?? null) ? $context['database'] : [];
        $name = trim((string) ($database['name'] ?? ''));
        return $name === ''
            ? '/phpmyadmin/'
            : '/phpmyadmin/index.php?route=/database/structure&db=' . rawurlencode($name);
    }

    /** @return array<string,mixed> */
    public function settings(): array
    {
        return $this->settings;
    }

    /** @return array<string,mixed> */
    private function loadSettings(): array
    {
        $path = $this->stateDirectory . DIRECTORY_SEPARATOR . 'phpmyadmin-adapter.json';
        $settings = $this->readJson($path);
        if (!is_array($settings) || (int) ($settings['version'] ?? 0) !== 1) {
            throw new RuntimeException('Access settings are unavailable.');
        }
        $idle = (int) ($settings['sessionIdleSeconds'] ?? 0);
        if ($idle < 60 || $idle > 86400) {
            throw new RuntimeException('Access settings are invalid.');
        }
        $trusted = is_array($settings['trustedIps'] ?? null) ? $settings['trustedIps'] : [];
        foreach ($trusted as $trustedIp) {
            if (!is_string($trustedIp) || filter_var($trustedIp, FILTER_VALIDATE_IP) === false) {
                throw new RuntimeException('Access settings are invalid.');
            }
        }
        $settings['trustedIps'] = array_values(array_unique($trusted));
        $trustedProxies = is_array($settings['trustedProxyIps'] ?? null) ? $settings['trustedProxyIps'] : [];
        foreach ($trustedProxies as $trustedProxy) {
            if (!is_string($trustedProxy) || !$this->validIpRule($trustedProxy)) {
                throw new RuntimeException('Access settings are invalid.');
            }
        }
        $settings['trustedProxyIps'] = array_values(array_unique($trustedProxies));
        if (isset($settings['dataDirectory']) && (!is_string($settings['dataDirectory']) || trim($settings['dataDirectory']) === '')) {
            throw new RuntimeException('Access settings are invalid.');
        }
        return $settings;
    }

    /** @param array<string,mixed> $launch @return array<string,mixed>|null */
    private function selectionFromLaunch(array $launch): ?array
    {
        $kind = (string) ($launch['kind'] ?? '');
        if ($kind === 'database') {
            $prefix = (string) ($launch['prefix'] ?? '');
            $databaseId = (int) ($launch['databaseId'] ?? 0);
            if (!$this->validPrefix($prefix) || $databaseId <= 0) {
                return null;
            }
            return [
                'mode' => 'panel_database',
                'prefix' => $prefix,
                'databaseId' => $databaseId,
                'host' => (string) $launch['host'],
                'clientIp' => (string) $launch['clientIp'],
                'accessLimit' => PHP_INT_MAX,
            ];
        }
        if ($kind !== 'domain') {
            return null;
        }
        $prefix = (string) ($launch['prefix'] ?? '');
        $domainId = (int) ($launch['domainId'] ?? 0);
        $accessId = (string) ($launch['accessId'] ?? '');
        if (!$this->validPrefix($prefix) || $domainId <= 0) {
            return null;
        }
        $limit = (int) ($launch['accessLimit'] ?? PHP_INT_MAX);
        if ($limit <= time()) {
            return null;
        }
        return [
            'mode' => $accessId === '' ? 'panel_domain' : 'temporary',
            'prefix' => $prefix,
            'domainId' => $domainId,
            'accessId' => $accessId,
            'host' => (string) $launch['host'],
            'clientIp' => (string) $launch['clientIp'],
            'accessLimit' => $limit,
        ];
    }

    /** @param array<string,mixed> $match @return array<string,mixed>|null */
    private function authenticateDirectLogin(array $match, string $login, string $password, string $ip): ?array
    {
        if ($login === '' || $password === '') {
            return null;
        }
        $document = $match['document'];
        $domain = $match['domain'];
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        $domainId = (int) ($domain['id'] ?? 0);
        if (!$this->validPrefix($prefix) || $domainId <= 0) {
            return null;
        }

        $email = (string) ($document['profile']['email'] ?? '');
        $passwordHash = (string) ($document['profile']['passwordHash'] ?? '');
        if ($this->isTrustedIp($ip)
            && $email !== ''
            && strcasecmp($login, $email) === 0
            && $passwordHash !== ''
            && password_verify($password, $passwordHash)) {
            return [
                'mode' => 'owner',
                'prefix' => $prefix,
                'domainId' => $domainId,
                'credentialFingerprint' => hash('sha256', $passwordHash),
                'host' => $this->requestHost(),
                'clientIp' => $ip,
                'accessLimit' => PHP_INT_MAX,
            ];
        }

        foreach ($domain['toolAccesses'] ?? [] as $access) {
            if (!is_array($access)
                || !hash_equals((string) ($access['login'] ?? ''), $login)
                || !hash_equals((string) ($access['password'] ?? ''), $password)
                || $this->accessError($access, $ip) !== null) {
                continue;
            }
            [, $end] = $this->accessTimes($access);
            return [
                'mode' => 'temporary',
                'prefix' => $prefix,
                'domainId' => $domainId,
                'accessId' => (string) ($access['id'] ?? ''),
                'host' => $this->requestHost(),
                'clientIp' => $ip,
                'accessLimit' => $end,
            ];
        }
        return null;
    }

    /** @param array<string,mixed> $match */
    private function ipMayAttemptLogin(array $match, string $ip): bool
    {
        if ($this->isTrustedIp($ip)) {
            return true;
        }
        foreach ($match['domain']['toolAccesses'] ?? [] as $access) {
            if (is_array($access) && in_array($ip, is_array($access['ips'] ?? null) ? $access['ips'] : [], true)) {
                return true;
            }
        }
        return false;
    }

    private function isTrustedIp(string $ip): bool
    {
        return in_array($ip, $this->settings['trustedIps'], true);
    }

    /** @param array<string,mixed> $access */
    private function accessError(array $access, string $ip): ?string
    {
        if (empty($access['active'])) {
            return 'inactive';
        }
        $ips = is_array($access['ips'] ?? null) ? $access['ips'] : [];
        $permissions = is_array($access['permissions'] ?? null) ? $access['permissions'] : [];
        if (!in_array($ip, $ips, true) || empty($permissions['phpmyadmin'])) {
            return 'not_allowed';
        }
        [$start, $end] = $this->accessTimes($access);
        if ($start <= 0 || $end <= $start || time() < $start || time() >= $end) {
            return 'expired';
        }
        return null;
    }

    /** @param array<string,mixed> $access @return array{0:int,1:int} */
    private function accessTimes(array $access): array
    {
        return [strtotime((string) ($access['startsAt'] ?? '')) ?: 0, strtotime((string) ($access['expiresAt'] ?? '')) ?: 0];
    }

    /** @param array<string,mixed> $domain @return array<string,mixed>|null */
    private function findAccess(array $domain, string $accessId): ?array
    {
        if ($accessId === '') {
            return null;
        }
        foreach ($domain['toolAccesses'] ?? [] as $access) {
            if (is_array($access) && hash_equals((string) ($access['id'] ?? ''), $accessId)) {
                return $access;
            }
        }
        return null;
    }

    /** @return array<string,mixed>|null */
    private function findDomainByHost(string $host): ?array
    {
        $candidates = [$host];
        if (strpos($host, 'www.') === 0) {
            $candidates[] = substr($host, 4);
        }
        foreach ($this->listDocuments() as $document) {
            if (empty($document['profile']['active'])) {
                continue;
            }
            foreach ($document['resources']['domains'] ?? [] as $domain) {
                if (!is_array($domain) || empty($domain['active'])) {
                    continue;
                }
                $name = strtolower(rtrim(trim((string) ($domain['domain'] ?? '')), '.'));
                if (in_array($name, $candidates, true)) {
                    return ['document' => $document, 'domain' => $domain];
                }
            }
        }
        return null;
    }

    /** @return array<int,array<string,mixed>> */
    private function listDocuments(): array
    {
        if (!is_dir($this->dataDirectory)) {
            return [];
        }
        $documents = [];
        foreach (glob($this->dataDirectory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $path) {
            if (!$this->isSafeFile($path)) {
                continue;
            }
            $document = $this->readJson($path);
            if (is_array($document)) {
                $documents[] = $document;
            }
        }
        return $documents;
    }

    /** @return array<string,mixed>|null */
    private function loadDocument(string $prefix): ?array
    {
        if (!$this->validPrefix($prefix)) {
            return null;
        }
        $document = $this->readJson($this->dataDirectory . DIRECTORY_SEPARATOR . $prefix . '.json');
        return is_array($document) ? $document : null;
    }

    /** @param array<string,mixed> $document @return array<string,mixed>|null */
    private function findDatabaseById(array $document, int $databaseId): ?array
    {
        if ($databaseId <= 0) {
            return null;
        }
        foreach ($document['resources']['databases'] ?? [] as $database) {
            if (is_array($database) && !empty($database['active']) && (int) ($database['id'] ?? 0) === $databaseId) {
                return $this->normalizeDatabase($database);
            }
        }
        return null;
    }

    /** @param array<string,mixed> $document @return array<string,mixed>|null */
    private function findDomainById(array $document, int $domainId): ?array
    {
        if ($domainId <= 0) {
            return null;
        }
        foreach ($document['resources']['domains'] ?? [] as $domain) {
            if (is_array($domain) && !empty($domain['active']) && (int) ($domain['id'] ?? 0) === $domainId) {
                return $domain;
            }
        }
        return null;
    }

    /** @param array<string,mixed> $document @param array<string,mixed> $domain @return array<string,mixed>|null */
    private function databaseForDomain(array $document, array $domain): ?array
    {
        $domainName = strtolower((string) ($domain['domain'] ?? ''));
        foreach ($document['resources']['databases'] ?? [] as $database) {
            if (is_array($database)
                && !empty($database['active'])
                && strtolower((string) ($database['domain'] ?? '')) === $domainName) {
                return $this->normalizeDatabase($database);
            }
        }
        return null;
    }

    /** @param array<string,mixed> $database @return array<string,mixed>|null */
    private function normalizeDatabase(array $database): ?array
    {
        $name = trim((string) ($database['name'] ?? ''));
        $username = trim((string) ($database['username'] ?? $name));
        $password = (string) ($database['password'] ?? '');
        $host = trim((string) ($database['host'] ?? $this->settings['mysqlHost'] ?? 'localhost'));
        $port = (int) ($database['port'] ?? $this->settings['mysqlPort'] ?? 3306);
        if ($name === '' || $username === '' || $password === '' || $host === '' || $port < 1 || $port > 65535) {
            return null;
        }
        $database['name'] = $name;
        $database['username'] = $username;
        $database['password'] = $password;
        $database['host'] = $host;
        $database['port'] = $port;
        return $database;
    }

    /** @param array<string,mixed> $document @param array<string,mixed>|null $domain @param array<string,mixed> $database @return array<string,mixed> */
    private function context(array $document, ?array $domain, array $database): array
    {
        return [
            'domain' => $domain ?? ['domain' => (string) ($database['domain'] ?? $this->requestHost())],
            'database' => $database,
            'tool' => 'phpmyadmin',
        ];
    }

    /** @param array<string,mixed> $selection */
    private function createSession(array $selection, string $host, string $ip): void
    {
        $token = $this->base64UrlEncode(random_bytes(32));
        $selection['host'] = $host;
        $selection['clientIp'] = $ip;
        $selection['lastSeen'] = time();
        $selection['expiresAt'] = $this->sessionExpiry($selection);
        $directory = $this->sessionDirectory();
        $this->ensureDirectory($directory);
        $this->writePrivateFile($directory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json', $this->encodeJson($selection));
        setcookie(self::COOKIE_NAME, $token, $this->cookieOptions((int) $selection['expiresAt']));
        $_COOKIE[self::COOKIE_NAME] = $token;
    }

    /** @return array<string,mixed>|null */
    private function readSession(string $host, string $ip): ?array
    {
        $token = (string) ($_COOKIE[self::COOKIE_NAME] ?? '');
        if (preg_match('/^[A-Za-z0-9_-]{40,64}$/D', $token) !== 1) {
            return null;
        }
        $path = $this->sessionDirectory() . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
        $selection = $this->readJson($path);
        if (!is_array($selection)
            || (int) ($selection['expiresAt'] ?? 0) <= time()
            || (int) ($selection['lastSeen'] ?? 0) + (int) $this->settings['sessionIdleSeconds'] <= time()
            || !hash_equals((string) ($selection['host'] ?? ''), $host)
            || !hash_equals((string) ($selection['clientIp'] ?? ''), $ip)) {
            @unlink($path);
            return null;
        }
        return $selection;
    }

    /** @param array<string,mixed> $selection */
    private function refreshSession(array $selection, string $host, string $ip): void
    {
        $token = (string) ($_COOKIE[self::COOKIE_NAME] ?? '');
        if (preg_match('/^[A-Za-z0-9_-]{40,64}$/D', $token) !== 1) {
            return;
        }
        $selection['host'] = $host;
        $selection['clientIp'] = $ip;
        $selection['lastSeen'] = time();
        $selection['expiresAt'] = $this->sessionExpiry($selection);
        $this->writePrivateFile($this->sessionDirectory() . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json', $this->encodeJson($selection));
        setcookie(self::COOKIE_NAME, $token, $this->cookieOptions((int) $selection['expiresAt']));
    }

    private function clearSession(): void
    {
        $token = (string) ($_COOKIE[self::COOKIE_NAME] ?? '');
        if (preg_match('/^[A-Za-z0-9_-]{40,64}$/D', $token) === 1) {
            @unlink($this->sessionDirectory() . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json');
        }
        setcookie(self::COOKIE_NAME, '', $this->cookieOptions(time() - 3600));
        unset($_COOKIE[self::COOKIE_NAME]);
    }

    /** @param array<string,mixed> $selection */
    private function sessionExpiry(array $selection): int
    {
        $idleExpiry = time() + (int) $this->settings['sessionIdleSeconds'];
        $accessLimit = (int) ($selection['accessLimit'] ?? PHP_INT_MAX);
        return min($idleExpiry, $accessLimit);
    }

    /** @return array<string,mixed> */
    private function cookieOptions(int $expires): array
    {
        return [
            'expires' => $expires,
            'path' => '/phpmyadmin/',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => true,
            'samesite' => 'Strict',
        ];
    }

    private function sessionDirectory(): string
    {
        return $this->stateDirectory . DIRECTORY_SEPARATOR . 'phpmyadmin-sessions';
    }

    private function requestHost(): string
    {
        $host = strtolower(trim((string) ($_SERVER['HTTP_HOST'] ?? '')));
        if ($host === '') {
            return '';
        }
        if ($host[0] === '[') {
            $end = strpos($host, ']');
            $host = $end === false ? '' : substr($host, 1, $end - 1);
        } elseif (substr_count($host, ':') === 1) {
            $host = explode(':', $host, 2)[0];
        }
        $host = rtrim($host, '.');
        return filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false ? '' : $host;
    }

    private function clientIp(): string
    {
        $remoteAddress = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        if (filter_var($remoteAddress, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        $forwardedFor = trim((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
        $trustedProxies = is_array($this->settings['trustedProxyIps'] ?? null)
            ? $this->settings['trustedProxyIps']
            : [];
        if ($forwardedFor === '' || !$this->ipInRules($remoteAddress, $trustedProxies)) {
            return $remoteAddress;
        }

        $forwardedAddresses = [];
        foreach (explode(',', $forwardedFor) as $forwardedAddress) {
            $forwardedAddress = trim($forwardedAddress);
            if (filter_var($forwardedAddress, FILTER_VALIDATE_IP) !== false) {
                $forwardedAddresses[] = $forwardedAddress;
            }
        }
        for ($index = count($forwardedAddresses) - 1; $index >= 0; $index--) {
            if (!$this->ipInRules($forwardedAddresses[$index], $trustedProxies)) {
                return $forwardedAddresses[$index];
            }
        }
        return $forwardedAddresses[0] ?? $remoteAddress;
    }

    private function validIpRule(string $rule): bool
    {
        $parts = explode('/', trim($rule), 2);
        $network = trim($parts[0]);
        if (filter_var($network, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        if (count($parts) === 1) {
            return true;
        }
        $prefixText = trim($parts[1]);
        if (preg_match('/^\d+$/D', $prefixText) !== 1) {
            return false;
        }
        $packed = inet_pton($network);
        return $packed !== false && (int) $prefixText <= strlen($packed) * 8;
    }

    /** @param array<int,mixed> $rules */
    private function ipInRules(string $ip, array $rules): bool
    {
        foreach ($rules as $rule) {
            if (is_string($rule) && $this->ipMatchesRule($ip, $rule)) {
                return true;
            }
        }
        return false;
    }

    private function ipMatchesRule(string $ip, string $rule): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !$this->validIpRule($rule)) {
            return false;
        }
        $parts = explode('/', trim($rule), 2);
        $packedIp = inet_pton($ip);
        $packedNetwork = inet_pton(trim($parts[0]));
        if ($packedIp === false || $packedNetwork === false || strlen($packedIp) !== strlen($packedNetwork)) {
            return false;
        }
        if (count($parts) === 1) {
            return hash_equals($packedNetwork, $packedIp);
        }

        $prefixLength = (int) trim($parts[1]);
        $wholeBytes = intdiv($prefixLength, 8);
        if ($wholeBytes > 0 && substr($packedIp, 0, $wholeBytes) !== substr($packedNetwork, 0, $wholeBytes)) {
            return false;
        }
        $remainingBits = $prefixLength % 8;
        if ($remainingBits === 0) {
            return true;
        }
        $mask = (0xff << (8 - $remainingBits)) & 0xff;
        return (ord($packedIp[$wholeBytes]) & $mask) === (ord($packedNetwork[$wholeBytes]) & $mask);
    }

    private function validPrefix(string $prefix): bool
    {
        return preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) === 1;
    }

    /** @return array<string,mixed>|null */
    private function readJson(string $path): ?array
    {
        if (!$this->isSafeFile($path)) {
            return null;
        }
        $size = filesize($path);
        if ($size === false || $size < 2 || $size > self::MAX_JSON_BYTES) {
            return null;
        }
        $json = file_get_contents($path);
        $decoded = is_string($json) ? json_decode($json, true) : null;
        return is_array($decoded) ? $decoded : null;
    }

    private function isSafeFile(string $path): bool
    {
        return is_file($path) && !is_link($path);
    }

    private function ensureDirectory(string $directory): void
    {
        if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
            throw new RuntimeException('Access storage is unavailable.');
        }
    }

    private function writePrivateFile(string $path, string $contents): void
    {
        $this->ensureDirectory(dirname($path));
        $temporary = tempnam(dirname($path), '.write-');
        if ($temporary === false) {
            throw new RuntimeException('Access storage is unavailable.');
        }
        try {
            if (file_put_contents($temporary, $contents, LOCK_EX) === false) {
                throw new RuntimeException('Access storage is unavailable.');
            }
            @chmod($temporary, 0600);
            if (!@rename($temporary, $path)) {
                @unlink($path);
                if (!@rename($temporary, $path)) {
                    throw new RuntimeException('Access storage is unavailable.');
                }
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    /** @param array<string,mixed> $value */
    private function encodeJson(array $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new RuntimeException('Access storage is unavailable.');
        }
        return $json;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function renderAccessPage(string $title, string $message, bool $login, string $domain): void
    {
        http_response_code($login ? 401 : 403);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
        $safeMessage = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
        $safeDomain = htmlspecialchars($domain, ENT_QUOTES, 'UTF-8');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $safeTitle . '</title><link rel="stylesheet" href="/panel/assets/vendor/bootstrap/css/bootstrap.min.css">'
            . '<link rel="stylesheet" href="/panel/assets/vendor/bootstrap-icons/font/bootstrap-icons.css"></head>'
            . '<body class="bg-light"><main class="container py-5"><div class="card border-0 shadow-sm mx-auto" style="max-width:520px"><div class="card-body p-4 p-md-5">'
            . '<div class="d-flex align-items-center gap-3 mb-4"><span class="btn btn-primary disabled"><i class="bi bi-shield-lock"></i></span><div><h1 class="h4 mb-0">' . $safeTitle . '</h1><small class="text-secondary">' . $safeDomain . ' · phpMyAdmin</small></div></div>'
            . ($safeMessage !== '' ? '<div class="alert alert-warning">' . $safeMessage . '</div>' : '');
        if ($login) {
            echo '<form method="post" autocomplete="on"><input type="hidden" name="imagopanel_tool_login" value="1">'
                . '<div class="mb-3"><label class="form-label">Login</label><input class="form-control" name="imagopanel_login" autocomplete="username" required maxlength="128"></div>'
                . '<div class="mb-4"><label class="form-label">Password</label><input class="form-control" type="password" name="imagopanel_password" autocomplete="current-password" required maxlength="256"></div>'
                . '<button class="btn btn-primary w-100" type="submit"><i class="bi bi-box-arrow-in-right me-2"></i>Sign in</button></form>';
        }
        echo '</div></div></main></body></html>';
        exit;
    }
}
