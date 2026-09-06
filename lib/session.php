<?php
declare(strict_types=1);

require_once __DIR__ . '/DataStore.php';

function startPanelSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name('IMAGOPANELSESSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function panelSessionExpired(): bool
{
    return !empty($_SESSION['last_activity'])
        && time() - (int) $_SESSION['last_activity'] > SESSION_IDLE_TIMEOUT;
}

function clearPanelSession(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function panelRememberCookieSecure(): bool
{
    return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
}

function panelBase64UrlEncode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function panelBase64UrlDecode(string $value): ?string
{
    if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1) {
        return null;
    }

    $padding = strlen($value) % 4;
    if ($padding !== 0) {
        $value .= str_repeat('=', 4 - $padding);
    }

    $decoded = base64_decode(strtr($value, '-_', '+/'), true);
    return $decoded === false ? null : $decoded;
}

function panelRememberCredentialFingerprint(string $passwordHash): string
{
    return hash_hmac('sha256', $passwordHash, REMEMBER_LOGIN_SECRET);
}

function panelCreateRememberToken(array $auth, string $passwordHash, ?int $issuedAt = null): string
{
    $issuedAt = $issuedAt ?? time();
    $payload = [
        'version' => 1,
        'role' => (string) ($auth['role'] ?? ''),
        'userId' => isset($auth['user_id']) ? (int) $auth['user_id'] : null,
        'prefix' => (string) ($auth['prefix'] ?? ''),
        'issuedAt' => $issuedAt,
        'expiresAt' => $issuedAt + (REMEMBER_LOGIN_DAYS * 86400),
        'credential' => panelRememberCredentialFingerprint($passwordHash),
    ];

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        throw new RuntimeException('Cannot create remember token');
    }

    $encodedPayload = panelBase64UrlEncode($json);
    $signature = hash_hmac('sha256', $encodedPayload, REMEMBER_LOGIN_SECRET, true);
    return $encodedPayload . '.' . panelBase64UrlEncode($signature);
}

function panelReadRememberToken(string $token, ?int $now = null): ?array
{
    if ($token === '' || strlen($token) > 4096) {
        return null;
    }

    $parts = explode('.', $token, 2);
    if (count($parts) !== 2) {
        return null;
    }

    $providedSignature = panelBase64UrlDecode($parts[1]);
    if ($providedSignature === null) {
        return null;
    }

    $expectedSignature = hash_hmac('sha256', $parts[0], REMEMBER_LOGIN_SECRET, true);
    if (!hash_equals($expectedSignature, $providedSignature)) {
        return null;
    }

    $json = panelBase64UrlDecode($parts[0]);
    $payload = $json === null ? null : json_decode($json, true);
    if (!is_array($payload)
        || (int) ($payload['version'] ?? 0) !== 1
        || !in_array((string) ($payload['role'] ?? ''), ['root', 'user'], true)
        || !is_string($payload['prefix'] ?? null)
        || !is_string($payload['credential'] ?? null)) {
        return null;
    }

    $now = $now ?? time();
    $issuedAt = (int) ($payload['issuedAt'] ?? 0);
    $expiresAt = (int) ($payload['expiresAt'] ?? 0);
    if ($issuedAt <= 0 || $issuedAt > $now + 300 || $expiresAt <= $now
        || $expiresAt > $issuedAt + (REMEMBER_LOGIN_DAYS * 86400)) {
        return null;
    }

    return $payload;
}

function panelSetRememberCookie(array $auth, string $passwordHash): void
{
    $expiresAt = time() + (REMEMBER_LOGIN_DAYS * 86400);
    setcookie(REMEMBER_LOGIN_COOKIE, panelCreateRememberToken($auth, $passwordHash), [
        'expires' => $expiresAt,
        'path' => '/',
        'secure' => panelRememberCookieSecure(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function panelForgetRememberCookie(): void
{
    setcookie(REMEMBER_LOGIN_COOKIE, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => panelRememberCookieSecure(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    unset($_COOKIE[REMEMBER_LOGIN_COOKIE]);
}

function panelRestoreRememberAuth(): ?array
{
    $token = isset($_COOKIE[REMEMBER_LOGIN_COOKIE]) ? (string) $_COOKIE[REMEMBER_LOGIN_COOKIE] : '';
    $payload = panelReadRememberToken($token);
    if ($payload === null) {
        if ($token !== '') {
            panelForgetRememberCookie();
        }
        return null;
    }

    $role = (string) $payload['role'];
    if ($role === 'root') {
        if ((string) $payload['prefix'] !== 'root'
            || !panelRootIpAllowed()
            || !hash_equals(panelRememberCredentialFingerprint(ROOT_PASSWORD_HASH), (string) $payload['credential'])) {
            panelForgetRememberCookie();
            return null;
        }

        $auth = ['role' => 'root', 'email' => ROOT_EMAIL, 'name' => 'Root', 'user_id' => null, 'prefix' => 'root'];
    } else {
        try {
            $store = new DataStore(DATA_DIRECTORY);
            $document = $store->load((string) $payload['prefix']);
        } catch (Throwable $exception) {
            $document = null;
        }

        $profile = is_array($document) ? ($document['profile'] ?? null) : null;
        $passwordHash = is_array($profile) ? (string) ($profile['passwordHash'] ?? '') : '';
        if (!is_array($profile)
            || empty($profile['active'])
            || !panelUserIpAllowed($profile)
            || (int) ($profile['id'] ?? 0) !== (int) ($payload['userId'] ?? 0)
            || $passwordHash === ''
            || !hash_equals(panelRememberCredentialFingerprint($passwordHash), (string) $payload['credential'])) {
            panelForgetRememberCookie();
            return null;
        }

        $auth = [
            'role' => 'user',
            'email' => (string) $profile['email'],
            'name' => (string) $profile['name'],
            'user_id' => (int) $profile['id'],
            'prefix' => (string) $profile['prefix'],
        ];
    }

    session_regenerate_id(true);
    $_SESSION['auth'] = $auth;
    $_SESSION['last_activity'] = time();
    return $auth;
}

function panelIpMatchesRule(string $ip, string $rule): bool
{
    $ip = trim($ip);
    $rule = trim($rule);
    if (filter_var($ip, FILTER_VALIDATE_IP) === false || $rule === '') {
        return false;
    }

    $parts = explode('/', $rule, 2);
    $network = trim($parts[0]);
    if (filter_var($network, FILTER_VALIDATE_IP) === false) {
        return false;
    }

    $packedIp = inet_pton($ip);
    $packedNetwork = inet_pton($network);
    if ($packedIp === false || $packedNetwork === false || strlen($packedIp) !== strlen($packedNetwork)) {
        return false;
    }

    if (count($parts) === 1) {
        return hash_equals($packedNetwork, $packedIp);
    }

    $prefixText = trim($parts[1]);
    if (preg_match('/^\d+$/D', $prefixText) !== 1) {
        return false;
    }

    $prefixLength = (int) $prefixText;
    $maximumPrefixLength = strlen($packedIp) * 8;
    if ($prefixLength < 0 || $prefixLength > $maximumPrefixLength) {
        return false;
    }

    $wholeBytes = intdiv($prefixLength, 8);
    if ($wholeBytes > 0
        && substr($packedIp, 0, $wholeBytes) !== substr($packedNetwork, 0, $wholeBytes)) {
        return false;
    }

    $remainingBits = $prefixLength % 8;
    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xff << (8 - $remainingBits)) & 0xff;
    return (ord($packedIp[$wholeBytes]) & $mask) === (ord($packedNetwork[$wholeBytes]) & $mask);
}

function panelIpInRules(string $ip, array $rules): bool
{
    foreach ($rules as $rule) {
        if (is_string($rule) && panelIpMatchesRule($ip, $rule)) {
            return true;
        }
    }

    return false;
}

function panelNormalizeExactIps($value, ?int $maximum = null): array
{
    $maximum = $maximum ?? USER_IP_ACCESS_MAX_ADDRESSES;
    $items = is_array($value) ? $value : preg_split('/[\s,;]+/u', trim((string) $value), -1, PREG_SPLIT_NO_EMPTY);
    $ips = [];
    foreach ($items ?: [] as $item) {
        $ip = trim((string) $item);
        if ($ip === '' || strpos($ip, '/') !== false || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('Invalid allowed IP: ' . $ip);
        }
        $packed = inet_pton($ip);
        $canonical = $packed === false ? false : inet_ntop($packed);
        if (!is_string($canonical) || $canonical === '') {
            throw new InvalidArgumentException('Invalid allowed IP: ' . $ip);
        }
        $ips[$canonical] = true;
        if (count($ips) > $maximum) throw new InvalidArgumentException('Too many allowed IP addresses');
    }
    return array_keys($ips);
}

function panelResolveClientIp(string $remoteAddress, string $forwardedFor, array $trustedProxyRules): string
{
    $remoteAddress = trim($remoteAddress);
    if (filter_var($remoteAddress, FILTER_VALIDATE_IP) === false) {
        return '';
    }

    if ($forwardedFor === '' || !panelIpInRules($remoteAddress, $trustedProxyRules)) {
        return $remoteAddress;
    }

    $forwardedAddresses = [];
    foreach (explode(',', $forwardedFor) as $address) {
        $address = trim($address);
        if (filter_var($address, FILTER_VALIDATE_IP) !== false) {
            $forwardedAddresses[] = $address;
        }
    }

    for ($index = count($forwardedAddresses) - 1; $index >= 0; $index--) {
        if (!panelIpInRules($forwardedAddresses[$index], $trustedProxyRules)) {
            return $forwardedAddresses[$index];
        }
    }

    return $forwardedAddresses[0] ?? $remoteAddress;
}

function panelClientIp(): string
{
    return panelResolveClientIp(
        (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
        (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''),
        ROOT_TRUSTED_PROXY_IPS
    );
}

function panelRootIpAllowed(): bool
{
    if (ROOT_ALLOWED_IPS === []) {
        return true;
    }

    $clientIp = panelClientIp();
    return $clientIp !== '' && panelIpInRules($clientIp, ROOT_ALLOWED_IPS);
}

function panelUserIpAllowed(array $profile): bool
{
    if (empty($profile['ipAccessEnabled'])) return true;
    $rules = is_array($profile['allowedIps'] ?? null) ? $profile['allowedIps'] : [];
    if (!$rules) return false;
    $clientIp = panelClientIp();
    return $clientIp !== '' && panelIpInRules($clientIp, $rules);
}

function panelAuth(): ?array
{
    $auth = isset($_SESSION['auth']) && is_array($_SESSION['auth']) ? $_SESSION['auth'] : null;
    if ($auth === null) {
        $auth = panelRestoreRememberAuth();
    }
    if ($auth !== null && ($auth['role'] ?? '') === 'root' && !panelRootIpAllowed()) {
        clearPanelSession();
        panelForgetRememberCookie();
        return null;
    }
    if ($auth !== null && ($auth['role'] ?? '') === 'user') {
        try {
            $store = new DataStore(DATA_DIRECTORY);
            $document = $store->load((string) ($auth['prefix'] ?? ''));
        } catch (Throwable $exception) {
            $document = null;
        }
        $profile = is_array($document) && is_array($document['profile'] ?? null) ? $document['profile'] : null;
        if (!is_array($profile) || empty($profile['active']) || !panelUserIpAllowed($profile)) {
            clearPanelSession();
            panelForgetRememberCookie();
            return null;
        }
    }

    return $auth;
}

function panelCsrfToken(): string
{
    return (string) ($_SESSION['csrf_token'] ?? '');
}

function panelCsrfValid(?string $token): bool
{
    $expected = panelCsrfToken();
    return $expected !== '' && is_string($token) && hash_equals($expected, $token);
}
