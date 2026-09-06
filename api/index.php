<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/Size.php';
require_once dirname(__DIR__) . '/lib/session.php';
require_once dirname(__DIR__) . '/lib/DataStore.php';
require_once dirname(__DIR__) . '/lib/StatusStore.php';
require_once dirname(__DIR__) . '/lib/RootAuditLog.php';
require_once dirname(__DIR__) . '/lib/root_request.php';
require_once dirname(__DIR__) . '/lib/SlidingWindowRateLimiter.php';
require_once dirname(__DIR__) . '/lib/PanelMailer.php';
require_once dirname(__DIR__) . '/lib/MailMigrationStore.php';
require_once dirname(__DIR__) . '/lib/MailMigrationRuntime.php';
require_once dirname(__DIR__) . '/lib/DnsService.php';
require_once dirname(__DIR__) . '/lib/DomainToolAccess.php';

try {
    domainToolSyncPhpMyAdminAdapterSettings();
} catch (Throwable $ignored) {
    // phpMyAdmin will fail closed if its isolated adapter settings cannot be refreshed.
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');

startPanelSession();
if (panelSessionExpired()) {
    clearPanelSession();
}

function apiResponse(array $payload, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function apiError(string $message, int $status = 400): void
{
    apiResponse(['ok' => false, 'data' => null, 'error' => $message], $status);
}

function requestPayload(): array
{
    $contentType = (string) ($_SERVER['CONTENT_TYPE'] ?? '');
    if (stripos($contentType, 'application/json') !== false) {
        $decoded = json_decode((string) file_get_contents('php://input'), true);
        return is_array($decoded) ? $decoded : [];
    }
    return array_merge($_GET, $_POST);
}

function requireMutationCsrf(array $payload): void
{
    $header = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? (string) $_SERVER['HTTP_X_CSRF_TOKEN'] : null;
    $token = $header ?: (isset($payload['_csrf']) ? (string) $payload['_csrf'] : null);
    if (!panelCsrfValid($token)) {
        apiError('Invalid CSRF token', 403);
    }
}

function isRoot(array $auth): bool
{
    return ($auth['role'] ?? '') === 'root';
}

function booleanValue($value): bool
{
    return in_array($value, [true, 1, '1', 'true', 'on', 'yes'], true);
}

function panelTariffs(): array
{
    $result = [];
    foreach (USER_TARIFFS as $key => $tariff) {
        $key = mb_strtolower(trim((string) $key));
        if (preg_match('/^[a-z0-9_-]{1,32}$/D', $key) !== 1 || !is_array($tariff)) continue;
        $tariff = tariffSizesInBytes($tariff, $key);
        $result[$key] = [
            'key' => $key,
            'name' => trim((string) ($tariff['name'] ?? $key)) ?: $key,
            'domain' => max(0, (int) ($tariff['domain'] ?? 0)),
            'db' => max(0, (int) ($tariff['db'] ?? 0)),
            'mailbydomain' => max(0, (int) ($tariff['mailbydomain'] ?? 0)),
            'wwwsize' => max(0, (float) ($tariff['wwwsize'] ?? 0)),
            'mailsize' => max(0, (float) ($tariff['mailsize'] ?? 0)),
            'dbsize' => max(0, (float) ($tariff['dbsize'] ?? 0)),
        ];
    }
    if (!$result) throw new RuntimeException('No valid user tariffs configured');
    return $result;
}

function profileTariffKey(array $profile): string
{
    $tariffs = panelTariffs();
    $key = mb_strtolower(trim((string) ($profile['tariff'] ?? DEFAULT_USER_TARIFF)));
    if (!isset($tariffs[$key])) $key = isset($tariffs[DEFAULT_USER_TARIFF]) ? DEFAULT_USER_TARIFF : (string) array_key_first($tariffs);
    return $key;
}

function tariffAggregateQuotas(array $tariff): array
{
    $multiply = static function (float $size, int $count): float {
        return $size <= 0 || $count <= 0 ? 0.0 : $size * $count;
    };
    $domainCount = (int) $tariff['domain'];
    $mailCount = $domainCount > 0 && (int) $tariff['mailbydomain'] > 0 ? $domainCount * (int) $tariff['mailbydomain'] : 0;
    return [
        'site' => $multiply((float) $tariff['wwwsize'], $domainCount),
        'database' => $multiply((float) $tariff['dbsize'], (int) $tariff['db']),
        'mail' => $multiply((float) $tariff['mailsize'], $mailCount),
    ];
}

function systemQuotaRuntimeState(): array
{
    $requested = SYSTEM_QUOTAS_ENABLED;
    $active = $requested && UNIX_ACCOUNTS_ENABLED && !WIN
        && UNIX_ID_BINARY !== '' && is_executable(UNIX_ID_BINARY)
        && SYSTEM_SETQUOTA_BINARY !== '' && is_executable(SYSTEM_SETQUOTA_BINARY)
        && is_dir(SYSTEM_QUOTA_MOUNTPOINT);
    $warning = '';
    if ($requested && !$active) {
        $warning = !UNIX_ACCOUNTS_ENABLED
            ? 'System quotas отключены: сначала включите UNIX_ACCOUNTS_ENABLED в config.php.'
            : 'System quotas запрошены, но системная поддержка или команды недоступны. Ограничения filesystem не применяются.';
    }
    return ['requested' => $requested, 'active' => $active, 'warning' => $warning];
}

function generateMailboxPassword(): string
{
    $groups = ['ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz', '0123456789', '+-_)(?%#!,.'];
    $all = implode('', $groups);
    $characters = [];
    foreach ($groups as $group) {
        $characters[] = $group[random_int(0, strlen($group) - 1)];
    }
    while (count($characters) < 8) {
        $characters[] = $all[random_int(0, strlen($all) - 1)];
    }
    for ($index = count($characters) - 1; $index > 0; $index--) {
        $target = random_int(0, $index);
        $temporary = $characters[$index];
        $characters[$index] = $characters[$target];
        $characters[$target] = $temporary;
    }
    return implode('', $characters);
}

function validDatabasePassword(string $password): bool
{
    return strlen($password) >= 8
        && strlen($password) <= 128
        && preg_match('/[A-Z]/', $password) === 1
        && preg_match('/[a-z]/', $password) === 1
        && preg_match('/[0-9]/', $password) === 1
        && preg_match('/[+\-_)(?%#!,.]/', $password) === 1;
}

function normalizeProfileEmailList($value): array
{
    $items = is_array($value) ? $value : preg_split('/[\s,;]+/u', trim((string) $value), -1, PREG_SPLIT_NO_EMPTY);
    $emails = [];
    foreach ($items ?: [] as $item) {
        $email = mb_strtolower(trim((string) $item));
        if ($email === '') continue;
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) throw new InvalidArgumentException('Invalid contact email: ' . $email);
        $emails[$email] = true;
        if (count($emails) > 20) throw new InvalidArgumentException('Too many contact emails');
    }
    return array_keys($emails);
}

function normalizeProfileText($value, string $field, int $maximum): string
{
    $text = trim((string) $value);
    if (preg_match('/[\x00]/', $text) === 1 || mb_strlen($text) > $maximum) {
        throw new InvalidArgumentException('Invalid ' . $field);
    }
    return $text;
}

function normalizeProfileSettings(array $record, array $existing = []): array
{
    $value = static function (string $key, $default = '') use ($record, $existing) {
        if (array_key_exists($key, $record)) return $record[$key];
        return array_key_exists($key, $existing) ? $existing[$key] : $default;
    };
    $defaultForwardEmail = mb_strtolower(trim((string) $value('defaultForwardEmail')));
    $defaultForwardEmail = str_replace('{domain}', '{DOMAIN}', $defaultForwardEmail);
    if ($defaultForwardEmail !== '') {
        $validationEmail = str_replace('{DOMAIN}', 'example.com', $defaultForwardEmail);
        if (!filter_var($validationEmail, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException('Invalid default forwarding email or {DOMAIN} template');
        }
    }
    $forwardNewDomains = booleanValue($value('mailForwardNewDomains', false));
    $forwardWholeDomain = booleanValue($value('mailForwardWholeDomain', false));
    $catchAllToInfo = booleanValue($value('mailCatchAllToInfo', true));
    if (($forwardNewDomains || $forwardWholeDomain) && $defaultForwardEmail === '') {
        throw new InvalidArgumentException('Default forwarding email is required');
    }
    if ($forwardWholeDomain) {
        $forwardNewDomains = false;
        $catchAllToInfo = false;
    }
    $ipAccessEnabled = booleanValue($value('ipAccessEnabled', false));
    $allowedIps = panelNormalizeExactIps($value('allowedIps', []));
    if ($ipAccessEnabled && !$allowedIps) {
        throw new InvalidArgumentException('At least one allowed IP is required');
    }
    return array_merge([
        'billingEmails' => normalizeProfileEmailList($value('billingEmails', [])),
        'technicalEmails' => normalizeProfileEmailList($value('technicalEmails', [])),
        'limitEmails' => normalizeProfileEmailList($value('limitEmails', [])),
        'contactPhone' => normalizeProfileText($value('contactPhone'), 'contact phone', 64),
        'companyName' => normalizeProfileText($value('companyName'), 'company name', 160),
        'companyRegistrationNumber' => normalizeProfileText($value('companyRegistrationNumber'), 'company registration number', 80),
        'companyAddress' => normalizeProfileText($value('companyAddress'), 'company address', 500),
        'defaultForwardEmail' => $defaultForwardEmail,
        'mailForwardNewDomains' => $forwardNewDomains,
        'mailForwardWholeDomain' => $forwardWholeDomain,
        'mailCatchAllToInfo' => $catchAllToInfo,
        'ipAccessEnabled' => $ipAccessEnabled,
        'allowedIps' => $allowedIps,
    ], DnsService::normalizeProfileSettings($record, $existing));
}

function profileForwardEmailForDomain(array $profile, string $domain): string
{
    $template = mb_strtolower(trim((string) ($profile['defaultForwardEmail'] ?? '')));
    $template = str_replace('{domain}', '{DOMAIN}', $template);
    if ($template === '') return '';
    $email = str_replace('{DOMAIN}', $domain, $template);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) throw new InvalidArgumentException('Invalid forwarding email after {DOMAIN} replacement');
    return mb_strtolower($email);
}

function databaseAccountName(string $database): string
{
    if (strlen($database) <= MYSQL_CLIENT_USER_MAX_LENGTH) {
        return $database;
    }
    $suffix = '_' . substr(hash('sha256', $database), 0, 8);
    return substr($database, 0, MYSQL_CLIENT_USER_MAX_LENGTH - strlen($suffix)) . $suffix;
}

function userRootPath(string $prefix): string
{
    return rtrim(USER_WEB_ROOT_DIRECTORY, '/') . '/' . $prefix;
}

function validRootPath(string $path): bool
{
    $normalized = str_replace('\\', '/', trim($path));
    return $normalized !== ''
        && $normalized[0] === '/'
        && preg_match('/[\x00\r\n"]/', $normalized) !== 1
        && !in_array('..', explode('/', $normalized), true);
}

function validRelativePath(string $path): bool
{
    $normalized = trim(str_replace('\\', '/', $path), '/');
    if ($normalized === '' || preg_match('/[\x00\r\n"]/', $normalized) === 1) {
        return false;
    }
    foreach (explode('/', $normalized) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return false;
        }
    }
    return true;
}

function normalizePanelComment($value): string
{
    $comment = trim((string) $value);
    if (mb_strlen($comment) > 2000) {
        throw new InvalidArgumentException('Comment is too long');
    }
    return $comment;
}

function documentsForAuth(DataStore $store, array $auth): array
{
    if (isRoot($auth)) {
        return $store->listDocuments();
    }
    $document = $store->load((string) $auth['prefix']);
    return $document === null ? [] : [$document];
}

function profileRow(array $document): array
{
    $profile = $document['profile'];
    $tariffs = panelTariffs();
    $tariffKey = profileTariffKey($profile);
    $tariff = $tariffs[$tariffKey];
    $domains = is_array($document['resources']['domains'] ?? null) ? $document['resources']['domains'] : [];
    $databases = is_array($document['resources']['databases'] ?? null) ? $document['resources']['databases'] : [];
    $mail = is_array($document['resources']['mail'] ?? null) ? $document['resources']['mail'] : [];
    $sum = static function (array $rows, string $key) {
        return array_reduce($rows, static function ($total, array $row) use ($key) {
            return (float) $total + (float) ($row[$key] ?? 0);
        }, 0.0);
    };
    $mailDomains = [];
    foreach ($mail as $mailbox) {
        $mailDomains[(string) ($mailbox['domain'] ?? '')] = true;
    }
    foreach ($domains as $domain) {
        if (!empty($domain['mailEnabled'])) $mailDomains[(string) ($domain['domain'] ?? '')] = true;
    }
    $siteBytes = 0.0;
    $countedPaths = [];
    foreach ($domains as $domain) {
        $path = trim(str_replace('\\', '/', (string) ($domain['path'] ?? '')), '/');
        if ($path === '' || isset($countedPaths[$path])) {
            continue;
        }
        $countedPaths[$path] = true;
        $siteBytes += (float) ($domain['folderBytes'] ?? 0);
    }

    return array_merge([
        'id' => (int) ($profile['id'] ?? 0),
        'name' => (string) ($profile['name'] ?? ''),
        'email' => (string) ($profile['email'] ?? ''),
        'comment' => (string) ($profile['comment'] ?? ''),
        'prefix' => (string) ($profile['prefix'] ?? ''),
        'rootPath' => userRootPath((string) ($profile['prefix'] ?? '')),
        'billingEmails' => array_values(is_array($profile['billingEmails'] ?? null) ? $profile['billingEmails'] : []),
        'technicalEmails' => array_values(is_array($profile['technicalEmails'] ?? null) ? $profile['technicalEmails'] : []),
        'limitEmails' => array_values(is_array($profile['limitEmails'] ?? null) ? $profile['limitEmails'] : []),
        'contactPhone' => (string) ($profile['contactPhone'] ?? ''),
        'companyName' => (string) ($profile['companyName'] ?? ''),
        'companyRegistrationNumber' => (string) ($profile['companyRegistrationNumber'] ?? ''),
        'companyAddress' => (string) ($profile['companyAddress'] ?? ''),
        'defaultForwardEmail' => (string) ($profile['defaultForwardEmail'] ?? ''),
        'mailForwardNewDomains' => !empty($profile['mailForwardNewDomains']),
        'mailForwardWholeDomain' => !empty($profile['mailForwardWholeDomain']),
        'mailCatchAllToInfo' => !array_key_exists('mailCatchAllToInfo', $profile) || !empty($profile['mailCatchAllToInfo']),
        'ipAccessEnabled' => !empty($profile['ipAccessEnabled']),
        'allowedIps' => array_values(is_array($profile['allowedIps'] ?? null) ? $profile['allowedIps'] : []),
        'tariff' => $tariffKey,
        'tariffName' => (string) $tariff['name'],
        'tariffLimits' => $tariff,
        'tariffRequest' => isset($profile['tariffRequest']) && is_array($profile['tariffRequest']) ? $profile['tariffRequest'] : null,
        'domains' => count($domains),
        'siteBytes' => $siteBytes,
        'siteQuotaBytes' => (float) ($profile['siteQuotaBytes'] ?? 0),
        'databases' => count($databases),
        'databaseBytes' => $sum($databases, 'bytes'),
        'databaseQuotaBytes' => (float) ($profile['databaseQuotaBytes'] ?? 0),
        'mailDomains' => count(array_filter(array_keys($mailDomains))),
        'mailAccounts' => count($mail),
        'mailBytes' => $sum($mail, 'bytes'),
        'mailQuotaBytes' => (float) ($profile['mailQuotaBytes'] ?? 0),
        'vhosts' => count($domains),
        'active' => !empty($profile['active']),
        'createdAt' => (string) ($profile['createdAt'] ?? ''),
        'createdAtTimestamp' => (($createdAtTimestamp = strtotime((string) ($profile['createdAt'] ?? ''))) !== false ? $createdAtTimestamp : 0),
        'statusCollectedAt' => (string) ($profile['statusCollectedAt'] ?? ''),
        'statusDurationMs' => (int) ($profile['statusDurationMs'] ?? 0),
        'statusOk' => array_key_exists('statusOk', $profile) ? !empty($profile['statusOk']) : null,
        'statusErrors' => (int) ($profile['statusErrors'] ?? 0),
    ], DnsService::publicProfile($profile));
}

function dnsRequestContext(DataStore $store, array $auth, array $payload, bool $mustExist): array
{
    $domain = mb_strtolower(trim((string) ($payload['domain'] ?? '')));
    if (!validDomain($domain)) throw new InvalidArgumentException('Invalid domain');
    $domainId = (int) ($payload['domainId'] ?? 0);
    if ($domainId > 0) {
        [$document, , $row] = locateResource($store, $auth, 'domains', $domainId);
        if (!hash_equals(mb_strtolower((string) ($row['domain'] ?? '')), $domain)) {
            throw new InvalidArgumentException('Domain does not match the selected record');
        }
        return [$document, $domain, $row];
    }
    if ($mustExist) throw new InvalidArgumentException('Saved domain is required');
    $document = resourceOwner($store, $auth, ['userId' => (int) ($payload['userId'] ?? 0)]);
    return [$document, $domain, []];
}

function dnsManagedZoneId(string $prefix, string $connectionId, string $domain): string
{
    return 'dnszone-' . substr(hash('sha256', $prefix . '|' . $connectionId . '|' . $domain), 0, 32);
}

function dnsManagementEnabledForAuth(DataStore $store, array $auth): bool
{
    foreach (documentsForAuth($store, $auth) as $document) {
        if (DnsService::managedConnections((array) ($document['profile'] ?? []))) return true;
    }
    return false;
}

function dnsManagedRows(array $documents): array
{
    $rows = [];
    foreach ($documents as $document) {
        $profile = (array) ($document['profile'] ?? []);
        $serverDomains = [];
        foreach (is_array($document['resources']['domains'] ?? null) ? $document['resources']['domains'] : [] as $serverDomain) {
            if (!is_array($serverDomain)) continue;
            $serverDomainName = mb_strtolower(rtrim(trim((string) ($serverDomain['domain'] ?? '')), '.'));
            if ($serverDomainName !== '') $serverDomains[$serverDomainName] = true;
        }
        $connections = [];
        foreach (DnsService::managedConnections($profile) as $connection) {
            $connections[(string) $connection['id']] = $connection;
        }
        foreach (is_array($document['resources']['dnsZones'] ?? null) ? $document['resources']['dnsZones'] : [] as $zone) {
            if (!is_array($zone)) continue;
            $connectionId = (string) ($zone['connectionId'] ?? '');
            if (!isset($connections[$connectionId])) continue;
            $connection = $connections[$connectionId];
            $updatedAt = trim((string) ($zone['updatedAt'] ?? $zone['createdAt'] ?? ''));
            $timestamp = $updatedAt !== '' ? strtotime($updatedAt) : false;
            $records = is_array($zone['records'] ?? null) ? $zone['records'] : [];
            $lastCopy = is_array($zone['lastCopyAttempt'] ?? null) ? $zone['lastCopyAttempt'] : [];
            $lastBulkChange = is_array($zone['lastBulkChangeAttempt'] ?? null) ? $zone['lastBulkChangeAttempt'] : [];
            $synchronized = !empty($zone['synchronized']);
            if (!array_key_exists('synchronized', $zone)) {
                $lastSync = trim((string) ($zone['synchronizedAt'] ?? $zone['sentAt'] ?? $zone['fetchedAt'] ?? ''));
                $lastSyncTimestamp = $lastSync !== '' ? strtotime($lastSync) : false;
                $synchronized = $lastSyncTimestamp !== false && ($timestamp === false || $lastSyncTimestamp >= $timestamp);
            }
            $rows[] = [
                'id' => (string) ($zone['id'] ?? ''),
                'domain' => (string) ($zone['domain'] ?? ''),
                'onServer' => isset($serverDomains[mb_strtolower(rtrim(trim((string) ($zone['domain'] ?? '')), '.'))]),
                'provider' => (string) $connection['provider'],
                'connectionId' => $connectionId,
                'connectionName' => (string) $connection['name'],
                'records' => count($records),
                'synchronized' => $synchronized,
                'synchronizedAt' => (string) ($zone['synchronizedAt'] ?? ''),
                'lastCopyStatus' => (string) ($lastCopy['status'] ?? ''),
                'lastCopyAt' => (string) ($lastCopy['at'] ?? ''),
                'lastCopySourceDomain' => (string) ($lastCopy['sourceDomain'] ?? ''),
                'lastCopyError' => (string) ($lastCopy['error'] ?? ''),
                'lastBulkChangeStatus' => (string) ($lastBulkChange['status'] ?? ''),
                'lastBulkChangeAt' => (string) ($lastBulkChange['at'] ?? ''),
                'lastBulkChangeError' => (string) ($lastBulkChange['error'] ?? ''),
                'status' => (string) ($zone['status'] ?? ''),
                'fetchedAt' => (string) ($zone['fetchedAt'] ?? ''),
                'sentAt' => (string) ($zone['sentAt'] ?? ''),
                'updatedAt' => $updatedAt,
                'updatedAtTimestamp' => $timestamp !== false ? $timestamp : 0,
                'userId' => (int) ($profile['id'] ?? 0),
                'user' => (string) ($profile['email'] ?? ''),
                'prefix' => (string) ($profile['prefix'] ?? ''),
            ];
        }
    }
    return $rows;
}

function dnsManagedRefreshQueue(DataStore $store, array $auth): array
{
    $zones = [];
    foreach (dnsManagedRows(documentsForAuth($store, $auth)) as $row) {
        $id = trim((string) ($row['id'] ?? ''));
        $domain = trim((string) ($row['domain'] ?? ''));
        if ($id === '' || $domain === '') continue;
        $zones[] = [
            'id' => $id,
            'domain' => $domain,
            'provider' => (string) ($row['provider'] ?? ''),
            'connectionName' => (string) ($row['connectionName'] ?? ''),
        ];
    }
    usort($zones, static function (array $left, array $right): int {
        return strnatcasecmp($left['domain'] . '|' . $left['connectionName'], $right['domain'] . '|' . $right['connectionName']);
    });
    return $zones;
}

function dnsManagedBulkOptions(DataStore $store, array $auth): array
{
    $zones = [];
    $users = [];
    $providers = [];
    foreach (dnsManagedRows(documentsForAuth($store, $auth)) as $row) {
        $id = trim((string) ($row['id'] ?? ''));
        $domain = trim((string) ($row['domain'] ?? ''));
        $provider = trim((string) ($row['provider'] ?? ''));
        $userId = (int) ($row['userId'] ?? 0);
        if ($id === '' || $domain === '' || $provider === '') continue;
        $zones[] = [
            'id' => $id,
            'domain' => $domain,
            'onServer' => !empty($row['onServer']),
            'provider' => $provider,
            'connectionName' => (string) ($row['connectionName'] ?? ''),
            'userId' => $userId,
            'user' => (string) ($row['user'] ?? ''),
            'prefix' => (string) ($row['prefix'] ?? ''),
        ];
        $providers[$provider] = strtoupper($provider);
        if ($userId > 0) {
            $users[$userId] = [
                'id' => $userId,
                'email' => (string) ($row['user'] ?? ''),
                'prefix' => (string) ($row['prefix'] ?? ''),
            ];
        }
    }
    usort($zones, static function (array $left, array $right): int {
        return strnatcasecmp($left['domain'] . '|' . $left['connectionName'], $right['domain'] . '|' . $right['connectionName']);
    });
    $userRows = array_values($users);
    usort($userRows, static function (array $left, array $right): int {
        return strnatcasecmp($left['email'] . '|' . $left['prefix'], $right['email'] . '|' . $right['prefix']);
    });
    ksort($providers, SORT_NATURAL | SORT_FLAG_CASE);
    return [
        'zones' => $zones,
        'users' => (string) ($auth['role'] ?? '') === 'root' ? $userRows : [],
        'providers' => array_map(static function (string $id, string $name): array {
            return ['id' => $id, 'name' => $name];
        }, array_keys($providers), array_values($providers)),
        'types' => DnsService::editableTypes(),
    ];
}

function dnsManagedZoneContext(DataStore $store, array $auth, string $zoneId): array
{
    if (preg_match('/^dnszone-[a-f0-9]{32}$/D', $zoneId) !== 1) throw new InvalidArgumentException('Invalid DNS zone ID');
    foreach (documentsForAuth($store, $auth) as $document) {
        $zones = is_array($document['resources']['dnsZones'] ?? null) ? $document['resources']['dnsZones'] : [];
        foreach ($zones as $index => $zone) {
            if (!is_array($zone) || !hash_equals((string) ($zone['id'] ?? ''), $zoneId)) continue;
            $profile = (array) ($document['profile'] ?? []);
            $connection = DnsService::managedConnection($profile, (string) ($zone['connectionId'] ?? ''));
            $dnsProfile = DnsService::profileForConnection($profile, (string) $connection['id']);
            return [$document, (int) $index, $zone, $connection, $dnsProfile];
        }
    }
    throw new RuntimeException('DNS zone not found');
}

function dnsManagedCopyTargets(DataStore $store, array $auth, string $sourceZoneId): array
{
    $targets = [];
    foreach (dnsManagedRows(documentsForAuth($store, $auth)) as $row) {
        if (!is_array($row) || hash_equals((string) ($row['id'] ?? ''), $sourceZoneId)) continue;
        $targets[] = [
            'id' => (string) ($row['id'] ?? ''),
            'domain' => (string) ($row['domain'] ?? ''),
            'provider' => (string) ($row['provider'] ?? ''),
            'connectionName' => (string) ($row['connectionName'] ?? ''),
            'user' => (string) ($row['user'] ?? ''),
            'prefix' => (string) ($row['prefix'] ?? ''),
        ];
    }
    usort($targets, static function (array $left, array $right): int {
        return strnatcasecmp($left['domain'] . '|' . $left['connectionName'], $right['domain'] . '|' . $right['connectionName']);
    });
    return $targets;
}

function dnsEditableRecordsSnapshot(array $data): array
{
    $records = [];
    foreach (is_array($data['records'] ?? null) ? $data['records'] : [] as $record) {
        if (!is_array($record) || empty($record['editable'])) continue;
        $records[] = $record;
    }
    return DnsService::normalizeManagedRecords($records);
}

function dnsManagedZoneUpdate(DataStore $store, array $document, string $zoneId, callable $callback): array
{
    $prefix = (string) ($document['profile']['prefix'] ?? '');
    return $store->mutate($prefix, static function (array $current) use ($zoneId, $callback): array {
        $zones = is_array($current['resources']['dnsZones'] ?? null) ? $current['resources']['dnsZones'] : [];
        $zoneIndex = null;
        foreach ($zones as $index => $zone) {
            if (is_array($zone) && hash_equals((string) ($zone['id'] ?? ''), $zoneId)) { $zoneIndex = (int) $index; break; }
        }
        if ($zoneIndex === null) throw new RuntimeException('DNS zone not found');
        $updated = $callback($zones[$zoneIndex]);
        if (!is_array($updated)) throw new RuntimeException('Invalid DNS zone update');
        $updated['updatedAt'] = gmdate('c');
        $zones[$zoneIndex] = $updated;
        $current['resources']['dnsZones'] = array_values($zones);
        return $current;
    });
}

function refreshManagedDnsZones(DataStore $store, array $auth): array
{
    $result = ['connections' => 0, 'zones' => 0, 'errors' => []];
    foreach (documentsForAuth($store, $auth) as $document) {
        $profile = (array) ($document['profile'] ?? []);
        $prefix = (string) ($profile['prefix'] ?? '');
        $existing = is_array($document['resources']['dnsZones'] ?? null) ? $document['resources']['dnsZones'] : [];
        $existingById = [];
        foreach ($existing as $row) {
            if (is_array($row) && (string) ($row['id'] ?? '') !== '') $existingById[(string) $row['id']] = $row;
        }
        $replacementByConnection = [];
        foreach (DnsService::managedConnections($profile) as $connection) {
            $connectionId = (string) $connection['id'];
            try {
                $zones = DnsService::listZones(DnsService::profileForConnection($profile, $connectionId));
                $now = gmdate('c');
                $replacementByConnection[$connectionId] = [];
                foreach ($zones as $providerZone) {
                    if (!is_array($providerZone)) continue;
                    $domain = mb_strtolower(rtrim(trim((string) ($providerZone['name'] ?? '')), '.'));
                    if (!validDomain($domain)) continue;
                    $id = dnsManagedZoneId($prefix, $connectionId, $domain);
                    $old = is_array($existingById[$id] ?? null) ? $existingById[$id] : [];
                    $replacementByConnection[$connectionId][] = array_merge($old, [
                        'id' => $id,
                        'domain' => $domain,
                        'connectionId' => $connectionId,
                        'provider' => (string) $connection['provider'],
                        'status' => (string) ($providerZone['status'] ?? ''),
                        'records' => is_array($old['records'] ?? null) ? $old['records'] : [],
                        'synchronized' => !empty($old['synchronized']),
                        'synchronizedAt' => (string) ($old['synchronizedAt'] ?? ''),
                        'createdAt' => (string) ($old['createdAt'] ?? $now),
                        'discoveredAt' => $now,
                        'updatedAt' => (string) ($old['updatedAt'] ?? $now),
                    ]);
                    $result['zones']++;
                }
                $result['connections']++;
            } catch (Throwable $exception) {
                $result['errors'][] = (string) $connection['name'] . ': ' . $exception->getMessage();
            }
        }
        if (!$replacementByConnection) continue;
        $store->mutate($prefix, static function (array $current) use ($replacementByConnection): array {
            $currentRows = is_array($current['resources']['dnsZones'] ?? null) ? $current['resources']['dnsZones'] : [];
            $next = [];
            foreach ($currentRows as $row) {
                if (!is_array($row) || isset($replacementByConnection[(string) ($row['connectionId'] ?? '')])) continue;
                $next[] = $row;
            }
            foreach ($replacementByConnection as $rows) foreach ($rows as $row) $next[] = $row;
            $current['resources']['dnsZones'] = array_values($next);
            return $current;
        });
    }
    return $result;
}

function resourceRows(array $documents, string $type): array
{
    $result = [];
    foreach ($documents as $document) {
        $profile = $document['profile'];
        $rows = is_array($document['resources'][$type] ?? null) ? $document['resources'][$type] : [];
        $databases = is_array($document['resources']['databases'] ?? null) ? $document['resources']['databases'] : [];
        $mail = is_array($document['resources']['mail'] ?? null) ? $document['resources']['mail'] : [];
        $countedDomainPaths = [];

        foreach ($rows as $row) {
            $row['userId'] = (int) ($profile['id'] ?? 0);
            $row['user'] = (string) ($profile['email'] ?? '');
            $row['prefix'] = (string) ($profile['prefix'] ?? '');
            $row['comment'] = (string) ($row['comment'] ?? '');
            $row['createdAt'] = trim((string) ($row['createdAt'] ?? $row['created'] ?? ''));
            if (($row['createdAt'] === '' || strtotime($row['createdAt']) === false) && isset($row['updatedAt'])) {
                $row['createdAt'] = trim((string) $row['updatedAt']);
            }
            $createdAtTimestamp = $row['createdAt'] !== '' ? strtotime($row['createdAt']) : false;
            $row['createdAtTimestamp'] = $createdAtTimestamp !== false ? $createdAtTimestamp : 0;

            if ($type === 'databases') {
                $databaseName = (string) ($row['name'] ?? '');
                $row['username'] = (string) ($row['username'] ?? ($databaseName !== '' ? databaseAccountName($databaseName) : ''));
                $row['host'] = (string) ($row['host'] ?? MYSQL_CLIENT_CONNECTION_HOST);
                $row['port'] = (int) ($row['port'] ?? MYSQL_CLIENT_CONNECTION_PORT);
            }

            if ($type === 'mail') {
                $forwardTo = is_array($row['forwardTo'] ?? null)
                    ? $row['forwardTo']
                    : preg_split('/[\s,;]+/u', trim((string) ($row['forwardTo'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
                $row['forwardTo'] = array_values(array_filter(array_map('strval', $forwardTo ?: [])));
                $row['forwardSearch'] = implode(' ', $row['forwardTo']);
                $row['catchAll'] = !empty($row['catchAll']);
            }

            if ($type === 'domains') {
                $path = trim(str_replace('\\', '/', (string) ($row['path'] ?? '')), '/');
                if (isset($countedDomainPaths[$path])) {
                    $row['folderBytes'] = 0;
                    $row['folderPrimary'] = false;
                    $row['primaryDomain'] = $countedDomainPaths[$path];
                } else {
                    $countedDomainPaths[$path] = (string) ($row['domain'] ?? '');
                    $row['folderPrimary'] = true;
                    $row['primaryDomain'] = (string) ($row['domain'] ?? '');
                }
                $linkedDatabase = null;
                foreach ($databases as $database) {
                    if (($database['domain'] ?? null) === ($row['domain'] ?? null)) {
                        $linkedDatabase = $database;
                        break;
                    }
                }
                $linkedMail = array_values(array_filter($mail, static function (array $mailbox) use ($row): bool {
                    return ($mailbox['domain'] ?? null) === ($row['domain'] ?? null);
                }));
                $row['database'] = $linkedDatabase['name'] ?? null;
                $row['databaseBytes'] = (float) ($linkedDatabase['bytes'] ?? 0);
                $row['mailAccounts'] = count($linkedMail);
                $row['mailBytes'] = array_reduce($linkedMail, static function ($total, array $mailbox) {
                    return (float) $total + (float) ($mailbox['bytes'] ?? 0);
                }, 0.0);
                $row['sslSort'] = !empty($row['sslValid'] ?? $row['ssl'] ?? false) ? 1 : 0;
                $toolAccesses = is_array($row['toolAccesses'] ?? null) ? $row['toolAccesses'] : [];
                $toolAvailability = ['phpmyadmin' => false, 'filemanager' => false, 'fileeditor' => false];
                foreach ($toolAccesses as $access) {
                    if (!is_array($access) || empty($access['active'])) continue;
                    $startsAt = strtotime((string) ($access['startsAt'] ?? '')) ?: 0;
                    $expiresAt = strtotime((string) ($access['expiresAt'] ?? '')) ?: 0;
                    if ($startsAt > time() || $expiresAt <= time()) continue;
                    $permissions = is_array($access['permissions'] ?? null) ? $access['permissions'] : [];
                    foreach (array_keys($toolAvailability) as $tool) {
                        if (!empty($permissions[$tool])) $toolAvailability[$tool] = true;
                    }
                }
                $row['toolAvailability'] = $toolAvailability;
                $row['toolAccessCount'] = count($toolAccesses);
                $row['dkim'] = array_key_exists('dkim', $row)
                    ? !empty($row['dkim'])
                    : count($linkedMail) > 0 && count(array_filter($linkedMail, static function (array $mailbox): bool {
                        return !empty($mailbox['dkim']);
                    })) === count($linkedMail);
                $row['spf'] = array_key_exists('spf', $row)
                    ? !empty($row['spf'])
                    : count($linkedMail) > 0 && count(array_filter($linkedMail, static function (array $mailbox): bool {
                        return !empty($mailbox['spf']);
                    })) === count($linkedMail);
                $row['dmarc'] = array_key_exists('dmarc', $row)
                    ? !empty($row['dmarc'])
                    : count($linkedMail) > 0 && count(array_filter($linkedMail, static function (array $mailbox): bool {
                        return !empty($mailbox['dmarc']);
                    })) === count($linkedMail);
            }
            unset($row['passwordHash'], $row['_passwordHashComment']);
            if ($type === 'databases' && !SHOW_DATABASE_PASSWORDS) unset($row['password']);
            if ($type === 'mail' && !SHOW_MAIL_PASSWORDS) unset($row['password']);
            $result[] = $row;
        }
    }
    return $result;
}

function migrateCreatedAtDates(DataStore $store): array
{
    $now = gmdate('c');
    $result = [
        'files' => 0,
        'filesUpdated' => 0,
        'profilesUpdated' => 0,
        'domainsUpdated' => 0,
        'databasesUpdated' => 0,
        'mailUpdated' => 0,
    ];

    $dateFor = static function (array $record) use ($now): string {
        foreach (['createdAt', 'created', 'updatedAt', 'modifiedAt', 'modified', 'updated'] as $field) {
            $value = trim((string) ($record[$field] ?? ''));
            if ($value !== '' && strtotime($value) !== false) {
                return $value;
            }
        }
        return $now;
    };

    foreach ($store->listDocuments() as $document) {
        $prefix = trim((string) ($document['profile']['prefix'] ?? ''));
        if ($prefix === '') {
            continue;
        }
        $result['files']++;
        $changed = false;
        $profileCreatedAt = trim((string) ($document['profile']['createdAt'] ?? ''));
        if ($profileCreatedAt === '' || strtotime($profileCreatedAt) === false) {
            $document['profile']['createdAt'] = $dateFor($document['profile']);
            $result['profilesUpdated']++;
            $changed = true;
        }

        foreach (['domains', 'databases', 'mail'] as $type) {
            $rows = is_array($document['resources'][$type] ?? null) ? $document['resources'][$type] : [];
            foreach ($rows as $index => $row) {
                if (!is_array($row)) {
                    continue;
                }
                $createdAt = trim((string) ($row['createdAt'] ?? ''));
                if ($createdAt !== '' && strtotime($createdAt) !== false) {
                    continue;
                }
                $document['resources'][$type][$index]['createdAt'] = $dateFor($row);
                $result[$type . 'Updated']++;
                $changed = true;
            }
        }

        if ($changed) {
            $store->mutate($prefix, static function (array $current) use ($document): array {
                return $document;
            });
            $result['filesUpdated']++;
        }
    }

    return $result;
}

function allRows(DataStore $store, StatusStore $statusStore, array $auth, string $type): array
{
    $documents = $statusStore->mergeDocuments(documentsForAuth($store, $auth));
    if ($type === 'users') {
        return array_map('profileRow', $documents);
    }
    if ($type === 'dnsManagement') {
        return dnsManagedRows(documentsForAuth($store, $auth));
    }
    if (!in_array($type, ['domains', 'databases', 'mail'], true)) {
        throw new InvalidArgumentException('Unknown resource type');
    }
    return resourceRows($documents, $type);
}

function tableResponse(array $rows, array $request): array
{
    $total = count($rows);
    $search = mb_strtolower(trim((string) ($request['search']['value'] ?? '')));
    if ($search !== '') {
        $rows = array_values(array_filter($rows, static function (array $row) use ($search): bool {
            return mb_strpos(mb_strtolower((string) json_encode($row, JSON_UNESCAPED_UNICODE)), $search) !== false;
        }));
    }

    $columns = isset($request['columns']) && is_array($request['columns']) ? $request['columns'] : [];
    foreach ($columns as $column) {
        if (($column['searchable'] ?? 'true') === 'false') continue;
        $keys = [];
        foreach (['data', 'name'] as $attribute) {
            $key = isset($column[$attribute]) && is_string($column[$attribute]) ? $column[$attribute] : '';
            if ($key !== '' && preg_match('/^[A-Za-z0-9_]+$/D', $key) === 1) $keys[$key] = true;
        }
        $needle = mb_strtolower(trim((string) ($column['search']['value'] ?? '')));
        if (!$keys || $needle === '') {
            continue;
        }
        $filterKeys = array_keys($keys);
        $rows = array_values(array_filter($rows, static function (array $row) use ($filterKeys, $needle): bool {
            $values = [];
            foreach ($filterKeys as $key) {
                $value = $row[$key] ?? '';
                $values[] = is_array($value) ? json_encode($value, JSON_UNESCAPED_UNICODE) : (string) $value;
            }
            return mb_strpos(mb_strtolower(implode(' ', $values)), $needle) !== false;
        }));
    }

    $filtered = count($rows);
    $orders = isset($request['order']) && is_array($request['order']) ? $request['order'] : [];
    $sorts = [];
    foreach ($orders as $order) {
        if (!is_array($order)) continue;
        $index = (int) ($order['column'] ?? -1);
        $column = isset($columns[$index]) && is_array($columns[$index]) ? $columns[$index] : [];
        if (($column['orderable'] ?? 'true') === 'false') continue;
        $key = isset($column['name']) && is_string($column['name']) && $column['name'] !== ''
            ? $column['name']
            : (isset($column['data']) && is_string($column['data']) ? $column['data'] : '');
        if ($key === '' || preg_match('/^[A-Za-z0-9_]+$/D', $key) !== 1) continue;
        $sorts[] = ['key' => $key, 'direction' => ($order['dir'] ?? 'asc') === 'desc' ? -1 : 1];
    }
    if ($sorts) {
        $indexedRows = [];
        foreach ($rows as $position => $row) $indexedRows[] = ['position' => $position, 'row' => $row];
        usort($indexedRows, static function (array $leftItem, array $rightItem) use ($sorts): int {
            foreach ($sorts as $sort) {
                $key = $sort['key'];
                $a = $leftItem['row'][$key] ?? '';
                $b = $rightItem['row'][$key] ?? '';
                if (is_bool($a)) $a = $a ? 1 : 0;
                if (is_bool($b)) $b = $b ? 1 : 0;
                if (is_numeric($a) && is_numeric($b)) {
                    $comparison = (float) $a <=> (float) $b;
                } else {
                    if (is_array($a)) $a = json_encode($a, JSON_UNESCAPED_UNICODE);
                    if (is_array($b)) $b = json_encode($b, JSON_UNESCAPED_UNICODE);
                    $comparison = strnatcasecmp((string) $a, (string) $b);
                }
                if ($comparison !== 0) return $comparison * $sort['direction'];
            }
            return $leftItem['position'] <=> $rightItem['position'];
        });
        $rows = array_map(static function (array $item): array { return $item['row']; }, $indexedRows);
    }

    $start = max(0, (int) ($request['start'] ?? 0));
    $length = max(1, min(300, (int) ($request['length'] ?? 10)));
    return [
        'draw' => (int) ($request['draw'] ?? 0),
        'recordsTotal' => $total,
        'recordsFiltered' => $filtered,
        'data' => array_slice($rows, $start, $length),
    ];
}

function rootOrFail(string $action, array $params): array
{
    $result = rootRequest($action, $params);
    if (empty($result['ok'])) {
        throw new RuntimeException((string) ($result['error'] ?? 'Root request failed'));
    }
    return $result;
}

function recommendedDnsRecordsForDomain(string $domain): array
{
    $dkimValue = null;
    if (OPENDKIM_MANAGEMENT_MODE === 'per_domain_keys') {
        $result = rootOrFail('opendkim_prepare', ['domain' => $domain]);
        $data = is_array($result['data'] ?? null) ? $result['data'] : [];
        $dkimValue = trim((string) ($data['dnsValue'] ?? ''));
        if ($dkimValue === '') throw new RuntimeException('Cannot prepare DKIM DNS record');
    }
    return DnsService::recommendedRecords($domain, $dkimValue);
}

function enforceVerificationRateLimit(array $auth): void
{
    $identity = implode('|', [
        (string) ($auth['role'] ?? ''),
        (string) ($auth['user_id'] ?? ''),
        (string) ($auth['prefix'] ?? ''),
        panelClientIp(),
    ]);
    $limiter = new SlidingWindowRateLimiter(
        DNS_VERIFY_RATE_LIMIT_DIRECTORY,
        DNS_VERIFY_RATE_LIMIT,
        DNS_VERIFY_RATE_WINDOW_SECONDS
    );
    $limit = $limiter->consume($identity);
    if (empty($limit['allowed'])) {
        $retryAfter = (int) ($limit['retryAfter'] ?? 1);
        header('Retry-After: ' . $retryAfter);
        apiResponse([
            'ok' => false,
            'data' => $limit,
            'error' => 'Разрешено не более ' . DNS_VERIFY_RATE_LIMIT
                . ' проверок в минуту. Повторите через ' . $retryAfter . ' сек.',
        ], 429);
    }
}

function rebuildApacheVhosts(string $prefix): void
{
    rootOrFail('apache_vhosts_rebuild', ['prefix' => $prefix]);
}

function locateResource(DataStore $store, array $auth, string $type, int $id): array
{
    foreach (documentsForAuth($store, $auth) as $document) {
        foreach ($document['resources'][$type] ?? [] as $index => $row) {
            if ((int) ($row['id'] ?? 0) === $id) {
                return [$document, (int) $index, $row];
            }
        }
    }
    throw new RuntimeException('Resource not found');
}

function apiMailMigrationStore(): MailMigrationStore
{
    return MailMigrationStore::configured();
}

function mailMigrationOwnedContext(DataStore $store, array $auth, int $mailboxId): array
{
    if ($mailboxId <= 0) throw new InvalidArgumentException('Invalid destination mailbox');
    [$document, , $mailbox] = locateResource($store, $auth, 'mail', $mailboxId);
    return [
        'prefix' => (string) ($document['profile']['prefix'] ?? ''),
        'mailboxId' => $mailboxId,
        'address' => (string) ($mailbox['address'] ?? ''),
    ];
}

function publicMailMigration(MailMigrationStore $store, array $job, bool $readProgress = false): array
{
    if ($readProgress && in_array((string) ($job['status'] ?? ''), ['pending', 'checking', 'ready', 'running'], true)) {
        $job = mailMigrationProgressFromLog($job, MailMigrationRuntime::readLog((string) $job['id']));
    }
    return $store->publicRow($job);
}

function allowedDomainLogFiles(): array
{
    return array_values(array_unique([
        USER_APACHE_ACCESS_LOG_FILE,
        USER_APACHE_ERROR_LOG_FILE,
        USER_PHP_ERROR_LOG_FILE,
    ]));
}

function domainLogContext(DataStore $store, array $auth, int $domainId, string $requestedFile): array
{
    if ($domainId <= 0 || !in_array($requestedFile, allowedDomainLogFiles(), true)) {
        throw new InvalidArgumentException('Invalid domain log request');
    }
    [$document, , $domain] = locateResource($store, $auth, 'domains', $domainId);
    $prefix = (string) ($document['profile']['prefix'] ?? '');
    $domainName = mb_strtolower(trim((string) ($domain['domain'] ?? '')));
    $relativePath = trim(str_replace('\\', '/', (string) ($domain['path'] ?? '')), '/');
    $publicDirectory = trim(USER_PUBLIC_HTML_DIRECTORY, '/');
    $logDirectoryName = trim(USER_PHP_LOG_DIRECTORY, '/');
    if (!validDomain($domainName)
        || !validRelativePath($relativePath)
        || $publicDirectory === ''
        || basename($relativePath) !== $publicDirectory
        || preg_match('/^[a-zA-Z0-9._-]+$/', $logDirectoryName) !== 1) {
        throw new RuntimeException('Invalid domain log path');
    }

    $userRoot = rtrim(str_replace('\\', '/', userRootPath($prefix)), '/');
    $documentRoot = $userRoot . '/' . $relativePath;
    $logDirectory = dirname($documentRoot) . '/' . $logDirectoryName;
    $expectedPath = $logDirectory . '/' . $requestedFile;
    if (!validRootPath($userRoot)
        || strpos($logDirectory, $userRoot . '/') !== 0
        || preg_match('/[\x00\r\n"]/', $expectedPath) === 1) {
        throw new RuntimeException('Unsafe domain log path');
    }

    if (!is_file($expectedPath)) {
        return ['domain' => $domainName, 'file' => $requestedFile, 'path' => $expectedPath, 'exists' => false];
    }
    if (is_link($expectedPath)) throw new RuntimeException('Domain log cannot be a symlink');
    $realRoot = realpath($userRoot);
    $realLogDirectory = realpath($logDirectory);
    $realFile = realpath($expectedPath);
    if ($realRoot === false || $realLogDirectory === false || $realFile === false
        || strpos(str_replace('\\', '/', $realLogDirectory), rtrim(str_replace('\\', '/', $realRoot), '/') . '/') !== 0
        || dirname(str_replace('\\', '/', $realFile)) !== str_replace('\\', '/', $realLogDirectory)) {
        throw new RuntimeException('Unsafe domain log target');
    }
    if (!is_readable($realFile)) throw new RuntimeException('Domain log is not readable');
    return ['domain' => $domainName, 'file' => $requestedFile, 'path' => $realFile, 'exists' => true];
}

function displayLogLine(string $line): string
{
    if (strlen($line) > DOMAIN_LOG_LINE_MAX_BYTES) {
        $line = substr($line, 0, DOMAIN_LOG_LINE_MAX_BYTES) . '…';
    }
    if (!mb_check_encoding($line, 'UTF-8')) {
        $line = mb_convert_encoding($line, 'UTF-8', 'UTF-8');
    }
    return $line;
}

function readDomainLogPage(string $path, int $page): array
{
    $page = max(1, min(100000, $page));
    $limit = max(1, DOMAIN_LOG_LINES_PER_PAGE);
    $skip = ($page - 1) * $limit;
    $handle = fopen($path, 'rb');
    if ($handle === false || fseek($handle, 0, SEEK_END) !== 0) throw new RuntimeException('Cannot open domain log');
    $position = ftell($handle);
    if ($position === false) {
        fclose($handle);
        throw new RuntimeException('Cannot read domain log');
    }

    $buffer = '';
    $seen = 0;
    $lines = [];
    $hasOlder = false;
    $skipTrailingEmpty = true;
    $stop = false;
    $consume = static function (string $line) use (&$seen, &$lines, &$hasOlder, &$skipTrailingEmpty, &$stop, $skip, $limit): void {
        $line = rtrim($line, "\r");
        if ($skipTrailingEmpty && $line === '') {
            $skipTrailingEmpty = false;
            return;
        }
        $skipTrailingEmpty = false;
        if ($seen < $skip) {
            $seen++;
            return;
        }
        if (count($lines) < $limit) {
            $lines[] = displayLogLine($line);
            $seen++;
            return;
        }
        $hasOlder = true;
        $stop = true;
    };

    while ($position > 0 && !$stop) {
        $length = min(8192, $position);
        $position -= $length;
        if (fseek($handle, $position, SEEK_SET) !== 0) break;
        $chunk = fread($handle, $length);
        if ($chunk === false) break;
        $buffer = $chunk . $buffer;
        $parts = explode("\n", $buffer);
        $buffer = array_shift($parts);
        for ($index = count($parts) - 1; $index >= 0 && !$stop; $index--) {
            $consume($parts[$index]);
        }
    }
    if (!$stop && $position === 0 && $buffer !== '') $consume($buffer);
    fclose($handle);

    return [
        'page' => $page,
        'linesPerPage' => $limit,
        'lines' => count($lines),
        'content' => implode("\n", array_reverse($lines)),
        'hasNewer' => $page > 1,
        'hasOlder' => $hasOlder,
    ];
}

function saveUser(DataStore $store, array $record): array
{
    $id = (int) ($record['id'] ?? 0);
    $existing = $id > 0 ? $store->findByUserId($id) : null;
    if ($id > 0 && $existing === null) {
        throw new RuntimeException('User not found');
    }
    $prefix = mb_strtolower(trim((string) ($record['prefix'] ?? '')));
    if ($existing !== null) {
        $prefix = (string) $existing['profile']['prefix'];
    }
    if (strpos($prefix, 'usr_') === 0 || preg_match('/^[a-z][a-z0-9_]{1,31}$/', $prefix) !== 1) {
        throw new InvalidArgumentException('Invalid prefix');
    }
    $email = mb_strtolower(trim((string) ($record['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new InvalidArgumentException('Invalid email');
    }
    $comment = normalizePanelComment($record['comment'] ?? '');
    foreach ($store->listDocuments() as $existingDocument) {
        if ((int) ($existingDocument['profile']['id'] ?? 0) !== $id
            && mb_strtolower((string) ($existingDocument['profile']['prefix'] ?? '')) === $prefix) {
            throw new InvalidArgumentException('Такой префикс используется');
        }
        if ((int) ($existingDocument['profile']['id'] ?? 0) !== $id
            && mb_strtolower((string) ($existingDocument['profile']['email'] ?? '')) === $email) {
            throw new InvalidArgumentException('Email already exists');
        }
    }

    $password = (string) ($record['password'] ?? '');
    if ($id === 0 && $password === '') {
        throw new InvalidArgumentException('Password is required');
    }
    $tariffs = panelTariffs();
    $tariffKey = mb_strtolower(trim((string) ($record['tariff'] ?? ($existing['profile']['tariff'] ?? DEFAULT_USER_TARIFF))));
    if (!isset($tariffs[$tariffKey])) throw new InvalidArgumentException('Invalid tariff');
    $tariff = $tariffs[$tariffKey];
    $aggregateQuotas = tariffAggregateQuotas($tariff);
    $profileSettings = normalizeProfileSettings($record, is_array($existing['profile'] ?? null) ? $existing['profile'] : []);
    $rootPath = userRootPath($prefix);
    if (!validRootPath($rootPath)) {
        throw new InvalidArgumentException('Invalid user root path');
    }
    $rootParams = [
        'id' => $id,
        'prefix' => $prefix,
        'email' => $email,
        'root_path' => $rootPath,
        'site_quota_bytes' => $aggregateQuotas['site'],
        'database_quota_bytes' => $aggregateQuotas['database'],
        'mail_quota_bytes' => $aggregateQuotas['mail'],
        'system_quota_bytes' => $aggregateQuotas['site'],
    ];
    if ($password !== '') {
        $rootParams['password'] = $password;
    }
    rootOrFail($id > 0 ? 'user_update' : 'user_create', $rootParams);

    if ($id === 0) {
        $now = gmdate('c');
        $document = [
            'schemaVersion' => 1,
            'profile' => array_merge([
                'id' => $store->nextUserId(),
                'name' => trim((string) ($record['name'] ?? '')),
                'email' => $email,
                'comment' => $comment,
                'prefix' => $prefix,
                'rootPath' => $rootPath,
                'tariff' => $tariffKey,
                'unixAccountManaged' => UNIX_ACCOUNTS_ENABLED,
                '_passwordHashComment' => 'Получить новый хеш: php -r "echo password_hash(\'НОВЫЙ_ПАРОЛЬ\', PASSWORD_DEFAULT), PHP_EOL;"',
                'passwordHash' => password_hash($password, PASSWORD_DEFAULT),
                'siteQuotaBytes' => $aggregateQuotas['site'],
                'databaseQuotaBytes' => $aggregateQuotas['database'],
                'mailQuotaBytes' => $aggregateQuotas['mail'],
                'active' => true,
                'createdAt' => $now,
                'updatedAt' => $now,
            ], $profileSettings),
            'resources' => ['domains' => [], 'databases' => [], 'mail' => [], 'dnsZones' => []],
        ];
        $store->create($prefix, $document);
        rebuildApacheVhosts($prefix);
        return profileRow($document);
    }

    $storedPrefix = (string) $existing['profile']['prefix'];
    $updated = $store->mutate($storedPrefix, static function (array $document) use ($record, $email, $comment, $password, $rootPath, $profileSettings, $tariffKey, $aggregateQuotas): array {
        $document['profile']['name'] = trim((string) ($record['name'] ?? ''));
        $document['profile']['email'] = $email;
        $document['profile']['comment'] = $comment;
        $document['profile']['rootPath'] = $rootPath;
        $document['profile']['tariff'] = $tariffKey;
        $document['profile']['unixAccountManaged'] = !empty($document['profile']['unixAccountManaged']) || UNIX_ACCOUNTS_ENABLED;
        $document['profile']['siteQuotaBytes'] = $aggregateQuotas['site'];
        $document['profile']['databaseQuotaBytes'] = $aggregateQuotas['database'];
        $document['profile']['mailQuotaBytes'] = $aggregateQuotas['mail'];
        unset($document['profile']['tariffRequest']);
        foreach ($profileSettings as $key => $value) $document['profile'][$key] = $value;
        if ($password !== '') {
            $document['profile']['_passwordHashComment'] = 'Получить новый хеш: php -r "echo password_hash(\'НОВЫЙ_ПАРОЛЬ\', PASSWORD_DEFAULT), PHP_EOL;"';
            $document['profile']['passwordHash'] = password_hash($password, PASSWORD_DEFAULT);
        }
        return $document;
    });
    rebuildApacheVhosts($storedPrefix);
    return profileRow($updated);
}

function saveOwnProfile(DataStore $store, array $auth, array $record): array
{
    if (isRoot($auth)) throw new InvalidArgumentException('Root profile is configured in config.php');
    $prefix = (string) ($auth['prefix'] ?? '');
    $document = $store->load($prefix);
    if ($document === null) throw new RuntimeException('User not found');
    $profile = is_array($document['profile'] ?? null) ? $document['profile'] : [];
    $email = mb_strtolower(trim((string) ($record['email'] ?? '')));
    if ($email === '' || !hash_equals(mb_strtolower((string) ($profile['email'] ?? '')), $email)) {
        throw new InvalidArgumentException('Primary email cannot be changed');
    }
    $name = normalizeProfileText($record['name'] ?? '', 'name', 120);
    if ($name === '') throw new InvalidArgumentException('Name is required');
    $password = (string) ($record['password'] ?? '');
    $passwordConfirmation = (string) ($record['passwordConfirmation'] ?? '');
    if ($password !== '' && !hash_equals($password, $passwordConfirmation)) {
        throw new InvalidArgumentException('Password confirmation does not match');
    }
    $settings = normalizeProfileSettings($record, $profile);
    $updated = $store->mutate($prefix, static function (array $current) use ($name, $password, $settings): array {
        $current['profile']['name'] = $name;
        foreach ($settings as $key => $value) $current['profile'][$key] = $value;
        if ($password !== '') {
            $current['profile']['_passwordHashComment'] = 'Получить новый хеш: php -r "echo password_hash(\'НОВЫЙ_ПАРОЛЬ\', PASSWORD_DEFAULT), PHP_EOL;"';
            $current['profile']['passwordHash'] = password_hash($password, PASSWORD_DEFAULT);
        }
        return $current;
    });
    $_SESSION['auth']['name'] = $name;
    if ($password !== '') panelForgetRememberCookie();
    return profileRow($updated);
}

function resourceOwner(DataStore $store, array $auth, array $record): array
{
    if (!isRoot($auth)) {
        $document = $store->load((string) $auth['prefix']);
    } else {
        $document = $store->findByUserId((int) ($record['userId'] ?? 0));
    }
    if ($document === null) {
        throw new RuntimeException('User not found');
    }
    return $document;
}

function validDomain(string $domain): bool
{
    return strlen($domain) <= 253
        && preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $domain) === 1;
}

function normalizeMailboxForwarding($value, string $primaryAddress): array
{
    $values = is_array($value) ? $value : preg_split('/[\s,;]+/u', trim((string) $value), -1, PREG_SPLIT_NO_EMPTY);
    $recipients = [];
    foreach ($values ?: [] as $candidate) {
        $recipient = mb_strtolower(trim((string) $candidate));
        if ($recipient === '') continue;
        $parts = explode('@', $recipient, 2);
        if (count($parts) !== 2
            || preg_match('/^[a-z0-9][a-z0-9._+-]{0,63}$/i', $parts[0]) !== 1
            || !validDomain($parts[1])) {
            throw new InvalidArgumentException('Invalid forwarding address: ' . $recipient);
        }
        if ($recipient !== $primaryAddress) $recipients[$recipient] = true;
    }
    return array_keys($recipients);
}

function normalizeMailboxAliases($value, string $domain, string $primaryAddress): array
{
    $values = is_array($value) ? $value : preg_split('/[\s,;]+/u', trim((string) $value), -1, PREG_SPLIT_NO_EMPTY);
    $aliases = [];
    foreach ($values ?: [] as $candidate) {
        $alias = mb_strtolower(trim((string) $candidate));
        if ($alias === '') continue;
        if (strpos($alias, '@') === false) $alias .= '@' . $domain;
        $parts = explode('@', $alias, 2);
        if (count($parts) !== 2
            || preg_match('/^[a-z0-9][a-z0-9._+-]{0,63}$/i', $parts[0]) !== 1
            || !validDomain($parts[1])
            || $parts[1] !== $domain) {
            throw new InvalidArgumentException('Invalid mailbox alias: ' . $alias);
        }
        if ($alias !== $primaryAddress) $aliases[$alias] = true;
    }
    return array_keys($aliases);
}

function normalizePhpVersion($value): string
{
    $selected = trim((string) $value);
    if ($selected === '') {
        $selected = APACHE_DEFAULT_PHP_VERSION;
    }
    foreach (APACHE_PHP_VERSIONS as $version) {
        if (is_array($version) && hash_equals((string) ($version['id'] ?? ''), $selected)) {
            return $selected;
        }
    }
    throw new InvalidArgumentException('Invalid PHP version');
}

function normalizeDomainToolIps($value): array
{
    $items = is_array($value) ? $value : preg_split('/[\s,;]+/u', trim((string) $value), -1, PREG_SPLIT_NO_EMPTY);
    $ips = [];
    foreach ($items ?: [] as $candidate) {
        $ip = trim((string) $candidate);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) throw new InvalidArgumentException('Invalid access IP: ' . $ip);
        $ips[$ip] = true;
    }
    if ($ips === []) throw new InvalidArgumentException('At least one access IP is required');
    return array_keys($ips);
}

function normalizeDomainToolAccesses($value, array $existing): array
{
    if (!is_array($value)) throw new InvalidArgumentException('Invalid domain tool accesses');
    if (count($value) > DOMAIN_TOOL_ACCESS_LIMIT) throw new InvalidArgumentException('Too many domain tool accesses');
    $existingById = [];
    foreach ($existing as $access) {
        if (is_array($access) && preg_match('/^[a-f0-9]{16}$/D', (string) ($access['id'] ?? '')) === 1) $existingById[(string) $access['id']] = $access;
    }
    $result = [];
    $ids = [];
    foreach (array_values($value) as $access) {
        if (!is_array($access)) throw new InvalidArgumentException('Invalid domain tool access');
        $id = mb_strtolower(trim((string) ($access['id'] ?? '')));
        if ($id === '') $id = bin2hex(random_bytes(8));
        if (preg_match('/^[a-f0-9]{16}$/D', $id) !== 1 || isset($ids[$id])) throw new InvalidArgumentException('Invalid domain tool access ID');
        $ids[$id] = true;
        $name = trim((string) ($access['name'] ?? ''));
        $login = trim((string) ($access['login'] ?? ''));
        $password = (string) ($access['password'] ?? '');
        if ($name === '' || mb_strlen($name) > 100) throw new InvalidArgumentException('Access name is required');
        if (preg_match('/^[A-Za-z0-9_.@-]{2,64}$/D', $login) !== 1) throw new InvalidArgumentException('Invalid access login');
        if (!validDatabasePassword($password)) throw new InvalidArgumentException('Access password must contain at least 8 characters, uppercase, lowercase, a number and a special character');
        $permissionsInput = is_array($access['permissions'] ?? null) ? $access['permissions'] : [];
        $permissions = [
            'phpmyadmin' => booleanValue($permissionsInput['phpmyadmin'] ?? false),
            'filemanager' => booleanValue($permissionsInput['filemanager'] ?? false),
            'fileeditor' => booleanValue($permissionsInput['fileeditor'] ?? false),
        ];
        if (!in_array(true, $permissions, true)) throw new InvalidArgumentException('Select at least one domain tool');
        $startsAt = strtotime((string) ($access['startsAt'] ?? ''));
        if ($startsAt === false || $startsAt <= 0) $startsAt = time();
        $expiresAt = strtotime((string) ($access['expiresAt'] ?? ''));
        if ($expiresAt === false || $expiresAt <= $startsAt) $expiresAt = $startsAt + (DOMAIN_TOOL_ACCESS_HOURS * 3600);
        if ($expiresAt - $startsAt > 366 * 86400) throw new InvalidArgumentException('Access period is too long');
        $old = $existingById[$id] ?? [];
        $result[] = [
            'id' => $id,
            'name' => $name,
            'login' => $login,
            'password' => $password,
            'ips' => normalizeDomainToolIps($access['ips'] ?? []),
            'permissions' => $permissions,
            'active' => booleanValue($access['active'] ?? true),
            'startsAt' => gmdate('c', $startsAt),
            'expiresAt' => gmdate('c', $expiresAt),
            'createdAt' => (string) ($old['createdAt'] ?? gmdate('c')),
            'updatedAt' => gmdate('c'),
        ];
    }
    return $result;
}

function documentProjectPaths(array $document, int $excludeDomainId = 0): array
{
    $paths = [];
    foreach ($document['resources']['domains'] ?? [] as $domain) {
        if ($excludeDomainId > 0 && (int) ($domain['id'] ?? 0) === $excludeDomainId) {
            continue;
        }
        $path = trim(str_replace('\\', '/', (string) ($domain['path'] ?? '')), '/');
        if ($path !== '' && validRelativePath($path)) {
            $paths[$path] = true;
        }
    }
    return array_keys($paths);
}

function normalizeDomainFolderBytes(array $domains): array
{
    $countedPaths = [];
    foreach ($domains as $index => $domain) {
        $path = trim(str_replace('\\', '/', (string) ($domain['path'] ?? '')), '/');
        if ($path === '' || isset($countedPaths[$path])) {
            $domains[$index]['folderBytes'] = 0;
            continue;
        }
        $countedPaths[$path] = true;
    }
    return array_values($domains);
}

function resolveDomainProjectPath(array $document, array $record, int $domainId, string $domain): string
{
    $mode = (string) ($record['projectPathMode'] ?? '');
    if ($mode === 'existing') {
        $path = trim(str_replace('\\', '/', (string) ($record['existingPath'] ?? '')), '/');
        if (!in_array($path, documentProjectPaths($document), true)) {
            throw new InvalidArgumentException('Selected project folder does not exist');
        }
        return $path;
    }

    if ($mode === 'new') {
        $folder = mb_strtolower(trim((string) ($record['projectFolder'] ?? '')));
        if ($folder === '') {
            $folder = $domain;
        }
        if (strlen($folder) > 128 || preg_match('/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/', $folder) !== 1) {
            throw new InvalidArgumentException('Invalid project folder name');
        }
        $path = $folder . '/' . trim(USER_PUBLIC_HTML_DIRECTORY, '/');
        if (in_array($path, documentProjectPaths($document, $domainId), true)) {
            throw new InvalidArgumentException('Project folder already exists; select it from the list');
        }
        return $path;
    }

    // Backward compatibility for older API clients: accept a complete relative path.
    $path = trim(str_replace('\\', '/', (string) ($record['path'] ?? '')));
    if (strlen($path) >= 2 && $path[0] === '{' && substr($path, -1) === '}') {
        $path = substr($path, 1, -1);
    }
    $path = trim($path, '/');
    $absoluteRoot = trim(str_replace('\\', '/', userRootPath((string) ($document['profile']['prefix'] ?? ''))), '/');
    if (stripos($path, $absoluteRoot . '/') === 0) {
        $path = substr($path, strlen($absoluteRoot) + 1);
    }
    $publicDirectory = trim(USER_PUBLIC_HTML_DIRECTORY, '/');
    if ($path !== '' && $path !== $publicDirectory && substr($path, -strlen('/' . $publicDirectory)) !== '/' . $publicDirectory) {
        $path .= '/' . $publicDirectory;
    }
    if (!validRelativePath($path)
        || ($path !== $publicDirectory && substr($path, -strlen('/' . $publicDirectory)) !== '/' . $publicDirectory)) {
        throw new InvalidArgumentException('Invalid domain relative path');
    }
    return $path;
}

function enforceTariffForSave(array $document, string $type, int $id, array $record, bool $createDatabase = false, bool $createMailbox = false): void
{
    if (!TARIFF_LIMITS_ENABLED) return;
    $profile = is_array($document['profile'] ?? null) ? $document['profile'] : [];
    $tariffs = panelTariffs();
    $tariff = $tariffs[profileTariffKey($profile)];
    $resources = is_array($document['resources'] ?? null) ? $document['resources'] : [];
    $domains = is_array($resources['domains'] ?? null) ? $resources['domains'] : [];
    $databases = is_array($resources['databases'] ?? null) ? $resources['databases'] : [];
    $mail = is_array($resources['mail'] ?? null) ? $resources['mail'] : [];
    $aggregate = tariffAggregateQuotas($tariff);
    $sumBytes = static function (array $rows): float {
        return array_reduce($rows, static function ($total, array $row): float { return (float) $total + (float) ($row['bytes'] ?? 0); }, 0.0);
    };
    $siteBytes = 0.0;
    $seenPaths = [];
    foreach ($domains as $domainRow) {
        $path = trim((string) ($domainRow['path'] ?? ''));
        if ($path !== '' && !isset($seenPaths[$path])) {
            $seenPaths[$path] = true;
            $siteBytes += (float) ($domainRow['folderBytes'] ?? 0);
        }
    }

    if ($type === 'domains' && $id === 0) {
        if ((int) $tariff['domain'] > 0 && count($domains) >= (int) $tariff['domain']) throw new RuntimeException('Лимит тарифа по количеству доменов исчерпан');
        if ($aggregate['site'] > 0 && $siteBytes >= $aggregate['site']) throw new RuntimeException('Лимит тарифа по размеру сайтов исчерпан');
        if ($createDatabase && (int) $tariff['db'] > 0 && count($databases) >= (int) $tariff['db']) throw new RuntimeException('Лимит тарифа по количеству баз данных исчерпан');
        if ($createDatabase && $aggregate['database'] > 0 && $sumBytes($databases) >= $aggregate['database']) throw new RuntimeException('Лимит тарифа по размеру баз данных исчерпан');
        if ($createMailbox && (float) $tariff['mailsize'] > 0 && IMPORT_MAIL_DEFAULT_QUOTA_MB * 1048576 > (float) $tariff['mailsize']) {
            throw new RuntimeException('Квота автоматически создаваемого ящика превышает лимит тарифа');
        }
    }
    if ($type === 'databases' && $id === 0 && (int) $tariff['db'] > 0 && count($databases) >= (int) $tariff['db']) {
        throw new RuntimeException('Лимит тарифа по количеству баз данных исчерпан');
    }
    if ($type === 'databases' && $id === 0 && $aggregate['database'] > 0 && $sumBytes($databases) >= $aggregate['database']) {
        throw new RuntimeException('Лимит тарифа по размеру баз данных исчерпан');
    }
    if ($type === 'mail') {
        $domain = mb_strtolower(trim((string) ($record['domain'] ?? '')));
        $mailForDomain = array_filter($mail, static function (array $row) use ($domain): bool {
            return mb_strtolower((string) ($row['domain'] ?? '')) === $domain;
        });
        if ($id === 0 && (int) $tariff['mailbydomain'] > 0 && count($mailForDomain) >= (int) $tariff['mailbydomain']) {
            throw new RuntimeException('Лимит тарифа по количеству почтовых ящиков этого домена исчерпан');
        }
        if ($id === 0 && $aggregate['mail'] > 0 && $sumBytes($mail) >= $aggregate['mail']) throw new RuntimeException('Лимит тарифа по размеру почты исчерпан');
        $quotaBytes = max(0, (float) ($record['quota'] ?? IMPORT_MAIL_DEFAULT_QUOTA_MB) * 1048576);
        if ((float) $tariff['mailsize'] > 0 && $quotaBytes > (float) $tariff['mailsize']) {
            throw new RuntimeException('Выбранная квота почтового ящика превышает лимит тарифа');
        }
    }
}

function assertDomainDnsReadyForCreation(string $domain, bool $requireWww): void
{
    $result = rootOrFail('apache_vhost_check', ['domain' => $domain]);
    $check = is_array($result['data'] ?? null) ? $result['data'] : [];
    if (empty($check['rootPoints'])) {
        throw new InvalidArgumentException('Домен не направлен на этот хостинг: ' . $domain);
    }
    if ($requireWww && empty($check['wwwPoints'])) {
        throw new InvalidArgumentException('Запись www не направлена на этот хостинг: www.' . $domain);
    }
}

function missingMailDnsRecords(string $domain): array
{
    $labels = [
        'mail_a' => 'MAIL A',
        'mx' => 'MX',
        'spf' => 'SPF',
        'dkim' => 'DKIM',
        'dmarc' => 'DMARC',
    ];
    try {
        $result = rootOrFail('opendkim_check', ['domain' => $domain]);
        $check = is_array($result['data'] ?? null) ? $result['data'] : [];
        $records = is_array($check['records'] ?? null) ? $check['records'] : [];
    } catch (Throwable $exception) {
        return array_values($labels);
    }
    $missing = [];
    foreach ($labels as $key => $label) {
        if (empty($records[$key]['valid'])) $missing[] = $label;
    }
    return $missing;
}

function saveResource(DataStore $store, array $auth, string $type, array $record, bool $rebuildVhosts = true): array
{
    $id = (int) ($record['id'] ?? 0);
    if ($id > 0) {
        [$document] = locateResource($store, $auth, $type, $id);
    } else {
        $document = resourceOwner($store, $auth, $record);
    }
    $document = (new StatusStore(STATUS_DIRECTORY, false))->mergeDocument($document);
    $prefix = (string) $document['profile']['prefix'];
    $createDatabase = booleanValue($record['createDatabase'] ?? false);
    $createMail = booleanValue($record['createMail'] ?? false);
    $domainMailMode = 'disabled';
    $domainMailForwardTo = [];
    $domainMailCatchAllToInfo = false;
    $savedId = $id;
    $warnings = [];

    if ($type === 'domains') {
        $domain = mb_strtolower(trim((string) ($record['domain'] ?? '')));
        if (!validDomain($domain)) {
            throw new InvalidArgumentException('Invalid domain');
        }
        foreach ($store->listDocuments() as $existingDocument) {
            foreach ($existingDocument['resources']['domains'] ?? [] as $existingDomain) {
                if ((int) ($existingDomain['id'] ?? 0) !== $id
                    && mb_strtolower((string) ($existingDomain['domain'] ?? '')) === $domain) {
                    throw new InvalidArgumentException('Domain already exists');
                }
            }
        }
        if ($id === 0) {
            assertDomainDnsReadyForCreation($domain, booleanValue($record['redirectWww'] ?? false));
        }
        $path = resolveDomainProjectPath($document, $record, $id, $domain);
        $phpVersion = normalizePhpVersion($record['phpVersion'] ?? APACHE_DEFAULT_PHP_VERSION);
        $existingToolAccesses = [];
        $existingDomainRecord = [];
        if ($id > 0) {
            foreach ($document['resources']['domains'] ?? [] as $existingDomain) {
                if ((int) ($existingDomain['id'] ?? 0) === $id) {
                    $existingDomainRecord = $existingDomain;
                    $existingToolAccesses = is_array($existingDomain['toolAccesses'] ?? null) ? $existingDomain['toolAccesses'] : [];
                    break;
                }
            }
        }
        if ($id === 0 && $createMail) {
            $profile = is_array($document['profile'] ?? null) ? $document['profile'] : [];
            $defaultForwardEmail = profileForwardEmailForDomain($profile, $domain);
            $forwardNewDomains = !empty($profile['mailForwardNewDomains']) && $defaultForwardEmail !== '';
            $forwardWholeDomain = !empty($profile['mailForwardWholeDomain']) && $defaultForwardEmail !== '';
            $domainMailCatchAllToInfo = !array_key_exists('mailCatchAllToInfo', $profile) || !empty($profile['mailCatchAllToInfo']);
            if ($forwardWholeDomain) {
                if (substr($defaultForwardEmail, strrpos($defaultForwardEmail, '@') + 1) === $domain) {
                    throw new InvalidArgumentException('Whole-domain forwarding cannot point to the same domain');
                }
                $domainMailMode = 'domain_forward';
                $domainMailForwardTo = [$defaultForwardEmail];
                $domainMailCatchAllToInfo = false;
            } elseif ($domainMailCatchAllToInfo || $forwardNewDomains) {
                $domainMailMode = 'info';
                $domainMailForwardTo = $forwardNewDomains ? [$defaultForwardEmail] : [];
            } else {
                $domainMailMode = 'domain_only';
            }
        } elseif ($id > 0) {
            $domainMailMode = (string) ($existingDomainRecord['mailMode'] ?? (!empty($existingDomainRecord['mailEnabled']) ? 'domain_only' : 'disabled'));
            $domainMailForwardTo = is_array($existingDomainRecord['mailForwardTo'] ?? null) ? array_values($existingDomainRecord['mailForwardTo']) : [];
            $domainMailCatchAllToInfo = !empty($existingDomainRecord['mailCatchAllToInfo']);
        }
        if ($id === 0 && $createMail) {
            $missingMailRecords = missingMailDnsRecords($domain);
            if ($missingMailRecords !== []) {
                $createMail = false;
                $domainMailMode = 'disabled';
                $domainMailForwardTo = [];
                $domainMailCatchAllToInfo = false;
                $warnings[] = 'Домен сохранён без почты. Настройте DNS-записи: ' . implode(', ', $missingMailRecords) . '.';
            }
        }
        enforceTariffForSave($document, $type, $id, $record, $createDatabase, $createMail && $domainMailMode === 'info');
        $normalized = [
            'id' => $id,
            'domain' => $domain,
            'path' => $path,
            'phpVersion' => $phpVersion,
            'comment' => normalizePanelComment($record['comment'] ?? ''),
            'ssl' => booleanValue($record['useSsl'] ?? false),
            'redirectHttp' => booleanValue($record['redirectHttp'] ?? false),
            'redirectWww' => booleanValue($record['redirectWww'] ?? false),
            'active' => true,
            'mailEnabled' => $id === 0 ? $createMail : !empty($existingDomainRecord['mailEnabled']),
            'mailMode' => $domainMailMode,
            'mailForwardTo' => $domainMailForwardTo,
            'mailCatchAllToInfo' => $domainMailCatchAllToInfo,
            'dnsConnectionId' => trim((string) ($record['dnsConnectionId'] ?? ($existingDomainRecord['dnsConnectionId'] ?? ''))),
            'toolAccesses' => $id > 0 ? normalizeDomainToolAccesses($record['toolAccesses'] ?? [], $existingToolAccesses) : [],
        ];
        if ($normalized['dnsConnectionId'] !== '') {
            $dnsValidationProfile = (array) ($document['profile'] ?? []);
            if (isRoot($auth)) $dnsValidationProfile['_useConfigDnsToken'] = true;
            DnsService::profileForConnection($dnsValidationProfile, $normalized['dnsConnectionId']);
        }
        if ($id === 0) {
            $normalized['bound'] = false;
            $normalized['folderBytes'] = 0;
        }
        rootOrFail($id > 0 ? 'domain_update' : 'domain_create', $normalized + ['prefix' => $prefix]);
    } elseif ($type === 'databases') {
        enforceTariffForSave($document, $type, $id, $record);
        $suffix = mb_strtolower(trim((string) ($record['name'] ?? '')));
        $suffix = preg_replace('/^' . preg_quote($prefix, '/') . '_/', '', $suffix) ?? '';
        if (preg_match('/^[a-z0-9_]{1,48}$/', $suffix) !== 1) {
            throw new InvalidArgumentException('Invalid database name');
        }
        $password = (string) ($record['password'] ?? '');
        if ($id > 0 && $password === '') {
            foreach ($document['resources']['databases'] ?? [] as $existingDatabase) {
                if ((int) ($existingDatabase['id'] ?? 0) === $id) {
                    $password = (string) ($existingDatabase['password'] ?? '');
                    break;
                }
            }
        }
        if (!validDatabasePassword($password)) {
            throw new InvalidArgumentException('Database password must contain at least 8 characters, uppercase, lowercase, a number and a special character');
        }
        $databaseName = $prefix . '_' . $suffix;
        $normalized = [
            'id' => $id,
            'name' => $databaseName,
            'username' => databaseAccountName($databaseName),
            'password' => $password,
            'host' => MYSQL_CLIENT_CONNECTION_HOST,
            'port' => MYSQL_CLIENT_CONNECTION_PORT,
            'comment' => normalizePanelComment($record['comment'] ?? ''),
            'bytes' => 0,
            'tables' => 0,
            'domain' => trim((string) ($record['domain'] ?? '')) ?: null,
            'active' => true,
        ];
        rootOrFail($id > 0 ? 'database_update' : 'database_create', $normalized + ['prefix' => $prefix]);
    } elseif ($type === 'mail') {
        $domain = mb_strtolower(trim((string) ($record['domain'] ?? '')));
        $mailbox = mb_strtolower(trim((string) ($record['mailbox'] ?? '')));
        if (!validDomain($domain) || preg_match('/^[a-z0-9.!#$%&\'*+\/=?^_`{|}~-]{1,64}$/i', $mailbox) !== 1) {
            throw new InvalidArgumentException('Invalid mail address');
        }
        $address = $mailbox . '@' . $domain;
        $aliases = normalizeMailboxAliases($record['aliases'] ?? [], $domain, $address);
        $forwardTo = normalizeMailboxForwarding($record['forwardTo'] ?? [], $address);
        $catchAll = booleanValue($record['catchAll'] ?? false);
        $domainOwned = false;
        $ownedDomainRecord = [];
        foreach ($document['resources']['domains'] ?? [] as $ownedDomain) {
            if (mb_strtolower((string) ($ownedDomain['domain'] ?? '')) === $domain) {
                $domainOwned = true;
                $ownedDomainRecord = $ownedDomain;
                break;
            }
        }
        if (!$domainOwned) {
            throw new InvalidArgumentException('Mail domain does not belong to the selected user');
        }
        if ($id === 0 && $catchAll && (string) ($ownedDomainRecord['mailMode'] ?? '') === 'domain_forward') {
            throw new InvalidArgumentException('Whole-domain forwarding is already enabled for this domain');
        }
        foreach ($store->listDocuments() as $existingDocument) {
            foreach ($existingDocument['resources']['mail'] ?? [] as $existingMailbox) {
                if ((int) ($existingMailbox['id'] ?? 0) === $id) continue;
                $existingAddress = mb_strtolower((string) ($existingMailbox['address'] ?? ''));
                $existingAliases = array_map('mb_strtolower', is_array($existingMailbox['aliases'] ?? null) ? $existingMailbox['aliases'] : []);
                if ($existingAddress === $address || in_array($address, $existingAliases, true)) throw new InvalidArgumentException('Mail address already exists');
                foreach ($aliases as $alias) {
                    if ($alias === $existingAddress || in_array($alias, $existingAliases, true)) throw new InvalidArgumentException('Mailbox alias already exists: ' . $alias);
                }
                if ($catchAll && !empty($existingMailbox['catchAll']) && substr($existingAddress, strrpos($existingAddress, '@') + 1) === $domain) {
                    throw new InvalidArgumentException('Catch-all already exists for domain: ' . $domain);
                }
            }
        }
        $password = (string) ($record['password'] ?? '');
        if ($id === 0 && $password === '') throw new InvalidArgumentException('Mailbox password is required');
        $quotaMb = (int) ($record['quota'] ?? IMPORT_MAIL_DEFAULT_QUOTA_MB);
        enforceTariffForSave($document, $type, $id, $record);
        $allowedQuotaMb = array_values(array_unique(array_map('intval', MAILBOX_QUOTA_OPTIONS_MB)));
        if (!in_array($quotaMb, $allowedQuotaMb, true)) {
            $existingQuotaMb = null;
            if ($id > 0) {
                foreach ($document['resources']['mail'] ?? [] as $existingMailbox) {
                    if ((int) ($existingMailbox['id'] ?? 0) === $id) {
                        $existingQuotaMb = (int) round((float) ($existingMailbox['quotaBytes'] ?? 0) / 1048576);
                        break;
                    }
                }
            }
            if ($existingQuotaMb === null || $quotaMb !== $existingQuotaMb) {
                throw new InvalidArgumentException('Invalid mailbox quota');
            }
        }
        $normalized = [
            'id' => $id,
            'domain' => $domain,
            'address' => $address,
            'aliases' => $aliases,
            'forwardTo' => $forwardTo,
            'catchAll' => $catchAll,
            'comment' => normalizePanelComment($record['comment'] ?? ''),
            'bytes' => 0,
            'quotaBytes' => $quotaMb * 1048576,
            'dkim' => false,
            'spf' => false,
            'dmarc' => false,
            'active' => true,
        ];
        $rootParams = $normalized + ['prefix' => $prefix, 'email' => $address];
        if ($password !== '') {
            $rootParams['password'] = $password;
        }
        rootOrFail($id > 0 ? 'mailbox_update' : 'create_mailbox', $rootParams);
        if ($password !== '') {
            $normalized['password'] = $password;
            $normalized['_passwordHashComment'] = 'Получить новый хеш: php -r "echo password_hash(\'НОВЫЙ_ПАРОЛЬ\', PASSWORD_DEFAULT), PHP_EOL;"';
            $normalized['passwordHash'] = password_hash($password, PASSWORD_DEFAULT);
        }
    } else {
        throw new InvalidArgumentException('Unknown resource type');
    }

    $allDocuments = $store->listDocuments();
    $updated = $store->mutate($prefix, static function (array $current) use ($type, $id, $normalized, $allDocuments, $createDatabase, $createMail, $domainMailMode, $domainMailForwardTo, $domainMailCatchAllToInfo, &$savedId): array {
        $rows = is_array($current['resources'][$type] ?? null) ? $current['resources'][$type] : [];
        $found = false;
        foreach ($rows as $index => $existing) {
            if ((int) ($existing['id'] ?? 0) !== $id || $id === 0) {
                continue;
            }
            if ($type === 'domains' && (string) ($existing['path'] ?? '') !== (string) ($normalized['path'] ?? '')) {
                $normalized['folderBytes'] = 0;
            }
            foreach (['folderBytes', 'bytes', 'tables', 'bound', 'dkim', 'spf', 'dmarc', 'password', 'passwordHash', '_passwordHashComment', 'createdAt'] as $preserve) {
                if (!array_key_exists($preserve, $normalized) && array_key_exists($preserve, $existing)) {
                    $normalized[$preserve] = $existing[$preserve];
                }
            }
            $rows[$index] = $normalized;
            $found = true;
            break;
        }
        if (!$found) {
            $normalized['id'] = DataStore::nextResourceId($allDocuments, $type);
            $normalized['createdAt'] = gmdate('c');
            $savedId = (int) $normalized['id'];
            $rows[] = $normalized;
        }
        $current['resources'][$type] = array_values($rows);

        if ($type === 'domains' && $id === 0) {
            $domain = $normalized['domain'];
            $prefix = (string) $current['profile']['prefix'];
            if ($createDatabase) {
                $databaseName = $prefix . '_' . preg_replace('/[^a-z0-9]+/', '_', $domain);
                $databaseName = trim($databaseName, '_');
                $databasePassword = generateMailboxPassword();
                $database = [
                    'id' => DataStore::nextResourceId($allDocuments, 'databases'),
                    'createdAt' => gmdate('c'),
                    'name' => $databaseName,
                    'username' => databaseAccountName($databaseName),
                    'password' => $databasePassword,
                    'host' => MYSQL_CLIENT_CONNECTION_HOST,
                    'port' => MYSQL_CLIENT_CONNECTION_PORT,
                    'bytes' => 0,
                    'tables' => 0,
                    'domain' => $domain,
                    'active' => true,
                ];
                rootOrFail('database_create', $database + ['prefix' => $prefix]);
                $current['resources']['databases'][] = $database;
            }
            if ($createMail) {
                if ($domainMailMode === 'info') {
                    $mailboxPassword = generateMailboxPassword();
                    $mailbox = ['id' => DataStore::nextResourceId($allDocuments, 'mail'), 'createdAt' => gmdate('c'), 'domain' => $domain, 'address' => 'info@' . $domain, 'aliases' => [], 'forwardTo' => $domainMailForwardTo, 'catchAll' => $domainMailCatchAllToInfo, 'bytes' => 0, 'quotaBytes' => IMPORT_MAIL_DEFAULT_QUOTA_MB * 1048576, 'dkim' => false, 'spf' => false, 'dmarc' => false, 'active' => true, 'password' => $mailboxPassword, '_passwordHashComment' => 'Получить новый хеш: php -r "echo password_hash(\'НОВЫЙ_ПАРОЛЬ\', PASSWORD_DEFAULT), PHP_EOL;"', 'passwordHash' => password_hash($mailboxPassword, PASSWORD_DEFAULT)];
                    rootOrFail('create_mailbox', ['prefix' => $prefix, 'domain' => $domain, 'email' => $mailbox['address'], 'password' => $mailboxPassword, 'aliases' => [], 'forwardTo' => $domainMailForwardTo, 'catchAll' => $domainMailCatchAllToInfo, 'quotaBytes' => $mailbox['quotaBytes'], 'pending_domain' => true]);
                    $current['resources']['mail'][] = $mailbox;
                } else {
                    rootOrFail('mail_domain_create', ['prefix' => $prefix, 'domain' => $domain, 'forwardTo' => $domainMailMode === 'domain_forward' ? $domainMailForwardTo : [], 'pending_domain' => true]);
                }
            }
        }
        if ($type === 'domains') {
            $current['resources']['domains'] = normalizeDomainFolderBytes($current['resources']['domains']);
        }
        return $current;
    });

    if ($type === 'domains' && $rebuildVhosts) {
        rebuildApacheVhosts($prefix);
    }

    $rows = resourceRows([$updated], $type);
    $saved = null;
    foreach ($rows as $row) {
        if ((int) ($row['id'] ?? 0) === $savedId) {
            $saved = $row;
            break;
        }
    }
    return ['record' => $saved, 'warnings' => $warnings];
}

function validateImportBatch(DataStore $store, array $auth, string $type, array $records): void
{
    if (!in_array($type, ['domains', 'mail'], true)) {
        throw new InvalidArgumentException('Unsupported import type');
    }
    if (count($records) === 0) {
        throw new InvalidArgumentException('Import is empty');
    }
    if (count($records) > IMPORT_MAX_ROWS) {
        throw new InvalidArgumentException('Too many import rows');
    }

    $existing = [];
    $existingCatchAll = [];
    foreach ($store->listDocuments() as $document) {
        foreach ($document['resources'][$type] ?? [] as $row) {
            $key = $type === 'domains' ? (string) ($row['domain'] ?? '') : (string) ($row['address'] ?? '');
            $existing[mb_strtolower($key)] = true;
            if ($type === 'mail') {
                foreach (is_array($row['aliases'] ?? null) ? $row['aliases'] : [] as $alias) $existing[mb_strtolower((string) $alias)] = true;
                if (!empty($row['catchAll'])) $existingCatchAll[mb_strtolower((string) ($row['domain'] ?? substr((string) ($row['address'] ?? ''), strrpos((string) ($row['address'] ?? ''), '@') + 1)))] = true;
            }
        }
    }
    $seen = [];
    $seenCatchAll = [];
    foreach ($records as $record) {
        if (!is_array($record)) {
            throw new InvalidArgumentException('Invalid import row');
        }
        $document = resourceOwner($store, $auth, $record);
        if ($type === 'domains') {
            $domain = mb_strtolower(trim((string) ($record['domain'] ?? '')));
            if (!validDomain($domain)) {
                throw new InvalidArgumentException('Invalid domain: ' . $domain);
            }
            resolveDomainProjectPath($document, $record, 0, $domain);
            $key = $domain;
        } else {
            $domain = mb_strtolower(trim((string) ($record['domain'] ?? '')));
            $mailbox = mb_strtolower(trim((string) ($record['mailbox'] ?? '')));
            if (!validDomain($domain) || preg_match('/^[a-z0-9.!#$%&\'*+\/=?^_`{|}~-]{1,64}$/i', $mailbox) !== 1) {
                throw new InvalidArgumentException('Invalid mail address');
            }
            $domainOwned = false;
            foreach ($document['resources']['domains'] ?? [] as $ownedDomain) {
                if (mb_strtolower((string) ($ownedDomain['domain'] ?? '')) === $domain) {
                    $domainOwned = true;
                    break;
                }
            }
            if (!$domainOwned) {
                throw new InvalidArgumentException('Mail domain does not belong to the selected user: ' . $domain);
            }
            $key = $mailbox . '@' . $domain;
            $aliases = normalizeMailboxAliases($record['aliases'] ?? [], $domain, $key);
            normalizeMailboxForwarding($record['forwardTo'] ?? [], $key);
            foreach ($aliases as $alias) {
                if (isset($existing[$alias]) || isset($seen[$alias])) throw new InvalidArgumentException('Duplicate mailbox alias: ' . $alias);
            }
            if (booleanValue($record['catchAll'] ?? false) && (isset($existingCatchAll[$domain]) || isset($seenCatchAll[$domain]))) {
                throw new InvalidArgumentException('Catch-all already exists for domain: ' . $domain);
            }
        }
        if (isset($existing[$key]) || isset($seen[$key])) {
            throw new InvalidArgumentException('Duplicate import record: ' . $key);
        }
        $seen[$key] = true;
        if ($type === 'mail') {
            foreach ($aliases as $alias) $seen[$alias] = true;
            if (booleanValue($record['catchAll'] ?? false)) $seenCatchAll[$domain] = true;
        }
    }
}

$auth = panelAuth();
if ($auth === null) {
    apiError('Authentication required', 401);
}
$_SESSION['last_activity'] = time();

$store = new DataStore(DATA_DIRECTORY);
$statusStore = new StatusStore(STATUS_DIRECTORY, false);
$payload = requestPayload();
$action = (string) ($payload['action'] ?? 'bootstrap');

try {
    if ($action === 'sessionCsrf') {
        apiResponse(['ok' => true, 'data' => [
            'csrfToken' => panelCsrfToken(),
        ], 'error' => null]);
    }

    if ($action === 'bootstrap') {
        $documents = $statusStore->mergeDocuments(documentsForAuth($store, $auth));
        apiResponse(['ok' => true, 'data' => [
            'users' => array_map('profileRow', $documents),
            'domains' => resourceRows($documents, 'domains'),
            'databases' => resourceRows($documents, 'databases'),
            'mail' => resourceRows($documents, 'mail'),
            'dnsManagementEnabled' => dnsManagementEnabledForAuth($store, $auth),
        ], 'error' => null]);
    }

    if ($action === 'serverDiagnostics') {
        if (!isRoot($auth)) apiError('Root access required', 403);
        $result = rootOrFail('server_diagnostics', []);
        apiResponse(['ok' => true, 'data' => $result['data'] ?? [], 'error' => null]);
    }

    if ($action === 'migrateCreatedAt') {
        if (!isRoot($auth)) {
            apiError('Root access required', 403);
        }
        requireMutationCsrf($payload);
        apiResponse(['ok' => true, 'data' => migrateCreatedAtDates($store), 'error' => null]);
    }

    if ($action === 'domainPermissionsAll') {
        if (!isRoot($auth)) apiError('Root access required', 403);
        requireMutationCsrf($payload);
        $result = rootOrFail('domain_permissions_all', []);
        apiResponse(['ok' => true, 'data' => $result['data'] ?? [], 'error' => null]);
    }

    if ($action === 'apacheVhostsRefreshAll') {
        if (!isRoot($auth)) apiError('Root access required', 403);
        requireMutationCsrf($payload);
        $result = rootOrFail('apache_vhosts_refresh_all', []);
        apiResponse(['ok' => true, 'data' => $result['data'] ?? [], 'error' => null]);
    }

    if ($action === 'apacheDisableDomain') {
        if (!isRoot($auth)) apiError('Root access required', 403);
        requireMutationCsrf($payload);
        $id = (int) ($payload['id'] ?? 0);
        [$document, $index, $row] = locateResource($store, $auth, 'domains', $id);
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        $domain = mb_strtolower(trim((string) ($row['domain'] ?? '')));
        if (!empty($row['active'])) {
            $store->mutate($prefix, static function (array $current) use ($index): array {
                $current['resources']['domains'][$index]['active'] = false;
                return $current;
            });
        }
        $result = rootOrFail('apache_vhosts_refresh_all', ['continue_after_invalid_current' => true]);
        $report = is_array($result['data'] ?? null) ? $result['data'] : [];
        $report['disabledDomain'] = ['id' => $id, 'domain' => $domain, 'prefix' => $prefix];
        apiResponse(['ok' => true, 'data' => $report, 'error' => null]);
    }

    if ($action === 'list') {
        $type = (string) ($payload['type'] ?? '');
        if ($type === 'users' && !isRoot($auth)) {
            apiError('Root access required', 403);
        }
        if ($type === 'logs') {
            if (!isRoot($auth)) {
                apiError('Root access required', 403);
            }
            $rootLog = new RootAuditLog(ROOT_LOG_DIRECTORY, ROOT_LOG_RETENTION_DAYS, ROOT_LOG_ENTRY_MAX_BYTES);
            apiResponse(tableResponse($rootLog->rows(ROOT_LOG_DEFAULT_DAYS), $payload));
        }
        if ($type === 'toolLogs') {
            if (!isRoot($auth)) {
                apiError('Root access required', 403);
            }
            $toolLog = new RootAuditLog(DOMAIN_TOOL_LOG_DIRECTORY, DOMAIN_TOOL_LOG_RETENTION_DAYS, DOMAIN_TOOL_LOG_ENTRY_MAX_BYTES);
            apiResponse(tableResponse($toolLog->rows(DOMAIN_TOOL_LOG_DEFAULT_DAYS), $payload));
        }
        apiResponse(tableResponse(allRows($store, $statusStore, $auth, $type), $payload));
    }

    if ($action === 'rootLogDetails') {
        if (!isRoot($auth)) {
            apiError('Root access required', 403);
        }
        $requestId = mb_strtolower(trim((string) ($payload['requestId'] ?? '')));
        $rootLog = new RootAuditLog(ROOT_LOG_DIRECTORY, ROOT_LOG_RETENTION_DAYS, ROOT_LOG_ENTRY_MAX_BYTES);
        $details = $rootLog->find($requestId);
        if ($details === null) {
            apiError('Root log record not found', 404);
        }
        apiResponse(['ok' => true, 'data' => $details, 'error' => null]);
    }

    if ($action === 'toolLogDetails') {
        if (!isRoot($auth)) {
            apiError('Root access required', 403);
        }
        $requestId = mb_strtolower(trim((string) ($payload['requestId'] ?? '')));
        $toolLog = new RootAuditLog(DOMAIN_TOOL_LOG_DIRECTORY, DOMAIN_TOOL_LOG_RETENTION_DAYS, DOMAIN_TOOL_LOG_ENTRY_MAX_BYTES);
        $details = $toolLog->find($requestId);
        if ($details === null) {
            apiError('Tool log record not found', 404);
        }
        apiResponse(['ok' => true, 'data' => $details, 'error' => null]);
    }

    if ($action === 'domainLog') {
        $context = domainLogContext(
            $store,
            $auth,
            (int) ($payload['id'] ?? 0),
            trim((string) ($payload['file'] ?? ''))
        );
        $page = max(1, (int) ($payload['page'] ?? 1));
        $data = [
            'domain' => $context['domain'],
            'file' => $context['file'],
            'exists' => $context['exists'],
            'page' => $page,
            'linesPerPage' => DOMAIN_LOG_LINES_PER_PAGE,
            'lines' => 0,
            'content' => '',
            'hasNewer' => $page > 1,
            'hasOlder' => false,
        ];
        if ($context['exists']) $data = array_merge($data, readDomainLogPage((string) $context['path'], $page));
        apiResponse(['ok' => true, 'data' => $data, 'error' => null]);
    }

    if ($action === 'domainLogDownload') {
        $context = domainLogContext(
            $store,
            $auth,
            (int) ($payload['id'] ?? 0),
            trim((string) ($payload['file'] ?? ''))
        );
        if (empty($context['exists'])) apiError('Domain log not found', 404);
        $downloadName = (string) $context['domain'] . '-' . (string) $context['file'];
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $downloadName . '"');
        $size = filesize((string) $context['path']);
        if ($size !== false) header('Content-Length: ' . $size);
        session_write_close();
        if (readfile((string) $context['path']) === false) throw new RuntimeException('Cannot download domain log');
        exit;
    }

    if (in_array($action, ['mailMigrationStatus', 'mailMigrationHistory', 'mailMigrationReport'], true)) {
        if (!MAIL_MIGRATION_ENABLED) apiError('Old mail import is disabled', 403);
        $context = mailMigrationOwnedContext($store, $auth, (int) ($payload['mailboxId'] ?? 0));
        $migrationStore = apiMailMigrationStore();
        $history = $migrationStore->history($context['prefix'], $context['mailboxId'], 10);
        if ($action === 'mailMigrationHistory') {
            $rows = [];
            foreach ($history as $index => $job) $rows[] = publicMailMigration($migrationStore, $job, $index === 0);
            apiResponse(['ok' => true, 'data' => ['history' => $rows], 'error' => null]);
        }
        $migrationId = mb_strtolower(trim((string) ($payload['migrationId'] ?? '')));
        $job = $migrationId !== '' ? $migrationStore->get($migrationId) : ($history[0] ?? null);
        if (!is_array($job)) apiResponse(['ok' => true, 'data' => ['migration' => null], 'error' => null]);
        if ((string) $job['user_prefix'] !== $context['prefix'] || (int) $job['mailbox_id'] !== $context['mailboxId']) {
            apiError('Mail migration not found', 404);
        }
        if ($action === 'mailMigrationStatus') {
            apiResponse(['ok' => true, 'data' => ['migration' => publicMailMigration($migrationStore, $job, true)], 'error' => null]);
        }
        $reportPath = MailMigrationRuntime::reportPath((string) $job['id']);
        $report = null;
        if (is_file($reportPath) && !is_link($reportPath) && is_readable($reportPath)) {
            $decoded = json_decode((string) file_get_contents($reportPath), true);
            if (is_array($decoded)) $report = $decoded;
        }
        if ($report === null) {
            $current = publicMailMigration($migrationStore, $job, true);
            $report = [
                'migrationId' => (string) $current['id'],
                'status' => (string) $current['status'],
                'server' => (string) $current['source_host'],
                'destination' => (string) $current['destination_email'],
                'folders' => (int) $current['folders_total'],
                'messages' => (int) $current['messages_done'],
                'messagesTotal' => (int) $current['messages_total'],
                'bytes' => (float) $current['bytes_done'],
                'bytesTotal' => (float) $current['bytes_total'],
                'skipped' => (int) $current['skipped_count'],
                'errors' => (int) $current['errors_count'],
                'error' => (string) $current['error_message'],
                'startedAt' => (string) $current['started_at'],
                'finishedAt' => (string) $current['finished_at'],
            ];
        }
        apiResponse(['ok' => true, 'data' => ['report' => $report], 'error' => null]);
    }

    if ($action === 'dnsManagedZonesQueue') {
        apiResponse(['ok' => true, 'data' => ['zones' => dnsManagedRefreshQueue($store, $auth)], 'error' => null]);
    }

    if ($action === 'dnsManagedBulkOptions') {
        apiResponse(['ok' => true, 'data' => dnsManagedBulkOptions($store, $auth), 'error' => null]);
    }

    if (in_array($action, ['dnsManagedZoneDetails', 'dnsManagedZoneCurrent'], true)) {
        [$document, , $zone, $connection, $dnsProfile] = dnsManagedZoneContext(
            $store,
            $auth,
            trim((string) ($payload['id'] ?? ''))
        );
        $domain = (string) ($zone['domain'] ?? '');
        if ($action === 'dnsManagedZoneCurrent') {
            apiResponse(['ok' => true, 'data' => DnsService::listRecords($dnsProfile, $domain), 'error' => null]);
        }
        apiResponse(['ok' => true, 'data' => [
            'zone' => [
                'id' => (string) $zone['id'],
                'domain' => $domain,
                'provider' => (string) $connection['provider'],
                'connectionName' => (string) $connection['name'],
                'records' => is_array($zone['records'] ?? null) ? $zone['records'] : [],
                'updatedAt' => (string) ($zone['updatedAt'] ?? ''),
            ],
            'recommended' => recommendedDnsRecordsForDomain($domain),
            'types' => DnsService::editableTypes(),
            'copyTargets' => dnsManagedCopyTargets($store, $auth, (string) $zone['id']),
        ], 'error' => null]);
    }

    requireMutationCsrf($payload);

    if ($action === 'dnsManagedBulkRecordApply') {
        [$document, , $zone, , $dnsProfile] = dnsManagedZoneContext(
            $store,
            $auth,
            trim((string) ($payload['id'] ?? ''))
        );
        $zoneId = (string) ($zone['id'] ?? '');
        $domain = (string) ($zone['domain'] ?? '');
        $values = is_array($payload['values'] ?? null)
            ? array_values($payload['values'])
            : preg_split('/\r?\n/u', (string) ($payload['values'] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
        $record = DnsService::recordForDomainTemplate(
            $domain,
            (string) ($payload['name'] ?? ''),
            (string) ($payload['type'] ?? ''),
            (int) ($payload['ttl'] ?? DNS_API_DEFAULT_TTL),
            is_array($values) ? $values : []
        );
        try {
            $current = DnsService::listRecords($dnsProfile, $domain);
            if (!in_array((string) $record['type'], is_array($current['types'] ?? null) ? $current['types'] : [], true)) {
                throw new InvalidArgumentException('The DNS provider does not support this record type');
            }
            DnsService::saveRecord($dnsProfile, $domain, $record);
            $snapshot = dnsEditableRecordsSnapshot(DnsService::listRecords($dnsProfile, $domain));
            $now = gmdate('c');
            dnsManagedZoneUpdate($store, $document, $zoneId, static function (array $currentZone) use ($snapshot, $record, $now): array {
                $currentZone['records'] = $snapshot;
                $currentZone['fetchedAt'] = $now;
                $currentZone['sentAt'] = $now;
                $currentZone['synchronized'] = true;
                $currentZone['synchronizedAt'] = $now;
                $currentZone['lastBulkChangeAttempt'] = [
                    'status' => 'success',
                    'at' => $now,
                    'name' => (string) $record['name'],
                    'type' => (string) $record['type'],
                    'error' => '',
                ];
                return $currentZone;
            });
            apiResponse(['ok' => true, 'data' => [
                'id' => $zoneId,
                'domain' => $domain,
                'record' => $record,
                'records' => count($snapshot),
            ], 'error' => null]);
        } catch (Throwable $exception) {
            $error = mb_substr(trim($exception->getMessage()), 0, 500);
            try {
                $failedAt = gmdate('c');
                dnsManagedZoneUpdate($store, $document, $zoneId, static function (array $currentZone) use ($record, $failedAt, $error): array {
                    $currentZone['synchronized'] = false;
                    $currentZone['lastBulkChangeAttempt'] = [
                        'status' => 'error',
                        'at' => $failedAt,
                        'name' => (string) $record['name'],
                        'type' => (string) $record['type'],
                        'error' => $error,
                    ];
                    return $currentZone;
                });
            } catch (Throwable $ignored) {
                // Preserve the provider failure when writing its status also fails.
            }
            throw $exception;
        }
    }

    if ($action === 'dnsManagedZonesRefresh') {
        apiResponse(['ok' => true, 'data' => refreshManagedDnsZones($store, $auth), 'error' => null]);
    }

    if ($action === 'dnsManagedZoneCopy') {
        [$sourceDocument, , $sourceZone] = dnsManagedZoneContext(
            $store,
            $auth,
            trim((string) ($payload['id'] ?? ''))
        );
        $sourceZoneId = (string) ($sourceZone['id'] ?? '');
        $sourceDomain = (string) ($sourceZone['domain'] ?? '');
        $sourceRecords = DnsService::normalizeManagedRecords(is_array($payload['records'] ?? null) ? $payload['records'] : []);
        $targetIds = is_array($payload['targetIds'] ?? null) ? array_values(array_unique(array_map('strval', $payload['targetIds']))) : [];
        $targetIds = array_values(array_filter($targetIds, static function (string $id) use ($sourceZoneId): bool {
            return $id !== '' && !hash_equals($id, $sourceZoneId);
        }));
        if (!$targetIds) throw new InvalidArgumentException('Select at least one target DNS zone');
        if (count($targetIds) > 100) throw new InvalidArgumentException('Too many target DNS zones');

        $results = [];
        foreach ($targetIds as $targetId) {
            $targetDocument = null;
            $targetZone = null;
            try {
                [$targetDocument, , $targetZone, $targetConnection, $targetDnsProfile] = dnsManagedZoneContext($store, $auth, $targetId);
                $targetDomain = (string) ($targetZone['domain'] ?? '');
                $copiedRecords = DnsService::recordsForDomainCopy($sourceRecords, $sourceDomain, $targetDomain);

                // Change provider DNS first. Update JSON only after the zone passes a second verification.
                $sync = DnsService::syncManagedRecords($targetDnsProfile, $targetDomain, $copiedRecords);
                $snapshot = dnsEditableRecordsSnapshot(DnsService::listRecords($targetDnsProfile, $targetDomain));
                $now = gmdate('c');
                dnsManagedZoneUpdate($store, $targetDocument, $targetId, static function (array $current) use ($snapshot, $now, $sourceZoneId, $sourceDomain, $sync): array {
                    $current['records'] = $snapshot;
                    $current['fetchedAt'] = $now;
                    $current['sentAt'] = $now;
                    $current['synchronized'] = true;
                    $current['synchronizedAt'] = $now;
                    $current['lastCopyAttempt'] = [
                        'status' => 'success',
                        'at' => $now,
                        'sourceZoneId' => $sourceZoneId,
                        'sourceDomain' => $sourceDomain,
                        'records' => count($snapshot),
                        'saved' => (int) ($sync['saved'] ?? 0),
                        'deleted' => (int) ($sync['deleted'] ?? 0),
                        'error' => '',
                    ];
                    return $current;
                });
                $results[] = ['id' => $targetId, 'domain' => $targetDomain, 'ok' => true, 'records' => count($snapshot), 'error' => ''];
            } catch (Throwable $exception) {
                $error = mb_substr(trim($exception->getMessage()), 0, 500);
                if (is_array($targetDocument) && is_array($targetZone)) {
                    try {
                        $failedAt = gmdate('c');
                        dnsManagedZoneUpdate($store, $targetDocument, $targetId, static function (array $current) use ($failedAt, $sourceZoneId, $sourceDomain, $error): array {
                            $current['synchronized'] = false;
                            $current['lastCopyAttempt'] = [
                                'status' => 'error',
                                'at' => $failedAt,
                                'sourceZoneId' => $sourceZoneId,
                                'sourceDomain' => $sourceDomain,
                                'records' => 0,
                                'error' => $error,
                            ];
                            return $current;
                        });
                    } catch (Throwable $ignored) {
                        // Preserve the provider error; a secondary status-write failure must not hide it.
                    }
                }
                $results[] = [
                    'id' => $targetId,
                    'domain' => is_array($targetZone) ? (string) ($targetZone['domain'] ?? '') : '',
                    'ok' => false,
                    'records' => 0,
                    'error' => $error !== '' ? $error : 'DNS zone copy failed',
                ];
            }
        }
        $successful = count(array_filter($results, static function (array $result): bool { return !empty($result['ok']); }));
        apiResponse(['ok' => true, 'data' => [
            'results' => $results,
            'successful' => $successful,
            'failed' => count($results) - $successful,
        ], 'error' => null]);
    }

    if (in_array($action, ['dnsManagedZoneFetch', 'dnsManagedZoneSave', 'dnsManagedZoneClear', 'dnsManagedZonePush'], true)) {
        [$document, , $zone, , $dnsProfile] = dnsManagedZoneContext(
            $store,
            $auth,
            trim((string) ($payload['id'] ?? ''))
        );
        $domain = (string) ($zone['domain'] ?? '');
        if ($action === 'dnsManagedZoneSave') {
            $records = DnsService::normalizeManagedRecords(is_array($payload['records'] ?? null) ? $payload['records'] : []);
            dnsManagedZoneUpdate($store, $document, (string) $zone['id'], static function (array $current) use ($records): array {
                $current['records'] = $records;
                $current['synchronized'] = false;
                return $current;
            });
            apiResponse(['ok' => true, 'data' => ['records' => count($records)], 'error' => null]);
        }
        if ($action === 'dnsManagedZoneClear') {
            dnsManagedZoneUpdate($store, $document, (string) $zone['id'], static function (array $current): array {
                $current['records'] = [];
                $current['synchronized'] = false;
                return $current;
            });
            apiResponse(['ok' => true, 'data' => ['records' => 0], 'error' => null]);
        }
        if ($action === 'dnsManagedZoneFetch') {
            $records = dnsEditableRecordsSnapshot(DnsService::listRecords($dnsProfile, $domain));
            $now = gmdate('c');
            dnsManagedZoneUpdate($store, $document, (string) $zone['id'], static function (array $current) use ($records, $now): array {
                $current['records'] = $records;
                $current['fetchedAt'] = $now;
                $current['synchronized'] = true;
                $current['synchronizedAt'] = $now;
                return $current;
            });
            apiResponse(['ok' => true, 'data' => ['records' => count($records)], 'error' => null]);
        }

        $records = DnsService::normalizeManagedRecords(is_array($zone['records'] ?? null) ? $zone['records'] : []);
        $sync = DnsService::syncManagedRecords($dnsProfile, $domain, $records);
        $snapshot = dnsEditableRecordsSnapshot(DnsService::listRecords($dnsProfile, $domain));
        $now = gmdate('c');
        dnsManagedZoneUpdate($store, $document, (string) $zone['id'], static function (array $current) use ($snapshot, $now): array {
            $current['records'] = $snapshot;
            $current['fetchedAt'] = $now;
            $current['sentAt'] = $now;
            $current['synchronized'] = true;
            $current['synchronizedAt'] = $now;
            return $current;
        });
        apiResponse(['ok' => true, 'data' => array_merge($sync, ['records' => count($snapshot)]), 'error' => null]);
    }

    if ($action === 'databasePhpMyAdminLaunch') {
        $databaseId = (int) ($payload['id'] ?? 0);
        [$document, , $database] = locateResource($store, $auth, 'databases', $databaseId);
        if (empty($database['active'])) apiError('Database is disabled', 409);
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        $token = domainToolCreateDatabaseLaunch($prefix, $databaseId);
        apiResponse(['ok' => true, 'data' => [
            'url' => '/phpmyadmin/?imagopanel_database_launch=' . rawurlencode($token),
        ], 'error' => null]);
    }

    if ($action === 'domainPanelToolLaunch') {
        $tool = trim((string) ($payload['tool'] ?? ''));
        if (!in_array($tool, ['filemanager', 'fileeditor'], true)) {
            throw new InvalidArgumentException('Unknown domain tool');
        }
        $domainId = (int) ($payload['id'] ?? 0);
        [$document, , $domain] = locateResource($store, $auth, 'domains', $domainId);
        if (empty($domain['active'])) apiError('Domain is disabled', 409);
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        $token = domainToolCreateDomainLaunch($tool, $prefix, $domainId);
        apiResponse(['ok' => true, 'data' => [
            'url' => '/' . $tool . '/?imagopanel_domain_launch=' . rawurlencode($token),
        ], 'error' => null]);
    }

    if ($action === 'dnsProviderTest') {
        $document = isRoot($auth)
            ? $store->findByUserId((int) ($payload['userId'] ?? 0))
            : $store->load((string) ($auth['prefix'] ?? ''));
        if ($document === null) throw new RuntimeException('User not found');
        $profile = (array) ($document['profile'] ?? []);
        $connection = is_array($payload['connection'] ?? null) ? $payload['connection'] : [];
        $result = DnsService::testConnectionSettings($connection, $profile);
        apiResponse(['ok' => true, 'data' => $result, 'error' => null]);
    }

    if (in_array($action, ['dnsRecommendedRecords', 'dnsProviderDetect', 'dnsRecords', 'dnsApplyRecommended', 'dnsRecordSave', 'dnsRecordDelete'], true)) {
        $mustExist = in_array($action, ['dnsRecords', 'dnsRecordSave', 'dnsRecordDelete'], true);
        [$document, $domain, $domainRow] = dnsRequestContext($store, $auth, $payload, $mustExist);
        $profile = (array) ($document['profile'] ?? []);
        if (isRoot($auth)) $profile['_useConfigDnsToken'] = true;

        if ($action === 'dnsRecommendedRecords') {
            apiResponse(['ok' => true, 'data' => ['records' => recommendedDnsRecordsForDomain($domain)], 'error' => null]);
        }
        if ($action === 'dnsProviderDetect') {
            $connectionId = trim((string) ($payload['dnsConnectionId'] ?? ($domainRow['dnsConnectionId'] ?? '')));
            $data = !empty($payload['verifyConnection'])
                ? DnsService::verifyAccess($profile, $domain, $connectionId)
                : DnsService::detect($profile, $domain);
            apiResponse(['ok' => true, 'data' => $data, 'error' => null]);
        }
        $connectionId = trim((string) ($payload['dnsConnectionId'] ?? ($domainRow['dnsConnectionId'] ?? '')));
        $dnsProfile = DnsService::profileForConnection($profile, $connectionId);
        $dnsAccess = DnsService::verifyAccess($profile, $domain, $connectionId);
        if (empty($dnsAccess['zoneFound']) || empty($dnsAccess['nameserversMatch'])) {
            throw new RuntimeException('The selected DNS API connection cannot manage this domain');
        }
        if ($action === 'dnsRecords') {
            apiResponse(['ok' => true, 'data' => DnsService::listRecords($dnsProfile, $domain), 'error' => null]);
        }
        if ($action === 'dnsApplyRecommended') {
            apiResponse(['ok' => true, 'data' => DnsService::applyRecommended($dnsProfile, $domain, recommendedDnsRecordsForDomain($domain)), 'error' => null]);
        }
        if ($action === 'dnsRecordSave') {
            $record = is_array($payload['record'] ?? null) ? $payload['record'] : [];
            apiResponse(['ok' => true, 'data' => DnsService::saveRecord($dnsProfile, $domain, $record), 'error' => null]);
        }
        DnsService::deleteRecord(
            $dnsProfile,
            $domain,
            (string) ($payload['name'] ?? ''),
            (string) ($payload['type'] ?? '')
        );
        apiResponse(['ok' => true, 'data' => ['deleted' => true], 'error' => null]);
    }

    if (in_array($action, ['mailMigrationTest', 'mailMigrationStart'], true)) {
        if (!MAIL_MIGRATION_ENABLED) apiError('Old mail import is disabled', 403);
        $context = mailMigrationOwnedContext($store, $auth, (int) ($payload['mailboxId'] ?? 0));
        $params = [
            'prefix' => $context['prefix'],
            'mailbox_id' => $context['mailboxId'],
            'source_host' => trim((string) ($payload['sourceHost'] ?? '')),
            'source_port' => (int) ($payload['sourcePort'] ?? 0),
            'source_security' => trim((string) ($payload['sourceSecurity'] ?? '')),
            'source_login' => trim((string) ($payload['sourceLogin'] ?? '')),
            'source_password' => (string) ($payload['sourcePassword'] ?? ''),
        ];
        $rootAction = $action === 'mailMigrationTest' ? 'mail_migration_test' : 'mail_migration_start';
        $result = rootOrFail($rootAction, $params);
        apiResponse(['ok' => true, 'data' => $result['data'] ?? [], 'error' => null]);
    }

    if ($action === 'tariffRequest') {
        if (isRoot($auth)) apiError('Root tariff is configured in config.php', 400);
        $requestedKey = mb_strtolower(trim((string) ($payload['tariff'] ?? '')));
        $tariffs = panelTariffs();
        if (!isset($tariffs[$requestedKey])) throw new InvalidArgumentException('Invalid tariff');
        $prefix = (string) ($auth['prefix'] ?? '');
        $document = $store->load($prefix);
        if ($document === null) throw new RuntimeException('User not found');
        $currentKey = profileTariffKey((array) ($document['profile'] ?? []));
        if ($requestedKey === $currentKey) throw new InvalidArgumentException('This tariff is already active');
        panelSendTariffRequest(ROOT_EMAIL, (array) $document['profile'], $tariffs[$currentKey], $tariffs[$requestedKey]);
        $updated = $store->mutate($prefix, static function (array $current) use ($requestedKey, $tariffs): array {
            $current['profile']['tariffRequest'] = [
                'key' => $requestedKey,
                'name' => (string) $tariffs[$requestedKey]['name'],
                'requestedAt' => gmdate('c'),
            ];
            return $current;
        });
        apiResponse(['ok' => true, 'data' => ['record' => profileRow($updated)], 'error' => null]);
    }

    if ($action === 'domainPermissions') {
        $id = (int) ($payload['id'] ?? 0);
        [$document] = locateResource($store, $auth, 'domains', $id);
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        $result = rootOrFail('domain_permissions', ['prefix' => $prefix, 'id' => $id]);
        apiResponse(['ok' => true, 'data' => $result['data'] ?? [], 'error' => null]);
    }

    if ($action === 'import') {
        $type = (string) ($payload['type'] ?? '');
        $records = isset($payload['records']) && is_array($payload['records']) ? array_values($payload['records']) : [];
        validateImportBatch($store, $auth, $type, $records);
        $saved = [];
        $vhostPrefixes = [];
        foreach ($records as $record) {
            $result = saveResource($store, $auth, $type, $record, false);
            $saved[] = $result['record'];
            if ($type === 'domains') {
                $owner = resourceOwner($store, $auth, $record);
                $vhostPrefixes[(string) ($owner['profile']['prefix'] ?? '')] = true;
            }
        }
        foreach (array_keys($vhostPrefixes) as $prefix) {
            rebuildApacheVhosts($prefix);
        }
        apiResponse(['ok' => true, 'data' => ['records' => $saved, 'count' => count($saved)], 'error' => null]);
    }

    if ($action === 'save') {
        $type = (string) ($payload['type'] ?? '');
        $record = isset($payload['record']) && is_array($payload['record']) ? $payload['record'] : [];
        if ($type === 'profile') {
            $result = ['record' => saveOwnProfile($store, $auth, $record)];
        } elseif ($type === 'users') {
            if (!isRoot($auth)) {
                apiError('Root access required', 403);
            }
            $result = ['record' => saveUser($store, $record)];
        } else {
            $result = saveResource($store, $auth, $type, $record);
        }
        apiResponse(['ok' => true, 'data' => $result, 'error' => null]);
    }

    if (in_array($action, ['toggle', 'delete'], true)) {
        $type = (string) ($payload['type'] ?? '');
        $id = (int) ($payload['id'] ?? 0);
        if ($type === 'users') {
            if (!isRoot($auth)) {
                apiError('Root access required', 403);
            }
            $document = $store->findByUserId($id);
            if ($document === null) {
                throw new RuntimeException('User not found');
            }
            $prefix = (string) $document['profile']['prefix'];
            rootOrFail('user_' . $action, ['id' => $id, 'prefix' => $prefix]);
            if ($action === 'delete') {
                $store->delete($prefix);
            } else {
                $store->mutate($prefix, static function (array $current): array {
                    $current['profile']['active'] = empty($current['profile']['active']);
                    return $current;
                });
                rebuildApacheVhosts($prefix);
            }
        } else {
            if (!in_array($type, ['domains', 'databases', 'mail'], true)) {
                throw new InvalidArgumentException('Unknown resource type');
            }
            [$document, $index, $row] = locateResource($store, $auth, $type, $id);
            $prefix = (string) $document['profile']['prefix'];
            rootOrFail($type . '_' . $action, ['prefix' => $prefix, 'id' => $id, 'record' => $row]);
            $store->mutate($prefix, static function (array $current) use ($type, $index, $action): array {
                if ($action === 'delete') {
                    array_splice($current['resources'][$type], $index, 1);
                } else {
                    $current['resources'][$type][$index]['active'] = empty($current['resources'][$type][$index]['active']);
                }
                if ($type === 'domains') {
                    $current['resources']['domains'] = normalizeDomainFolderBytes($current['resources']['domains']);
                }
                return $current;
            });
            if ($type === 'domains') {
                rebuildApacheVhosts($prefix);
                if ($action === 'delete') {
                    rootOrFail('domain_project_cleanup', [
                        'prefix' => $prefix,
                        'path' => (string) ($row['path'] ?? ''),
                    ]);
                }
            }
        }
        apiResponse(['ok' => true, 'data' => ['id' => $id], 'error' => null]);
    }

    if ($action === 'resetPassword') {
        if (!SHOW_MAIL_PASSWORDS) apiError('Password display is disabled', 403);
        [$document, $index, $row] = locateResource($store, $auth, 'mail', (int) ($payload['id'] ?? 0));
        $prefix = (string) $document['profile']['prefix'];
        $password = generateMailboxPassword();
        rootOrFail('mailbox_password', ['prefix' => $prefix, 'email' => $row['address'], 'password' => $password]);
        $store->mutate($prefix, static function (array $current) use ($index, $password): array {
            $current['resources']['mail'][$index]['password'] = $password;
            $current['resources']['mail'][$index]['_passwordHashComment'] = 'Получить новый хеш: php -r "echo password_hash(\'НОВЫЙ_ПАРОЛЬ\', PASSWORD_DEFAULT), PHP_EOL;"';
            $current['resources']['mail'][$index]['passwordHash'] = password_hash($password, PASSWORD_DEFAULT);
            return $current;
        });
        apiResponse(['ok' => true, 'data' => ['password' => $password], 'error' => null]);
    }

    if ($action === 'verify') {
        $kind = (string) ($payload['kind'] ?? '');
        $domain = mb_strtolower(trim((string) ($payload['domain'] ?? '')));
        if (!validDomain($domain)) {
            throw new InvalidArgumentException('Invalid domain');
        }
        enforceVerificationRateLimit($auth);
        $rootAction = $kind === 'mail' ? 'opendkim_check' : 'apache_vhost_check';
        $result = rootOrFail($rootAction, ['domain' => $domain]);
        apiResponse(['ok' => true, 'data' => $result['data'] ?? [], 'error' => null]);
    }

    apiError('Unknown action');
} catch (InvalidArgumentException $exception) {
    apiError($exception->getMessage(), 422);
} catch (Throwable $exception) {
    apiError($exception->getMessage(), 500);
}
