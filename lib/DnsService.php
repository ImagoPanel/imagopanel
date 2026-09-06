<?php
declare(strict_types=1);

require_once __DIR__ . '/HetznerDnsProvider.php';
require_once __DIR__ . '/JokerDnsProvider.php';
require_once __DIR__ . '/RegruDnsProvider.php';
require_once __DIR__ . '/NamecheapDnsProvider.php';
require_once __DIR__ . '/InternetBsDnsProvider.php';
require_once __DIR__ . '/DnsTxtValue.php';

final class DnsService
{
    private const EDITABLE_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'SRV'];

    public static function publicProviders(): array
    {
        $providers = [];
        foreach (DNS_API_PROVIDERS as $provider) {
            if (!is_array($provider)) continue;
            $id = mb_strtolower(trim((string) ($provider['id'] ?? '')));
            if ($id === '') continue;
            $providers[] = [
                'id' => $id,
                'name' => trim((string) ($provider['name'] ?? $id)),
                'enabled' => !empty($provider['enabled']),
                'planned' => !empty($provider['planned']),
                'apiUrl' => self::defaultApiUrl($id),
            ];
        }
        return $providers;
    }

    public static function normalizeProfileSettings(array $record, array $existing): array
    {
        if (!array_key_exists('dnsConnections', $record)) return ['dnsConnections' => self::storedConnections($existing)];
        if (!is_array($record['dnsConnections'])) throw new InvalidArgumentException('Invalid DNS connections');
        $existingById = [];
        foreach (self::storedConnections($existing) as $connection) $existingById[(string) $connection['id']] = $connection;
        $connections = [];
        $names = [];
        $ids = [];
        foreach (array_values($record['dnsConnections']) as $submitted) {
            if (!is_array($submitted)) throw new InvalidArgumentException('Invalid DNS connection');
            $id = trim((string) ($submitted['id'] ?? ''));
            if ($id === '') $id = 'dns-' . bin2hex(random_bytes(8));
            if (preg_match('/^[A-Za-z0-9_-]{6,64}$/D', $id) !== 1) throw new InvalidArgumentException('Invalid DNS connection ID');
            if (isset($ids[$id])) throw new InvalidArgumentException('Duplicate DNS connection ID');
            $ids[$id] = true;
            $old = is_array($existingById[$id] ?? null) ? $existingById[$id] : [];
            $name = trim((string) ($submitted['name'] ?? ''));
            if ($name === '' || mb_strlen($name) > 120 || preg_match('/[\x00-\x1F\x7F]/', $name) === 1) throw new InvalidArgumentException('DNS connection name is required');
            $nameKey = mb_strtolower($name);
            if (isset($names[$nameKey])) throw new InvalidArgumentException('DNS connection name must be unique');
            $names[$nameKey] = true;
            $provider = mb_strtolower(trim((string) ($submitted['provider'] ?? '')));
            $definition = self::providerDefinition($provider);
            if ($definition === null || empty($definition['enabled'])) throw new InvalidArgumentException('Selected DNS provider is not available yet');
            $apiUrl = trim((string) ($submitted['apiUrl'] ?? '')) ?: self::defaultApiUrl($provider);
            self::assertApiUrl($provider, $apiUrl);
            $authType = $provider === 'internetbs'
                ? 'api_key_password'
                : (in_array($provider, ['regru', 'namecheap'], true)
                    ? 'login_password'
                    : ($provider === 'joker' && (string) ($submitted['authType'] ?? '') === 'login_password' ? 'login_password' : 'api_key'));
            $active = !array_key_exists('active', $submitted) || !empty($submitted['active']);
            $manageAllDomains = !empty($submitted['manageAllDomains']);
            $sameProvider = (string) ($old['provider'] ?? '') === $provider;
            $secret = static function (string $key) use ($submitted, $old, $sameProvider): string {
                $value = (string) ($submitted[$key] ?? '');
                return $value !== '' ? $value : ($sameProvider ? (string) ($old[$key] ?? '') : '');
            };
            $apiToken = in_array($authType, ['api_key', 'api_key_password'], true) ? trim($secret('apiToken')) : '';
            $username = $authType === 'login_password' ? trim($secret('username')) : '';
            $password = in_array($authType, ['login_password', 'api_key_password'], true) ? $secret('password') : '';
            foreach ([$apiToken, $username, $password] as $credential) {
                if (strlen($credential) > 4096 || preg_match('/[\x00-\x1F\x7F]/', $credential) === 1) throw new InvalidArgumentException('Invalid DNS credential');
            }
            if ($authType === 'api_key' && $apiToken === '') throw new InvalidArgumentException('DNS API key is required');
            if ($authType === 'login_password' && ($username === '' || $password === '')) throw new InvalidArgumentException('DNS login and password are required');
            if ($authType === 'api_key_password' && ($apiToken === '' || $password === '')) throw new InvalidArgumentException('DNS API key and password are required');
            $createdAt = trim((string) ($old['createdAt'] ?? '')) ?: gmdate('c');
            $candidate = compact('id', 'name', 'provider', 'apiUrl', 'authType', 'apiToken', 'username', 'password', 'active', 'manageAllDomains', 'createdAt');
            $compareKeys = ['name', 'provider', 'apiUrl', 'authType', 'apiToken', 'username', 'password', 'active', 'manageAllDomains'];
            $changed = !$old;
            foreach ($compareKeys as $key) {
                if (($candidate[$key] ?? null) !== ($old[$key] ?? null)) { $changed = true; break; }
            }
            $candidate['updatedAt'] = $changed ? gmdate('c') : (trim((string) ($old['updatedAt'] ?? '')) ?: $createdAt);
            $connections[] = $candidate;
            if (count($connections) > 20) throw new InvalidArgumentException('Too many DNS connections');
        }
        return ['dnsConnections' => $connections];
    }

    public static function publicProfile(array $profile): array
    {
        $rows = [];
        $show = defined('SHOW_DNS_PROVIDER_CREDENTIALS') && SHOW_DNS_PROVIDER_CREDENTIALS;
        foreach (self::storedConnections($profile) as $connection) {
            $rows[] = [
                'id' => $connection['id'], 'name' => $connection['name'], 'provider' => $connection['provider'],
                'apiUrl' => $connection['apiUrl'], 'authType' => $connection['authType'],
                'apiTokenConfigured' => $connection['apiToken'] !== '', 'usernameConfigured' => $connection['username'] !== '',
                'passwordConfigured' => $connection['password'] !== '', 'apiToken' => $show ? $connection['apiToken'] : '',
                'username' => $show ? $connection['username'] : '', 'password' => $show ? $connection['password'] : '',
                'active' => $connection['active'], 'manageAllDomains' => $connection['manageAllDomains'],
                'createdAt' => $connection['createdAt'], 'updatedAt' => $connection['updatedAt'],
            ];
        }
        return ['dnsConnections' => $rows];
    }

    public static function storedConnections(array $profile): array
    {
        $source = is_array($profile['dnsConnections'] ?? null) ? $profile['dnsConnections'] : [];
        $fallbackCreatedAt = (string) ($profile['updatedAt'] ?? ($profile['createdAt'] ?? ''));
        if (!$source && trim((string) ($profile['dnsProvider'] ?? '')) !== '') {
            $source[] = ['id' => 'dns-legacy', 'name' => (string) ($profile['dnsConnectionName'] ?? 'DNS'), 'provider' => $profile['dnsProvider'], 'apiUrl' => $profile['dnsApiUrl'] ?? '', 'authType' => 'api_key', 'apiToken' => $profile['dnsApiToken'] ?? ''];
        }
        $result = [];
        foreach ($source as $index => $row) {
            if (!is_array($row)) continue;
            $provider = mb_strtolower(trim((string) ($row['provider'] ?? '')));
            if ($provider === '') continue;
            $result[] = [
                'id' => (string) ($row['id'] ?? ('dns-legacy-' . ($index + 1))), 'name' => trim((string) ($row['name'] ?? '')) ?: strtoupper($provider),
                'provider' => $provider, 'apiUrl' => trim((string) ($row['apiUrl'] ?? '')) ?: self::defaultApiUrl($provider),
                'authType' => (string) ($row['authType'] ?? 'api_key'), 'apiToken' => (string) ($row['apiToken'] ?? ''),
                'username' => (string) ($row['username'] ?? ''), 'password' => (string) ($row['password'] ?? ''),
                'active' => !array_key_exists('active', $row) || !empty($row['active']),
                'manageAllDomains' => !empty($row['manageAllDomains']),
                'createdAt' => (string) ($row['createdAt'] ?? $fallbackCreatedAt), 'updatedAt' => (string) ($row['updatedAt'] ?? $fallbackCreatedAt),
            ];
        }
        return $result;
    }

    public static function publicConnectionsForProvider(array $profile, string $provider): array
    {
        $rows = [];
        foreach (self::storedConnections($profile) as $connection) {
            if ($connection['provider'] === $provider && $connection['active']) $rows[] = ['id' => $connection['id'], 'name' => $connection['name'], 'provider' => $provider];
        }
        if (!$rows && !empty($profile['_useConfigDnsToken']) && self::hasConfigCredentials($provider)) {
            $rows[] = ['id' => '__config_' . $provider, 'name' => strtoupper($provider) . ' (config.php)', 'provider' => $provider];
        }
        return $rows;
    }

    public static function profileForConnection(array $profile, string $connectionId): array
    {
        if (strpos($connectionId, '__config_') === 0 && !empty($profile['_useConfigDnsToken'])) {
            $provider = substr($connectionId, 9);
            return ['dnsProvider' => $provider, 'dnsApiUrl' => self::defaultApiUrl($provider), '_useConfigDnsToken' => true];
        }
        foreach (self::storedConnections($profile) as $connection) {
            if (hash_equals((string) $connection['id'], $connectionId)) {
                if (!$connection['active']) throw new InvalidArgumentException('Selected DNS API connection is inactive');
                return [
                'dnsProvider' => $connection['provider'], 'dnsApiUrl' => $connection['apiUrl'], 'dnsAuthType' => $connection['authType'],
                'dnsApiToken' => $connection['apiToken'], 'dnsApiUsername' => $connection['username'], 'dnsApiPassword' => $connection['password'],
                ];
            }
        }
        throw new InvalidArgumentException('Select a DNS API connection');
    }

    public static function managedConnections(array $profile): array
    {
        return array_values(array_filter(self::storedConnections($profile), static function (array $connection): bool {
            return !empty($connection['active']) && !empty($connection['manageAllDomains']);
        }));
    }

    public static function managedConnection(array $profile, string $connectionId): array
    {
        foreach (self::managedConnections($profile) as $connection) {
            if (hash_equals((string) $connection['id'], $connectionId)) return $connection;
        }
        throw new InvalidArgumentException('DNS connection is not enabled for all available domains');
    }

    public static function listZones(array $profile): array
    {
        return self::providerForProfile($profile)->listZones();
    }

    public static function editableTypes(): array
    {
        return self::EDITABLE_TYPES;
    }

    public static function normalizeManagedRecords(array $records): array
    {
        if (count($records) > 1000) throw new InvalidArgumentException('Too many DNS records');
        $normalized = [];
        $identities = [];
        foreach (array_values($records) as $record) {
            if (!is_array($record)) throw new InvalidArgumentException('Invalid DNS record');
            $row = self::normalizeRecord($record);
            $identity = $row['name'] . '|' . $row['type'];
            if (isset($identities[$identity])) throw new InvalidArgumentException('Duplicate DNS record: ' . $identity);
            $identities[$identity] = true;
            $row['editable'] = true;
            $normalized[] = $row;
        }
        return $normalized;
    }

    /** @param array<int,mixed> $values @return array<string,mixed> */
    public static function recordForDomainTemplate(string $domain, string $name, string $type, int $ttl, array $values): array
    {
        $domain = self::normalizeManagedDomain($domain);
        $name = mb_strtolower(rtrim(trim(str_ireplace('{domain}', $domain, $name)), '.'));
        if ($name === '' || $name === '@' || hash_equals($name, $domain)) {
            $name = '@';
        } else {
            $domainSuffix = '.' . $domain;
            if (mb_substr($name, -mb_strlen($domainSuffix)) === $domainSuffix) {
                $name = mb_substr($name, 0, -mb_strlen($domainSuffix));
            }
        }
        $expandedValues = array_map(static function ($value) use ($domain): string {
            return str_ireplace('{domain}', $domain, trim((string) $value));
        }, $values);
        return self::normalizeRecord([
            'name' => $name,
            'type' => $type,
            'ttl' => $ttl,
            'values' => $expandedValues,
        ]);
    }

    public static function recordsForDomainCopy(array $records, string $sourceDomain, string $targetDomain): array
    {
        $sourceDomain = self::normalizeManagedDomain($sourceDomain);
        $targetDomain = self::normalizeManagedDomain($targetDomain);
        if (hash_equals($sourceDomain, $targetDomain)) {
            throw new InvalidArgumentException('Source and target DNS zones must be different');
        }

        $copied = [];
        foreach (self::normalizeManagedRecords($records) as $record) {
            $record['name'] = self::replaceDomainReference((string) $record['name'], $sourceDomain, $targetDomain);
            $record['values'] = array_map(static function (string $value) use ($sourceDomain, $targetDomain): string {
                return self::replaceDomainReference($value, $sourceDomain, $targetDomain);
            }, $record['values']);
            $copied[] = $record;
        }
        return self::normalizeManagedRecords($copied);
    }

    public static function syncManagedRecords(array $profile, string $domain, array $records): array
    {
        $desired = self::normalizeManagedRecords($records);
        $provider = self::providerForProfile($profile);
        $currentResult = $provider->listRecords($domain);
        $desiredMap = [];
        foreach ($desired as $record) $desiredMap[$record['name'] . '|' . $record['type']] = true;

        $deleted = 0;
        foreach (is_array($currentResult['records'] ?? null) ? $currentResult['records'] : [] as $rrset) {
            if (!is_array($rrset)) continue;
            $name = (string) ($rrset['name'] ?? '');
            $type = strtoupper((string) ($rrset['type'] ?? ''));
            if (!in_array($type, self::EDITABLE_TYPES, true) || !empty($rrset['protection']['change'])) continue;
            if (!isset($desiredMap[$name . '|' . $type])) {
                $provider->deleteRecord($domain, $name, $type);
                $deleted++;
            }
        }

        foreach ($desired as $record) {
            $provider->upsertRecord($domain, $record['name'], $record['type'], $record['values'], $record['ttl']);
        }
        return ['provider' => $provider->id(), 'saved' => count($desired), 'deleted' => $deleted];
    }

    public static function testConnectionSettings(array $submitted, array $profile): array
    {
        $settings = self::normalizeProfileSettings(['dnsConnections' => [$submitted]], $profile);
        $connection = $settings['dnsConnections'][0];
        return self::providerForProfile(self::profileForConnection($settings, (string) $connection['id']))->testConnection();
    }

    public static function providerForProfile(array $profile): DnsProviderInterface
    {
        $provider = mb_strtolower(trim((string) ($profile['dnsProvider'] ?? DNS_API_DEFAULT_PROVIDER)));
        $url = trim((string) ($profile['dnsApiUrl'] ?? self::defaultApiUrl($provider)));
        self::assertApiUrl($provider, $url);
        $token = trim((string) ($profile['dnsApiToken'] ?? ''));
        if ($provider === 'hetzner') {
            if ($token === '' && !empty($profile['_useConfigDnsToken'])) $token = DNS_HETZNER_API_TOKEN;
            return new HetznerDnsProvider($url, $token, DNS_API_REQUEST_TIMEOUT_SECONDS);
        }
        if ($provider === 'joker') {
            if ($token === '' && !empty($profile['_useConfigDnsToken'])) $token = DNS_JOKER_API_TOKEN;
            return new JokerDnsProvider($url, $token, DNS_API_REQUEST_TIMEOUT_SECONDS, (string) ($profile['dnsApiUsername'] ?? ''), (string) ($profile['dnsApiPassword'] ?? ''));
        }
        if ($provider === 'regru') {
            $username = trim((string) ($profile['dnsApiUsername'] ?? ''));
            $password = (string) ($profile['dnsApiPassword'] ?? '');
            if (!empty($profile['_useConfigDnsToken'])) {
                if ($username === '') $username = DNS_REGRU_API_USERNAME;
                if ($password === '') $password = DNS_REGRU_API_PASSWORD;
            }
            return new RegruDnsProvider($url, $username, $password, DNS_API_REQUEST_TIMEOUT_SECONDS);
        }
        if ($provider === 'namecheap') {
            $username = trim((string) ($profile['dnsApiUsername'] ?? ''));
            $apiKey = (string) ($profile['dnsApiPassword'] ?? '');
            if (!empty($profile['_useConfigDnsToken'])) {
                if ($username === '') $username = DNS_NAMECHEAP_API_USERNAME;
                if ($apiKey === '') $apiKey = DNS_NAMECHEAP_API_KEY;
            }
            return new NamecheapDnsProvider($url, $username, $apiKey, DNS_NAMECHEAP_CLIENT_IP, DNS_API_REQUEST_TIMEOUT_SECONDS);
        }
        if ($provider === 'internetbs') {
            $apiKey = $token;
            $password = (string) ($profile['dnsApiPassword'] ?? '');
            if (!empty($profile['_useConfigDnsToken'])) {
                if ($apiKey === '') $apiKey = DNS_INTERNETBS_API_KEY;
                if ($password === '') $password = DNS_INTERNETBS_API_PASSWORD;
            }
            return new InternetBsDnsProvider($url, $apiKey, $password, DNS_API_REQUEST_TIMEOUT_SECONDS);
        }
        throw new InvalidArgumentException('Selected DNS provider is not available yet');
    }

    public static function detect(array $profile, string $domain): array
    {
        $delegated = self::liveNameservers($domain);
        $detectedProvider = self::providerFromNameservers($delegated);
        $connections = self::publicConnectionsForProvider($profile, $detectedProvider);
        return ['provider' => $detectedProvider, 'nameservers' => $delegated, 'credentialsConfigured' => !empty($connections), 'connections' => $connections];
    }

    public static function verifyAccess(array $profile, string $domain, string $connectionId): array
    {
        $delegated = self::liveNameservers($domain);
        $detectedProvider = self::providerFromNameservers($delegated);
        $connection = self::profileForConnection($profile, $connectionId);
        if ($detectedProvider === '' || (string) $connection['dnsProvider'] !== $detectedProvider) {
            throw new InvalidArgumentException('Selected connection does not match the domain DNS provider');
        }
        try {
            $provider = self::providerForProfile($connection);
        } catch (InvalidArgumentException $exception) {
            return [
                'provider' => $detectedProvider,
                'zoneFound' => false,
                'credentialsConfigured' => false,
                'nameservers' => $delegated,
                'assignedNameservers' => [],
                'nameserversMatch' => false,
                'zoneStatus' => '',
            ];
        }
        $zone = $provider->getZone($domain);
        $assigned = self::nameserversFromZone($zone, 'assigned');
        $matches = !$assigned || (bool) array_intersect($delegated, $assigned);
        return [
            'provider' => $provider->id(),
            'connectionId' => $connectionId,
            'zoneFound' => true,
            'credentialsConfigured' => true,
            'nameservers' => $delegated,
            'assignedNameservers' => $assigned,
            'nameserversMatch' => $matches,
            'zoneStatus' => (string) ($zone['status'] ?? ''),
        ];
    }

    public static function listRecords(array $profile, string $domain): array
    {
        $provider = self::providerForProfile($profile);
        $result = $provider->listRecords($domain);
        $rows = [];
        foreach ($result['records'] as $rrset) {
            if (!is_array($rrset)) continue;
            $values = [];
            foreach (is_array($rrset['records'] ?? null) ? $rrset['records'] : [] as $record) {
                if (is_array($record) && array_key_exists('value', $record)) {
                    $values[] = self::displayValue((string) ($rrset['type'] ?? ''), (string) $record['value']);
                }
            }
            $type = strtoupper((string) ($rrset['type'] ?? ''));
            $rows[] = [
                'name' => (string) ($rrset['name'] ?? ''),
                'type' => $type,
                'ttl' => isset($rrset['ttl']) ? (int) $rrset['ttl'] : DNS_API_DEFAULT_TTL,
                'values' => $values,
                'editable' => in_array($type, self::EDITABLE_TYPES, true) && empty($rrset['protection']['change']),
            ];
        }
        return [
            'provider' => $provider->id(),
            'zone' => (string) ($result['zone']['name'] ?? $domain),
            'records' => $rows,
            'types' => self::editableTypesForProvider($provider),
        ];
    }

    public static function saveRecord(array $profile, string $domain, array $record): array
    {
        $normalized = self::normalizeRecord($record);
        $provider = self::providerForProfile($profile);
        $saved = $provider->upsertRecord($domain, $normalized['name'], $normalized['type'], $normalized['values'], $normalized['ttl']);
        return ['provider' => $provider->id(), 'record' => $saved];
    }

    public static function deleteRecord(array $profile, string $domain, string $name, string $type): void
    {
        [$name, $type] = self::normalizeRecordIdentity($name, $type);
        $provider = self::providerForProfile($profile);
        $provider->deleteRecord($domain, $name, $type);
    }

    public static function applyRecommended(array $profile, string $domain, ?array $recommendedRecords = null): array
    {
        $provider = self::providerForProfile($profile);
        $records = $recommendedRecords ?? self::recommendedRecords($domain);
        $editableTypes = self::editableTypesForProvider($provider);
        $current = $provider->listRecords($domain)['records'];
        $currentMap = [];
        foreach ($current as $rrset) {
            if (!is_array($rrset)) continue;
            $key = (string) ($rrset['name'] ?? '') . '|' . strtoupper((string) ($rrset['type'] ?? ''));
            $currentMap[$key] = $rrset;
        }
        $applied = 0;
        $skipped = [];
        foreach ($records as $record) {
            if (!in_array($record['type'], $editableTypes, true)) {
                $skipped[$record['type']] = true;
                continue;
            }
            if ($record['name'] === '@' && $record['type'] === 'TXT' && isset($currentMap['@|TXT'])) {
                $preserved = [];
                foreach (is_array($currentMap['@|TXT']['records'] ?? null) ? $currentMap['@|TXT']['records'] : [] as $value) {
                    if (!is_array($value) || !isset($value['value'])) continue;
                    $display = self::displayValue('TXT', (string) $value['value']);
                    if (preg_match('/^v=spf1\b/i', $display) !== 1) $preserved[] = $display;
                }
                $record['values'] = array_values(array_unique(array_merge($preserved, $record['values'])));
            }
            $provider->upsertRecord($domain, $record['name'], $record['type'], $record['values'], $record['ttl']);
            $applied++;
        }
        return ['provider' => $provider->id(), 'records' => $applied, 'skippedTypes' => array_keys($skipped)];
    }

    public static function recommendedRecords(string $domain, ?string $dkimValue = null): array
    {
        $domain = mb_strtolower(trim($domain));
        if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $domain) !== 1) {
            throw new InvalidArgumentException('Invalid domain');
        }

        $records = [];
        foreach (DNS_API_RECOMMENDED_RECORDS as $index => $configuredRecord) {
            if (!is_array($configuredRecord)) {
                throw new RuntimeException('Invalid recommended DNS record configuration at index ' . $index);
            }
            $record = $configuredRecord;
            $record['name'] = str_ireplace('{domain}', $domain, (string) ($record['name'] ?? ''));
            if ($dkimValue !== null
                && strtoupper((string) ($record['type'] ?? '')) === 'TXT'
                && mb_strtolower(trim((string) ($record['name'] ?? ''))) === mb_strtolower(DNS_DKIM_SELECTOR . '._domainkey')) {
                $record['values'] = [$dkimValue];
            }
            $values = is_array($record['values'] ?? null) ? $record['values'] : [$record['values'] ?? ''];
            $record['values'] = array_map(static function ($value) use ($domain): string {
                return str_ireplace('{domain}', $domain, (string) $value);
            }, $values);
            try {
                $records[] = self::normalizeRecord($record);
            } catch (InvalidArgumentException $exception) {
                throw new RuntimeException('Invalid recommended DNS record configuration at index ' . $index . ': ' . $exception->getMessage());
            }
        }
        if (!$records) throw new RuntimeException('Recommended DNS records are not configured');
        return $records;
    }

    private static function normalizeRecord(array $record): array
    {
        [$name, $type] = self::normalizeRecordIdentity((string) ($record['name'] ?? ''), (string) ($record['type'] ?? ''));
        $ttl = (int) ($record['ttl'] ?? DNS_API_DEFAULT_TTL);
        $values = is_array($record['values'] ?? null)
            ? $record['values']
            : preg_split('/\r?\n/u', (string) ($record['values'] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
        $values = array_values(array_unique(array_filter(array_map(static function ($value): string {
            return trim((string) $value);
        }, $values ?: []), static function (string $value): bool { return $value !== ''; })));

        if ($ttl < 60 || $ttl > 2147483647) throw new InvalidArgumentException('DNS TTL must be between 60 and 2147483647 seconds');
        if (!$values || count($values) > 50) throw new InvalidArgumentException('DNS record must contain from 1 to 50 values');
        foreach ($values as $value) {
            if (strlen($value) > 4096 || preg_match('/[\x00\r\n]/', $value) === 1) throw new InvalidArgumentException('Invalid DNS record value');
            if ($type === 'A' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) throw new InvalidArgumentException('Invalid IPv4 address');
            if ($type === 'AAAA' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) throw new InvalidArgumentException('Invalid IPv6 address');
        }
        return ['name' => $name, 'type' => $type, 'ttl' => $ttl, 'values' => $values];
    }

    private static function editableTypesForProvider(DnsProviderInterface $provider): array
    {
        // Namecheap setHosts does not document SRV; Internet.bs does not document CAA.
        if ($provider->id() === 'namecheap') return array_values(array_diff(self::EDITABLE_TYPES, ['SRV']));
        if ($provider->id() === 'internetbs') return array_values(array_diff(self::EDITABLE_TYPES, ['CAA']));
        return self::EDITABLE_TYPES;
    }

    private static function normalizeManagedDomain(string $domain): string
    {
        $domain = mb_strtolower(rtrim(trim($domain), '.'));
        if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $domain) !== 1) {
            throw new InvalidArgumentException('Invalid DNS zone domain');
        }
        return $domain;
    }

    private static function replaceDomainReference(string $value, string $sourceDomain, string $targetDomain): string
    {
        $pattern = '/(?<![a-z0-9-])' . preg_quote($sourceDomain, '/') . '(?![a-z0-9-])/iu';
        $replaced = preg_replace($pattern, $targetDomain, $value);
        if ($replaced === null) throw new RuntimeException('Cannot replace DNS zone reference');
        return $replaced;
    }

    private static function normalizeRecordIdentity(string $name, string $type): array
    {
        $name = mb_strtolower(trim($name));
        if ($name === '') $name = '@';
        $type = strtoupper(trim($type));
        if (preg_match('/^(?:@|\*|[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?)$/D', $name) !== 1 || strpos($name, '..') !== false) {
            throw new InvalidArgumentException('Invalid DNS record name');
        }
        if (!in_array($type, self::EDITABLE_TYPES, true)) throw new InvalidArgumentException('Unsupported DNS record type');
        return [$name, $type];
    }

    private static function providerDefinition(string $provider): ?array
    {
        foreach (self::publicProviders() as $definition) {
            if ($definition['id'] === $provider) return $definition;
        }
        return null;
    }

    private static function defaultApiUrl(string $provider): string
    {
        if ($provider === 'hetzner') return DNS_HETZNER_API_URL;
        if ($provider === 'joker') return DNS_JOKER_API_URL;
        if ($provider === 'regru') return DNS_REGRU_API_URL;
        if ($provider === 'namecheap') return DNS_NAMECHEAP_API_URL;
        if ($provider === 'internetbs') return DNS_INTERNETBS_API_URL;
        return '';
    }

    private static function assertApiUrl(string $provider, string $url): void
    {
        $allowedHosts = [];
        $label = 'DNS';
        if ($provider === 'hetzner') {
            $allowedHosts = DNS_HETZNER_ALLOWED_API_HOSTS;
            $label = 'Hetzner';
        } elseif ($provider === 'joker') {
            $allowedHosts = DNS_JOKER_ALLOWED_API_HOSTS;
            $label = 'Joker.com';
        } elseif ($provider === 'regru') {
            $allowedHosts = DNS_REGRU_ALLOWED_API_HOSTS;
            $label = 'REG.RU';
        } elseif ($provider === 'namecheap') {
            $allowedHosts = DNS_NAMECHEAP_ALLOWED_API_HOSTS;
            $label = 'Namecheap';
        } elseif ($provider === 'internetbs') {
            $allowedHosts = DNS_INTERNETBS_ALLOWED_API_HOSTS;
            $label = 'Internet.bs';
        } else {
            throw new InvalidArgumentException('Selected DNS provider is not available yet');
        }
        $parts = parse_url($url);
        $host = mb_strtolower((string) ($parts['host'] ?? ''));
        if (($parts['scheme'] ?? '') !== 'https' || !in_array($host, $allowedHosts, true)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) || isset($parts['query'])) {
            throw new InvalidArgumentException('Invalid ' . $label . ' API URL');
        }
    }

    private static function liveNameservers(string $domain): array
    {
        $result = [];
        foreach (dns_get_record($domain, DNS_NS) ?: [] as $record) {
            $target = mb_strtolower(rtrim((string) ($record['target'] ?? ''), '.'));
            if ($target !== '') $result[$target] = true;
        }
        return array_keys($result);
    }

    private static function nameserversFromZone(array $zone, string $key): array
    {
        $values = $zone['authoritative_nameservers'][$key] ?? [];
        $result = [];
        foreach (is_array($values) ? $values : [] as $value) {
            if (is_array($value)) $value = $value['name'] ?? $value['hostname'] ?? '';
            $value = mb_strtolower(rtrim(trim((string) $value), '.'));
            if ($value !== '') $result[$value] = true;
        }
        return array_keys($result);
    }

    private static function providerFromNameservers(array $nameservers): string
    {
        foreach ($nameservers as $nameserver) {
            $nameserver = mb_strtolower((string) $nameserver);
            if (substr($nameserver, -15) === '.ns.hetzner.com'
                || in_array($nameserver, ['ns1.first-ns.de', 'robotns2.second-ns.de', 'robotns3.second-ns.com'], true)) {
                return 'hetzner';
            }
            if (in_array($nameserver, DNS_JOKER_NAMESERVERS, true)
                || substr($nameserver, -13) === '.ns.joker.com') {
                return 'joker';
            }
            if (in_array($nameserver, DNS_REGRU_NAMESERVERS, true)) {
                return 'regru';
            }
            if (in_array($nameserver, DNS_NAMECHEAP_NAMESERVERS, true)) {
                return 'namecheap';
            }
            if (in_array($nameserver, DNS_INTERNETBS_NAMESERVERS, true)) {
                return 'internetbs';
            }
        }
        return '';
    }

    private static function hasConfigCredentials(string $provider): bool
    {
        if ($provider === 'hetzner') return trim((string) DNS_HETZNER_API_TOKEN) !== '' && DNS_HETZNER_API_TOKEN !== 'CHANGE_ME';
        if ($provider === 'joker') {
            $token = trim((string) DNS_JOKER_API_TOKEN);
            return ($token !== '' && $token !== 'CHANGE_ME')
                || (trim((string) DNS_JOKER_API_USERNAME) !== '' && trim((string) DNS_JOKER_API_PASSWORD) !== '');
        }
        if ($provider === 'regru') {
            return trim((string) DNS_REGRU_API_USERNAME) !== ''
                && trim((string) DNS_REGRU_API_PASSWORD) !== ''
                && DNS_REGRU_API_PASSWORD !== 'CHANGE_ME';
        }
        if ($provider === 'namecheap') {
            return trim((string) DNS_NAMECHEAP_API_USERNAME) !== ''
                && trim((string) DNS_NAMECHEAP_API_KEY) !== ''
                && DNS_NAMECHEAP_API_KEY !== 'CHANGE_ME';
        }
        if ($provider === 'internetbs') {
            return trim((string) DNS_INTERNETBS_API_KEY) !== ''
                && DNS_INTERNETBS_API_KEY !== 'CHANGE_ME'
                && trim((string) DNS_INTERNETBS_API_PASSWORD) !== ''
                && DNS_INTERNETBS_API_PASSWORD !== 'CHANGE_ME';
        }
        return false;
    }

    private static function displayValue(string $type, string $value): string
    {
        return strtoupper($type) === 'TXT' ? DnsTxtValue::toDisplay($value) : $value;
    }
}
