<?php
declare(strict_types=1);

require_once __DIR__ . '/DnsProviderInterface.php';
require_once __DIR__ . '/DnsTxtValue.php';

final class InternetBsDnsProvider implements DnsProviderInterface
{
    private const EDITABLE_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV'];

    private string $apiUrl;
    private string $apiKey;
    private string $password;
    private int $timeout;

    public function __construct(string $apiUrl, string $apiKey, string $password, int $timeout = 15)
    {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->apiKey = trim($apiKey);
        $this->password = $password;
        $this->timeout = max(2, $timeout);

        if ($this->apiKey === '' || $this->apiKey === 'CHANGE_ME' || $this->password === '' || $this->password === 'CHANGE_ME') {
            throw new InvalidArgumentException('Internet.bs API key and password are not configured');
        }
    }

    public function id(): string
    {
        return 'internetbs';
    }

    public function testConnection(): array
    {
        $response = $this->request('/Domain/List', ['CompactList' => 'YES']);
        return [
            'provider' => $this->id(),
            'zones' => isset($response['domaincount']) ? (int) $response['domaincount'] : count($this->domainsFromResponse($response)),
        ];
    }

    public function getZone(string $domain): array
    {
        $domain = self::normalizeDomain($domain);
        $this->fetchRecords($domain);
        return $this->zone($domain);
    }

    public function listZones(): array
    {
        $response = $this->request('/Domain/List', ['CompactList' => 'YES']);
        $zones = [];
        foreach ($this->domainsFromResponse($response) as $domain) {
            try {
                $domain = self::normalizeDomain($domain);
            } catch (InvalidArgumentException $exception) {
                continue;
            }
            $zones[$domain] = ['name' => $domain, 'status' => 'active'];
        }
        ksort($zones, SORT_NATURAL | SORT_FLAG_CASE);
        return array_values($zones);
    }

    public function listRecords(string $domain): array
    {
        $domain = self::normalizeDomain($domain);
        $groups = [];
        foreach ($this->fetchRecords($domain) as $record) {
            $type = strtoupper(trim((string) ($record['type'] ?? '')));
            $value = trim((string) ($record['value'] ?? ''));
            if ($type === '' || $value === '') continue;
            $name = self::relativeName((string) ($record['name'] ?? ''), $domain);
            $ttl = max(0, (int) ($record['ttl'] ?? DNS_API_DEFAULT_TTL));
            $displayValue = self::displayValue($type, $value, (int) ($record['priority'] ?? 10));
            $identity = $name . '|' . $type;
            if (!isset($groups[$identity])) {
                $groups[$identity] = [
                    'name' => $name,
                    'type' => $type,
                    'ttl' => $ttl,
                    'records' => [],
                    'protection' => ['change' => !in_array($type, self::EDITABLE_TYPES, true)],
                ];
            }
            $groups[$identity]['ttl'] = min((int) $groups[$identity]['ttl'], $ttl);
            $groups[$identity]['records'][] = ['value' => $displayValue];
        }

        return ['zone' => $this->zone($domain), 'records' => array_values($groups)];
    }

    public function upsertRecord(string $domain, string $name, string $type, array $values, ?int $ttl): array
    {
        $domain = self::normalizeDomain($domain);
        $name = self::normalizeName($name);
        $type = strtoupper(trim($type));
        if (!in_array($type, self::EDITABLE_TYPES, true)) {
            throw new InvalidArgumentException('DNS record type is not supported by Internet.bs API');
        }
        $ttl = $ttl === null ? DNS_API_DEFAULT_TTL : $ttl;
        if ($ttl < 60 || $ttl > 2147483647) throw new InvalidArgumentException('Internet.bs DNS TTL must be between 60 and 2147483647 seconds');
        if (!$values) throw new InvalidArgumentException('DNS record value is required');

        $fullName = self::fullName($name, $domain);
        $desired = [];
        foreach (array_values($values) as $value) {
            $wire = self::wireRecord($type, trim((string) $value));
            $identity = self::recordIdentity($wire['value'], $wire['priority']);
            $desired[$identity] = $wire;
        }
        if (!$desired) throw new InvalidArgumentException('DNS record value is required');

        $current = [];
        foreach ($this->fetchRecords($domain) as $record) {
            if (strcasecmp(rtrim((string) ($record['name'] ?? ''), '.'), $fullName) !== 0
                || strtoupper(trim((string) ($record['type'] ?? ''))) !== $type) continue;
            $current[] = $record;
        }

        $currentMap = [];
        foreach ($current as $record) {
            $wire = self::wireFromApiRecord($type, $record);
            $currentMap[self::recordIdentity($wire['value'], $wire['priority'])][] = (int) ($record['ttl'] ?? DNS_API_DEFAULT_TTL);
        }
        $unchanged = count($current) === count($desired);
        foreach ($desired as $identity => $wire) {
            if (count($currentMap[$identity] ?? []) !== 1 || (int) $currentMap[$identity][0] !== $ttl) {
                $unchanged = false;
                break;
            }
        }

        if (!$unchanged) {
            if ($current) {
                $this->removeRecordSet($fullName, $type);
                $this->waitUntilRecordSetMissing($domain, $fullName, $type);
                // The API can report an empty set before its delayed delete cache is cleared.
                usleep(2000000);
            }
            try {
                foreach ($desired as $wire) $this->addRecord($fullName, $type, $wire, $ttl);
            } catch (Throwable $exception) {
                $this->restoreRecordSet($domain, $fullName, $type, $current);
                throw $exception;
            }
        }

        return [
            'name' => $name,
            'type' => $type,
            'ttl' => $ttl,
            'records' => array_map(static function ($value): array {
                return ['value' => trim((string) $value)];
            }, array_values($values)),
        ];
    }

    public function deleteRecord(string $domain, string $name, string $type): void
    {
        $domain = self::normalizeDomain($domain);
        $name = self::normalizeName($name);
        $type = strtoupper(trim($type));
        if (!in_array($type, self::EDITABLE_TYPES, true)) throw new InvalidArgumentException('DNS record type is protected');
        try {
            $this->removeRecordSet(self::fullName($name, $domain), $type);
        } catch (RuntimeException $exception) {
            if (strpos($exception->getMessage(), '[104002]') === false) throw $exception;
        }
    }

    private function addRecord(string $fullName, string $type, array $wire, int $ttl): void
    {
        $parameters = [
            'FullRecordName' => $fullName,
            'Type' => $type,
            'Value' => $wire['value'],
            'Ttl' => $ttl,
        ];
        if ($wire['priority'] !== null) $parameters['Priority'] = $wire['priority'];
        $this->request('/Domain/DnsRecord/Add', $parameters);
    }

    private function removeRecordSet(string $fullName, string $type): void
    {
        $this->request('/Domain/DnsRecord/Remove', ['FullRecordName' => $fullName, 'Type' => $type]);
    }

    private function restoreRecordSet(string $domain, string $fullName, string $type, array $records): void
    {
        try {
            $this->removeRecordSet($fullName, $type);
            $this->waitUntilRecordSetMissing($domain, $fullName, $type);
            usleep(2000000);
        } catch (RuntimeException $exception) {
            if (strpos($exception->getMessage(), '[104002]') === false) {
                throw new RuntimeException('Internet.bs DNS record replacement and rollback failed: ' . $exception->getMessage());
            }
        }
        foreach ($records as $record) {
            $wire = self::wireFromApiRecord($type, $record);
            $restoreTtl = max(60, (int) ($record['ttl'] ?? DNS_API_DEFAULT_TTL));
            try {
                $this->addRecord($fullName, $type, $wire, $restoreTtl);
            } catch (Throwable $exception) {
                throw new RuntimeException('Internet.bs DNS record replacement and rollback failed: ' . $exception->getMessage());
            }
        }
    }

    private function waitUntilRecordSetMissing(string $domain, string $fullName, string $type): void
    {
        for ($attempt = 0; $attempt < 15; $attempt++) {
            foreach ($this->fetchRecords($domain) as $candidate) {
                if (strcasecmp(rtrim((string) ($candidate['name'] ?? ''), '.'), $fullName) !== 0
                    || strtoupper(trim((string) ($candidate['type'] ?? ''))) !== $type) continue;
                usleep(200000);
                continue 2;
            }
            return;
        }
        throw new RuntimeException('Internet.bs did not confirm DNS record-set removal before replacement');
    }

    private function fetchRecords(string $domain): array
    {
        $response = $this->request('/Domain/DnsRecord/List', ['Domain' => self::normalizeDomain($domain)]);
        $records = $response['records'] ?? [];
        if (!is_array($records)) return [];
        return array_values(array_filter($records, 'is_array'));
    }

    private function zone(string $domain): array
    {
        return [
            'name' => $domain,
            'status' => 'active',
            'authoritative_nameservers' => ['assigned' => DNS_INTERNETBS_NAMESERVERS],
        ];
    }

    private function domainsFromResponse(array $response): array
    {
        $domains = $response['domain'] ?? [];
        if (is_string($domains)) return [$domains];
        return is_array($domains) ? array_values(array_filter($domains, 'is_string')) : [];
    }

    private function request(string $path, array $parameters = []): array
    {
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL extension is required for DNS API');
        if (preg_match('#^/Domain/(?:List|DnsRecord/(?:Add|Remove|List))$#D', $path) !== 1) {
            throw new InvalidArgumentException('Invalid Internet.bs API resource path');
        }
        $body = http_build_query(array_merge([
            'ApiKey' => $this->apiKey,
            'Password' => $this->password,
            'ResponseFormat' => 'JSON',
        ], $parameters), '', '&', PHP_QUERY_RFC3986);
        $handle = curl_init($this->apiUrl . $path);
        if ($handle === false) throw new RuntimeException('Cannot initialize Internet.bs API request');
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_CONNECTTIMEOUT => min(5, $this->timeout),
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $raw = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $curlError = curl_error($handle);
        curl_close($handle);

        if ($raw === false) throw new RuntimeException('Internet.bs DNS API connection failed: ' . $curlError);
        $decoded = json_decode((string) $raw, true);
        if (!is_array($decoded)) throw new RuntimeException('Invalid JSON from Internet.bs DNS API');
        if ($status < 200 || $status >= 300 || strtoupper((string) ($decoded['status'] ?? '')) !== 'SUCCESS') {
            $code = trim((string) ($decoded['code'] ?? $status));
            $message = trim((string) ($decoded['message'] ?? 'Internet.bs DNS API request failed'));
            throw new RuntimeException('Internet.bs DNS API' . ($code !== '' ? ' [' . $code . ']' : '') . ': ' . $message);
        }
        return $decoded;
    }

    private static function wireRecord(string $type, string $value): array
    {
        if ($value === '') throw new InvalidArgumentException('DNS record value is required');
        if ($type === 'TXT') {
            return ['priority' => null, 'value' => DnsTxtValue::toPresentation($value)];
        }
        if ($type === 'MX') {
            if (preg_match('/^(\d+)\s+(.+)$/D', $value, $match) !== 1) {
                throw new InvalidArgumentException('Internet.bs MX value must be: priority hostname');
            }
            $target = trim($match[2]);
            if ($target !== '.') $target = rtrim($target, '.');
            return ['priority' => self::priority($match[1]), 'value' => $target];
        }
        if ($type === 'SRV') {
            if (preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/D', $value, $match) !== 1) {
                throw new InvalidArgumentException('Internet.bs SRV value must be: priority weight port hostname');
            }
            $target = trim($match[4]);
            if ($target !== '.') $target = rtrim($target, '.');
            return ['priority' => self::priority($match[1]), 'value' => $match[2] . ' ' . $match[3] . ' ' . $target];
        }
        return ['priority' => null, 'value' => $value];
    }

    private static function wireFromApiRecord(string $type, array $record): array
    {
        $value = trim((string) ($record['value'] ?? ''));
        if ($type === 'TXT') $value = DnsTxtValue::toPresentation($value);
        return [
            'priority' => in_array($type, ['MX', 'SRV'], true) ? (int) ($record['priority'] ?? 10) : null,
            'value' => $value,
        ];
    }

    private static function displayValue(string $type, string $value, int $priority): string
    {
        if ($type === 'TXT') return DnsTxtValue::toDisplay($value);
        if (in_array($type, ['MX', 'SRV'], true)) {
            $value = trim($value);
            if ($value !== '.' && substr($value, -2) !== ' .') $value = rtrim($value, '.');
            return $priority . ' ' . $value;
        }
        return $value;
    }

    private static function priority(string $value): int
    {
        $priority = (int) $value;
        if ($priority < 0 || $priority > 65535) throw new InvalidArgumentException('Invalid Internet.bs DNS priority');
        return $priority;
    }

    private static function recordIdentity(string $value, ?int $priority): string
    {
        return ($priority === null ? '-' : (string) $priority) . '|' . rtrim(trim($value), '.');
    }

    private static function fullName(string $name, string $domain): string
    {
        if ($name === '@') return $domain;
        if ($name === $domain || substr($name, -strlen('.' . $domain)) === '.' . $domain) return $name;
        return $name . '.' . $domain;
    }

    private static function relativeName(string $name, string $domain): string
    {
        $name = mb_strtolower(rtrim(trim($name), '.'));
        if ($name === $domain || $name === '') return '@';
        $suffix = '.' . $domain;
        return substr($name, -strlen($suffix)) === $suffix ? substr($name, 0, -strlen($suffix)) : $name;
    }

    private static function normalizeName(string $name): string
    {
        $name = mb_strtolower(rtrim(trim($name), '.'));
        return $name === '' ? '@' : $name;
    }

    private static function normalizeDomain(string $domain): string
    {
        $domain = mb_strtolower(rtrim(trim($domain), '.'));
        if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $domain) !== 1) {
            throw new InvalidArgumentException('Invalid domain');
        }
        return $domain;
    }
}
