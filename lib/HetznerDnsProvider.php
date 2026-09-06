<?php
declare(strict_types=1);

require_once __DIR__ . '/DnsProviderInterface.php';
require_once __DIR__ . '/DnsTxtValue.php';

final class HetznerDnsProvider implements DnsProviderInterface
{
    private string $apiUrl;
    private string $token;
    private int $timeout;

    public function __construct(string $apiUrl, string $token, int $timeout = 15)
    {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->token = trim($token);
        $this->timeout = max(2, $timeout);

        if ($this->token === '' || $this->token === 'CHANGE_ME') {
            throw new InvalidArgumentException('Hetzner API key is not configured');
        }
    }

    public function id(): string
    {
        return 'hetzner';
    }

    public function testConnection(): array
    {
        $response = $this->request('GET', '/zones', null, ['per_page' => 1]);
        return [
            'provider' => $this->id(),
            'zones' => (int) ($response['meta']['pagination']['total_entries'] ?? count((array) ($response['zones'] ?? []))),
        ];
    }

    public function getZone(string $domain): array
    {
        $response = $this->request('GET', '/zones', null, ['name' => $domain, 'per_page' => 1]);
        $zones = is_array($response['zones'] ?? null) ? $response['zones'] : [];
        if (!$zones || !is_array($zones[0])) {
            throw new RuntimeException('DNS zone was not found in the Hetzner account');
        }
        return $zones[0];
    }

    public function listZones(): array
    {
        $page = 1;
        $zones = [];
        do {
            $response = $this->request('GET', '/zones', null, [
                'page' => $page,
                'per_page' => 100,
                'sort' => 'name:asc',
            ]);
            foreach (is_array($response['zones'] ?? null) ? $response['zones'] : [] as $zone) {
                if (!is_array($zone)) continue;
                $name = mb_strtolower(rtrim(trim((string) ($zone['name'] ?? '')), '.'));
                if ($name === '') continue;
                $zones[] = [
                    'name' => $name,
                    'status' => (string) ($zone['status'] ?? ''),
                ];
            }
            $next = $response['meta']['pagination']['next_page'] ?? null;
            $page = is_numeric($next) ? (int) $next : 0;
        } while ($page > 0);

        return $zones;
    }

    public function listRecords(string $domain): array
    {
        $zone = $this->getZone($domain);
        $zoneId = (string) ($zone['id'] ?? $domain);
        $page = 1;
        $records = [];
        do {
            $response = $this->request('GET', '/zones/' . rawurlencode($zoneId) . '/rrsets', null, [
                'page' => $page,
                'per_page' => 100,
                'sort' => 'name:asc',
            ]);
            foreach (is_array($response['rrsets'] ?? null) ? $response['rrsets'] : [] as $record) {
                if (is_array($record)) $records[] = $record;
            }
            $next = $response['meta']['pagination']['next_page'] ?? null;
            $page = is_numeric($next) ? (int) $next : 0;
        } while ($page > 0);

        return ['zone' => $zone, 'records' => $records];
    }

    public function upsertRecord(string $domain, string $name, string $type, array $values, ?int $ttl): array
    {
        $zone = $this->getZone($domain);
        $zoneId = (string) ($zone['id'] ?? $domain);
        $base = '/zones/' . rawurlencode($zoneId) . '/rrsets';
        $recordPath = $base . '/' . self::recordNamePath($name) . '/' . rawurlencode($type);
        $records = array_map(static function (string $value) use ($type): array {
            return ['value' => self::wireValue($type, $value)];
        }, array_values($values));

        if ($this->recordExists($base, $name, $type)) {
            $this->request('POST', $recordPath . '/actions/set_records', ['records' => $records]);
            $this->request('POST', $recordPath . '/actions/change_ttl', ['ttl' => $ttl]);
        } else {
            $this->request('POST', $base, [
                'name' => $name,
                'type' => $type,
                'ttl' => $ttl,
                'records' => $records,
            ]);
        }

        return $this->request('GET', $recordPath)['rrset'] ?? [];
    }

    public function deleteRecord(string $domain, string $name, string $type): void
    {
        $zone = $this->getZone($domain);
        $zoneId = (string) ($zone['id'] ?? $domain);
        $path = '/zones/' . rawurlencode($zoneId) . '/rrsets/' . self::recordNamePath($name) . '/' . rawurlencode($type);
        $this->request('DELETE', $path);
    }

    private function recordExists(string $basePath, string $name, string $type): bool
    {
        $response = $this->request('GET', $basePath, null, ['name' => $name, 'type' => $type, 'per_page' => 50]);
        foreach (is_array($response['rrsets'] ?? null) ? $response['rrsets'] : [] as $rrset) {
            if (is_array($rrset)
                && (string) ($rrset['name'] ?? '') === $name
                && strtoupper((string) ($rrset['type'] ?? '')) === strtoupper($type)) {
                return true;
            }
        }
        return false;
    }

    public static function displayValue(string $type, string $value): string
    {
        return strtoupper($type) === 'TXT' ? DnsTxtValue::toDisplay($value) : $value;
    }

    private static function wireValue(string $type, string $value): string
    {
        $type = strtoupper($type);
        if ($type === 'MX') {
            if (preg_match('/^(\d+)\s+(.+)$/D', trim($value), $match) !== 1) {
                throw new InvalidArgumentException('Hetzner MX value must be: priority hostname');
            }
            $target = trim($match[2]);
            if ($target !== '.' && substr($target, -1) !== '.' && strpos($target, '.') !== false) {
                $target .= '.';
            }
            return $match[1] . ' ' . $target;
        }
        if ($type !== 'TXT') return $value;
        return DnsTxtValue::toPresentation($value);
    }

    private static function recordNamePath(string $name): string
    {
        return str_replace(['%40', '%2A'], ['@', '*'], rawurlencode($name));
    }

    private function request(string $method, string $path, ?array $body = null, array $query = []): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL extension is required for DNS API');
        }
        $url = $this->apiUrl . $path;
        if ($query) $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $handle = curl_init($url);
        if ($handle === false) throw new RuntimeException('Cannot initialize DNS API request');

        $headers = ['Accept: application/json', 'Authorization: Bearer ' . $this->token];
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => min(5, $this->timeout),
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        if ($body !== null) {
            $encoded = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($encoded === false) throw new RuntimeException('Cannot encode DNS API request');
            $headers[] = 'Content-Type: application/json';
            $options[CURLOPT_HTTPHEADER] = $headers;
            $options[CURLOPT_POSTFIELDS] = $encoded;
        }
        curl_setopt_array($handle, $options);
        $raw = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $curlError = curl_error($handle);
        curl_close($handle);

        if ($raw === false) throw new RuntimeException('Hetzner DNS API connection failed: ' . $curlError);
        $decoded = $raw === '' ? [] : json_decode((string) $raw, true);
        if (!is_array($decoded)) $decoded = [];
        if ($status < 200 || $status >= 300) {
            $message = trim((string) ($decoded['error']['message'] ?? 'Hetzner DNS API request failed'));
            throw new RuntimeException('Hetzner DNS API [' . $status . ']: ' . $message);
        }
        return $decoded;
    }
}
