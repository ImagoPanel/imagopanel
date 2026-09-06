<?php
declare(strict_types=1);

require_once __DIR__ . '/DnsProviderInterface.php';

final class RegruDnsProvider implements DnsProviderInterface
{
    private const SUPPORTED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'SRV'];

    private string $apiUrl;
    private string $username;
    private string $password;
    private int $timeout;

    public function __construct(string $apiUrl, string $username, string $password, int $timeout = 15)
    {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->username = trim($username);
        $this->password = $password;
        $this->timeout = max(2, $timeout);

        if ($this->username === '' || $this->password === '' || $this->password === 'CHANGE_ME') {
            throw new InvalidArgumentException('REG.RU API login and API password are not configured');
        }
    }

    public function id(): string
    {
        return 'regru';
    }

    public function testConnection(): array
    {
        $response = $this->request('service/get_list', ['servtype' => 'domain']);
        return [
            'provider' => $this->id(),
            'zones' => count(is_array($response['answer']['services'] ?? null) ? $response['answer']['services'] : []),
        ];
    }

    public function getZone(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        $response = $this->request('zone/get_resource_records', ['domains' => [['dname' => $domain]]]);
        $zone = $this->domainAnswer($response, $domain);
        return [
            'name' => $domain,
            'status' => 'active',
            'authoritative_nameservers' => ['assigned' => DNS_REGRU_NAMESERVERS],
            '_regru_zone' => $zone,
        ];
    }

    public function listZones(): array
    {
        $response = $this->request('service/get_list', ['servtype' => 'domain']);
        $zones = [];
        foreach (is_array($response['answer']['services'] ?? null) ? $response['answer']['services'] : [] as $service) {
            if (!is_array($service)) continue;
            $name = mb_strtolower(rtrim(trim((string) ($service['dname'] ?? $service['domain'] ?? '')), '.'));
            if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $name) !== 1) continue;
            $zones[$name] = [
                'name' => $name,
                'status' => (string) ($service['state'] ?? 'active'),
            ];
        }
        ksort($zones, SORT_NATURAL | SORT_FLAG_CASE);
        return array_values($zones);
    }

    public function listRecords(string $domain): array
    {
        $zone = $this->getZone($domain);
        $rawZone = is_array($zone['_regru_zone'] ?? null) ? $zone['_regru_zone'] : [];
        $ttl = self::ttlSeconds((string) ($rawZone['soa']['ttl'] ?? ''));
        $groups = [];
        foreach (is_array($rawZone['rrs'] ?? null) ? $rawZone['rrs'] : [] as $record) {
            if (!is_array($record)) continue;
            $type = strtoupper(trim((string) ($record['rectype'] ?? $record['type'] ?? '')));
            $name = self::normalizeName((string) ($record['subname'] ?? $record['name'] ?? '@'));
            $content = trim((string) ($record['content'] ?? $record['value'] ?? ''));
            if ($type === '' || $content === '') continue;
            $priority = trim((string) ($record['prio'] ?? $record['priority'] ?? ''));
            $value = $content;
            if ($type === 'MX' && $priority !== '') $value = $priority . ' ' . $content;
            if ($type === 'SRV' && $priority !== '' && preg_match('/^\d+\s+\d+\s+\d+\s+/D', $content) !== 1) {
                $value = $priority . ' ' . $content;
            }
            $key = $name . '|' . $type;
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'name' => $name,
                    'type' => $type,
                    'ttl' => $ttl,
                    'records' => [],
                    'protection' => ['change' => !in_array($type, self::SUPPORTED_TYPES, true)],
                ];
            }
            $groups[$key]['records'][] = ['value' => $value];
        }
        unset($zone['_regru_zone']);
        return ['zone' => $zone, 'records' => array_values($groups)];
    }

    public function upsertRecord(string $domain, string $name, string $type, array $values, ?int $ttl): array
    {
        $domain = $this->normalizeDomain($domain);
        $name = self::normalizeName($name);
        $type = strtoupper(trim($type));
        if (!in_array($type, self::SUPPORTED_TYPES, true)) {
            throw new InvalidArgumentException('DNS record type is not supported by REG.RU integration');
        }
        $ttl = $ttl === null ? DNS_API_DEFAULT_TTL : $ttl;
        if ($ttl < 60 || $ttl > 2147483647) throw new InvalidArgumentException('Invalid REG.RU DNS TTL');
        if (!$values) throw new InvalidArgumentException('DNS record value is required');

        if ($this->recordExists($domain, $name, $type)) {
            $this->deleteRecord($domain, $name, $type);
        }
        foreach ($values as $value) {
            $this->addRecord($domain, $name, $type, trim((string) $value), $ttl);
        }

        return [
            'name' => $name,
            'type' => $type,
            'ttl' => $ttl,
            'records' => array_map(static function ($value): array {
                return ['value' => (string) $value];
            }, array_values($values)),
        ];
    }

    public function deleteRecord(string $domain, string $name, string $type): void
    {
        $domain = $this->normalizeDomain($domain);
        $name = self::normalizeName($name);
        $type = strtoupper(trim($type));
        $this->domainAnswer($this->request('zone/remove_record', [
            'domains' => [['dname' => $domain]],
            'subdomain' => $name,
            'record_type' => $type,
        ]), $domain);
    }

    private function recordExists(string $domain, string $name, string $type): bool
    {
        foreach ($this->listRecords($domain)['records'] as $record) {
            if (!is_array($record)) continue;
            if ((string) ($record['name'] ?? '') === $name && strtoupper((string) ($record['type'] ?? '')) === $type) return true;
        }
        return false;
    }

    private function addRecord(string $domain, string $name, string $type, string $value, int $ttl): void
    {
        if ($value === '') throw new InvalidArgumentException('DNS record value is required');
        // REG.API manages TTL through the zone SOA, not per individual resource record.
        $params = ['domains' => [['dname' => $domain]], 'subdomain' => $name];
        $command = '';
        if ($type === 'A') {
            $command = 'zone/add_alias';
            $params['ipaddr'] = $value;
        } elseif ($type === 'AAAA') {
            $command = 'zone/add_aaaa';
            $params['ipaddr'] = $value;
        } elseif ($type === 'CNAME') {
            $command = 'zone/add_cname';
            $params['canonical_name'] = $value;
        } elseif ($type === 'TXT') {
            if (strlen($value) > 512) throw new InvalidArgumentException('REG.RU TXT record is limited to 512 bytes');
            $command = 'zone/add_txt';
            $params['text'] = self::unquoteTxt($value);
        } elseif ($type === 'MX') {
            if (preg_match('/^(\d+)\s+(.+)$/D', $value, $match) !== 1) throw new InvalidArgumentException('REG.RU MX value must be: priority hostname');
            $command = 'zone/add_mx';
            $params['priority'] = (int) $match[1];
            $params['mail_server'] = $match[2];
        } elseif ($type === 'CAA') {
            if (preg_match('/^(\d+)\s+(issue|issuewild|iodef)\s+(.+)$/Di', $value, $match) !== 1) throw new InvalidArgumentException('REG.RU CAA value must be: flags tag value');
            $command = 'zone/add_caa';
            $params['flags'] = (int) $match[1];
            $params['tag'] = mb_strtolower($match[2]);
            $params['value'] = self::unquoteTxt($match[3]);
        } elseif ($type === 'SRV') {
            if (preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/D', $value, $match) !== 1) throw new InvalidArgumentException('REG.RU SRV value must be: priority weight port hostname');
            $command = 'zone/add_srv';
            $params['service'] = $name;
            $params['priority'] = (int) $match[1];
            $params['weight'] = (int) $match[2];
            $params['port'] = (int) $match[3];
            $params['target'] = $match[4];
            unset($params['subdomain']);
        }
        if ($command === '') throw new InvalidArgumentException('Unsupported REG.RU DNS record type');
        $this->domainAnswer($this->request($command, $params), $domain);
    }

    private function request(string $command, array $parameters): array
    {
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL extension is required for DNS API');
        if (preg_match('/^[a-z][a-z0-9_]*\/[a-z][a-z0-9_]*$/D', $command) !== 1) throw new InvalidArgumentException('Invalid REG.RU API command');
        $input = json_encode($parameters, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($input === false) throw new RuntimeException('Cannot encode REG.RU API request');
        $handle = curl_init($this->apiUrl . '/' . $command);
        if ($handle === false) throw new RuntimeException('Cannot initialize REG.RU API request');
        $body = http_build_query([
            'username' => $this->username,
            'password' => $this->password,
            'input_format' => 'json',
            'output_format' => 'json',
            'io_encoding' => 'utf8',
            'lang' => 'en',
            'input_data' => $input,
        ], '', '&', PHP_QUERY_RFC3986);
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
        if ($raw === false) throw new RuntimeException('REG.RU API connection failed: ' . $curlError);
        $decoded = json_decode((string) $raw, true);
        if (!is_array($decoded)) throw new RuntimeException('Invalid JSON from REG.RU API');
        if ($status < 200 || $status >= 300 || mb_strtolower((string) ($decoded['result'] ?? '')) !== 'success') {
            $code = trim((string) ($decoded['error_code'] ?? $status));
            $message = trim((string) ($decoded['error_text'] ?? 'REG.RU API request failed'));
            throw new RuntimeException('REG.RU API [' . $code . ']: ' . $message);
        }
        return $decoded;
    }

    private function domainAnswer(array $response, string $domain): array
    {
        $domains = is_array($response['answer']['domains'] ?? null) ? $response['answer']['domains'] : [];
        if (!$domains || !is_array($domains[0])) throw new RuntimeException('REG.RU API did not return the DNS zone');
        $answer = $domains[0];
        if (isset($answer['result']) && mb_strtolower((string) $answer['result']) !== 'success') {
            $code = trim((string) ($answer['error_code'] ?? 'ZONE_ERROR'));
            $message = trim((string) ($answer['error_text'] ?? ('Cannot manage REG.RU DNS zone: ' . $domain)));
            throw new RuntimeException('REG.RU API [' . $code . ']: ' . $message);
        }
        return $answer;
    }

    private static function normalizeName(string $name): string
    {
        $name = mb_strtolower(rtrim(trim($name), '.'));
        return $name === '' ? '@' : $name;
    }

    private function normalizeDomain(string $domain): string
    {
        $domain = mb_strtolower(rtrim(trim($domain), '.'));
        if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $domain) !== 1) throw new InvalidArgumentException('Invalid domain');
        return $domain;
    }

    private static function ttlSeconds(string $value): int
    {
        $value = mb_strtolower(trim($value));
        if ($value === '') return DNS_API_DEFAULT_TTL;
        if (ctype_digit($value)) return max(60, (int) $value);
        if (preg_match('/^(\d+)\s*([smhdw])$/D', $value, $match) !== 1) return DNS_API_DEFAULT_TTL;
        $multipliers = ['s' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800];
        return max(60, (int) $match[1] * $multipliers[$match[2]]);
    }

    private static function unquoteTxt(string $value): string
    {
        if (strlen($value) >= 2 && $value[0] === '"' && substr($value, -1) === '"') {
            return stripcslashes(substr($value, 1, -1));
        }
        return $value;
    }
}
