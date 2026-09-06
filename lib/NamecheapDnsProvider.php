<?php
declare(strict_types=1);

require_once __DIR__ . '/DnsProviderInterface.php';

final class NamecheapDnsProvider implements DnsProviderInterface
{
    private const EDITABLE_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA'];
    private const API_RECORD_TYPES = ['A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'MXE', 'NS', 'TXT', 'URL', 'URL301', 'FRAME'];
    private const MAX_HOST_RECORDS = 800;

    private string $apiUrl;
    private string $username;
    private string $apiKey;
    private string $clientIp;
    private int $timeout;
    private ?array $tlds = null;

    public function __construct(string $apiUrl, string $username, string $apiKey, string $clientIp, int $timeout = 15)
    {
        $this->apiUrl = $apiUrl;
        $this->username = trim($username);
        $this->apiKey = trim($apiKey);
        $this->clientIp = trim($clientIp);
        $this->timeout = max(2, $timeout);

        if ($this->username === '' || $this->apiKey === '' || $this->apiKey === 'CHANGE_ME') {
            throw new InvalidArgumentException('Namecheap API username and API key are not configured');
        }
        if (strlen($this->username) > 20 || strlen($this->apiKey) > 50) {
            throw new InvalidArgumentException('Namecheap API username or API key exceeds the documented length');
        }
        if (filter_var($this->clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new InvalidArgumentException('Namecheap ClientIp must be a valid public IPv4 address');
        }
    }

    public function id(): string
    {
        return 'namecheap';
    }

    public function testConnection(): array
    {
        $document = $this->request('namecheap.domains.getList', ['ListType' => 'ALL', 'Page' => 1, 'PageSize' => 10]);
        $xpath = new DOMXPath($document);
        $total = $xpath->evaluate('string((//*[local-name()="Paging"]/*[local-name()="TotalItems"])[1])');
        return [
            'provider' => $this->id(),
            'zones' => ctype_digit((string) $total) ? (int) $total : $xpath->query('//*[local-name()="DomainGetListResult"]/*[local-name()="Domain"]')->length,
        ];
    }

    public function getZone(string $domain): array
    {
        $result = $this->fetchHosts($domain);
        return $this->zoneFromHosts($domain, $result);
    }

    public function listZones(): array
    {
        $page = 1;
        $totalPages = 1;
        $zones = [];
        do {
            $document = $this->request('namecheap.domains.getList', ['ListType' => 'ALL', 'Page' => $page, 'PageSize' => 100, 'SortBy' => 'NAME']);
            $xpath = new DOMXPath($document);
            foreach ($xpath->query('//*[local-name()="DomainGetListResult"]/*[local-name()="Domain"]') as $node) {
                if (!$node instanceof DOMElement || !self::xmlBool($node->getAttribute('IsOurDNS'))) continue;
                $name = $this->normalizeDomain($node->getAttribute('Name'));
                $zones[$name] = [
                    'name' => $name,
                    'status' => self::xmlBool($node->getAttribute('IsExpired')) ? 'expired' : 'active',
                ];
            }
            $totalItems = (int) $xpath->evaluate('string((//*[local-name()="Paging"]/*[local-name()="TotalItems"])[1])');
            $pageSize = max(1, (int) $xpath->evaluate('string((//*[local-name()="Paging"]/*[local-name()="PageSize"])[1])'));
            $totalPages = max(1, (int) ceil($totalItems / $pageSize));
            $page++;
        } while ($page <= $totalPages && $page <= 1000);

        ksort($zones, SORT_NATURAL | SORT_FLAG_CASE);
        return array_values($zones);
    }

    public function listRecords(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        $result = $this->fetchHosts($domain);
        $groups = [];
        foreach ($result['records'] as $record) {
            $type = $record['type'];
            $value = $type === 'MX'
                ? (string) $record['mxPref'] . ' ' . self::displayHostname($record['address'])
                : $record['address'];
            $key = $record['name'] . '|' . $type;
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'name' => $record['name'],
                    'type' => $type,
                    'ttl' => $record['ttl'],
                    'records' => [],
                    'protection' => ['change' => !in_array($type, self::EDITABLE_TYPES, true)],
                ];
            }
            $groups[$key]['ttl'] = min((int) $groups[$key]['ttl'], $record['ttl']);
            $groups[$key]['records'][] = ['value' => $value];
        }

        return [
            'zone' => $this->zoneFromHosts($domain, $result),
            'records' => array_values($groups),
        ];
    }

    public function upsertRecord(string $domain, string $name, string $type, array $values, ?int $ttl): array
    {
        $domain = $this->normalizeDomain($domain);
        $name = self::normalizeName($name);
        $type = strtoupper(trim($type));
        if (!in_array($type, self::EDITABLE_TYPES, true)) {
            throw new InvalidArgumentException('DNS record type is not supported by Namecheap API');
        }
        $ttl = $ttl === null ? DNS_API_DEFAULT_TTL : $ttl;
        if ($ttl < 60 || $ttl > 60000) throw new InvalidArgumentException('Namecheap DNS TTL must be between 60 and 60000 seconds');
        if (!$values) throw new InvalidArgumentException('DNS record value is required');

        $current = $this->fetchHosts($domain);
        $records = array_values(array_filter($current['records'], static function (array $record) use ($name, $type): bool {
            return $record['name'] !== $name || $record['type'] !== $type;
        }));
        foreach (array_values($values) as $value) {
            $records[] = $this->managedRecord($name, $type, trim((string) $value), $ttl);
        }
        $this->setHosts($domain, $records);

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
        if (!in_array($type, self::EDITABLE_TYPES, true)) throw new InvalidArgumentException('DNS record type is protected');
        $current = $this->fetchHosts($domain);
        $records = array_values(array_filter($current['records'], static function (array $record) use ($name, $type): bool {
            return $record['name'] !== $name || $record['type'] !== $type;
        }));
        if (count($records) === count($current['records'])) return;
        $this->setHosts($domain, $records);
    }

    private function fetchHosts(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        [$sld, $tld] = $this->splitDomain($domain);
        $document = $this->request('namecheap.domains.dns.getHosts', ['SLD' => $sld, 'TLD' => $tld]);
        $xpath = new DOMXPath($document);
        $result = $xpath->query('//*[local-name()="DomainDNSGetHostsResult"]')->item(0);
        if (!$result instanceof DOMElement) throw new RuntimeException('Namecheap API did not return the DNS zone');
        $records = [];
        foreach ($xpath->query('./*[local-name()="Host"]', $result) as $host) {
            if (!$host instanceof DOMElement) continue;
            $type = strtoupper(trim($host->getAttribute('Type')));
            $address = trim($host->getAttribute('Address'));
            if ($type === '' || $address === '') continue;
            $records[] = [
                'name' => self::normalizeName($host->getAttribute('Name')),
                'type' => $type,
                'address' => $address,
                'mxPref' => max(0, (int) $host->getAttribute('MXPref')),
                'ttl' => self::normalizeTtl((int) $host->getAttribute('TTL')),
            ];
        }
        return [
            'usingOurDns' => self::xmlBool($result->getAttribute('IsUsingOurDNS')),
            'records' => $records,
        ];
    }

    private function zoneFromHosts(string $domain, array $result): array
    {
        return [
            'name' => $domain,
            'status' => !empty($result['usingOurDns']) ? 'active' : 'nameservers_mismatch',
            'authoritative_nameservers' => ['assigned' => DNS_NAMECHEAP_NAMESERVERS],
        ];
    }

    private function managedRecord(string $name, string $type, string $value, int $ttl): array
    {
        if ($value === '') throw new InvalidArgumentException('DNS record value is required');
        $address = $value;
        $mxPref = 10;
        if ($type === 'MX') {
            if (preg_match('/^(\d+)\s+(.+)$/D', $value, $match) !== 1) {
                throw new InvalidArgumentException('Namecheap MX value must be: priority hostname');
            }
            $mxPref = (int) $match[1];
            $address = trim($match[2]);
            if ($mxPref < 0 || $mxPref > 65535 || $address === '') throw new InvalidArgumentException('Invalid Namecheap MX record');
            $address = self::absoluteHostname($address);
        }
        return ['name' => $name, 'type' => $type, 'address' => $address, 'mxPref' => $mxPref, 'ttl' => $ttl];
    }

    private static function absoluteHostname(string $hostname): string
    {
        $hostname = trim($hostname);
        if ($hostname === '.' || substr($hostname, -1) === '.') return $hostname;

        // Namecheap treats a dotted MX target without the final dot as relative
        // and appends the current zone (mail.example.com -> mail.example.com.example.com).
        return strpos($hostname, '.') !== false ? $hostname . '.' : $hostname;
    }

    private static function displayHostname(string $hostname): string
    {
        $hostname = trim($hostname);
        return $hostname === '.' ? $hostname : rtrim($hostname, '.');
    }

    private function setHosts(string $domain, array $records): void
    {
        if (!$records) {
            throw new InvalidArgumentException('Namecheap API requires at least one host record; the final record cannot be removed');
        }
        if (count($records) > self::MAX_HOST_RECORDS) throw new InvalidArgumentException('Namecheap DNS zone contains too many host records');
        [$sld, $tld] = $this->splitDomain($domain);
        $params = ['SLD' => $sld, 'TLD' => $tld];
        $hasMx = false;
        foreach (array_values($records) as $offset => $record) {
            $index = $offset + 1;
            $type = strtoupper((string) ($record['type'] ?? ''));
            if (!in_array($type, self::API_RECORD_TYPES, true)) {
                throw new RuntimeException('Namecheap cannot safely preserve unsupported DNS record type: ' . $type);
            }
            $ttl = self::normalizeTtl((int) ($record['ttl'] ?? DNS_API_DEFAULT_TTL));
            $params['HostName' . $index] = self::normalizeName((string) ($record['name'] ?? '@'));
            $params['RecordType' . $index] = $type;
            $params['Address' . $index] = (string) ($record['address'] ?? '');
            $params['TTL' . $index] = $ttl;
            if ($type === 'MX') {
                $hasMx = true;
                $params['MXPref' . $index] = max(0, (int) ($record['mxPref'] ?? 10));
            }
        }
        if ($hasMx) $params['EmailType'] = 'MX';
        $document = $this->request('namecheap.domains.dns.setHosts', $params);
        $xpath = new DOMXPath($document);
        $success = $xpath->evaluate('string((//*[local-name()="DomainDNSSetHostsResult"]/@IsSuccess)[1])');
        if (!self::xmlBool((string) $success)) throw new RuntimeException('Namecheap did not confirm DNS zone update');
    }

    private function splitDomain(string $domain): array
    {
        foreach ($this->tldList() as $tld) {
            $suffix = '.' . $tld;
            if (substr($domain, -strlen($suffix)) !== $suffix) continue;
            $sld = substr($domain, 0, -strlen($suffix));
            if ($sld !== '' && strpos($sld, '.') === false) return [$sld, $tld];
        }
        throw new InvalidArgumentException('Cannot determine Namecheap SLD and TLD for domain: ' . $domain);
    }

    private function tldList(): array
    {
        if ($this->tlds !== null) return $this->tlds;
        $document = $this->request('namecheap.domains.getTldList');
        $xpath = new DOMXPath($document);
        $tlds = [];
        foreach ($xpath->query('//*[local-name()="Tlds" or local-name()="TldList"]/*[local-name()="Tld"]') as $node) {
            if (!$node instanceof DOMElement) continue;
            $name = mb_strtolower(trim($node->getAttribute('Name')));
            if ($name !== '' && preg_match('/^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/D', $name) === 1) $tlds[$name] = true;
        }
        if (!$tlds) throw new RuntimeException('Namecheap API did not return the TLD list');
        $this->tlds = array_keys($tlds);
        usort($this->tlds, static function (string $left, string $right): int {
            return strlen($right) <=> strlen($left);
        });
        return $this->tlds;
    }

    private function request(string $command, array $parameters = []): DOMDocument
    {
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL extension is required for DNS API');
        if (!class_exists('DOMDocument')) throw new RuntimeException('PHP DOM extension is required for Namecheap API');
        if (preg_match('/^namecheap\.[a-z]+(?:\.[a-z]+)*$/Di', $command) !== 1) throw new InvalidArgumentException('Invalid Namecheap API command');
        $body = http_build_query(array_merge([
            'ApiUser' => $this->username,
            'ApiKey' => $this->apiKey,
            'UserName' => $this->username,
            'Command' => $command,
            'ClientIp' => $this->clientIp,
        ], $parameters), '', '&', PHP_QUERY_RFC3986);
        $handle = curl_init($this->apiUrl);
        if ($handle === false) throw new RuntimeException('Cannot initialize Namecheap API request');
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Accept: application/xml', 'Content-Type: application/x-www-form-urlencoded'],
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
        if ($raw === false) throw new RuntimeException('Namecheap API connection failed: ' . $curlError);
        if ($status < 200 || $status >= 300) throw new RuntimeException('Namecheap API HTTP error: ' . $status);

        $previous = libxml_use_internal_errors(true);
        $document = new DOMDocument();
        $document->resolveExternals = false;
        $document->substituteEntities = false;
        $loaded = $document->loadXML((string) $raw, LIBXML_NONET | LIBXML_NOBLANKS);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        if (!$loaded) throw new RuntimeException('Invalid XML from Namecheap API');
        $xpath = new DOMXPath($document);
        $statusValue = strtoupper((string) $xpath->evaluate('string(/*[local-name()="ApiResponse"]/@Status)'));
        if ($statusValue !== 'OK') {
            $errors = [];
            foreach ($xpath->query('//*[local-name()="Errors"]/*[local-name()="Error"]') as $error) {
                if (!$error instanceof DOMElement) continue;
                $number = trim($error->getAttribute('Number'));
                $message = trim($error->textContent);
                $errors[] = ($number !== '' ? '[' . $number . '] ' : '') . ($message !== '' ? $message : 'Namecheap API request failed');
            }
            throw new RuntimeException($errors ? 'Namecheap API ' . implode('; ', $errors) : 'Namecheap API request failed');
        }
        return $document;
    }

    private static function normalizeName(string $name): string
    {
        $name = mb_strtolower(rtrim(trim($name), '.'));
        return $name === '' ? '@' : $name;
    }

    private function normalizeDomain(string $domain): string
    {
        $domain = mb_strtolower(rtrim(trim($domain), '.'));
        if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $domain) !== 1) {
            throw new InvalidArgumentException('Invalid domain');
        }
        return $domain;
    }

    private static function normalizeTtl(int $ttl): int
    {
        if ($ttl <= 0) return min(60000, max(60, DNS_API_DEFAULT_TTL));
        if ($ttl < 60 || $ttl > 60000) throw new RuntimeException('Namecheap DNS record has unsupported TTL: ' . $ttl);
        return $ttl;
    }

    private static function xmlBool(string $value): bool
    {
        return in_array(mb_strtolower(trim($value)), ['true', '1', 'yes'], true);
    }
}
