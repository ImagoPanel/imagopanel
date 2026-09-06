<?php
declare(strict_types=1);

require_once __DIR__ . '/DnsProviderInterface.php';

final class JokerDnsProvider implements DnsProviderInterface
{
    private const SUPPORTED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'SRV'];

    private string $apiUrl;
    private string $token;
    private string $username;
    private string $password;
    private int $timeout;
    private ?string $authSid = null;

    public function __construct(string $apiUrl, string $token, int $timeout = 15, string $username = '', string $password = '')
    {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->token = trim($token);
        $this->username = trim($username);
        $this->password = $password;
        $this->timeout = max(2, $timeout);

        $hasApiKey = $this->token !== '' && $this->token !== 'CHANGE_ME';
        $hasLogin = $this->username !== '' && $this->password !== '';
        if (!$hasApiKey && !$hasLogin) {
            throw new InvalidArgumentException('Joker.com API key or login and password are not configured');
        }
    }

    public function id(): string
    {
        return 'joker';
    }

    public function testConnection(): array
    {
        $response = $this->command('dns-zone-list', ['pattern' => '*']);
        return [
            'provider' => $this->id(),
            'zones' => count($this->bodyLines($response['body'])),
        ];
    }

    public function getZone(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        // include-defaults=1 is required because dns-zone-put replaces the complete zone.
        $response = $this->command('dns-zone-get', ['domain' => $domain, 'include-defaults' => 1]);
        return [
            'name' => $domain,
            'status' => 'active',
            'authoritative_nameservers' => ['assigned' => DNS_JOKER_NAMESERVERS],
            '_joker_zone' => $response['body'],
        ];
    }

    public function listZones(): array
    {
        $response = $this->command('dns-zone-list', ['pattern' => '*']);
        $zones = [];
        foreach ($this->bodyLines((string) $response['body']) as $line) {
            if (preg_match('/(?:^|\s)((?=.{1,253}(?:\s|$))(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?:\s|$)/i', trim($line), $match) !== 1) {
                continue;
            }
            $name = mb_strtolower(rtrim((string) $match[1], '.'));
            $zones[$name] = ['name' => $name, 'status' => 'active'];
        }
        ksort($zones, SORT_NATURAL | SORT_FLAG_CASE);
        return array_values($zones);
    }

    public function listRecords(string $domain): array
    {
        $zone = $this->getZone($domain);
        $groups = [];
        foreach ($this->zoneLines((string) $zone['_joker_zone']) as $line) {
            $parsed = self::parseRecordLine($line);
            if ($parsed === null) continue;
            $key = $parsed['name'] . '|' . $parsed['type'];
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'name' => $parsed['name'],
                    'type' => $parsed['type'],
                    'ttl' => $parsed['ttl'],
                    'records' => [],
                    'protection' => ['change' => !in_array($parsed['type'], self::SUPPORTED_TYPES, true)],
                ];
            }
            $groups[$key]['records'][] = ['value' => $parsed['value']];
        }
        unset($zone['_joker_zone']);
        return ['zone' => $zone, 'records' => array_values($groups)];
    }

    public function upsertRecord(string $domain, string $name, string $type, array $values, ?int $ttl): array
    {
        $domain = $this->normalizeDomain($domain);
        $name = self::normalizeName($name);
        $type = strtoupper(trim($type));
        if (!in_array($type, self::SUPPORTED_TYPES, true)) {
            throw new InvalidArgumentException('DNS record type is not supported by Joker.com integration');
        }
        $ttl = $ttl === null ? DNS_API_DEFAULT_TTL : $ttl;
        $zone = $this->getZone($domain);
        $lines = $this->withoutRecord($this->zoneLines((string) $zone['_joker_zone']), $name, $type);
        foreach ($values as $value) {
            $lines[] = self::buildRecordLine($name, $type, trim((string) $value), $ttl);
        }
        $this->putZone($domain, $lines);

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
        $zone = $this->getZone($domain);
        $original = $this->zoneLines((string) $zone['_joker_zone']);
        $lines = $this->withoutRecord($original, $name, $type);
        if (count($lines) === count($original)) {
            throw new RuntimeException('DNS record was not found in the Joker.com zone');
        }
        $this->putZone($domain, $lines);
    }

    private function putZone(string $domain, array $lines): void
    {
        $zone = implode("\n", $lines);
        if ($zone !== '') $zone .= "\n";
        $this->command('dns-zone-put', ['domain' => $domain, 'zone' => $zone]);
    }

    private function withoutRecord(array $lines, string $name, string $type): array
    {
        return array_values(array_filter($lines, static function (string $line) use ($name, $type): bool {
            $identity = self::recordIdentity($line);
            return $identity === null || $identity[0] !== $name || $identity[1] !== $type;
        }));
    }

    private static function recordIdentity(string $line): ?array
    {
        $tokens = self::tokenize($line);
        if (count($tokens) < 2 || substr(ltrim($line), 0, 1) === '#') return null;
        $type = strtoupper((string) $tokens[1]);
        if (preg_match('/^[A-Z][A-Z0-9]*$/D', $type) !== 1) return null;
        return [self::normalizeName((string) $tokens[0]), $type];
    }

    private static function parseRecordLine(string $line): ?array
    {
        $tokens = self::tokenize($line);
        if (count($tokens) < 5) return null;
        $identity = self::recordIdentity($line);
        if ($identity === null) return null;
        [$name, $type] = $identity;
        $priority = (string) $tokens[2];
        $target = (string) $tokens[3];
        $ttlIndex = 4;
        $value = $target;

        if ($type === 'TXT') {
            $value = self::quoteTxt($target);
        } elseif ($type === 'MX') {
            $value = $priority . ' ' . $target;
        } elseif ($type === 'SRV') {
            $priorityParts = explode('/', $priority, 2);
            $targetParts = explode(':', $target, 2);
            if (count($priorityParts) !== 2 || count($targetParts) !== 2) return null;
            $port = $targetParts[0] === '.' && $targetParts[1] === '1' ? '0' : $targetParts[1];
            $value = $priorityParts[0] . ' ' . $priorityParts[1] . ' ' . $port . ' ' . $targetParts[0];
        } elseif ($type === 'CAA') {
            if (!isset($tokens[4], $tokens[5])) return null;
            $value = '0 ' . $target . ' ' . (string) $tokens[4];
            $ttlIndex = 5;
        }

        $ttl = isset($tokens[$ttlIndex]) && ctype_digit((string) $tokens[$ttlIndex])
            ? (int) $tokens[$ttlIndex]
            : DNS_API_DEFAULT_TTL;
        return ['name' => $name, 'type' => $type, 'ttl' => $ttl, 'value' => $value];
    }

    private static function buildRecordLine(string $name, string $type, string $value, int $ttl): string
    {
        if ($value === '') throw new InvalidArgumentException('DNS record value is required');
        if ($ttl < 60 || $ttl > 2147483647) {
            throw new InvalidArgumentException('DNS TTL must be between 60 and 2147483647 seconds');
        }
        if ($type === 'TXT') {
            return $name . ' TXT 0 ' . self::quoteTxt(self::unquoteTxt($value)) . ' ' . $ttl;
        }
        if ($type === 'MX') {
            if (preg_match('/^(\d+)\s+(.+)$/D', $value, $match) !== 1) {
                throw new InvalidArgumentException('Joker.com MX value must be: priority hostname');
            }
            return $name . ' MX ' . $match[1] . ' ' . self::quoteIfNeeded($match[2]) . ' ' . $ttl;
        }
        if ($type === 'SRV') {
            if (preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/D', $value, $match) !== 1) {
                throw new InvalidArgumentException('Joker.com SRV value must be: priority weight port hostname');
            }
            $port = (int) $match[3];
            $target = trim((string) $match[4]);
            // RFC 2782 permits port 0 and defines Target "." as service unavailable,
            // but Joker DMAPI accepts only ports 1-65535. A client must still stop when
            // Target is ".", so 1 is a safe placeholder accepted by the provider.
            if ($port === 0 && $target === '.') $port = 1;
            if ($port < 1 || $port > 65535) {
                throw new InvalidArgumentException('Joker.com SRV port must be between 1 and 65535');
            }
            return $name . ' SRV ' . $match[1] . '/' . $match[2] . ' ' . self::quoteIfNeeded($target . ':' . $port) . ' ' . $ttl;
        }
        if ($type === 'CAA') {
            if (preg_match('/^(\d+)\s+(issue|issuewild|iodef)\s+(.+)$/Di', $value, $match) !== 1 || (int) $match[1] !== 0) {
                throw new InvalidArgumentException('Joker.com CAA value must be: 0 issue value, 0 issuewild value or 0 iodef value');
            }
            return $name . ' CAA 0 ' . mb_strtolower($match[2]) . ' ' . self::quoteTxt(self::unquoteTxt($match[3])) . ' ' . $ttl;
        }
        return $name . ' ' . $type . ' 0 ' . self::quoteIfNeeded($value) . ' ' . $ttl;
    }

    private static function tokenize(string $line): array
    {
        $tokens = [];
        if (preg_match_all('/"(?:\\\\.|[^"\\\\])*"|\S+/u', trim($line), $matches) !== false) {
            foreach ($matches[0] as $token) {
                $tokens[] = self::unquoteTxt((string) $token);
            }
        }
        return $tokens;
    }

    private static function quoteIfNeeded(string $value): string
    {
        return preg_match('/\s/u', $value) === 1 ? self::quoteTxt($value) : $value;
    }

    private static function quoteTxt(string $value): string
    {
        return '"' . addcslashes($value, "\\\"") . '"';
    }

    private static function unquoteTxt(string $value): string
    {
        if (strlen($value) >= 2 && $value[0] === '"' && substr($value, -1) === '"') {
            return stripcslashes(substr($value, 1, -1));
        }
        return $value;
    }

    private static function normalizeName(string $name): string
    {
        $name = mb_strtolower(rtrim(trim($name), '.'));
        return $name === '' ? '@' : $name;
    }

    private function normalizeDomain(string $domain): string
    {
        $domain = mb_strtolower(rtrim(trim($domain), '.'));
        if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $domain) !== 1) {
            throw new InvalidArgumentException('Invalid domain');
        }
        return $domain;
    }

    private function zoneLines(string $zone): array
    {
        $zone = str_replace(["\r\n", "\r"], "\n", $zone);
        return array_values(array_filter(explode("\n", $zone), static function (string $line): bool {
            return trim($line) !== '';
        }));
    }

    private function command(string $command, array $parameters): array
    {
        if ($command !== 'login') $parameters['auth-sid'] = $this->login();
        return $this->request($command, $parameters);
    }

    private function login(): string
    {
        if ($this->authSid !== null) return $this->authSid;
        $parameters = $this->token !== '' && $this->token !== 'CHANGE_ME'
            ? ['api-key' => $this->token]
            : ['username' => $this->username, 'password' => $this->password];
        $response = $this->request('login', $parameters);
        $sid = trim((string) ($response['headers']['auth-sid'] ?? ''));
        if ($sid === '') throw new RuntimeException('Joker.com DMAPI did not return Auth-SID');
        $this->authSid = $sid;
        return $sid;
    }

    private function request(string $command, array $parameters): array
    {
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL extension is required for DNS API');
        if (preg_match('/^[a-z][a-z0-9-]*$/D', $command) !== 1) throw new InvalidArgumentException('Invalid Joker.com DMAPI command');
        $handle = curl_init($this->apiUrl . '/request/' . $command);
        if ($handle === false) throw new RuntimeException('Cannot initialize Joker.com DMAPI request');
        $body = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Accept: text/plain', 'Content-Type: application/x-www-form-urlencoded'],
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
        if ($raw === false) throw new RuntimeException('Joker.com DMAPI connection failed: ' . $curlError);

        $parsed = self::parseResponse((string) $raw);
        $statusCode = (int) ($parsed['headers']['status-code'] ?? -1);
        $ok = $status >= 200 && $status < 300 && ($statusCode === 0 || ($statusCode >= 1000 && $statusCode <= 1999));
        if (!$ok) {
            $message = trim((string) ($parsed['headers']['error'] ?? $parsed['headers']['status-text'] ?? 'Joker.com DMAPI request failed'));
            throw new RuntimeException('Joker.com DMAPI [' . $statusCode . ']: ' . $message);
        }
        return $parsed;
    }

    private static function parseResponse(string $raw): array
    {
        $raw = str_replace(["\r\n", "\r"], "\n", $raw);
        $headers = [];
        $body = [];
        $readingHeaders = true;
        foreach (explode("\n", $raw) as $line) {
            if ($readingHeaders && trim($line) === '') {
                $readingHeaders = false;
                continue;
            }
            if ($readingHeaders && preg_match('/^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$/D', $line, $match) === 1) {
                $key = mb_strtolower($match[1]);
                $headers[$key] = isset($headers[$key]) && $headers[$key] !== ''
                    ? $headers[$key] . ' | ' . trim($match[2])
                    : trim($match[2]);
                continue;
            }
            $readingHeaders = false;
            $body[] = $line;
        }
        return ['headers' => $headers, 'body' => rtrim(implode("\n", $body), "\n")];
    }

    private function bodyLines(string $body): array
    {
        return array_values(array_filter(preg_split('/\r?\n/', $body) ?: [], static function (string $line): bool {
            return trim($line) !== '';
        }));
    }
}
