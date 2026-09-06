<?php
declare(strict_types=1);

/**
 * Manages only ImagoPanel DKIM data. The shared_key_all_domains mode
 * intentionally performs no filesystem operations.
 */
final class OpenDkimManager
{
    public const MODE_SHARED_ALL = 'shared_key_all_domains';
    public const MODE_SHARED_MANAGED = 'shared_key_managed_domains';
    public const MODE_PER_DOMAIN = 'per_domain_keys';

    private $options;
    private $reloadService;

    public function __construct(array $options, ?callable $reloadService = null)
    {
        $this->options = $options;
        $this->reloadService = $reloadService;
        $this->mode();
    }

    public static function fromConfig(?callable $reloadService = null): self
    {
        return new self([
            'mode' => OPENDKIM_MANAGEMENT_MODE,
            'selector' => DNS_DKIM_SELECTOR,
            'shared_dns_value' => DNS_DKIM_VALUE,
            'signing_domains_file' => OPENDKIM_SIGNING_DOMAINS_FILE,
            'key_table_file' => OPENDKIM_KEY_TABLE_FILE,
            'signing_table_file' => OPENDKIM_SIGNING_TABLE_FILE,
            'keys_directory' => OPENDKIM_KEYS_DIRECTORY,
            'pending_directory' => OPENDKIM_PENDING_KEYS_DIRECTORY,
            'lock_file' => OPENDKIM_LOCK_FILE,
            'key_bits' => OPENDKIM_KEY_BITS,
            'openssl_binary' => OPENDKIM_OPENSSL_BINARY,
            'pending_ttl' => OPENDKIM_PENDING_KEY_TTL_SECONDS,
            'owner' => OPENDKIM_FILE_OWNER,
            'group' => OPENDKIM_FILE_GROUP,
            'directory_mode' => OPENDKIM_DIRECTORY_MODE,
            'private_key_mode' => OPENDKIM_PRIVATE_KEY_MODE,
            'table_file_mode' => OPENDKIM_TABLE_FILE_MODE,
        ], $reloadService);
    }

    public function mode(): string
    {
        $mode = trim((string) ($this->options['mode'] ?? ''));
        if (!in_array($mode, [self::MODE_SHARED_ALL, self::MODE_SHARED_MANAGED, self::MODE_PER_DOMAIN], true)) {
            throw new RuntimeException('Invalid OPENDKIM_MANAGEMENT_MODE');
        }
        return $mode;
    }

    public function dnsValue(string $domain, bool $prepare = false): string
    {
        $domain = $this->normalizeDomain($domain);
        if ($this->mode() !== self::MODE_PER_DOMAIN) {
            return $this->sharedDnsValue();
        }
        $metadata = $this->keyMetadata($this->permanentKeyDirectory($domain), $domain, false);
        if ($metadata === null) {
            $metadata = $this->keyMetadata($this->pendingKeyDirectory($domain), $domain, true);
        }
        if ($metadata !== null) return (string) $metadata['dns_value'];
        if (!$prepare) throw new RuntimeException('DKIM key is not prepared for domain');
        return (string) $this->prepare($domain)['dnsValue'];
    }

    public function prepare(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        if ($this->mode() !== self::MODE_PER_DOMAIN) {
            return ['domain' => $domain, 'selector' => $this->selector(), 'dnsValue' => $this->sharedDnsValue(), 'temporary' => false];
        }
        return $this->withLock(function () use ($domain): array {
            $permanent = $this->keyMetadata($this->permanentKeyDirectory($domain), $domain, false);
            if ($permanent !== null) return $this->publicMetadata($permanent, false);
            $pending = $this->keyMetadata($this->pendingKeyDirectory($domain), $domain, true);
            if ($pending !== null) return $this->publicMetadata($pending, true);

            $pendingRoot = $this->requiredPath('pending_directory');
            $this->ensureDirectory($pendingRoot);
            $directory = $this->pendingKeyDirectory($domain);
            if (file_exists($directory)) throw new RuntimeException('Invalid existing pending DKIM path');
            if (!mkdir($directory, $this->directoryMode(), true) && !is_dir($directory)) {
                throw new RuntimeException('Cannot create pending DKIM directory');
            }
            $this->applyOwnership($directory, $this->directoryMode());
            try {
                [$privateKey, $public] = $this->generateKeyPair();
                $metadata = [
                    'domain' => $domain,
                    'selector' => $this->selector(),
                    'dns_value' => 'v=DKIM1; k=rsa; p=' . $public,
                    'created_at' => gmdate('c'),
                    'temporary' => true,
                ];
                $this->atomicWrite($directory . DIRECTORY_SEPARATOR . $this->selector() . '.private', $privateKey, $this->privateKeyMode());
                $this->atomicWrite($directory . DIRECTORY_SEPARATOR . 'metadata.json', $this->encodeJson($metadata), $this->privateKeyMode());
                $this->atomicWrite($directory . DIRECTORY_SEPARATOR . '.imagopanel-pending', "pending\n", $this->privateKeyMode());
                return $this->publicMetadata($metadata, true);
            } catch (Throwable $exception) {
                $this->removeTree($directory, $pendingRoot);
                throw $exception;
            }
        });
    }

    public function activate(string $domain, ?string $previousDomain = null): array
    {
        $domain = $this->normalizeDomain($domain);
        $previousDomain = $previousDomain !== null && trim($previousDomain) !== '' ? $this->normalizeDomain($previousDomain) : null;
        if ($this->mode() === self::MODE_SHARED_ALL) {
            return ['domain' => $domain, 'mode' => $this->mode(), 'changed' => false, 'dnsValue' => $this->sharedDnsValue()];
        }
        return $this->withLock(function () use ($domain, $previousDomain): array {
            $domains = $this->managedDomains();
            if ($previousDomain !== null && $previousDomain !== $domain) unset($domains[$previousDomain]);
            $domains[$domain] = true;

            if ($this->mode() === self::MODE_SHARED_MANAGED) {
                $dnsValue = $this->sharedDnsValue();
                $this->updateManagedFiles($domains, false);
                return ['domain' => $domain, 'mode' => $this->mode(), 'changed' => true, 'dnsValue' => $dnsValue];
            }

            $metadata = $this->keyMetadata($this->permanentKeyDirectory($domain), $domain, false);
            $pendingDirectory = $this->pendingKeyDirectory($domain);
            $movedPending = false;
            if ($metadata === null) {
                $pending = $this->keyMetadata($pendingDirectory, $domain, true);
                if ($pending === null) {
                    // The internal lock is already held; generate without locking again.
                    $pending = $this->generatePendingKeyUnlocked($domain);
                }
                $keysRoot = $this->requiredPath('keys_directory');
                $this->ensureDirectory($keysRoot);
                $target = $this->permanentKeyDirectory($domain);
                if (file_exists($target)) throw new RuntimeException('Permanent DKIM path already exists and is not managed by ImagoPanel');
                if (!rename($pendingDirectory, $target)) throw new RuntimeException('Cannot activate pending DKIM key');
                $movedPending = true;
                $metadata = $pending;
                $metadata['temporary'] = false;
                $metadata['activated_at'] = gmdate('c');
                $this->atomicWrite($target . DIRECTORY_SEPARATOR . 'metadata.json', $this->encodeJson($metadata), $this->privateKeyMode());
                @unlink($target . DIRECTORY_SEPARATOR . '.imagopanel-pending');
                $this->atomicWrite($target . DIRECTORY_SEPARATOR . '.imagopanel-managed', "managed\n", $this->privateKeyMode());
            }
            try {
                $this->updateManagedFiles($domains, true);
            } catch (Throwable $exception) {
                if ($movedPending) {
                    $target = $this->permanentKeyDirectory($domain);
                    @unlink($target . DIRECTORY_SEPARATOR . '.imagopanel-managed');
                    $this->atomicWrite($target . DIRECTORY_SEPARATOR . '.imagopanel-pending', "pending\n", $this->privateKeyMode());
                    @rename($target, $pendingDirectory);
                }
                throw $exception;
            }
            if ($previousDomain !== null && $previousDomain !== $domain) $this->removeManagedKeyDirectory($previousDomain);
            return ['domain' => $domain, 'mode' => $this->mode(), 'changed' => true, 'dnsValue' => (string) $metadata['dns_value']];
        });
    }

    public function remove(string $domain): array
    {
        return $this->removeDomains([$domain]);
    }

    public function removeDomains(array $domains): array
    {
        $normalized = [];
        foreach ($domains as $domain) $normalized[$this->normalizeDomain((string) $domain)] = true;
        if ($this->mode() === self::MODE_SHARED_ALL || $normalized === []) {
            return ['mode' => $this->mode(), 'removed' => array_keys($normalized), 'changed' => false];
        }
        return $this->withLock(function () use ($normalized): array {
            $managed = $this->managedDomains();
            foreach ($normalized as $domain => $_) unset($managed[$domain]);
            $this->updateManagedFiles($managed, $this->mode() === self::MODE_PER_DOMAIN);
            if ($this->mode() === self::MODE_PER_DOMAIN) {
                foreach (array_keys($normalized) as $domain) $this->removeManagedKeyDirectory($domain);
            }
            return ['mode' => $this->mode(), 'removed' => array_keys($normalized), 'changed' => true];
        });
    }

    public function cleanupPending(?int $now = null): array
    {
        $now = $now ?? time();
        $ttl = $this->positiveInteger('pending_ttl', 3600);
        $root = $this->requiredPath('pending_directory');
        if (!is_dir($root)) return ['checked' => 0, 'removed' => 0, 'directories' => []];
        return $this->withLock(function () use ($now, $ttl, $root): array {
            $checked = 0;
            $removed = [];
            $entries = scandir($root);
            if ($entries === false) throw new RuntimeException('Cannot read pending DKIM directory');
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                $directory = $root . DIRECTORY_SEPARATOR . $entry;
                if (!is_dir($directory) || is_link($directory) || !is_file($directory . DIRECTORY_SEPARATOR . '.imagopanel-pending')) continue;
                $checked++;
                $metadata = $this->decodeMetadata($directory . DIRECTORY_SEPARATOR . 'metadata.json');
                $created = is_array($metadata) ? strtotime((string) ($metadata['created_at'] ?? '')) : false;
                if ($created === false) $created = filemtime($directory);
                if ($created !== false && $now - $created > $ttl) {
                    $this->removeTree($directory, $root);
                    $removed[] = $entry;
                }
            }
            return ['checked' => $checked, 'removed' => count($removed), 'directories' => $removed];
        });
    }

    private function generatePendingKeyUnlocked(string $domain): array
    {
        $root = $this->requiredPath('pending_directory');
        $this->ensureDirectory($root);
        $directory = $this->pendingKeyDirectory($domain);
        if (file_exists($directory)) throw new RuntimeException('Invalid existing pending DKIM path');
        if (!mkdir($directory, $this->directoryMode(), true) && !is_dir($directory)) throw new RuntimeException('Cannot create pending DKIM directory');
        $this->applyOwnership($directory, $this->directoryMode());
        try {
            [$private, $public] = $this->generateKeyPair();
            $metadata = ['domain' => $domain, 'selector' => $this->selector(), 'dns_value' => 'v=DKIM1; k=rsa; p=' . $public, 'created_at' => gmdate('c'), 'temporary' => true];
            $this->atomicWrite($directory . DIRECTORY_SEPARATOR . $this->selector() . '.private', $private, $this->privateKeyMode());
            $this->atomicWrite($directory . DIRECTORY_SEPARATOR . 'metadata.json', $this->encodeJson($metadata), $this->privateKeyMode());
            $this->atomicWrite($directory . DIRECTORY_SEPARATOR . '.imagopanel-pending', "pending\n", $this->privateKeyMode());
            return $metadata;
        } catch (Throwable $exception) {
            $this->removeTree($directory, $root);
            throw $exception;
        }
    }

    private function updateManagedFiles(array $domains, bool $perDomain): void
    {
        ksort($domains, SORT_NATURAL | SORT_FLAG_CASE);
        $files = [$this->requiredPath('signing_domains_file') => array_keys($domains)];
        if ($perDomain) {
            $keyLines = [];
            $signingLines = [];
            foreach (array_keys($domains) as $domain) {
                $selector = $this->selector();
                $keyLines[] = $selector . '._domainkey.' . $domain . ' ' . $domain . ':' . $selector . ':' . $this->permanentKeyDirectory($domain) . DIRECTORY_SEPARATOR . $selector . '.private';
                $signingLines[] = '*@' . $domain . ' ' . $selector . '._domainkey.' . $domain;
            }
            $files[$this->requiredPath('key_table_file')] = $keyLines;
            $files[$this->requiredPath('signing_table_file')] = $signingLines;
        }

        $snapshots = [];
        foreach ($files as $path => $_) $snapshots[$path] = is_file($path) ? file_get_contents($path) : null;
        $changed = false;
        $reloadAttempted = false;
        try {
            foreach ($files as $path => $lines) {
                if ($this->writeManagedBlock($path, $lines)) $changed = true;
            }
            if ($changed) {
                $reloadAttempted = true;
                $this->reloadOpenDkim();
            }
        } catch (Throwable $exception) {
            foreach ($snapshots as $path => $content) {
                if ($content === null) {
                    @unlink($path);
                } elseif (is_string($content)) {
                    try { $this->atomicWrite($path, $content, $this->tableFileMode()); } catch (Throwable $ignored) {}
                }
            }
            if ($reloadAttempted) {
                try { $this->reloadOpenDkim(); } catch (Throwable $ignored) {}
            }
            throw $exception;
        }
    }

    private function generateKeyPair(): array
    {
        $generator = $this->options['key_generator'] ?? null;
        if (is_callable($generator)) {
            $pair = $generator($this->positiveInteger('key_bits', 2048));
            if (!is_array($pair) || trim((string) ($pair['private'] ?? '')) === '' || trim((string) ($pair['public'] ?? '')) === '') {
                throw new RuntimeException('Invalid DKIM key generator result');
            }
            return [(string) $pair['private'], preg_replace('/\s+/', '', (string) $pair['public']) ?: ''];
        }
        $bits = $this->positiveInteger('key_bits', 2048);
        if (extension_loaded('openssl') && function_exists('openssl_pkey_new')) {
            $resource = @openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            if ($resource !== false) {
                $private = '';
                if (@openssl_pkey_export($resource, $private)) {
                    $details = @openssl_pkey_get_details($resource);
                    $public = is_array($details) ? preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', (string) ($details['key'] ?? '')) : '';
                    if (is_string($public) && $public !== '') return [$private, $public];
                }
            }
        }

        $binary = trim((string) ($this->options['openssl_binary'] ?? ''));
        if ($binary === '' || !is_executable($binary)) {
            throw new RuntimeException('Cannot generate DKIM key: PHP OpenSSL failed and OPENDKIM_OPENSSL_BINARY is unavailable');
        }
        $private = $this->runOpenSsl([$binary, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:' . $bits]);
        $publicPem = $this->runOpenSsl([$binary, 'pkey', '-pubout'], $private);
        $public = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $publicPem);
        if (!is_string($public) || $public === '') throw new RuntimeException('Cannot normalize DKIM public key');
        return [$private, $public];
    }

    private function runOpenSsl(array $command, string $stdin = ''): string
    {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($process)) throw new RuntimeException('Cannot start OpenSSL');
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        if ($code !== 0 || trim((string) $stdout) === '') throw new RuntimeException(trim((string) $stderr) ?: 'OpenSSL DKIM key generation failed');
        return (string) $stdout;
    }

    private function managedDomains(): array
    {
        $path = $this->requiredPath('signing_domains_file');
        if (!is_file($path)) return [];
        $content = file_get_contents($path);
        if (!is_string($content)) throw new RuntimeException('Cannot read OpenDKIM SigningDomains');
        $panel = $this->panelBlock($content);
        $domains = [];
        foreach (preg_split('/\r?\n/', $panel) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            if ($this->isDomain($line)) $domains[mb_strtolower($line)] = true;
        }
        if ($this->mode() === self::MODE_PER_DOMAIN) {
            foreach (array_keys($domains) as $domain) {
                if ($this->keyMetadata($this->permanentKeyDirectory($domain), $domain, false) === null) unset($domains[$domain]);
            }
        }
        return $domains;
    }

    private function writeManagedBlock(string $path, array $panelLines): bool
    {
        $existing = is_file($path) ? file_get_contents($path) : '';
        if (!is_string($existing)) throw new RuntimeException('Cannot read OpenDKIM table: ' . $path);
        $admin = $this->adminContent($existing);
        $panel = implode("\n", array_values(array_unique(array_filter(array_map('trim', $panelLines), static function (string $line): bool { return $line !== ''; }))));
        $content = "# BEGIN SERVER ADMIN\n" . $admin . ($admin === '' ? '' : "\n") . "# END SERVER ADMIN\n\n# BEGIN IMAGOPANEL\n" . $panel . ($panel === '' ? '' : "\n") . "# END IMAGOPANEL\n";
        if ($existing === $content) return false;
        $this->atomicWrite($path, $content, $this->tableFileMode());
        return true;
    }

    private function adminContent(string $content): string
    {
        $this->assertBalancedMarkers($content, '# BEGIN SERVER ADMIN', '# END SERVER ADMIN');
        $this->assertBalancedMarkers($content, '# BEGIN IMAGOPANEL', '# END IMAGOPANEL');
        $withoutPanel = preg_replace('/# BEGIN IMAGOPANEL\R?.*?\R?# END IMAGOPANEL\R?/s', '', $content);
        $admin = is_string($withoutPanel) ? $withoutPanel : $content;
        $admin = preg_replace('/^\s*# BEGIN SERVER ADMIN\R?/m', '', $admin);
        $admin = preg_replace('/^\s*# END SERVER ADMIN\R?/m', '', is_string($admin) ? $admin : '');
        return trim(is_string($admin) ? $admin : '');
    }

    private function panelBlock(string $content): string
    {
        $this->assertBalancedMarkers($content, '# BEGIN IMAGOPANEL', '# END IMAGOPANEL');
        if (strpos($content, '# BEGIN IMAGOPANEL') === false) return '';
        preg_match('/# BEGIN IMAGOPANEL\R?(.*?)\R?# END IMAGOPANEL/s', $content, $match);
        return trim((string) ($match[1] ?? ''));
    }

    private function assertBalancedMarkers(string $content, string $begin, string $end): void
    {
        $begins = substr_count($content, $begin);
        $ends = substr_count($content, $end);
        if ($begins !== $ends || $begins > 1) throw new RuntimeException('Invalid OpenDKIM managed block markers');
    }

    private function reloadOpenDkim(): void
    {
        if ($this->reloadService === null) throw new RuntimeException('OpenDKIM reload callback is not configured');
        ($this->reloadService)();
    }

    private function keyMetadata(string $directory, string $domain, bool $pending): ?array
    {
        if (!is_dir($directory) || is_link($directory)) return null;
        $marker = $directory . DIRECTORY_SEPARATOR . ($pending ? '.imagopanel-pending' : '.imagopanel-managed');
        if (!is_file($marker)) return null;
        $metadata = $this->decodeMetadata($directory . DIRECTORY_SEPARATOR . 'metadata.json');
        if (!is_array($metadata) || !hash_equals($domain, (string) ($metadata['domain'] ?? '')) || trim((string) ($metadata['dns_value'] ?? '')) === '') return null;
        if (!is_file($directory . DIRECTORY_SEPARATOR . $this->selector() . '.private')) return null;
        return $metadata;
    }

    private function decodeMetadata(string $path): ?array
    {
        if (!is_file($path)) return null;
        $content = file_get_contents($path);
        $decoded = is_string($content) ? json_decode($content, true) : null;
        return is_array($decoded) ? $decoded : null;
    }

    private function publicMetadata(array $metadata, bool $temporary): array
    {
        return ['domain' => (string) $metadata['domain'], 'selector' => (string) $metadata['selector'], 'dnsValue' => (string) $metadata['dns_value'], 'temporary' => $temporary, 'createdAt' => (string) ($metadata['created_at'] ?? '')];
    }

    private function removeManagedKeyDirectory(string $domain): void
    {
        $directory = $this->permanentKeyDirectory($domain);
        if (!is_dir($directory) || !is_file($directory . DIRECTORY_SEPARATOR . '.imagopanel-managed')) return;
        $this->removeTree($directory, $this->requiredPath('keys_directory'));
    }

    private function removeTree(string $directory, string $root): void
    {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        $target = rtrim(str_replace('\\', '/', $directory), '/');
        if ($root === '' || $target === '' || strpos($target, $root . '/') !== 0 || $target === $root || is_link($directory)) {
            throw new RuntimeException('Unsafe DKIM directory removal target');
        }
        if (!file_exists($directory)) return;
        $items = scandir($directory);
        if ($items === false) throw new RuntimeException('Cannot read DKIM directory');
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $path = $directory . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path) && !is_link($path)) $this->removeTree($path, $root); else if (!unlink($path)) throw new RuntimeException('Cannot remove DKIM file');
        }
        if (!rmdir($directory)) throw new RuntimeException('Cannot remove DKIM directory');
    }

    private function atomicWrite(string $path, string $content, int $mode): void
    {
        $directory = dirname($path);
        $this->ensureDirectory($directory);
        $temporary = tempnam($directory, '.imagopanel-dkim-');
        if ($temporary === false) throw new RuntimeException('Cannot create temporary OpenDKIM file');
        try {
            if (file_put_contents($temporary, $content, LOCK_EX) === false) throw new RuntimeException('Cannot write OpenDKIM file');
            $this->applyOwnership($temporary, $mode);
            if (PHP_OS_FAMILY === 'Windows' && file_exists($path)) @unlink($path);
            if (!rename($temporary, $path)) throw new RuntimeException('Cannot replace OpenDKIM file');
            $this->applyOwnership($path, $mode);
        } finally {
            if (file_exists($temporary)) @unlink($temporary);
        }
    }

    private function ensureDirectory(string $directory): void
    {
        if (is_dir($directory)) return;
        if (file_exists($directory) || (!mkdir($directory, $this->directoryMode(), true) && !is_dir($directory))) throw new RuntimeException('Cannot create OpenDKIM directory: ' . $directory);
        $this->applyOwnership($directory, $this->directoryMode());
    }

    private function applyOwnership(string $path, int $mode): void
    {
        if (!@chmod($path, $mode)) throw new RuntimeException('Cannot set OpenDKIM permissions: ' . $path);
        $owner = trim((string) ($this->options['owner'] ?? ''));
        $group = trim((string) ($this->options['group'] ?? ''));
        if ($owner !== '' && !@chown($path, ctype_digit($owner) ? (int) $owner : $owner)) throw new RuntimeException('Cannot set OpenDKIM owner: ' . $path);
        if ($group !== '' && !@chgrp($path, ctype_digit($group) ? (int) $group : $group)) throw new RuntimeException('Cannot set OpenDKIM group: ' . $path);
    }

    private function withLock(callable $callback)
    {
        $path = $this->requiredPath('lock_file');
        $this->ensureDirectory(dirname($path));
        $handle = fopen($path, 'c+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Cannot lock OpenDKIM operation');
        }
        try { return $callback(); } finally { flock($handle, LOCK_UN); fclose($handle); }
    }

    private function normalizeDomain(string $domain): string
    {
        $domain = mb_strtolower(trim($domain));
        if (!$this->isDomain($domain)) throw new InvalidArgumentException('Invalid domain');
        return $domain;
    }

    private function isDomain(string $domain): bool
    {
        return strlen($domain) <= 253 && preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $domain) === 1;
    }

    private function selector(): string
    {
        $selector = trim((string) ($this->options['selector'] ?? ''));
        if (preg_match('/^[a-z0-9_-]{1,63}$/iD', $selector) !== 1) throw new RuntimeException('Invalid DKIM selector');
        return $selector;
    }

    private function sharedDnsValue(): string
    {
        $value = trim((string) ($this->options['shared_dns_value'] ?? ''));
        if (preg_match('/^v=DKIM1;\s*k=rsa;\s*p=[A-Za-z0-9+\/=]+$/', $value) !== 1) throw new RuntimeException('Invalid shared DKIM DNS value');
        return $value;
    }

    private function permanentKeyDirectory(string $domain): string
    {
        return rtrim($this->requiredPath('keys_directory'), '/\\') . DIRECTORY_SEPARATOR . $domain;
    }

    private function pendingKeyDirectory(string $domain): string
    {
        return rtrim($this->requiredPath('pending_directory'), '/\\') . DIRECTORY_SEPARATOR . hash('sha256', $domain);
    }

    private function requiredPath(string $key): string
    {
        $path = trim((string) ($this->options[$key] ?? ''));
        if ($path === '' || strpos($path, "\0") !== false) throw new RuntimeException('Invalid OpenDKIM path: ' . $key);
        return $path;
    }

    private function positiveInteger(string $key, int $fallback): int
    {
        $value = (int) ($this->options[$key] ?? $fallback);
        if ($value <= 0) throw new RuntimeException('Invalid OpenDKIM numeric setting: ' . $key);
        return $value;
    }

    private function directoryMode(): int { return (int) ($this->options['directory_mode'] ?? 0750); }
    private function privateKeyMode(): int { return (int) ($this->options['private_key_mode'] ?? 0600); }
    private function tableFileMode(): int { return (int) ($this->options['table_file_mode'] ?? 0640); }

    private function encodeJson(array $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if ($json === false) throw new RuntimeException('Cannot encode DKIM metadata');
        return $json . "\n";
    }
}
