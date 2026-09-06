<?php
declare(strict_types=1);

final class MailMigrationRuntime
{
    public static function validateSource(array $params): array
    {
        $host = mb_strtolower(trim((string) ($params['source_host'] ?? '')));
        $port = (int) ($params['source_port'] ?? 0);
        $security = mb_strtolower(trim((string) ($params['source_security'] ?? 'ssl')));
        $login = trim((string) ($params['source_login'] ?? ''));
        $password = (string) ($params['source_password'] ?? '');

        $hostValid = filter_var($host, FILTER_VALIDATE_IP) !== false
            || preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/D', $host) === 1;
        if (!$hostValid || strpos($host, '..') !== false) throw new InvalidArgumentException('Invalid old IMAP server');
        if (!in_array($port, array_map('intval', MAIL_MIGRATION_ALLOWED_PORTS), true)) throw new InvalidArgumentException('This IMAP port is not allowed');
        if (!in_array($security, ['ssl', 'starttls', 'none'], true)) throw new InvalidArgumentException('Invalid IMAP security mode');
        if ($login === '' || $login[0] === '-' || strlen($login) > 254 || preg_match('/[\x00-\x1f\x7f]/', $login) === 1) throw new InvalidArgumentException('Invalid old IMAP login');
        if ($password === '' || strlen($password) > 4096 || preg_match('/[\x00\r\n]/', $password) === 1) throw new InvalidArgumentException('Invalid old IMAP password');
        self::assertSourceAddressAllowed($host);
        return [
            'source_host' => $host,
            'source_port' => $port,
            'source_security' => $security,
            'source_login' => $login,
            'source_password' => $password,
        ];
    }

    public static function assertDependencies(): void
    {
        if (!MAIL_MIGRATION_ENABLED) throw new RuntimeException('Old mail import is disabled');
        if (MAIL_MIGRATION_IMAPSYNC_BINARY === '' || !is_file(MAIL_MIGRATION_IMAPSYNC_BINARY) || !is_executable(MAIL_MIGRATION_IMAPSYNC_BINARY)) {
            throw new RuntimeException('imapsync is not installed or MAIL_MIGRATION_IMAPSYNC_BINARY is incorrect');
        }
    }

    public static function assertBackgroundDependencies(): void
    {
        self::assertDependencies();
        foreach ([MAIL_MIGRATION_PHP_BINARY, MAIL_MIGRATION_SYSTEMD_RUN_BINARY] as $binary) {
            if ($binary === '' || !is_file($binary) || !is_executable($binary)) {
                throw new RuntimeException('Background mail migration dependency is not available: ' . basename((string) $binary));
            }
        }
    }

    public static function ensureDirectories(): void
    {
        $directories = [
            MAIL_MIGRATION_RUNTIME_DIRECTORY => [0750, USER_WEB_GROUP],
            MAIL_MIGRATION_JOB_DIRECTORY => [0750, USER_WEB_GROUP],
            MAIL_MIGRATION_CREDENTIAL_DIRECTORY => [0700, null],
            MAIL_MIGRATION_TEMP_DIRECTORY => [0700, null],
            MAIL_MIGRATION_LOG_DIRECTORY => [0750, USER_WEB_GROUP],
            MAIL_MIGRATION_REPORT_DIRECTORY => [0750, USER_WEB_GROUP],
        ];
        foreach ($directories as $directory => $settings) {
            if ($directory === '' || $directory[0] !== '/' || is_link($directory)) throw new RuntimeException('Unsafe mail migration directory');
            if (!is_dir($directory) && !mkdir($directory, $settings[0], true) && !is_dir($directory)) {
                throw new RuntimeException('Cannot create mail migration directory');
            }
            @chmod($directory, $settings[0]);
            if ($settings[1] !== null) @chgrp($directory, $settings[1]);
        }
    }

    public static function credentialPaths(string $id): array
    {
        self::requireId($id);
        $base = rtrim(MAIL_MIGRATION_CREDENTIAL_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $id;
        return [$base . '.source.pass', $base . '.destination.pass'];
    }

    public static function writeCredentials(string $id, string $sourcePassword, string $destinationPassword): array
    {
        self::ensureDirectories();
        [$source, $destination] = self::credentialPaths($id);
        self::writeSecret($source, $sourcePassword);
        try {
            self::writeSecret($destination, $destinationPassword);
        } catch (Throwable $exception) {
            @unlink($source);
            throw $exception;
        }
        return [$source, $destination];
    }

    public static function removeCredentials(string $id): void
    {
        foreach (self::credentialPaths($id) as $file) {
            if (is_file($file) && !is_link($file)) @unlink($file);
        }
    }

    public static function removeTemporaryDirectory(string $id): void
    {
        self::requireId($id);
        $base = rtrim(MAIL_MIGRATION_TEMP_DIRECTORY, '/\\');
        $directory = $base . DIRECTORY_SEPARATOR . $id;
        if (!is_dir($directory) || is_link($directory)) return;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $entry) {
            if ($entry->isLink()) {
                @unlink($entry->getPathname());
            } elseif ($entry->isDir()) {
                @rmdir($entry->getPathname());
            } else {
                @unlink($entry->getPathname());
            }
        }
        @rmdir($directory);
    }

    public static function command(array $job, string $sourcePassFile, string $destinationPassFile, bool $analyze): array
    {
        self::requireId((string) $job['id']);
        $jobTemp = rtrim(MAIL_MIGRATION_TEMP_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . (string) $job['id'];
        if (!is_dir($jobTemp) && !mkdir($jobTemp, 0700, true) && !is_dir($jobTemp)) throw new RuntimeException('Cannot create imapsync temporary directory');
        @chmod($jobTemp, 0700);
        $command = [
            MAIL_MIGRATION_IMAPSYNC_BINARY,
            '--host1', (string) $job['source_host'],
            '--port1', (string) $job['source_port'],
            '--user1', (string) $job['source_login'],
            '--passfile1', $sourcePassFile,
            '--host2', MAIL_CLIENT_IMAP_HOST,
            '--port2', (string) MAIL_CLIENT_IMAP_PORT,
            '--user2', (string) $job['destination_email'],
            '--passfile2', $destinationPassFile,
            '--tmpdir', $jobTemp,
            '--pidfile', $jobTemp . DIRECTORY_SEPARATOR . 'imapsync.pid',
            '--pidfilelocking',
            '--nolog',
            '--noemailreport1',
            '--noemailreport2',
            '--syncinternaldates',
        ];
        self::appendSecurity($command, '1', (string) $job['source_security']);
        self::appendSecurity($command, '2', MAIL_CLIENT_IMAP_PORT === 993 ? 'ssl' : 'starttls');
        if ($analyze) $command[] = '--justfoldersizes';
        return $command;
    }

    public static function logPath(string $id): string
    {
        self::requireId($id);
        return rtrim(MAIL_MIGRATION_LOG_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $id . '.log';
    }

    public static function reportPath(string $id): string
    {
        self::requireId($id);
        return rtrim(MAIL_MIGRATION_REPORT_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $id . '.json';
    }

    public static function readLog(string $id): string
    {
        $file = self::logPath($id);
        if (!is_file($file) || is_link($file) || !is_readable($file)) return '';
        $size = filesize($file);
        if ($size === false) return '';
        $maximum = max(65536, (int) MAIL_MIGRATION_MAX_LOG_BYTES);
        $handle = fopen($file, 'rb');
        if ($handle === false) return '';
        if ($size > $maximum) fseek($handle, $size - $maximum);
        $content = stream_get_contents($handle, $maximum);
        fclose($handle);
        return is_string($content) ? $content : '';
    }

    public static function friendlyError(string $output): string
    {
        $text = mb_strtolower($output);
        if (strpos($text, 'authentication failed') !== false || strpos($text, 'login failed') !== false || strpos($text, 'no login') !== false) return 'Authentication failed';
        if (strpos($text, 'ssl') !== false && (strpos($text, 'error') !== false || strpos($text, 'failed') !== false)) return 'TLS error';
        if (strpos($text, 'timed out') !== false || strpos($text, 'timeout') !== false) return 'Connection timeout';
        if (strpos($text, 'name or service not known') !== false || strpos($text, 'cannot connect') !== false || strpos($text, 'connection refused') !== false) return 'Cannot connect to IMAP server';
        return 'IMAP migration failed';
    }

    private static function appendSecurity(array &$command, string $side, string $security): void
    {
        if ($security === 'ssl') {
            $command[] = '--ssl' . $side;
            $command[] = '--notls' . $side;
        } elseif ($security === 'starttls') {
            $command[] = '--nossl' . $side;
            $command[] = '--tls' . $side;
        } else {
            $command[] = '--nossl' . $side;
            $command[] = '--notls' . $side;
        }
    }

    private static function assertSourceAddressAllowed(string $host): void
    {
        if (MAIL_MIGRATION_ALLOW_PRIVATE_SOURCE_HOSTS) return;
        $addresses = [];
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $addresses[] = $host;
        } else {
            foreach (gethostbynamel($host) ?: [] as $address) $addresses[] = $address;
            if (function_exists('dns_get_record')) {
                foreach (dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                    if (!empty($record['ipv6'])) $addresses[] = (string) $record['ipv6'];
                }
            }
        }
        if ($addresses === []) throw new InvalidArgumentException('Old IMAP server cannot be resolved');
        foreach (array_unique($addresses) as $address) {
            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                throw new InvalidArgumentException('Private or reserved old IMAP server addresses are not allowed');
            }
        }
    }

    private static function writeSecret(string $file, string $secret): void
    {
        if (is_link($file) || file_exists($file)) throw new RuntimeException('Temporary credential file already exists');
        $previous = umask(0077);
        $handle = fopen($file, 'xb');
        umask($previous);
        if ($handle === false) throw new RuntimeException('Cannot create temporary credential file');
        $written = fwrite($handle, $secret . PHP_EOL);
        fflush($handle);
        fclose($handle);
        @chmod($file, 0600);
        if ($written !== strlen($secret) + 1) {
            @unlink($file);
            throw new RuntimeException('Cannot write temporary credential file');
        }
    }

    private static function requireId(string $id): void
    {
        if (preg_match('/^[a-f0-9]{32}$/D', $id) !== 1) throw new InvalidArgumentException('Invalid migration ID');
    }
}
