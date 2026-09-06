<?php
declare(strict_types=1);

final class RootAuditLog
{
    private $directory;
    private $retentionDays;
    private $maximumEntryBytes;

    public function __construct(string $directory, int $retentionDays, int $maximumEntryBytes)
    {
        $this->directory = rtrim($directory, '/\\');
        $this->retentionDays = max(1, $retentionDays);
        $this->maximumEntryBytes = max(65536, $maximumEntryBytes);
    }

    public function start(string $action, array $params, array $meta): array
    {
        $this->deleteExpiredFiles();
        $now = $this->now();
        $requestId = bin2hex(random_bytes(16));
        $prefix = mb_strtolower(trim((string) ($meta['user_prefix'] ?? $params['prefix'] ?? '')));
        $email = mb_strtolower(trim((string) ($meta['user_email'] ?? $params['email'] ?? '')));
        $clientIp = trim((string) ($meta['client_ip'] ?? ''));
        if (filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
            $clientIp = '';
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $email = $this->emailForPrefix($prefix);
        }

        $context = [
            'requestId' => $requestId,
            'filePath' => $this->filePath($now),
            'startedAt' => microtime(true),
            'timestamp' => $now->format(DATE_ATOM),
            'timestampMs' => (int) floor(microtime(true) * 1000),
            'user' => ['email' => $email, 'prefix' => $prefix],
            'ip' => $clientIp,
            'action' => $action,
            'environment' => WIN ? 'WIN' : (TASK ? 'TASK' : 'PROD'),
        ];

        $this->append($context['filePath'], [
            'schemaVersion' => 1,
            'event' => 'started',
            'requestId' => $requestId,
            'timestamp' => $context['timestamp'],
            'timestampMs' => $context['timestampMs'],
            'user' => $context['user'],
            'status' => 'nofinished',
            'ip' => $clientIp,
            'action' => $action,
            'durationMs' => null,
            'request' => $this->redact(['action' => $action, 'params' => $params]),
            'response' => null,
            'error' => null,
            'environment' => $context['environment'],
        ]);

        return $context;
    }

    public function finish(array $context, array $response, ?array $error): void
    {
        $now = $this->now();
        $ok = !empty($response['ok']);
        $this->append((string) $context['filePath'], [
            'schemaVersion' => 1,
            'event' => 'finished',
            'requestId' => (string) $context['requestId'],
            'timestamp' => $now->format(DATE_ATOM),
            'timestampMs' => (int) floor(microtime(true) * 1000),
            'user' => $context['user'] ?? ['email' => '', 'prefix' => ''],
            'status' => $ok ? 'success' : 'error',
            'ip' => (string) ($context['ip'] ?? ''),
            'action' => (string) ($context['action'] ?? ''),
            'durationMs' => round(max(0, microtime(true) - (float) ($context['startedAt'] ?? microtime(true))) * 1000, 3),
            'request' => null,
            'response' => $this->redact($response),
            'error' => $this->redact($error),
            'environment' => (string) ($context['environment'] ?? ''),
        ]);
    }

    public function rows(int $days): array
    {
        $records = $this->readRecords(max(1, min($this->retentionDays, $days)));
        $rows = [];
        foreach ($records as $record) {
            $user = is_array($record['user'] ?? null) ? $record['user'] : [];
            $email = (string) ($user['email'] ?? '');
            $prefix = (string) ($user['prefix'] ?? '');
            $error = is_array($record['error'] ?? null) ? $record['error'] : [];
            $response = is_array($record['response'] ?? null) ? $record['response'] : [];
            $rows[] = [
                'requestId' => (string) ($record['requestId'] ?? ''),
                'timestamp' => (string) ($record['startedTimestamp'] ?? $record['timestamp'] ?? ''),
                'timestampMs' => (int) ($record['startedTimestampMs'] ?? $record['timestampMs'] ?? 0),
                'user' => trim($email . ($email !== '' && $prefix !== '' ? ' / ' : '') . $prefix),
                'email' => $email,
                'prefix' => $prefix,
                'status' => (string) ($record['status'] ?? 'nofinished'),
                'ip' => (string) ($record['ip'] ?? ''),
                'operation' => (string) ($record['action'] ?? ''),
                'durationMs' => isset($record['durationMs']) ? (float) $record['durationMs'] : null,
                'errorMessage' => (string) ($error['message'] ?? $response['error'] ?? ''),
            ];
        }
        return $rows;
    }

    public function find(string $requestId): ?array
    {
        if (preg_match('/^[a-f0-9]{32}$/D', $requestId) !== 1) {
            return null;
        }
        $records = $this->readRecords($this->retentionDays);
        return isset($records[$requestId]) ? $records[$requestId] : null;
    }

    private function readRecords(int $days): array
    {
        $records = [];
        foreach ($this->filesForDays($days) as $file) {
            $handle = @fopen($file, 'rb');
            if ($handle === false || !flock($handle, LOCK_SH)) {
                if (is_resource($handle)) {
                    fclose($handle);
                }
                continue;
            }
            while (($line = fgets($handle, $this->maximumEntryBytes + 2)) !== false) {
                if (strlen($line) > $this->maximumEntryBytes) {
                    continue;
                }
                $event = json_decode(trim($line), true);
                if (!is_array($event)) {
                    continue;
                }
                $requestId = (string) ($event['requestId'] ?? '');
                if (preg_match('/^[a-f0-9]{32}$/D', $requestId) !== 1) {
                    continue;
                }
                if (!isset($records[$requestId])) {
                    $records[$requestId] = [
                        'requestId' => $requestId,
                        'status' => 'nofinished',
                        'request' => null,
                        'response' => null,
                        'error' => null,
                        'events' => [],
                    ];
                }
                $records[$requestId]['events'][] = $event;
                if (($event['event'] ?? '') === 'started') {
                    $records[$requestId]['startedTimestamp'] = (string) ($event['timestamp'] ?? '');
                    $records[$requestId]['startedTimestampMs'] = (int) ($event['timestampMs'] ?? 0);
                    $records[$requestId]['user'] = $event['user'] ?? [];
                    $records[$requestId]['ip'] = (string) ($event['ip'] ?? '');
                    $records[$requestId]['action'] = (string) ($event['action'] ?? '');
                    $records[$requestId]['request'] = $event['request'] ?? null;
                    $records[$requestId]['environment'] = (string) ($event['environment'] ?? '');
                } elseif (($event['event'] ?? '') === 'finished') {
                    $records[$requestId]['finishedTimestamp'] = (string) ($event['timestamp'] ?? '');
                    $records[$requestId]['finishedTimestampMs'] = (int) ($event['timestampMs'] ?? 0);
                    if (!isset($records[$requestId]['startedTimestamp'])) {
                        $records[$requestId]['startedTimestamp'] = (string) ($event['timestamp'] ?? '');
                        $records[$requestId]['startedTimestampMs'] = (int) ($event['timestampMs'] ?? 0);
                        $records[$requestId]['user'] = $event['user'] ?? [];
                        $records[$requestId]['ip'] = (string) ($event['ip'] ?? '');
                        $records[$requestId]['action'] = (string) ($event['action'] ?? '');
                        $records[$requestId]['environment'] = (string) ($event['environment'] ?? '');
                    }
                    $records[$requestId]['status'] = (string) ($event['status'] ?? 'error');
                    $records[$requestId]['durationMs'] = isset($event['durationMs']) ? (float) $event['durationMs'] : null;
                    $records[$requestId]['response'] = $event['response'] ?? null;
                    $records[$requestId]['error'] = $event['error'] ?? null;
                }
            }
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        return $records;
    }

    private function filesForDays(int $days): array
    {
        $files = [];
        $date = $this->now()->setTime(0, 0, 0);
        for ($offset = 0; $offset < $days; $offset++) {
            $candidate = $this->filePath($date->modify('-' . $offset . ' days'));
            if (is_file($candidate) && is_readable($candidate) && !is_link($candidate)) {
                $files[] = $candidate;
            }
        }
        return $files;
    }

    private function filePath(DateTimeImmutable $date): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . $date->format('Y')
            . DIRECTORY_SEPARATOR . $date->format('m') . DIRECTORY_SEPARATOR . $date->format('d') . '.jsonl';
    }

    private function append(string $file, array $event): void
    {
        $directory = dirname($file);
        $this->ensureDirectory($directory);
        if (is_link($file)) {
            throw new RuntimeException('Root log file cannot be a symlink');
        }
        $encoded = json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($encoded === false || strlen($encoded) > $this->maximumEntryBytes) {
            throw new RuntimeException('Root log entry is too large');
        }
        $handle = @fopen($file, 'ab');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            throw new RuntimeException('Cannot lock root log file');
        }
        $line = $encoded . PHP_EOL;
        $written = fwrite($handle, $line);
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        if ($written !== strlen($line)) {
            throw new RuntimeException('Cannot write root log entry');
        }
        @chmod($file, 0640);
        if (!WIN) {
            @chgrp($file, USER_WEB_GROUP);
        }
    }

    private function ensureDirectory(string $directory): void
    {
        if (is_link($directory)) {
            throw new RuntimeException('Root log directory cannot be a symlink');
        }
        if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
            throw new RuntimeException('Cannot create root log directory');
        }
        $managedDirectories = [];
        $current = $directory;
        while ($current !== '' && strpos(str_replace('\\', '/', $current), str_replace('\\', '/', $this->directory)) === 0) {
            $managedDirectories[] = $current;
            if (rtrim($current, '/\\') === rtrim($this->directory, '/\\')) {
                break;
            }
            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }
            $current = $parent;
        }
        foreach (array_reverse($managedDirectories) as $managedDirectory) {
            if (is_link($managedDirectory)) {
                throw new RuntimeException('Root log directory cannot be a symlink');
            }
            @chmod($managedDirectory, 0750);
            if (!WIN) {
                @chgrp($managedDirectory, USER_WEB_GROUP);
            }
        }
    }

    private function deleteExpiredFiles(): void
    {
        if (!is_dir($this->directory)) {
            return;
        }
        $cutoff = $this->now()->setTime(0, 0, 0)->modify('-' . ($this->retentionDays - 1) . ' days')->getTimestamp();
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $entry) {
            if ($entry->isLink()) {
                continue;
            }
            if ($entry->isFile() && strtolower($entry->getExtension()) === 'jsonl') {
                $normalizedPath = str_replace('\\', '/', $entry->getPathname());
                if (preg_match('~/([0-9]{4})/([0-9]{2})/([0-9]{2})\.jsonl$~D', $normalizedPath, $match) === 1) {
                    $fileDate = DateTimeImmutable::createFromFormat('!Y-m-d', $match[1] . '-' . $match[2] . '-' . $match[3], new DateTimeZone(PANEL_TIMEZONE));
                    if ($fileDate instanceof DateTimeImmutable && $fileDate->getTimestamp() < $cutoff) {
                        @unlink($entry->getPathname());
                    }
                }
            } elseif ($entry->isDir()) {
                $contents = @scandir($entry->getPathname());
                if (is_array($contents) && count($contents) === 2) {
                    @rmdir($entry->getPathname());
                }
            }
        }
    }

    private function emailForPrefix(string $prefix): string
    {
        if ($prefix === '' || preg_match('/^[a-z][a-z0-9_]{1,31}$/D', $prefix) !== 1) {
            return '';
        }
        $path = rtrim(DATA_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . $prefix . '.json';
        $json = is_file($path) && is_readable($path) ? file_get_contents($path) : false;
        $document = $json === false ? null : json_decode($json, true);
        $email = is_array($document) ? mb_strtolower(trim((string) ($document['profile']['email'] ?? ''))) : '';
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : '';
    }

    private function redact($value, ?string $key = null)
    {
        if ($key !== null && preg_match('/password|passwd|secret|token|authorization|cookie|private.?key/i', $key) === 1) {
            return '[REDACTED]';
        }
        if (!is_array($value)) {
            return $value;
        }
        $result = [];
        foreach ($value as $childKey => $childValue) {
            $result[$childKey] = $this->redact($childValue, is_string($childKey) ? $childKey : null);
        }
        return $result;
    }

    private function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone(PANEL_TIMEZONE));
    }
}
