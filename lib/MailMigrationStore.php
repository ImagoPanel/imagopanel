<?php
declare(strict_types=1);

final class MailMigrationStore
{
    private $directory;

    public function __construct(string $directory)
    {
        $directory = rtrim(str_replace('\\', '/', trim($directory)), '/');
        if ($directory === '' || preg_match('/[\x00\r\n]/', $directory) === 1) {
            throw new InvalidArgumentException('Invalid mail migration job directory');
        }
        $this->directory = $directory;
    }

    public static function configured(): self
    {
        return new self(MAIL_MIGRATION_JOB_DIRECTORY);
    }

    public function assertInstalled(): void
    {
        if (is_link($this->directory)) throw new RuntimeException('Mail migration job directory cannot be a symlink');
        if (!is_dir($this->directory) && !mkdir($this->directory, 0750, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Cannot create mail migration job directory');
        }
        @chmod($this->directory, 0750);
        @chgrp($this->directory, USER_WEB_GROUP);
    }

    public function create(array $job): array
    {
        $this->assertInstalled();
        $id = (string) ($job['id'] ?? '');
        $file = $this->jobFile($id);
        if (file_exists($file) || is_link($file)) throw new RuntimeException('Mail migration job already exists');
        $now = gmdate('Y-m-d H:i:s');
        $defaults = [
            'id' => $id,
            'user_prefix' => '',
            'mailbox_id' => 0,
            'destination_email' => '',
            'source_host' => '',
            'source_port' => 0,
            'source_security' => '',
            'source_login' => '',
            'status' => 'pending',
            'folders_total' => 0,
            'folders_done' => 0,
            'messages_total' => 0,
            'messages_done' => 0,
            'bytes_total' => 0,
            'bytes_done' => 0,
            'current_folder' => '',
            'skipped_count' => 0,
            'errors_count' => 0,
            'error_message' => '',
            'pid' => null,
            'log_file' => '',
            'report_file' => '',
            'started_at' => null,
            'finished_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
        ];
        $row = $defaults;
        foreach ($job as $key => $value) {
            if (array_key_exists($key, $defaults)) $row[$key] = $value;
        }
        $row['id'] = $id;
        $row['created_at'] = $now;
        $row['updated_at'] = $now;
        $this->writeNew($file, $row);
        return $this->normalize($row);
    }

    public function get(string $id): array
    {
        if (is_link($this->directory)) throw new RuntimeException('Mail migration job directory cannot be a symlink');
        return $this->normalize($this->readFile($this->jobFile($id)));
    }

    public function history(string $prefix, int $mailboxId, int $limit = 10): array
    {
        $limit = max(1, min(25, $limit));
        $rows = array_values(array_filter($this->allRows(), static function (array $row) use ($prefix, $mailboxId): bool {
            return (string) ($row['user_prefix'] ?? '') === $prefix && (int) ($row['mailbox_id'] ?? 0) === $mailboxId;
        }));
        usort($rows, static function (array $left, array $right): int {
            return strcmp((string) ($right['created_at'] ?? ''), (string) ($left['created_at'] ?? ''));
        });
        return array_slice($rows, 0, $limit);
    }

    public function hasActive(string $prefix, int $mailboxId): bool
    {
        foreach ($this->allRows() as $row) {
            if ((string) ($row['user_prefix'] ?? '') === $prefix
                && (int) ($row['mailbox_id'] ?? 0) === $mailboxId
                && in_array((string) ($row['status'] ?? ''), ['pending', 'checking', 'ready', 'running'], true)) return true;
        }
        return false;
    }

    public function staleActive(int $seconds): array
    {
        $cutoff = gmdate('Y-m-d H:i:s', time() - max(300, $seconds));
        $rows = array_values(array_filter($this->allRows(), static function (array $row) use ($cutoff): bool {
            return in_array((string) ($row['status'] ?? ''), ['pending', 'checking', 'ready', 'running'], true)
                && (string) ($row['updated_at'] ?? '') < $cutoff;
        }));
        usort($rows, static function (array $left, array $right): int {
            return strcmp((string) ($left['updated_at'] ?? ''), (string) ($right['updated_at'] ?? ''));
        });
        return $rows;
    }

    public function update(string $id, array $changes): array
    {
        $allowed = [
            'status', 'folders_total', 'folders_done', 'messages_total', 'messages_done',
            'bytes_total', 'bytes_done', 'current_folder', 'skipped_count', 'errors_count',
            'error_message', 'pid', 'started_at', 'finished_at',
        ];
        $file = $this->jobFile($id);
        if (!is_file($file) || is_link($file)) throw new RuntimeException('Mail migration not found');
        $handle = fopen($file, 'r+b');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Cannot lock mail migration job');
        }
        try {
            $content = stream_get_contents($handle);
            $row = json_decode(is_string($content) ? $content : '', true);
            if (!is_array($row)) throw new RuntimeException('Invalid mail migration job JSON');
            foreach ($changes as $key => $value) {
                if (in_array($key, $allowed, true)) $row[$key] = $value;
            }
            $row['updated_at'] = gmdate('Y-m-d H:i:s');
            $encoded = $this->encode($row);
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                throw new RuntimeException('Cannot update mail migration job');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        @chmod($file, 0640);
        @chgrp($file, USER_WEB_GROUP);
        return $this->normalize($row);
    }

    public function publicRow(array $row): array
    {
        unset($row['log_file'], $row['report_file']);
        return $row;
    }

    private function allRows(): array
    {
        if (is_link($this->directory)) throw new RuntimeException('Mail migration job directory cannot be a symlink');
        if (!is_dir($this->directory)) return [];
        $rows = [];
        foreach (glob($this->directory . '/*.json') ?: [] as $file) {
            if (!is_file($file) || is_link($file)) continue;
            try {
                $rows[] = $this->normalize($this->readFile($file));
            } catch (Throwable $ignored) {
            }
        }
        return $rows;
    }

    private function readFile(string $file): array
    {
        if (!is_file($file) || is_link($file)) throw new RuntimeException('Mail migration not found');
        $handle = fopen($file, 'rb');
        if ($handle === false || !flock($handle, LOCK_SH)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Cannot read mail migration job');
        }
        try {
            $content = stream_get_contents($handle, 1048577);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        if (!is_string($content) || strlen($content) > 1048576) throw new RuntimeException('Mail migration job is too large');
        $row = json_decode($content, true);
        if (!is_array($row)) throw new RuntimeException('Invalid mail migration job JSON');
        return $row;
    }

    private function writeNew(string $file, array $row): void
    {
        $encoded = $this->encode($row);
        $previous = umask(0027);
        $handle = fopen($file, 'x+b');
        umask($previous);
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Cannot create mail migration job');
        }
        try {
            if (fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) throw new RuntimeException('Cannot write mail migration job');
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        @chmod($file, 0640);
        @chgrp($file, USER_WEB_GROUP);
    }

    private function encode(array $row): string
    {
        $encoded = json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if ($encoded === false) throw new RuntimeException('Cannot encode mail migration job');
        return $encoded . PHP_EOL;
    }

    private function jobFile(string $id): string
    {
        if (preg_match('/^[a-f0-9]{32}$/D', $id) !== 1) throw new InvalidArgumentException('Invalid migration ID');
        return $this->directory . '/' . $id . '.json';
    }

    private function normalize(array $row): array
    {
        foreach (['mailbox_id', 'source_port', 'folders_total', 'folders_done', 'messages_total', 'messages_done', 'skipped_count', 'errors_count', 'pid'] as $key) {
            $row[$key] = isset($row[$key]) ? (int) $row[$key] : 0;
        }
        foreach (['bytes_total', 'bytes_done'] as $key) $row[$key] = isset($row[$key]) ? (float) $row[$key] : 0.0;
        return $row;
    }
}

function mailMigrationProgressFromLog(array $job, string $content): array
{
    $progress = $job;
    $number = static function (string $value): float {
        return (float) preg_replace('/[^0-9]/', '', $value);
    };
    $lastMatch = static function (string $pattern, string $subject) {
        if (preg_match_all($pattern, $subject, $matches, PREG_SET_ORDER) < 1) return null;
        return $matches[count($matches) - 1];
    };
    $match = $lastMatch('/Host1 Nb folders\s*:\s*([0-9,._ ]+)/i', $content);
    if ($match) $progress['folders_total'] = (int) $number($match[1]);
    $match = $lastMatch('/Host1 Nb messages\s*:\s*([0-9,._ ]+)/i', $content);
    if ($match) $progress['messages_total'] = (int) $number($match[1]);
    $match = $lastMatch('/Host1 Total size\s*:\s*([0-9,._ ]+)\s+bytes/i', $content);
    if ($match) $progress['bytes_total'] = $number($match[1]);
    $match = $lastMatch('/Messages transferred\s*:\s*([0-9,._ ]+)/i', $content);
    if ($match) $progress['messages_done'] = (int) $number($match[1]);
    $match = $lastMatch('/Total bytes transferred\s*:\s*([0-9,._ ]+)/i', $content);
    if ($match) $progress['bytes_done'] = $number($match[1]);
    $match = $lastMatch('/Messages skipped\s*:\s*([0-9,._ ]+)/i', $content);
    if ($match) $progress['skipped_count'] = (int) $number($match[1]);
    $match = $lastMatch('/Errors\s*:\s*([0-9,._ ]+)/i', $content);
    if ($match) $progress['errors_count'] = (int) $number($match[1]);
    $match = $lastMatch('/Folder\s+([0-9]+)\/([0-9]+)\s+\[(.*?)\]/i', $content);
    if ($match) {
        $progress['folders_done'] = max(0, (int) $match[1] - 1);
        $progress['folders_total'] = max((int) ($progress['folders_total'] ?? 0), (int) $match[2]);
        $progress['current_folder'] = trim((string) $match[3]);
    }
    if (($progress['status'] ?? '') === 'running' && (int) ($progress['messages_done'] ?? 0) === 0) {
        $copied = preg_match_all('/^\s*msg\s+.*?\bcopied to\b.*$/mi', $content);
        if (is_int($copied) && $copied > 0) $progress['messages_done'] = $copied;
    }
    $total = (float) ($progress['bytes_total'] ?? 0);
    $done = (float) ($progress['bytes_done'] ?? 0);
    if ($total <= 0 || $done <= 0) {
        $total = (int) ($progress['messages_total'] ?? 0);
        $done = (int) ($progress['messages_done'] ?? 0);
    }
    $progress['percent'] = $total > 0 ? min(100, max(0, round($done * 100 / $total, 1))) : 0;
    return $progress;
}
