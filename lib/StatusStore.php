<?php
declare(strict_types=1);

final class StatusStore
{
    private string $directory;

    public function __construct(string $directory, bool $createDirectory = true)
    {
        $this->directory = rtrim(str_replace('\\', '/', $directory), '/');
        if ($createDirectory && !is_dir($this->directory) && !mkdir($this->directory, 0755, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Cannot create status directory');
        }
    }

    public function load(string $prefix): ?array
    {
        $path = $this->path($prefix);
        if (!is_file($path)) {
            return null;
        }
        $decoded = json_decode((string) file_get_contents($path), true);
        return is_array($decoded) ? $decoded : null;
    }

    public function write(string $prefix, array $status): void
    {
        if (!is_dir($this->directory)) {
            throw new RuntimeException('Status directory does not exist');
        }
        $path = $this->path($prefix);
        $json = json_encode($status, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (!is_string($json)) {
            throw new RuntimeException('Cannot encode status JSON');
        }
        $temporary = tempnam($this->directory, $prefix . '.tmp.');
        if ($temporary === false) {
            throw new RuntimeException('Cannot create temporary status file');
        }
        try {
            if (file_put_contents($temporary, $json . PHP_EOL, LOCK_EX) === false) {
                throw new RuntimeException('Cannot write temporary status file');
            }
            @chmod($temporary, 0644);
            if (!rename($temporary, $path)) {
                throw new RuntimeException('Cannot replace status file');
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    public function mergeDocuments(array $documents): array
    {
        return array_map(function (array $document): array {
            return $this->mergeDocument($document);
        }, $documents);
    }

    public function mergeDocument(array $document): array
    {
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        $status = $this->load($prefix);
        if ($status === null) {
            return $document;
        }

        $allowed = [
            'domains' => ['folderBytes', 'folderExists', 'folderPrimary', 'primaryDomain', 'bound', 'wwwBound', 'sslValid', 'dkim', 'spf', 'dmarc', 'checkedAt'],
            'databases' => ['bytes', 'tables', 'exists', 'checkedAt'],
            'mail' => ['bytes', 'exists', 'dkim', 'spf', 'dmarc', 'checkedAt'],
        ];
        foreach ($allowed as $type => $fields) {
            $statusRows = is_array($status['resources'][$type] ?? null) ? $status['resources'][$type] : [];
            $byId = [];
            foreach ($statusRows as $statusRow) {
                if (is_array($statusRow) && isset($statusRow['id'])) {
                    $byId[(int) $statusRow['id']] = $statusRow;
                }
            }
            foreach ($document['resources'][$type] ?? [] as $index => $row) {
                $statusRow = $byId[(int) ($row['id'] ?? 0)] ?? null;
                if (!is_array($statusRow)) {
                    continue;
                }
                foreach ($fields as $field) {
                    if (array_key_exists($field, $statusRow) && $statusRow[$field] !== null) {
                        $document['resources'][$type][$index][$field] = $statusRow[$field];
                    }
                }
            }
        }
        $document['profile']['statusCollectedAt'] = (string) ($status['collectedAt'] ?? '');
        $document['profile']['statusDurationMs'] = (int) ($status['durationMs'] ?? 0);
        $document['profile']['statusOk'] = !empty($status['ok']);
        $document['profile']['statusErrors'] = count(is_array($status['errors'] ?? null) ? $status['errors'] : []);
        return $document;
    }

    private function path(string $prefix): string
    {
        if (preg_match('/^[a-z][a-z0-9_]{1,31}$/', $prefix) !== 1) {
            throw new InvalidArgumentException('Invalid status prefix');
        }
        return $this->directory . '/' . $prefix . '.json';
    }
}
