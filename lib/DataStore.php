<?php
declare(strict_types=1);

final class DataStore
{
    private string $directory;
    private string $lockDirectory;

    public function __construct(string $directory)
    {
        $this->directory = rtrim($directory, '/\\');
        $this->lockDirectory = $this->directory . DIRECTORY_SEPARATOR . '.locks';

        if (!is_dir($this->directory) && !mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Cannot create data directory');
        }
        if (!is_dir($this->lockDirectory) && !mkdir($this->lockDirectory, 0700, true) && !is_dir($this->lockDirectory)) {
            throw new RuntimeException('Cannot create lock directory');
        }
    }

    public function listDocuments(): array
    {
        $documents = [];
        $paths = glob($this->directory . DIRECTORY_SEPARATOR . '*.json') ?: [];
        sort($paths, SORT_STRING);

        foreach ($paths as $path) {
            $prefix = basename($path, '.json');
            if (!$this->validPrefix($prefix)) {
                continue;
            }
            $document = $this->load($prefix);
            if ($document !== null) {
                $documents[] = $document;
            }
        }

        return $documents;
    }

    public function load(string $prefix): ?array
    {
        $path = $this->path($prefix);
        if (!is_file($path)) {
            return null;
        }

        $json = file_get_contents($path);
        if ($json === false) {
            throw new RuntimeException('Cannot read user data');
        }

        $document = json_decode($json, true);
        if (!is_array($document) || !isset($document['profile'], $document['resources'])) {
            throw new RuntimeException('Invalid user data: ' . $prefix);
        }

        return $document;
    }

    public function findByEmail(string $email): ?array
    {
        $needle = mb_strtolower(trim($email));
        foreach ($this->listDocuments() as $document) {
            $stored = mb_strtolower((string) ($document['profile']['email'] ?? ''));
            if ($stored !== '' && hash_equals($stored, $needle)) {
                return $document;
            }
        }
        return null;
    }

    public function findByUserId(int $userId): ?array
    {
        foreach ($this->listDocuments() as $document) {
            if ((int) ($document['profile']['id'] ?? 0) === $userId) {
                return $document;
            }
        }
        return null;
    }

    public function nextUserId(): int
    {
        $maximum = 0;
        foreach ($this->listDocuments() as $document) {
            $maximum = max($maximum, (int) ($document['profile']['id'] ?? 0));
        }
        return $maximum + 1;
    }

    public function create(string $prefix, array $document): void
    {
        if (is_file($this->path($prefix))) {
            throw new RuntimeException('Такой префикс используется');
        }
        $this->withLock($prefix, function () use ($prefix, $document): void {
            if (is_file($this->path($prefix))) {
                throw new RuntimeException('Такой префикс используется');
            }
            $this->write($prefix, $document);
        });
    }

    public function mutate(string $prefix, callable $callback): array
    {
        return $this->withLock($prefix, function () use ($prefix, $callback): array {
            $document = $this->load($prefix);
            if ($document === null) {
                throw new RuntimeException('User data not found');
            }
            $updated = $callback($document);
            if (!is_array($updated)) {
                throw new RuntimeException('Invalid updated user data');
            }
            $updated['profile']['updatedAt'] = gmdate('c');
            $this->write($prefix, $updated);
            return $updated;
        });
    }

    public function delete(string $prefix): void
    {
        $this->withLock($prefix, function () use ($prefix): void {
            $path = $this->path($prefix);
            if (!is_file($path)) {
                throw new RuntimeException('User data not found');
            }
            if (!unlink($path)) {
                throw new RuntimeException('Cannot delete user data');
            }
        });
    }

    public static function nextResourceId(array $documents, string $type): int
    {
        $maximum = 0;
        foreach ($documents as $document) {
            $rows = $document['resources'][$type] ?? [];
            foreach (is_array($rows) ? $rows : [] as $row) {
                $maximum = max($maximum, (int) ($row['id'] ?? 0));
            }
        }
        return $maximum + 1;
    }

    private function write(string $prefix, array $document): void
    {
        $json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('Cannot encode user data');
        }
        $json .= PHP_EOL;

        $path = $this->path($prefix);
        $temporary = tempnam($this->directory, '.write-');
        if ($temporary === false) {
            throw new RuntimeException('Cannot create temporary data file');
        }

        try {
            if (file_put_contents($temporary, $json, LOCK_EX) === false) {
                throw new RuntimeException('Cannot write user data');
            }
            @chmod($temporary, 0600);

            if (DIRECTORY_SEPARATOR === '\\' && is_file($path)) {
                if (!copy($temporary, $path)) {
                    throw new RuntimeException('Cannot replace user data');
                }
                @unlink($temporary);
            } elseif (!rename($temporary, $path)) {
                throw new RuntimeException('Cannot publish user data');
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    private function withLock(string $prefix, callable $callback)
    {
        $this->assertPrefix($prefix);
        $lockPath = $this->lockDirectory . DIRECTORY_SEPARATOR . $prefix . '.lock';
        $handle = fopen($lockPath, 'c+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            throw new RuntimeException('Cannot lock user data');
        }

        try {
            return $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function path(string $prefix): string
    {
        $this->assertPrefix($prefix);
        return $this->directory . DIRECTORY_SEPARATOR . $prefix . '.json';
    }

    private function assertPrefix(string $prefix): void
    {
        if (!$this->validPrefix($prefix)) {
            throw new InvalidArgumentException('Invalid user prefix');
        }
    }

    private function validPrefix(string $prefix): bool
    {
        return preg_match('/^[a-z][a-z0-9_]{1,31}$/', $prefix) === 1;
    }
}
