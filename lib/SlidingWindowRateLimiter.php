<?php
declare(strict_types=1);

final class SlidingWindowRateLimiter
{
    private string $directory;
    private int $maximum;
    private int $windowSeconds;

    public function __construct(string $directory, int $maximum, int $windowSeconds)
    {
        $this->directory = rtrim($directory, '/\\');
        $this->maximum = max(1, $maximum);
        $this->windowSeconds = max(1, $windowSeconds);

        if (!is_dir($this->directory)
            && !mkdir($this->directory, 0700, true)
            && !is_dir($this->directory)) {
            throw new RuntimeException('Cannot create verification rate-limit directory');
        }
    }

    public function consume(string $key, ?float $now = null): array
    {
        $now = $now ?? microtime(true);
        $path = $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
        $handle = fopen($path, 'c+');
        if ($handle === false) {
            throw new RuntimeException('Cannot open verification rate-limit file');
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Cannot lock verification rate-limit file');
            }

            rewind($handle);
            $decoded = json_decode((string) stream_get_contents($handle), true);
            $timestamps = is_array($decoded) ? $decoded : [];
            $threshold = $now - $this->windowSeconds;
            $timestamps = array_values(array_filter($timestamps, static function ($timestamp) use ($threshold, $now): bool {
                return is_numeric($timestamp) && (float) $timestamp > $threshold && (float) $timestamp <= $now + 5;
            }));
            sort($timestamps, SORT_NUMERIC);

            $allowed = count($timestamps) < $this->maximum;
            if ($allowed) {
                $timestamps[] = $now;
            }
            $retryAfter = $allowed || $timestamps === []
                ? 0
                : max(1, (int) ceil(((float) $timestamps[0] + $this->windowSeconds) - $now));

            $json = json_encode($timestamps, JSON_UNESCAPED_SLASHES);
            if (!is_string($json)) {
                throw new RuntimeException('Cannot encode verification rate-limit data');
            }
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $json) === false || !fflush($handle)) {
                throw new RuntimeException('Cannot write verification rate-limit data');
            }
            @chmod($path, 0600);
            flock($handle, LOCK_UN);

            return [
                'allowed' => $allowed,
                'limit' => $this->maximum,
                'windowSeconds' => $this->windowSeconds,
                'remaining' => max(0, $this->maximum - count($timestamps)),
                'retryAfter' => $retryAfter,
            ];
        } finally {
            fclose($handle);
        }
    }
}
