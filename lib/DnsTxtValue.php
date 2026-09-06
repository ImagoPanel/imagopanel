<?php
declare(strict_types=1);

final class DnsTxtValue
{
    public static function toDisplay(string $value): string
    {
        $decoded = self::decodePresentation($value);
        return $decoded === null ? $value : $decoded;
    }

    public static function toPresentation(string $value, int $maximumChunkBytes = 255): string
    {
        if ($maximumChunkBytes < 1 || $maximumChunkBytes > 255) {
            throw new InvalidArgumentException('DNS TXT chunk size must be between 1 and 255 bytes');
        }

        $decoded = self::decodePresentation($value);
        $logicalValue = $decoded === null ? $value : $decoded;
        $chunks = self::splitByBytes($logicalValue, $maximumChunkBytes);

        return implode(' ', array_map(static function (string $chunk): string {
            return '"' . addcslashes($chunk, "\\\"") . '"';
        }, $chunks));
    }

    private static function decodePresentation(string $value): ?string
    {
        $value = trim($value);
        $length = strlen($value);
        if ($length < 2 || $value[0] !== '"') return null;

        $offset = 0;
        $result = '';
        while ($offset < $length) {
            while ($offset < $length && preg_match('/\s/u', $value[$offset]) === 1) $offset++;
            if ($offset >= $length || $value[$offset] !== '"') return null;
            $offset++;

            $closed = false;
            while ($offset < $length) {
                $character = $value[$offset];
                if ($character === '"') {
                    $closed = true;
                    $offset++;
                    break;
                }
                if ($character === '\\' && $offset + 1 < $length
                    && ($value[$offset + 1] === '"' || $value[$offset + 1] === '\\')) {
                    $result .= $value[$offset + 1];
                    $offset += 2;
                    continue;
                }
                $result .= $character;
                $offset++;
            }
            if (!$closed) return null;

            while ($offset < $length && preg_match('/\s/u', $value[$offset]) === 1) $offset++;
            if ($offset < $length && $value[$offset] !== '"') return null;
        }

        return $result;
    }

    private static function splitByBytes(string $value, int $maximumChunkBytes): array
    {
        if ($value === '') return [''];

        $chunks = [];
        while (strlen($value) > $maximumChunkBytes) {
            $cut = $maximumChunkBytes;
            if (preg_match('//u', $value) === 1) {
                while ($cut > 0 && (ord($value[$cut]) & 0xC0) === 0x80) $cut--;
            }
            if ($cut === 0) $cut = $maximumChunkBytes;
            $chunks[] = substr($value, 0, $cut);
            $value = substr($value, $cut);
        }
        $chunks[] = $value;
        return $chunks;
    }
}
