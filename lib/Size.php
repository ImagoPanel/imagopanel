<?php
declare(strict_types=1);

/**
 * Converts values such as 512K, 7.40M, 7,40M, 1G, or 1T to bytes.
 * Returns float so values from 2G also work on 32-bit PHP 7.4 builds.
 * Tariff configuration uses the string "0" for an unlimited value.
 */
function bytesFromHuman($value): float
{
    if (!is_string($value)) {
        throw new InvalidArgumentException('Size must be a string such as 100M');
    }

    $value = trim($value);
    if ($value === '0') return 0.0;
    if (preg_match('/^([1-9][0-9]*(?:[.,][0-9]+)?)([KMGT])$/iD', $value, $match) !== 1) {
        throw new InvalidArgumentException('Size must be 0 or a positive number followed by K, M, G or T');
    }

    $multipliers = [
        'K' => 1024.0,
        'M' => 1048576.0,
        'G' => 1073741824.0,
        'T' => 1099511627776.0,
    ];
    $multiplier = $multipliers[strtoupper($match[2])];
    $bytes = (float) str_replace(',', '.', $match[1]) * $multiplier;

    // Above 2^53, an integer byte count can no longer be represented exactly as a float.
    if (!is_finite($bytes) || $bytes > 9007199254740991.0) {
        throw new InvalidArgumentException('Size exceeds the supported byte range');
    }

    return $bytes;
}

/** Converts every size limit in one tariff to bytes. */
function tariffSizesInBytes(array $tariff, string $tariffName = ''): array
{
    foreach (['wwwsize', 'mailsize', 'dbsize'] as $field) {
        try {
            $tariff[$field] = bytesFromHuman($tariff[$field] ?? '0');
        } catch (InvalidArgumentException $exception) {
            $location = $tariffName !== '' ? 'USER_TARIFFS[' . $tariffName . '][' . $field . ']' : $field;
            throw new InvalidArgumentException('Invalid ' . $location . ': ' . $exception->getMessage(), 0, $exception);
        }
    }
    return $tariff;
}
