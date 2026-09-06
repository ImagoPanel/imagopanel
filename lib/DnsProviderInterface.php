<?php
declare(strict_types=1);

interface DnsProviderInterface
{
    public function id(): string;

    public function testConnection(): array;

    public function getZone(string $domain): array;

    public function listZones(): array;

    public function listRecords(string $domain): array;

    public function upsertRecord(string $domain, string $name, string $type, array $values, ?int $ttl): array;

    public function deleteRecord(string $domain, string $name, string $type): void;
}
