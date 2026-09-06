<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/OpenDkimManager.php';
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/DnsService.php';

function testAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function testRemoveTree(string $path): void
{
    if (!file_exists($path)) return;
    if (is_file($path) || is_link($path)) {
        @unlink($path);
        return;
    }
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        testRemoveTree($path . DIRECTORY_SEPARATOR . $entry);
    }
    @rmdir($path);
}

function testOptions(string $root, string $mode): array
{
    return [
        'mode' => $mode,
        'selector' => 'default',
        'shared_dns_value' => 'v=DKIM1; k=rsa; p=QUJDRA==',
        'signing_domains_file' => $root . '/SigningDomains',
        'key_table_file' => $root . '/KeyTable',
        'signing_table_file' => $root . '/SigningTable',
        'keys_directory' => $root . '/keys',
        'pending_directory' => $root . '/pending',
        'lock_file' => $root . '/locks/opendkim.lock',
        'key_bits' => 2048,
        'pending_ttl' => 3600,
        'owner' => '',
        'group' => '',
        'directory_mode' => 0750,
        'private_key_mode' => 0600,
        'table_file_mode' => 0640,
        'key_generator' => static function (int $bits): array {
            testAssert($bits >= 2048, 'Generated test key must request at least 2048 bits');
            return ['private' => "TEST PRIVATE KEY MATERIAL\n", 'public' => 'QUJDRA=='];
        },
    ];
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'imagopanel-opendkim-' . bin2hex(random_bytes(6));
if (!mkdir($root, 0750, true) && !is_dir($root)) throw new RuntimeException('Cannot create test directory');

try {
    $reloads = 0;
    $manager = new OpenDkimManager(testOptions($root . '/shared-all', OpenDkimManager::MODE_SHARED_ALL), static function () use (&$reloads): void { $reloads++; });
    $manager->prepare('all.example');
    $manager->activate('all.example');
    $manager->remove('all.example');
    testAssert($reloads === 0, 'shared_key_all_domains must not reload OpenDKIM');
    testAssert(!file_exists($root . '/shared-all'), 'shared_key_all_domains must not write files');

    $managedRoot = $root . '/shared-managed';
    mkdir($managedRoot, 0750, true);
    file_put_contents($managedRoot . '/SigningDomains', "manual.example\n");
    $reloads = 0;
    $manager = new OpenDkimManager(testOptions($managedRoot, OpenDkimManager::MODE_SHARED_MANAGED), static function () use (&$reloads): void { $reloads++; });
    $manager->activate('panel.example');
    $contents = (string) file_get_contents($managedRoot . '/SigningDomains');
    testAssert(strpos($contents, "# BEGIN SERVER ADMIN\nmanual.example") !== false, 'Administrator SigningDomains content must be preserved');
    testAssert(strpos($contents, "# BEGIN IMAGOPANEL\npanel.example") !== false, 'Managed domain must be written to ImagoPanel block');
    $manager->activate('panel.example');
    testAssert($reloads === 1, 'Unchanged managed table must not reload OpenDKIM');
    $manager->remove('panel.example');
    testAssert($reloads === 2, 'Managed domain removal must reload OpenDKIM');
    testAssert(strpos((string) file_get_contents($managedRoot . '/SigningDomains'), 'manual.example') !== false, 'Administrator domain must survive removal');

    $rollbackRoot = $root . '/rollback';
    mkdir($rollbackRoot, 0750, true);
    $originalSigningDomains = "administrator.example\n";
    file_put_contents($rollbackRoot . '/SigningDomains', $originalSigningDomains);
    $reloads = 0;
    $manager = new OpenDkimManager(testOptions($rollbackRoot, OpenDkimManager::MODE_SHARED_MANAGED), static function () use (&$reloads): void {
        $reloads++;
        if ($reloads === 1) throw new RuntimeException('Simulated OpenDKIM restart failure');
    });
    try {
        $manager->activate('must-rollback.example');
        throw new RuntimeException('OpenDKIM restart failure was not propagated');
    } catch (RuntimeException $exception) {
        testAssert($exception->getMessage() === 'Simulated OpenDKIM restart failure', 'Unexpected rollback exception');
    }
    testAssert((string) file_get_contents($rollbackRoot . '/SigningDomains') === $originalSigningDomains, 'OpenDKIM table must be restored after restart failure');
    testAssert($reloads === 2, 'Restored OpenDKIM configuration must be applied after rollback');

    $perDomainRoot = $root . '/per-domain';
    $reloads = 0;
    $manager = new OpenDkimManager(testOptions($perDomainRoot, OpenDkimManager::MODE_PER_DOMAIN), static function () use (&$reloads): void { $reloads++; });
    $prepared = $manager->prepare('keys.example');
    testAssert(!empty($prepared['temporary']) && strpos((string) $prepared['dnsValue'], 'v=DKIM1; k=rsa; p=') === 0, 'Per-domain DNS key must be generated before save');
    $pendingDirectory = $perDomainRoot . '/pending/' . hash('sha256', 'keys.example');
    testAssert(is_file($pendingDirectory . '/default.private'), 'Temporary private key is missing');
    $manager->activate('keys.example');
    testAssert(is_file($perDomainRoot . '/keys/keys.example/.imagopanel-managed'), 'Temporary key must be promoted to permanent directory');
    testAssert(!file_exists($pendingDirectory), 'Temporary directory must disappear after activation');
    testAssert(strpos((string) file_get_contents($perDomainRoot . '/KeyTable'), 'default._domainkey.keys.example') !== false, 'KeyTable entry is missing');
    testAssert(strpos((string) file_get_contents($perDomainRoot . '/SigningTable'), '*@keys.example') !== false, 'SigningTable entry is missing');
    testAssert($reloads === 1, 'Per-domain activation must reload OpenDKIM once');
    $manager->prepare('renamed.example');
    $manager->activate('renamed.example', 'keys.example');
    testAssert(!file_exists($perDomainRoot . '/keys/keys.example'), 'Managed permanent key must be removed with domain');
    testAssert(is_file($perDomainRoot . '/keys/renamed.example/.imagopanel-managed'), 'Renamed domain key must be activated');
    testAssert(strpos((string) file_get_contents($perDomainRoot . '/SigningTable'), '*@renamed.example') !== false, 'Renamed SigningTable entry is missing');
    testAssert($reloads === 2, 'Per-domain rename must reload OpenDKIM once');
    $manager->remove('renamed.example');
    testAssert(!file_exists($perDomainRoot . '/keys/renamed.example'), 'Managed permanent key must be removed with domain');
    testAssert($reloads === 3, 'Per-domain removal must reload OpenDKIM once');

    $manager->prepare('stale.example');
    $cleanup = $manager->cleanupPending(time() + 7200);
    testAssert((int) $cleanup['removed'] === 1, 'Temporary key older than TTL must be removed');

    $dynamicDkim = 'v=DKIM1; k=rsa; p=VEVTVF9LRVk=';
    $recommended = DnsService::recommendedRecords('dynamic.example', $dynamicDkim);
    $dkimRecords = array_values(array_filter($recommended, static function (array $record): bool {
        return $record['type'] === 'TXT' && $record['name'] === DNS_DKIM_SELECTOR . '._domainkey';
    }));
    testAssert(count($dkimRecords) === 1 && ($dkimRecords[0]['values'][0] ?? '') === $dynamicDkim, 'Recommended DNS records must use the per-domain DKIM value');

    $bulkA = DnsService::recordForDomainTemplate('example.test', 'www.example.test.', 'A', 3600, ['192.0.2.40']);
    testAssert($bulkA['name'] === 'www' && $bulkA['values'] === ['192.0.2.40'], 'Bulk DNS names must be normalized relative to each zone');
    $bulkMx = DnsService::recordForDomainTemplate('example.test', '', 'MX', 3600, ['10 mail.{domain}.']);
    testAssert($bulkMx['name'] === '@' && $bulkMx['values'] === ['10 mail.example.test.'], 'Bulk DNS placeholders must be expanded for each zone');

    fwrite(STDOUT, "OpenDkimManager tests passed\n");
} finally {
    testRemoveTree($root);
}
