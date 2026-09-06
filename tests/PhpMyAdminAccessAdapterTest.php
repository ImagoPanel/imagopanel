<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/phpmyadmin/imagopanel-access/Adapter.php';

function pmaAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function pmaWriteJson(string $path, array $data): void
{
    $json = json_encode($data, JSON_UNESCAPED_SLASHES);
    if (!is_string($json) || file_put_contents($path, $json, LOCK_EX) === false) {
        throw new RuntimeException('Cannot prepare test fixture');
    }
}

function pmaRemoveTree(string $path): void
{
    if (!is_dir($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($path);
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'imagopanel-pma-adapter-' . bin2hex(random_bytes(8));
$dataDirectory = $root . DIRECTORY_SEPARATOR . 'data';
$stateDirectory = $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'domain-tool-state';
$launchDirectory = $stateDirectory . DIRECTORY_SEPARATOR . 'panel-tool-launches';
mkdir($dataDirectory, 0750, true);
mkdir($launchDirectory, 0750, true);

$now = time();
$document = [
    'profile' => [
        'prefix' => 'alice',
        'email' => 'alice@example.test',
        'passwordHash' => password_hash('OwnerPassword9', PASSWORD_DEFAULT),
        'active' => true,
    ],
    'resources' => [
        'domains' => [[
            'id' => 10,
            'domain' => 'example.test',
            'active' => true,
            'toolAccesses' => [[
                'id' => '0123456789abcdef',
                'login' => 'temporary',
                'password' => 'TemporaryPassword9',
                'active' => true,
                'ips' => ['203.0.113.10'],
                'permissions' => ['phpmyadmin' => true],
                'startsAt' => gmdate('c', $now - 60),
                'expiresAt' => gmdate('c', $now + 3600),
            ]],
        ]],
        'databases' => [[
            'id' => 20,
            'domain' => 'example.test',
            'name' => 'alice_example',
            'username' => 'alice_example',
            'password' => 'DatabasePassword9',
            'host' => 'localhost',
            'port' => 3306,
            'active' => true,
        ]],
    ],
];
pmaWriteJson($dataDirectory . DIRECTORY_SEPARATOR . 'alice.json', $document);
pmaWriteJson($stateDirectory . DIRECTORY_SEPARATOR . 'phpmyadmin-adapter.json', [
    'version' => 1,
    'trustedIps' => ['203.0.113.10'],
    'trustedProxyIps' => ['192.0.2.0/24'],
    'dataDirectory' => $dataDirectory,
    'sessionIdleSeconds' => 900,
    'mysqlHost' => 'localhost',
    'mysqlPort' => 3306,
]);

try {
    $adapter = new ImagoPanelPhpMyAdminAccessAdapter($root);
    $adapterSource = (string) file_get_contents(dirname(__DIR__) . '/phpmyadmin/imagopanel-access/Adapter.php');
    pmaAssert(strpos($adapterSource, 'DomainToolAccess.php') === false, 'Adapter must not depend on AGPL DomainToolAccess');
    pmaAssert(preg_match('/\b(?:require|include)(?:_once)?\b/', $adapterSource) !== 1, 'Adapter must not include application code');

    $clientIpMethod = new ReflectionMethod(ImagoPanelPhpMyAdminAccessAdapter::class, 'clientIp');
    $clientIpMethod->setAccessible(true);
    $_SERVER['REMOTE_ADDR'] = '192.0.2.20';
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.10, 192.0.2.10';
    pmaAssert($clientIpMethod->invoke($adapter) === '203.0.113.10', 'Trusted proxy chain must resolve to the originating client IP');
    $_SERVER['REMOTE_ADDR'] = '198.51.100.20';
    pmaAssert($clientIpMethod->invoke($adapter) === '198.51.100.20', 'Forwarded headers from untrusted peers must be ignored');
    unset($_SERVER['HTTP_X_FORWARDED_FOR']);

    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    pmaWriteJson($launchDirectory . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json', [
        'kind' => 'database',
        'tool' => 'phpmyadmin',
        'prefix' => 'alice',
        'databaseId' => 20,
        'host' => 'panel.example.test',
        'clientIp' => '203.0.113.10',
        'expiresAt' => $now + 60,
    ]);
    pmaAssert($adapter->consumeLaunch($token, 'panel.example.test', '203.0.113.10') !== null, 'Valid launch must be accepted');
    pmaAssert($adapter->consumeLaunch($token, 'panel.example.test', '203.0.113.10') === null, 'Launch must be one-time');

    $wrongIpToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    pmaWriteJson($launchDirectory . DIRECTORY_SEPARATOR . hash('sha256', $wrongIpToken) . '.json', [
        'kind' => 'database',
        'tool' => 'phpmyadmin',
        'host' => 'panel.example.test',
        'clientIp' => '203.0.113.10',
        'expiresAt' => $now + 60,
    ]);
    pmaAssert($adapter->consumeLaunch($wrongIpToken, 'panel.example.test', '203.0.113.11') === null, 'Launch must be bound to the originating IP');

    $wrongToolToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    pmaWriteJson($launchDirectory . DIRECTORY_SEPARATOR . hash('sha256', $wrongToolToken) . '.json', [
        'kind' => 'domain',
        'tool' => 'filemanager',
        'host' => 'panel.example.test',
        'clientIp' => '203.0.113.10',
        'expiresAt' => $now + 60,
    ]);
    pmaAssert($adapter->consumeLaunch($wrongToolToken, 'panel.example.test', '203.0.113.10') === null, 'Launch for another tool must fail closed');

    $databaseContext = $adapter->resolveSelection([
        'mode' => 'panel_database',
        'prefix' => 'alice',
        'databaseId' => 20,
        'host' => 'panel.example.test',
        'clientIp' => '203.0.113.10',
        'accessLimit' => PHP_INT_MAX,
    ], 'panel.example.test', '203.0.113.10');
    pmaAssert(($databaseContext['database']['name'] ?? '') === 'alice_example', 'Panel launch must select the requested database');

    $temporaryContext = $adapter->resolveSelection([
        'mode' => 'temporary',
        'prefix' => 'alice',
        'domainId' => 10,
        'accessId' => '0123456789abcdef',
        'host' => 'example.test',
        'clientIp' => '203.0.113.10',
        'accessLimit' => $now + 3600,
    ], 'example.test', '203.0.113.10');
    pmaAssert(($temporaryContext['database']['name'] ?? '') === 'alice_example', 'Active temporary access must resolve its linked database');
    pmaAssert($adapter->resolveSelection([
        'mode' => 'temporary',
        'prefix' => 'alice',
        'domainId' => 10,
        'accessId' => '0123456789abcdef',
        'host' => 'example.test',
        'clientIp' => '203.0.113.10',
        'accessLimit' => $now - 1,
    ], 'example.test', '203.0.113.10') === null, 'Expired access must fail closed');
    pmaAssert($adapter->resolveSelection([
        'mode' => 'temporary',
        'prefix' => 'alice',
        'domainId' => 10,
        'accessId' => '0123456789abcdef',
        'host' => 'example.test',
        'clientIp' => '203.0.113.10',
        'accessLimit' => $now + 3600,
    ], 'example.test', '203.0.113.11') === null, 'Session must be bound to its IP');

    $document['resources']['domains'][0]['toolAccesses'][0]['ips'] = [];
    pmaWriteJson($dataDirectory . DIRECTORY_SEPARATOR . 'alice.json', $document);
    pmaAssert($adapter->resolveSelection([
        'mode' => 'temporary',
        'prefix' => 'alice',
        'domainId' => 10,
        'accessId' => '0123456789abcdef',
        'host' => 'example.test',
        'clientIp' => '203.0.113.10',
        'accessLimit' => $now + 3600,
    ], 'example.test', '203.0.113.10') === null, 'Current IP restrictions must be revalidated on every request');

    pmaAssert($adapter->blowfishSecret() === $adapter->blowfishSecret(), 'Blowfish secret must remain stable');
    pmaAssert(ImagoPanelPhpMyAdminAccessAdapter::databaseUrl($databaseContext) === '/phpmyadmin/index.php?route=/database/structure&db=alice_example', 'Database URL must select the database');
    echo "PhpMyAdminAccessAdapterTest: OK\n";
} finally {
    pmaRemoveTree($root);
}
