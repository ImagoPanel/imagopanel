<?php
declare(strict_types=1);

if (isset($argv) && is_array($argv) && in_array('--task', $argv, true)) {
    $_SERVER['HTTP_HOST'] = 'task.lv';
} elseif (isset($argv) && is_array($argv) && in_array('--prod', $argv, true)) {
    $_SERVER['HTTP_HOST'] = '';
}

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/OpenDkimManager.php';

if (PHP_SAPI !== 'cli') exit(1);
if (!WIN && function_exists('posix_geteuid') && posix_geteuid() !== 0) {
    fwrite(STDERR, "OpenDKIM cleanup must run as root\n");
    exit(2);
}

try {
    $result = OpenDkimManager::fromConfig()->cleanupPending();
    fwrite(STDOUT, json_encode(['ok' => true, 'data' => $result], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(0);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
