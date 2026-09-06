<?php
declare(strict_types=1);

if (isset($argv) && is_array($argv) && in_array('--task', $argv, true)) {
    $_SERVER['HTTP_HOST'] = 'task.lv';
} elseif (isset($argv) && is_array($argv) && in_array('--prod', $argv, true)) {
    $_SERVER['HTTP_HOST'] = '';
}

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/MailMigrationStore.php';
require_once dirname(__DIR__) . '/lib/MailMigrationRuntime.php';

if (PHP_SAPI !== 'cli') exit(1);
if (!MAIL_MIGRATION_ENABLED) exit(0);

try {
    $store = MailMigrationStore::configured();
    $cleanedJobs = 0;
    foreach ($store->staleActive(MAIL_MIGRATION_STALE_SECONDS) as $job) {
        $id = (string) $job['id'];
        $store->update($id, [
            'status' => 'failed',
            'errors_count' => max(1, (int) $job['errors_count']),
            'error_message' => 'Background mail import stopped unexpectedly',
            'pid' => null,
            'finished_at' => gmdate('Y-m-d H:i:s'),
        ]);
        MailMigrationRuntime::removeCredentials($id);
        MailMigrationRuntime::removeTemporaryDirectory($id);
        $cleanedJobs++;
    }

    $cleanedFiles = 0;
    $cutoff = time() - max(300, MAIL_MIGRATION_STALE_SECONDS);
    foreach (glob(rtrim(MAIL_MIGRATION_CREDENTIAL_DIRECTORY, '/\\') . DIRECTORY_SEPARATOR . '*.pass') ?: [] as $file) {
        if (!is_file($file) || is_link($file) || (int) filemtime($file) >= $cutoff) continue;
        $name = basename($file);
        if (preg_match('/^([a-f0-9]{32})\.(?:source|destination)\.pass$/D', $name, $match) !== 1) continue;
        try {
            $job = $store->get($match[1]);
            if (in_array((string) $job['status'], ['pending', 'checking', 'ready', 'running'], true)) continue;
        } catch (Throwable $ignored) {
        }
        if (@unlink($file)) $cleanedFiles++;
    }
    fwrite(STDOUT, json_encode(['ok' => true, 'cleanedJobs' => $cleanedJobs, 'cleanedCredentialFiles' => $cleanedFiles]) . PHP_EOL);
    exit(0);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
