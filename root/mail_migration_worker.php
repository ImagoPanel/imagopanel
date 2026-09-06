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

function workerJobId(array $arguments): string
{
    foreach ($arguments as $argument) {
        if (strpos((string) $argument, '--job=') === 0) {
            $id = substr((string) $argument, 6);
            if (preg_match('/^[a-f0-9]{32}$/D', $id) === 1) return $id;
        }
    }
    throw new InvalidArgumentException('Invalid migration job ID');
}

function workerAppend(string $file, string $message): void
{
    if (is_link($file)) throw new RuntimeException('Migration log cannot be a symlink');
    if (file_put_contents($file, '[' . gmdate('c') . '] ' . $message . PHP_EOL, FILE_APPEND | LOCK_EX) === false) {
        throw new RuntimeException('Cannot write migration log');
    }
    @chmod($file, 0640);
    @chgrp($file, USER_WEB_GROUP);
}

function workerRun(array $command, string $logFile, int $timeoutSeconds, callable $started, callable $heartbeat): int
{
    if ($command === [] || (string) $command[0] !== MAIL_MIGRATION_IMAPSYNC_BINARY) throw new RuntimeException('Unexpected migration command');
    $process = proc_open($command, [
        0 => ['file', '/dev/null', 'rb'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes, dirname(__DIR__), null, ['bypass_shell' => true]);
    if (!is_resource($process)) throw new RuntimeException('Cannot start imapsync');
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $status = proc_get_status($process);
    $started((int) ($status['pid'] ?? 0));
    $startedAt = microtime(true);
    $lastHeartbeat = 0.0;
    $exitCode = -1;
    $tail = '';
    $lineBuffers = ['', ''];
    $copied = 0;
    while (true) {
        foreach ([1, 2] as $pipeIndex) {
            $chunk = (string) stream_get_contents($pipes[$pipeIndex]);
            if ($chunk === '') continue;
            if (file_put_contents($logFile, $chunk, FILE_APPEND | LOCK_EX) === false) throw new RuntimeException('Cannot write migration log');
            $tail = substr($tail . $chunk, -262144);
            $lineBuffers[$pipeIndex - 1] .= $chunk;
            $lines = preg_split('/\r?\n/', $lineBuffers[$pipeIndex - 1]);
            $lineBuffers[$pipeIndex - 1] = (string) array_pop($lines);
            foreach ($lines as $line) if (preg_match('/^\s*msg\s+.*?\bcopied to\b/i', $line) === 1) $copied++;
        }
        $status = proc_get_status($process);
        if (!$status['running']) {
            $exitCode = (int) $status['exitcode'];
            break;
        }
        if (microtime(true) - $lastHeartbeat >= 15) {
            $heartbeat((int) ($status['pid'] ?? 0), $copied, $tail);
            $lastHeartbeat = microtime(true);
        }
        if (microtime(true) - $startedAt >= $timeoutSeconds) {
            proc_terminate($process);
            usleep(200000);
            $status = proc_get_status($process);
            if ($status['running']) proc_terminate($process, 9);
            proc_close($process);
            throw new RuntimeException('Mail import exceeded the configured maximum duration');
        }
        sleep(1);
    }
    foreach ([1, 2] as $pipeIndex) {
        $chunk = (string) stream_get_contents($pipes[$pipeIndex]);
        if ($chunk !== '') {
            file_put_contents($logFile, $chunk, FILE_APPEND | LOCK_EX);
            $tail = substr($tail . $chunk, -262144);
            $copied += preg_match_all('/^\s*msg\s+.*?\bcopied to\b.*$/mi', $lineBuffers[$pipeIndex - 1] . $chunk) ?: 0;
        }
        fclose($pipes[$pipeIndex]);
    }
    $heartbeat((int) ($status['pid'] ?? 0), $copied, $tail);
    @chmod($logFile, 0640);
    @chgrp($logFile, USER_WEB_GROUP);
    $closed = proc_close($process);
    return $exitCode >= 0 ? $exitCode : $closed;
}

function workerWriteReport(string $id, array $job): void
{
    $report = [
        'migrationId' => $id,
        'status' => (string) ($job['status'] ?? 'failed'),
        'server' => (string) ($job['source_host'] ?? ''),
        'destination' => (string) ($job['destination_email'] ?? ''),
        'folders' => (int) ($job['folders_total'] ?? 0),
        'messages' => (int) ($job['messages_done'] ?? 0),
        'messagesTotal' => (int) ($job['messages_total'] ?? 0),
        'bytes' => (float) ($job['bytes_done'] ?? 0),
        'bytesTotal' => (float) ($job['bytes_total'] ?? 0),
        'skipped' => (int) ($job['skipped_count'] ?? 0),
        'errors' => (int) ($job['errors_count'] ?? 0),
        'error' => (string) ($job['error_message'] ?? ''),
        'startedAt' => (string) ($job['started_at'] ?? ''),
        'finishedAt' => (string) ($job['finished_at'] ?? ''),
    ];
    $encoded = json_encode($report, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($encoded === false || file_put_contents(MailMigrationRuntime::reportPath($id), $encoded . PHP_EOL, LOCK_EX) === false) {
        throw new RuntimeException('Cannot write mail migration report');
    }
    @chmod(MailMigrationRuntime::reportPath($id), 0640);
    @chgrp(MailMigrationRuntime::reportPath($id), USER_WEB_GROUP);
}

if (PHP_SAPI !== 'cli') exit(1);

$jobId = '';
$store = null;
try {
    if (!PROD) throw new RuntimeException('Mail migration worker is available only in production');
    $jobId = workerJobId($argv ?? []);
    MailMigrationRuntime::assertDependencies();
    MailMigrationRuntime::ensureDirectories();
    $store = MailMigrationStore::configured();
    $job = $store->get($jobId);
    if ((string) $job['status'] !== 'pending') throw new RuntimeException('Migration job is not pending');
    [$sourceFile, $destinationFile] = MailMigrationRuntime::credentialPaths($jobId);
    if (!is_file($sourceFile) || !is_file($destinationFile) || is_link($sourceFile) || is_link($destinationFile)) {
        throw new RuntimeException('Temporary migration credentials are unavailable');
    }
    $logFile = MailMigrationRuntime::logPath($jobId);
    if (file_exists($logFile) && (is_link($logFile) || !unlink($logFile))) throw new RuntimeException('Cannot initialize migration log');
    workerAppend($logFile, 'Checking source and destination mailboxes');
    $store->update($jobId, ['status' => 'checking', 'started_at' => gmdate('Y-m-d H:i:s')]);
    $analysisExit = workerRun(
        MailMigrationRuntime::command($job, $sourceFile, $destinationFile, true),
        $logFile,
        MAIL_MIGRATION_TEST_TIMEOUT_SECONDS,
        static function (int $pid) use ($store, $jobId): void { $store->update($jobId, ['pid' => $pid]); },
        static function (int $pid) use ($store, $jobId): void { $store->update($jobId, ['pid' => $pid]); }
    );
    $analysisLog = MailMigrationRuntime::readLog($jobId);
    if ($analysisExit !== 0) throw new RuntimeException(MailMigrationRuntime::friendlyError($analysisLog));
    $analysis = mailMigrationProgressFromLog($job, $analysisLog);
    $store->update($jobId, [
        'status' => 'ready',
        'folders_total' => (int) ($analysis['folders_total'] ?? 0),
        'messages_total' => (int) ($analysis['messages_total'] ?? 0),
        'bytes_total' => (float) ($analysis['bytes_total'] ?? 0),
    ]);
    workerAppend($logFile, 'Starting message transfer');
    $store->update($jobId, ['status' => 'running']);
    $syncExit = workerRun(
        MailMigrationRuntime::command($job, $sourceFile, $destinationFile, false),
        $logFile,
        MAIL_MIGRATION_MAX_RUNTIME_SECONDS,
        static function (int $pid) use ($store, $jobId): void { $store->update($jobId, ['pid' => $pid]); },
        static function (int $pid, int $copied, string $tail) use ($store, $jobId): void {
            $live = mailMigrationProgressFromLog($store->get($jobId), $tail);
            $store->update($jobId, [
                'pid' => $pid,
                'folders_done' => (int) ($live['folders_done'] ?? 0),
                'folders_total' => (int) ($live['folders_total'] ?? 0),
                'messages_done' => max($copied, (int) ($live['messages_done'] ?? 0)),
                'messages_total' => (int) ($live['messages_total'] ?? 0),
                'bytes_done' => (float) ($live['bytes_done'] ?? 0),
                'bytes_total' => (float) ($live['bytes_total'] ?? 0),
                'current_folder' => (string) ($live['current_folder'] ?? ''),
                'errors_count' => (int) ($live['errors_count'] ?? 0),
            ]);
        }
    );
    $progress = mailMigrationProgressFromLog($store->get($jobId), MailMigrationRuntime::readLog($jobId));
    $errors = (int) ($progress['errors_count'] ?? 0);
    $finalStatus = $syncExit === 0 && $errors === 0 ? 'completed'
        : ((int) ($progress['messages_done'] ?? 0) > 0 ? 'completed_with_errors' : 'failed');
    $errorMessage = $finalStatus === 'failed' ? MailMigrationRuntime::friendlyError(MailMigrationRuntime::readLog($jobId)) : '';
    $job = $store->update($jobId, [
        'status' => $finalStatus,
        'folders_done' => (int) ($progress['folders_total'] ?? 0),
        'folders_total' => (int) ($progress['folders_total'] ?? 0),
        'messages_done' => (int) ($progress['messages_done'] ?? 0),
        'messages_total' => (int) ($progress['messages_total'] ?? 0),
        'bytes_done' => (float) ($progress['bytes_done'] ?? 0),
        'bytes_total' => (float) ($progress['bytes_total'] ?? 0),
        'current_folder' => '',
        'skipped_count' => (int) ($progress['skipped_count'] ?? 0),
        'errors_count' => max($errors, $syncExit === 0 ? 0 : 1),
        'error_message' => $errorMessage,
        'pid' => null,
        'finished_at' => gmdate('Y-m-d H:i:s'),
    ]);
    workerWriteReport($jobId, $job);
    MailMigrationRuntime::removeCredentials($jobId);
    MailMigrationRuntime::removeTemporaryDirectory($jobId);
    exit($finalStatus === 'failed' ? 1 : 0);
} catch (Throwable $exception) {
    if ($jobId !== '') {
        MailMigrationRuntime::removeCredentials($jobId);
        MailMigrationRuntime::removeTemporaryDirectory($jobId);
    }
    if ($store instanceof MailMigrationStore && $jobId !== '') {
        try {
            $job = $store->update($jobId, [
                'status' => 'failed', 'errors_count' => 1, 'error_message' => $exception->getMessage(),
                'pid' => null, 'finished_at' => gmdate('Y-m-d H:i:s'),
            ]);
            workerWriteReport($jobId, $job);
        } catch (Throwable $ignored) {
        }
    }
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
