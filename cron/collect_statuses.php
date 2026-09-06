<?php
declare(strict_types=1);

/**
 * Hourly status collection without modifying user settings:
 * 0 * * * * /usr/bin/php /var/www/imagopanel/public_html/cron/collect_statuses.php --prod >> /var/log/imagopanel-statuses.log 2>&1
 *
 * Use --task for TASK. Add --dry-run to inspect results without writing JSON.
 * Collect one user with --prefix=USER_PREFIX.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

$arguments = isset($_SERVER['argv']) && is_array($_SERVER['argv']) ? $_SERVER['argv'] : [];
if (in_array('--task', $arguments, true)) {
    $_SERVER['HTTP_HOST'] = 'task.lv';
}

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/DataStore.php';
require_once dirname(__DIR__) . '/lib/StatusStore.php';
require_once dirname(__DIR__) . '/lib/OpenDkimManager.php';

$dryRun = in_array('--dry-run', $arguments, true);
if (WIN && !$dryRun) {
    fwrite(STDERR, "Windows supports only --dry-run because Linux status commands are disabled\n");
    exit(4);
}
$selectedPrefix = '';
foreach ($arguments as $argument) {
    if (strpos($argument, '--prefix=') === 0) {
        $selectedPrefix = mb_strtolower(trim(substr($argument, 9)));
    }
}
if ($selectedPrefix !== '' && preg_match('/^[a-z][a-z0-9_]{1,31}$/', $selectedPrefix) !== 1) {
    fwrite(STDERR, "Invalid prefix\n");
    exit(2);
}

function statusCommand(array $command, array $replacements = [], array $environment = []): ?array
{
    if ($command === []) {
        return null;
    }
    $resolved = array_map(static function ($argument) use ($replacements): string {
        return strtr((string) $argument, $replacements);
    }, $command);
    $process = proc_open(
        $resolved,
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname(__DIR__),
        $environment === [] ? null : $environment,
        ['bypass_shell' => true]
    );
    if (!is_resource($process)) {
        return ['ok' => false, 'exitCode' => -1, 'stdout' => '', 'stderr' => 'Cannot start command', 'timedOut' => false];
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = '';
    $stderr = '';
    $started = microtime(true);
    $timedOut = false;
    $exitCode = -1;
    while (true) {
        $stdout .= (string) stream_get_contents($pipes[1]);
        $stderr .= (string) stream_get_contents($pipes[2]);
        $processStatus = proc_get_status($process);
        if (!$processStatus['running']) {
            $exitCode = (int) $processStatus['exitcode'];
            break;
        }
        if (microtime(true) - $started >= STATS_COMMAND_TIMEOUT_SECONDS) {
            $timedOut = true;
            proc_terminate($process);
            usleep(100000);
            $processStatus = proc_get_status($process);
            if ($processStatus['running']) {
                proc_terminate($process, 9);
            }
            break;
        }
        usleep(20000);
    }
    $stdout .= (string) stream_get_contents($pipes[1]);
    $stderr .= (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $closedCode = proc_close($process);
    if ($exitCode < 0 && $closedCode >= 0) {
        $exitCode = $closedCode;
    }
    $maximumOutput = 1048576;
    return [
        'ok' => !$timedOut && $exitCode === 0,
        'exitCode' => $exitCode,
        'stdout' => substr($stdout, 0, $maximumOutput),
        'stderr' => substr($stderr, 0, $maximumOutput),
        'timedOut' => $timedOut,
    ];
}

function statusNumber(?array $result): ?float
{
    if ($result === null || empty($result['ok'])) {
        return null;
    }
    return preg_match('/^\s*(\d+(?:\.\d+)?)/m', (string) $result['stdout'], $match) === 1 ? (float) $match[1] : null;
}

function statusError(array &$errors, string $scope, int $id, string $check, ?array $result, string $fallback): void
{
    $message = $fallback;
    if ($result !== null) {
        $message = trim((string) ($result['stderr'] ?? '')) ?: $fallback;
        if (!empty($result['timedOut'])) {
            $message = 'Command timeout';
        }
    }
    $errors[] = ['scope' => $scope, 'id' => $id, 'check' => $check, 'error' => mb_substr($message, 0, 500)];
}

function statusRelativePath(string $path): ?string
{
    $normalized = trim(str_replace('\\', '/', $path), '/');
    if ($normalized === '' || preg_match('/[\x00\r\n"]/', $normalized) === 1) {
        return null;
    }
    foreach (explode('/', $normalized) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return null;
        }
    }
    return $normalized;
}

function statusDnsValues(?array $result): array
{
    if ($result === null || empty($result['ok'])) {
        return [];
    }
    return array_values(array_filter(array_map('trim', preg_split('/\r?\n/', (string) $result['stdout']) ?: [])));
}

function statusDnsBound(?array $result): ?bool
{
    if ($result === null || empty($result['ok']) || STATS_HOSTING_PUBLIC_IPS === []) {
        return null;
    }
    return count(array_intersect(statusDnsValues($result), STATS_HOSTING_PUBLIC_IPS)) > 0;
}

function statusTxtMatches(?array $result, string $expected): ?bool
{
    if ($result === null || empty($result['ok'])) {
        return null;
    }
    $normalize = static function (string $value): string {
        return (string) preg_replace('/["\s]+/', '', $value);
    };
    return strpos($normalize((string) $result['stdout']), $normalize($expected)) !== false;
}

function collectUserStatus(array $document): array
{
    $started = microtime(true);
    $profile = is_array($document['profile'] ?? null) ? $document['profile'] : [];
    $prefix = (string) ($profile['prefix'] ?? '');
    $domains = is_array($document['resources']['domains'] ?? null) ? $document['resources']['domains'] : [];
    $databases = is_array($document['resources']['databases'] ?? null) ? $document['resources']['databases'] : [];
    $mailboxes = is_array($document['resources']['mail'] ?? null) ? $document['resources']['mail'] : [];
    $errors = [];
    $domainStatuses = [];
    $databaseStatuses = [];
    $mailStatuses = [];
    $countedPaths = [];
    $domainDns = [];

    foreach ($domains as $domain) {
        $id = (int) ($domain['id'] ?? 0);
        $name = mb_strtolower(trim((string) ($domain['domain'] ?? '')));
        $relativePath = statusRelativePath((string) ($domain['path'] ?? ''));
        $pathKey = $relativePath ?? '';
        $isPrimary = $pathKey !== '' && !isset($countedPaths[$pathKey]);
        $primaryDomain = $isPrimary ? $name : (string) ($countedPaths[$pathKey] ?? '');
        $folderBytes = null;
        $folderExists = null;
        if ($relativePath === null || preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $name) !== 1) {
            statusError($errors, 'domain', $id, 'configuration', null, 'Invalid domain or path');
        } elseif (!$isPrimary) {
            $folderBytes = 0.0;
            $folderExists = true;
        } else {
            $countedPaths[$pathKey] = $name;
            $absolutePath = rtrim(USER_WEB_ROOT_DIRECTORY, '/') . '/' . $prefix . '/' . $relativePath;
            $folderExists = STATS_DOMAIN_DIRECTORY_SIZE_COMMAND === [] ? null : is_dir($absolutePath);
            if ($folderExists === true) {
                $folderResult = statusCommand(STATS_DOMAIN_DIRECTORY_SIZE_COMMAND, ['{DOMAIN_PUBLIC_PATH}' => $absolutePath]);
                $folderBytes = statusNumber($folderResult);
                if ($folderResult !== null && $folderBytes === null) {
                    statusError($errors, 'domain', $id, 'folder_size', $folderResult, 'Cannot read domain folder size');
                }
            } elseif ($folderExists === false) {
                $folderBytes = 0.0;
                statusError($errors, 'domain', $id, 'folder_exists', null, 'Domain folder does not exist');
            }
        }

        $dnsResult = statusCommand(STATS_DOMAIN_DNS_CHECK_COMMAND, ['{DOMAIN}' => $name]);
        $wwwResult = statusCommand(STATS_DOMAIN_DNS_CHECK_COMMAND, ['{DOMAIN}' => 'www.' . $name]);
        $sslResult = statusCommand(STATS_SSL_CHECK_COMMAND, ['{DOMAIN}' => $name]);
        $dkimResult = statusCommand(STATS_DKIM_CHECK_COMMAND, ['{DOMAIN}' => $name, '{DKIM_SELECTOR}' => DNS_DKIM_SELECTOR]);
        $spfResult = statusCommand(STATS_SPF_CHECK_COMMAND, ['{DOMAIN}' => $name]);
        $dmarcResult = statusCommand(STATS_DMARC_CHECK_COMMAND, ['{DOMAIN}' => $name]);
        $dmarcExpected = str_replace('{domain}', $name, DNS_DMARC_VALUE);
        $dkimExpected = DNS_DKIM_VALUE;
        if (OPENDKIM_MANAGEMENT_MODE === OpenDkimManager::MODE_PER_DOMAIN) {
            try {
                $dkimExpected = OpenDkimManager::fromConfig()->dnsValue($name, false);
            } catch (Throwable $exception) {
                $dkimExpected = '';
                if (!empty($domain['active'])) statusError($errors, 'domain', $id, 'dkim_key', null, $exception->getMessage());
            }
        }
        $domainDns[$name] = [
            'dkim' => $dkimExpected === '' ? false : statusTxtMatches($dkimResult, $dkimExpected),
            'spf' => statusTxtMatches($spfResult, DNS_SPF_VALUE),
            'dmarc' => statusTxtMatches($dmarcResult, $dmarcExpected),
        ];
        $domainStatuses[] = [
            'id' => $id,
            'domain' => $name,
            'path' => $relativePath,
            'folderBytes' => $folderBytes,
            'folderExists' => $folderExists,
            'folderPrimary' => $isPrimary,
            'primaryDomain' => $primaryDomain,
            'bound' => statusDnsBound($dnsResult),
            'wwwBound' => statusDnsBound($wwwResult),
            'sslValid' => $sslResult === null ? null : !empty($sslResult['ok']),
            'dkim' => $domainDns[$name]['dkim'],
            'spf' => $domainDns[$name]['spf'],
            'dmarc' => $domainDns[$name]['dmarc'],
            'checkedAt' => gmdate('c'),
        ];
    }

    foreach ($databases as $database) {
        $id = (int) ($database['id'] ?? 0);
        $name = trim((string) ($database['name'] ?? ''));
        $bytes = null;
        $tables = null;
        $exists = null;
        if (preg_match('/^[a-z0-9_]{1,64}$/', $name) !== 1) {
            statusError($errors, 'database', $id, 'configuration', null, 'Invalid database name');
        } elseif (STATS_MYSQL_COMMAND !== []) {
            $replacements = [
                '{MYSQL_HOST}' => MYSQL_ADMIN_HOST,
                '{MYSQL_PORT}' => (string) MYSQL_ADMIN_PORT,
                '{MYSQL_USER}' => MYSQL_ADMIN_USER,
                '{SQL}' => str_replace('{DATABASE}', $name, STATS_DATABASE_SIZE_SQL),
            ];
            $environment = ['MYSQL_PWD' => MYSQL_ADMIN_PASSWORD, 'LANG' => 'C'];
            $sizeResult = statusCommand(STATS_MYSQL_COMMAND, $replacements, $environment);
            $bytes = statusNumber($sizeResult);
            $replacements['{SQL}'] = str_replace('{DATABASE}', $name, STATS_DATABASE_TABLE_COUNT_SQL);
            $tableResult = statusCommand(STATS_MYSQL_COMMAND, $replacements, $environment);
            $tableNumber = statusNumber($tableResult);
            $tables = $tableNumber === null ? null : (int) $tableNumber;
            $exists = $bytes !== null && $tables !== null;
            if ($sizeResult !== null && $bytes === null) {
                statusError($errors, 'database', $id, 'size', $sizeResult, 'Cannot read database size');
            }
            if ($tableResult !== null && $tables === null) {
                statusError($errors, 'database', $id, 'tables', $tableResult, 'Cannot read database tables');
            }
        }
        $databaseStatuses[] = ['id' => $id, 'name' => $name, 'bytes' => $bytes, 'tables' => $tables, 'exists' => $exists, 'checkedAt' => gmdate('c')];
    }

    foreach ($mailboxes as $mailbox) {
        $id = (int) ($mailbox['id'] ?? 0);
        $address = mb_strtolower(trim((string) ($mailbox['address'] ?? '')));
        $domain = mb_strtolower(trim((string) ($mailbox['domain'] ?? '')));
        $localPart = strpos($address, '@') === false ? '' : substr($address, 0, strrpos($address, '@'));
        $bytes = null;
        $exists = null;
        if ($localPart === '' || preg_match('/^[a-z0-9.!#$%&\'*+\/=?^_`{|}~-]{1,64}$/i', $localPart) !== 1
            || preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $domain) !== 1) {
            statusError($errors, 'mail', $id, 'configuration', null, 'Invalid mail address');
        } else {
            $mailPath = rtrim(MAIL_STORAGE_DIRECTORY, '/') . '/' . $domain . '/' . $localPart;
            $exists = STATS_MAILBOX_SIZE_COMMAND === [] ? null : is_dir($mailPath);
            if ($exists === true) {
                $mailResult = statusCommand(STATS_MAILBOX_SIZE_COMMAND, ['{MAILBOX_PATH}' => $mailPath]);
                $bytes = statusNumber($mailResult);
                if ($mailResult !== null && $bytes === null) {
                    statusError($errors, 'mail', $id, 'size', $mailResult, 'Cannot read mailbox size');
                }
            } elseif ($exists === false) {
                $bytes = 0.0;
                statusError($errors, 'mail', $id, 'exists', null, 'Mailbox directory does not exist');
            }
        }
        $dns = $domainDns[$domain] ?? ['dkim' => null, 'spf' => null, 'dmarc' => null];
        $mailStatuses[] = [
            'id' => $id,
            'address' => $address,
            'bytes' => $bytes,
            'exists' => $exists,
            'dkim' => $dns['dkim'],
            'spf' => $dns['spf'],
            'dmarc' => $dns['dmarc'],
            'checkedAt' => gmdate('c'),
        ];
    }

    $sum = static function (array $rows, string $field): float {
        return array_reduce($rows, static function (float $total, array $row) use ($field): float {
            return $total + (float) ($row[$field] ?? 0);
        }, 0.0);
    };
    $existingMailboxes = count(array_filter($mailStatuses, static function (array $row): bool { return !empty($row['exists']); }));
    return [
        'schemaVersion' => 1,
        'prefix' => $prefix,
        'userId' => (int) ($profile['id'] ?? 0),
        'collectedAt' => gmdate('c'),
        'durationMs' => (int) round((microtime(true) - $started) * 1000),
        'ok' => $errors === [],
        'errors' => $errors,
        'summary' => [
            'domains' => count($domainStatuses),
            'siteBytes' => $sum($domainStatuses, 'folderBytes'),
            'databases' => count($databaseStatuses),
            'databaseBytes' => $sum($databaseStatuses, 'bytes'),
            'mailAccounts' => count($mailStatuses),
            'mailAccountsExisting' => $existingMailboxes,
            'mailBytes' => $sum($mailStatuses, 'bytes'),
        ],
        'resources' => ['domains' => $domainStatuses, 'databases' => $databaseStatuses, 'mail' => $mailStatuses],
    ];
}

$lockDirectory = dirname(STATS_CRON_LOCK_FILE);
if (!is_dir($lockDirectory) && !mkdir($lockDirectory, 0755, true) && !is_dir($lockDirectory)) {
    fwrite(STDERR, "Cannot create cron lock directory\n");
    exit(1);
}
$lock = fopen(STATS_CRON_LOCK_FILE, 'c');
if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Status collection is already running\n");
    exit(0);
}

try {
    $dataStore = new DataStore(DATA_DIRECTORY);
    $documents = $dataStore->listDocuments();
    $statusStore = $dryRun ? null : new StatusStore(STATUS_DIRECTORY);
    $result = [];
    foreach ($documents as $document) {
        $prefix = (string) ($document['profile']['prefix'] ?? '');
        if ($selectedPrefix !== '' && $prefix !== $selectedPrefix) {
            continue;
        }
        $status = collectUserStatus($document);
        if ($statusStore !== null) {
            $statusStore->write($prefix, $status);
        }
        $result[] = $status;
        fwrite(STDOUT, sprintf("%s: %s, %d ms, %d errors\n", $prefix, $status['ok'] ? 'OK' : 'WARNING', $status['durationMs'], count($status['errors'])));
    }
    if ($selectedPrefix !== '' && $result === []) {
        fwrite(STDERR, "User prefix not found\n");
        exit(3);
    }
    if ($dryRun) {
        fwrite(STDOUT, json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . PHP_EOL);
    }
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
} finally {
    flock($lock, LOCK_UN);
    fclose($lock);
}
