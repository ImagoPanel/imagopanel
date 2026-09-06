<?php
declare(strict_types=1);

/**
 * Sends a privileged operation to root/root.php through STDIN and receives
 * JSON through STDOUT. Process diagnostics are read only from STDERR.
 * Linux TASK/PROD always uses sudo -n; the Windows call exists only to test
 * the protocol locally with the installed PHP CLI. TASK/PROD is passed as a
 * CLI argument because the child process does not receive HTTP_HOST.
 */
function rootRequest(string $action, array $params = []): array
{
    if ($action === '') {
        return ['ok' => false, 'data' => null, 'error' => 'Root action is required'];
    }

    $auth = isset($_SESSION['auth']) && is_array($_SESSION['auth']) ? $_SESSION['auth'] : [];
    $actorRole = (string) ($auth['role'] ?? '');
    $request = [
        'action' => $action,
        'params' => $params,
        'meta' => [
            'actor_role' => $actorRole,
            'client_ip' => function_exists('panelClientIp') ? panelClientIp() : '',
            'user_email' => $actorRole === 'user' ? (string) ($auth['email'] ?? '') : '',
            'user_prefix' => $actorRole === 'user' ? (string) ($auth['prefix'] ?? '') : '',
        ],
    ];
    $encoded = json_encode($request, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($encoded === false) {
        return ['ok' => false, 'data' => null, 'error' => 'Cannot encode root request'];
    }

    if (WIN) {
        if (!ROOT_ALLOW_WINDOWS_DIRECT_CALL) {
            return ['ok' => false, 'data' => null, 'error' => 'Direct Windows root.php call is disabled'];
        }
        $command = [ROOT_WINDOWS_PHP_BINARY, '-d', 'display_errors=stderr', '-d', 'display_startup_errors=0', ROOT_SCRIPT_PATH, '--win'];
    } else {
        $command = [
            ROOT_SUDO_BINARY,
            '-n',
            ROOT_PHP_BINARY,
            '-d',
            'display_errors=stderr',
            '-d',
            'display_startup_errors=0',
            ROOT_SCRIPT_PATH,
            TASK ? '--task' : '--prod',
        ];
    }

    $process = proc_open(
        $command,
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
        dirname(ROOT_SCRIPT_PATH),
        null,
        ['bypass_shell' => true]
    );

    if (!is_resource($process)) {
        return ['ok' => false, 'data' => null, 'error' => 'Cannot start root.php'];
    }

    fwrite($pipes[0], $encoded);
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1], ROOT_RESPONSE_MAX_BYTES + 1);
    $stderr = stream_get_contents($pipes[2], ROOT_RESPONSE_MAX_BYTES + 1);
    fclose($pipes[1]);
    fclose($pipes[2]);

    $exitCode = proc_close($process);
    if ($exitCode !== 0) {
        return [
            'ok' => false,
            'data' => null,
            'error' => trim((string) $stderr) ?: 'root.php failed',
            'exit_code' => $exitCode,
        ];
    }

    if (strlen((string) $stdout) > ROOT_RESPONSE_MAX_BYTES) {
        return ['ok' => false, 'data' => null, 'error' => 'root.php response is too large'];
    }

    $response = json_decode((string) $stdout, true);
    if (!is_array($response) || !array_key_exists('ok', $response)) {
        return ['ok' => false, 'data' => null, 'error' => 'Invalid JSON from root.php'];
    }

    return $response;
}
