<?php


declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';

header('Content-Type: text/xml; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
header('X-Content-Type-Options: nosniff');

function mailAutoconfigXml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
}

function mailAutoconfigDomain(string $value): string
{
    $value = mb_strtolower(rtrim(trim($value), '.'));
    if (preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/D', $value) !== 1) {
        return '';
    }
    return $value;
}

function mailAutoconfigEmail(string $value): string
{
    $value = trim(html_entity_decode($value, ENT_QUOTES | ENT_XML1, 'UTF-8'));
    if (strlen($value) > 320 || filter_var($value, FILTER_VALIDATE_EMAIL) === false) return '';
    return $value;
}

function mailAutoconfigRequestEmail(): string
{
    $email = mailAutoconfigEmail((string) ($_GET['emailaddress'] ?? $_GET['email'] ?? ''));
    if ($email !== '') return $email;

    $body = file_get_contents('php://input');
    if (!is_string($body) || $body === '' || strlen($body) > 65536) return '';
    if (preg_match('/<\s*(?:[a-z0-9_-]+:)?EMailAddress\s*>\s*([^<]{3,320})\s*<\/\s*(?:[a-z0-9_-]+:)?EMailAddress\s*>/iu', $body, $match) !== 1) {
        return '';
    }
    return mailAutoconfigEmail($match[1]);
}

function mailAutoconfigHostDomain(): string
{
    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    if (preg_match('/^\[([^]]+)](?::\d+)?$/D', $host, $match) === 1) return '';
    $host = preg_replace('/:\d+$/D', '', $host) ?? '';
    $host = preg_replace('/^(?:autoconfig|autodiscover)\./i', '', $host) ?? '';
    return mailAutoconfigDomain($host);
}

function mailAutoconfigRequestedDomain(string $email): string
{
    if ($email !== '') {
        $separator = strrpos($email, '@');
        if ($separator !== false) {
            $domain = mailAutoconfigDomain(substr($email, $separator + 1));
            if ($domain !== '') return $domain;
        }
    }
    return mailAutoconfigHostDomain();
}

function mailAutoconfigThunderbirdXml(string $domain): string
{
    $domainXml = mailAutoconfigXml($domain);
    $imapHost = mailAutoconfigXml(rtrim(MAIL_CLIENT_IMAP_HOST, '.'));
    $pop3Host = mailAutoconfigXml(rtrim(MAIL_CLIENT_POP3_HOST, '.'));
    $smtpHost = mailAutoconfigXml(rtrim(MAIL_CLIENT_SMTP_HOST, '.'));

    return '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<clientConfig version="1.1">' . "\n"
        . '  <emailProvider id="' . $domainXml . '">' . "\n"
        . '    <domain>' . $domainXml . '</domain>' . "\n"
        . '    <displayName>' . $domainXml . ' Mail</displayName>' . "\n"
        . '    <displayShortName>' . $domainXml . '</displayShortName>' . "\n"
        . '    <incomingServer type="pop3">' . "\n"
        . '      <hostname>' . $pop3Host . '</hostname>' . "\n"
        . '      <port>' . MAIL_CLIENT_POP3_PORT . '</port>' . "\n"
        . '      <socketType>SSL</socketType>' . "\n"
        . '      <authentication>password-cleartext</authentication>' . "\n"
        . '      <username>%EMAILADDRESS%</username>' . "\n"
        . '    </incomingServer>' . "\n"
        . '    <incomingServer type="imap">' . "\n"
        . '      <hostname>' . $imapHost . '</hostname>' . "\n"
        . '      <port>' . MAIL_CLIENT_IMAP_PORT . '</port>' . "\n"
        . '      <socketType>SSL</socketType>' . "\n"
        . '      <authentication>password-cleartext</authentication>' . "\n"
        . '      <username>%EMAILADDRESS%</username>' . "\n"
        . '    </incomingServer>' . "\n"
        . '    <outgoingServer type="smtp">' . "\n"
        . '      <hostname>' . $smtpHost . '</hostname>' . "\n"
        . '      <port>' . MAIL_CLIENT_SMTP_PORT . '</port>' . "\n"
        . '      <socketType>SSL</socketType>' . "\n"
        . '      <authentication>password-cleartext</authentication>' . "\n"
        . '      <username>%EMAILADDRESS%</username>' . "\n"
        . '    </outgoingServer>' . "\n"
        . '    <outgoingServer type="smtp">' . "\n"
        . '      <hostname>' . $smtpHost . '</hostname>' . "\n"
        . '      <port>' . MAIL_CLIENT_SMTP_STARTTLS_PORT . '</port>' . "\n"
        . '      <socketType>STARTTLS</socketType>' . "\n"
        . '      <authentication>password-cleartext</authentication>' . "\n"
        . '      <username>%EMAILADDRESS%</username>' . "\n"
        . '    </outgoingServer>' . "\n"
        . '  </emailProvider>' . "\n"
        . '</clientConfig>' . "\n";
}

function mailAutoconfigAutodiscoverProtocol(string $type, string $host, int $port, string $email): string
{
    return '      <Protocol>' . "\n"
        . '        <Type>' . mailAutoconfigXml($type) . '</Type>' . "\n"
        . '        <Server>' . mailAutoconfigXml(rtrim($host, '.')) . '</Server>' . "\n"
        . '        <Port>' . $port . '</Port>' . "\n"
        . '        <DomainRequired>off</DomainRequired>' . "\n"
        . '        <LoginName>' . mailAutoconfigXml($email) . '</LoginName>' . "\n"
        . '        <SPA>off</SPA>' . "\n"
        . '        <SSL>on</SSL>' . "\n"
        . '        <AuthRequired>on</AuthRequired>' . "\n"
        . ($type === 'SMTP' ? '        <UsePOPAuth>off</UsePOPAuth>' . "\n" . '        <SMTPLast>off</SMTPLast>' . "\n" : '')
        . '      </Protocol>' . "\n";
}

function mailAutoconfigAutodiscoverXml(string $email, string $domain): string
{
    return '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">' . "\n"
        . '  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">' . "\n"
        . '    <User><DisplayName>' . mailAutoconfigXml($domain . ' Mail') . '</DisplayName><AutoDiscoverSMTPAddress>' . mailAutoconfigXml($email) . '</AutoDiscoverSMTPAddress></User>' . "\n"
        . '    <Account>' . "\n"
        . '      <AccountType>email</AccountType>' . "\n"
        . '      <Action>settings</Action>' . "\n"
        . mailAutoconfigAutodiscoverProtocol('POP3', MAIL_CLIENT_POP3_HOST, MAIL_CLIENT_POP3_PORT, $email)
        . mailAutoconfigAutodiscoverProtocol('IMAP', MAIL_CLIENT_IMAP_HOST, MAIL_CLIENT_IMAP_PORT, $email)
        . mailAutoconfigAutodiscoverProtocol('SMTP', MAIL_CLIENT_SMTP_HOST, MAIL_CLIENT_SMTP_PORT, $email)
        . '    </Account>' . "\n"
        . '  </Response>' . "\n"
        . '</Autodiscover>' . "\n";
}

function mailAutoconfigUuid(string $seed): string
{
    $hex = substr(hash('sha256', $seed), 0, 32);
    return substr($hex, 0, 8) . '-'
        . substr($hex, 8, 4) . '-'
        . substr($hex, 12, 4) . '-'
        . substr($hex, 16, 4) . '-'
        . substr($hex, 20, 12);
}

function mailAutoconfigAppleXml(string $email, string $domain, string $protocol): string
{
    $protocol = strtoupper($protocol);
    $imap = $protocol === 'IMAP';
    $accountType = $imap ? 'EmailTypeIMAP' : 'EmailTypePOP';
    $incomingHost = $imap ? MAIL_CLIENT_IMAP_HOST : MAIL_CLIENT_POP3_HOST;
    $incomingPort = $imap ? MAIL_CLIENT_IMAP_PORT : MAIL_CLIENT_POP3_PORT;
    $identity = $email !== '' ? $email : $domain;
    $profileSeed = 'imagopanel-apple-profile|' . $identity . '|' . $protocol;
    $profileUuid = mailAutoconfigUuid($profileSeed);
    $mailUuid = mailAutoconfigUuid($profileSeed . '|mail');
    $identifierSuffix = substr(hash('sha256', $profileSeed), 0, 24);
    $profileIdentifier = 'com.imagopanel.mail.profile.' . $identifierSuffix;
    $mailIdentifier = $profileIdentifier . '.account';
    $displayName = ($email !== '' ? $email : $domain . ' Mail') . ' (' . $protocol . ')';
    $emailFields = '';

    if ($email !== '') {
        $emailXml = mailAutoconfigXml($email);
        $emailFields = '            <key>EmailAccountName</key>' . "\n"
            . '            <string>' . $emailXml . '</string>' . "\n"
            . '            <key>EmailAddress</key>' . "\n"
            . '            <string>' . $emailXml . '</string>' . "\n"
            . '            <key>IncomingMailServerUsername</key>' . "\n"
            . '            <string>' . $emailXml . '</string>' . "\n"
            . '            <key>OutgoingMailServerUsername</key>' . "\n"
            . '            <string>' . $emailXml . '</string>' . "\n";
    }

    return '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' . "\n"
        . '<plist version="1.0">' . "\n"
        . '<dict>' . "\n"
        . '    <key>PayloadContent</key>' . "\n"
        . '    <array>' . "\n"
        . '        <dict>' . "\n"
        . '            <key>EmailAccountDescription</key>' . "\n"
        . '            <string>' . mailAutoconfigXml($displayName) . '</string>' . "\n"
        . '            <key>EmailAccountType</key>' . "\n"
        . '            <string>' . $accountType . '</string>' . "\n"
        . $emailFields
        . '            <key>IncomingMailServerAuthentication</key>' . "\n"
        . '            <string>EmailAuthPassword</string>' . "\n"
        . '            <key>IncomingMailServerHostName</key>' . "\n"
        . '            <string>' . mailAutoconfigXml(rtrim($incomingHost, '.')) . '</string>' . "\n"
        . '            <key>IncomingMailServerPortNumber</key>' . "\n"
        . '            <integer>' . $incomingPort . '</integer>' . "\n"
        . '            <key>IncomingMailServerUseSSL</key>' . "\n"
        . '            <true/>' . "\n"
        . '            <key>OutgoingMailServerAuthentication</key>' . "\n"
        . '            <string>EmailAuthPassword</string>' . "\n"
        . '            <key>OutgoingMailServerHostName</key>' . "\n"
        . '            <string>' . mailAutoconfigXml(rtrim(MAIL_CLIENT_SMTP_HOST, '.')) . '</string>' . "\n"
        . '            <key>OutgoingMailServerPortNumber</key>' . "\n"
        . '            <integer>' . MAIL_CLIENT_SMTP_PORT . '</integer>' . "\n"
        . '            <key>OutgoingMailServerUseSSL</key>' . "\n"
        . '            <true/>' . "\n"
        . '            <key>OutgoingPasswordSameAsIncomingPassword</key>' . "\n"
        . '            <true/>' . "\n"
        . '            <key>PayloadDisplayName</key>' . "\n"
        . '            <string>Apple Mail</string>' . "\n"
        . '            <key>PayloadIdentifier</key>' . "\n"
        . '            <string>' . $mailIdentifier . '</string>' . "\n"
        . '            <key>PayloadType</key>' . "\n"
        . '            <string>com.apple.mail.managed</string>' . "\n"
        . '            <key>PayloadUUID</key>' . "\n"
        . '            <string>' . $mailUuid . '</string>' . "\n"
        . '            <key>PayloadVersion</key>' . "\n"
        . '            <integer>1</integer>' . "\n"
        . '        </dict>' . "\n"
        . '    </array>' . "\n"
        . '    <key>PayloadDescription</key>' . "\n"
        . '    <string>Secure Apple Mail settings for ' . mailAutoconfigXml($identity) . '. The password is requested during installation.</string>' . "\n"
        . '    <key>PayloadDisplayName</key>' . "\n"
        . '    <string>' . mailAutoconfigXml($displayName) . '</string>' . "\n"
        . '    <key>PayloadIdentifier</key>' . "\n"
        . '    <string>' . $profileIdentifier . '</string>' . "\n"
        . '    <key>PayloadOrganization</key>' . "\n"
        . '    <string>ImagoPanel</string>' . "\n"
        . '    <key>PayloadRemovalDisallowed</key>' . "\n"
        . '    <false/>' . "\n"
        . '    <key>PayloadType</key>' . "\n"
        . '    <string>Configuration</string>' . "\n"
        . '    <key>PayloadUUID</key>' . "\n"
        . '    <string>' . $profileUuid . '</string>' . "\n"
        . '    <key>PayloadVersion</key>' . "\n"
        . '    <integer>1</integer>' . "\n"
        . '</dict>' . "\n"
        . '</plist>' . "\n";
}

function mailAutoconfigAppleFileName(string $email, string $domain, string $protocol): string
{
    $base = $email !== '' ? str_replace('@', '-', mb_strtolower($email)) : $domain;
    $base = preg_replace('/[^a-z0-9._-]+/', '-', $base) ?? 'mail';
    $base = trim($base, '.-_');
    if ($base === '') $base = 'mail';
    return $base . '-' . mb_strtolower($protocol) . '.mobileconfig';
}

function mailAutoconfigError(string $message, int $status): void
{
    http_response_code($status);
    echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<error><message>' . mailAutoconfigXml($message) . '</message></error>' . "\n";
    exit;
}

$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if (!in_array($method, ['GET', 'POST', 'HEAD'], true)) {
    header('Allow: GET, POST, HEAD');
    mailAutoconfigError('Method not allowed', 405);
}

$path = mb_strtolower((string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?? '/'));
$autodiscoverPath = $path === '/autodiscover/autodiscover.xml';
$applePaths = [
    '/mail/apple.mobileconfig' => strtoupper((string) MAIL_CLIENT_APPLE_DEFAULT_PROTOCOL),
    '/mail/apple-pop3.mobileconfig' => 'POP3',
    '/mail/apple-imap.mobileconfig' => 'IMAP',
];
$appleProtocol = (string) ($applePaths[$path] ?? '');
$applePath = $appleProtocol !== '';
$mozillaPaths = [
    '/mail/config-v1.1.xml',
    '/.well-known/autoconfig/mail/config-v1.1.xml',
    '/config.xml',
];
if (!$autodiscoverPath && !$applePath && !in_array($path, $mozillaPaths, true)) mailAutoconfigError('Unknown autoconfiguration path', 404);

foreach ([MAIL_CLIENT_IMAP_HOST, MAIL_CLIENT_POP3_HOST, MAIL_CLIENT_SMTP_HOST, MAIL_CLIENT_AUTODISCOVER_HOST] as $configuredHost) {
    if (mailAutoconfigDomain((string) $configuredHost) === '') mailAutoconfigError('Invalid mail server configuration', 500);
}
foreach ([MAIL_CLIENT_IMAP_PORT, MAIL_CLIENT_POP3_PORT, MAIL_CLIENT_SMTP_PORT, MAIL_CLIENT_SMTP_STARTTLS_PORT, MAIL_CLIENT_AUTODISCOVER_PORT] as $configuredPort) {
    if (!is_int($configuredPort) || $configuredPort < 1 || $configuredPort > 65535) mailAutoconfigError('Invalid mail port configuration', 500);
}

$email = mailAutoconfigRequestEmail();
$domain = mailAutoconfigRequestedDomain($email);
if ($domain === '') mailAutoconfigError('Invalid or missing mail domain', 400);
if ($autodiscoverPath && $email === '') mailAutoconfigError('Valid EMailAddress is required', 400);
if ($applePath && !in_array($appleProtocol, ['POP3', 'IMAP'], true)) mailAutoconfigError('Invalid Apple mail protocol configuration', 500);
if ($applePath && (array_key_exists('email', $_GET) || array_key_exists('emailaddress', $_GET)) && $email === '') {
    mailAutoconfigError('Invalid Apple mail address', 400);
}

$response = '';
if ($applePath) {
    header('Content-Type: application/x-apple-aspen-config');
    header('Content-Disposition: attachment; filename="' . mailAutoconfigAppleFileName($email, $domain, $appleProtocol) . '"');
    $response = mailAutoconfigAppleXml($email, $domain, $appleProtocol);
} elseif ($autodiscoverPath) {
    $response = mailAutoconfigAutodiscoverXml($email, $domain);
} else {
    $response = mailAutoconfigThunderbirdXml($domain);
}
if ($method !== 'HEAD') echo $response;
