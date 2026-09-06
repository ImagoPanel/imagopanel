<?php
declare(strict_types=1);

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailException;

function panelPublicBaseUrl(): string
{
    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    if ($host === '' || preg_match('/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/D', $host) !== 1) {
        $host = 'example.com';
    }
    $scheme = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
    $directory = trim(str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
    return $scheme . '://' . $host . ($directory === '' ? '' : '/' . $directory);
}

function panelMailShell(string $title, string $intro, string $content, string $buttonLabel = '', string $buttonUrl = ''): string
{
    $button = '';
    if ($buttonLabel !== '' && $buttonUrl !== '') {
        $button = '<p style="margin:28px 0 8px"><a href="' . htmlspecialchars($buttonUrl, ENT_QUOTES, 'UTF-8')
            . '" style="display:inline-block;background:#33e19b;color:#071323;text-decoration:none;font-weight:700;padding:13px 22px;border-radius:10px">'
            . htmlspecialchars($buttonLabel, ENT_QUOTES, 'UTF-8') . '</a></p>';
    }
    return '<!doctype html><html><body style="margin:0;background:#f3f6fa;color:#13213a;font-family:Arial,sans-serif">'
        . '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 12px"><tr><td align="center">'
        . '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 35px rgba(7,19,35,.12)">'
        . '<tr><td style="background:#071323;color:#fff;padding:24px 30px;font-size:22px;font-weight:800">ImagoPanel</td></tr>'
        . '<tr><td style="padding:32px 30px"><h1 style="font-size:28px;line-height:1.2;margin:0 0 14px;color:#071323">'
        . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1><p style="font-size:16px;line-height:1.6;color:#60708a;margin:0 0 24px">'
        . htmlspecialchars($intro, ENT_QUOTES, 'UTF-8') . '</p>' . $content . $button
        . '<p style="font-size:13px;line-height:1.5;color:#8793a6;margin:28px 0 0">Если вы не выполняли это действие, просто проигнорируйте письмо.</p>'
        . '</td></tr></table></td></tr></table></body></html>';
}

function panelSendHtmlMail(string $recipient, string $subject, string $html, string $plainText): void
{
    if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        throw new InvalidArgumentException('Invalid recipient email');
    }
    try {
        $mailer = new PHPMailer(true);
        $transport = mb_strtolower(trim(PANEL_MAIL_TRANSPORT));
        if ($transport === 'smtp') {
            if (PANEL_SMTP_HOST === '') throw new RuntimeException('SMTP host is not configured');
            $mailer->isSMTP();
            $mailer->Host = PANEL_SMTP_HOST;
            $mailer->Port = PANEL_SMTP_PORT;
            $mailer->SMTPAuth = PANEL_SMTP_USERNAME !== '';
            if ($mailer->SMTPAuth) {
                $mailer->Username = PANEL_SMTP_USERNAME;
                $mailer->Password = PANEL_SMTP_PASSWORD;
            }
            if (PANEL_SMTP_ENCRYPTION !== '') $mailer->SMTPSecure = PANEL_SMTP_ENCRYPTION;
        } elseif ($transport === 'mail') {
            $mailer->isMail();
        } else {
            throw new RuntimeException('Unsupported panel mail transport');
        }
        $mailer->CharSet = 'UTF-8';
        $mailer->setFrom(PANEL_MAIL_FROM, PANEL_MAIL_FROM_NAME);
        $mailer->addAddress($recipient);
        $mailer->isHTML(true);
        $mailer->Subject = $subject;
        $mailer->Body = $html;
        $mailer->AltBody = $plainText;
        $mailer->send();
    } catch (MailException $exception) {
        error_log('ImagoPanel mail error: ' . $exception->getMessage());
        throw new RuntimeException('Cannot send email');
    }
}

function panelSendLoginCode(string $recipient, string $code, string $token): void
{
    $url = panelPublicBaseUrl() . '/?verify_login=' . rawurlencode($token);
    $content = '<div style="background:#f0fff8;border:1px solid #b9f4dc;border-radius:14px;padding:20px;text-align:center">'
        . '<div style="font-size:13px;color:#60708a;margin-bottom:8px">Проверочный код</div>'
        . '<div style="font-size:36px;letter-spacing:8px;font-weight:800;color:#071323">' . htmlspecialchars($code, ENT_QUOTES, 'UTF-8') . '</div>'
        . '<div style="font-size:13px;color:#60708a;margin-top:8px">Действует ' . (int) ceil(USER_LOGIN_2FA_TTL_SECONDS / 60) . ' минут.</div></div>';
    panelSendHtmlMail(
        $recipient,
        'Код входа в ImagoPanel',
        panelMailShell('Подтвердите вход', 'Введите код в панели или откройте ссылку в том же браузере.', $content, 'Подтвердить вход', $url),
        'Код входа ImagoPanel: ' . $code . '. Ссылка: ' . $url
    );
}

function panelSendTariffRequest(string $recipient, array $profile, array $currentTariff, array $requestedTariff): void
{
    $content = '<table role="presentation" width="100%" cellspacing="0" cellpadding="8" style="border-collapse:collapse">'
        . '<tr><td style="color:#60708a">Пользователь</td><td><strong>' . htmlspecialchars((string) ($profile['email'] ?? ''), ENT_QUOTES, 'UTF-8') . '</strong></td></tr>'
        . '<tr><td style="color:#60708a">Текущий тариф</td><td><strong>' . htmlspecialchars((string) ($currentTariff['name'] ?? ''), ENT_QUOTES, 'UTF-8') . '</strong></td></tr>'
        . '<tr><td style="color:#60708a">Запрошенный тариф</td><td><strong>' . htmlspecialchars((string) ($requestedTariff['name'] ?? ''), ENT_QUOTES, 'UTF-8') . '</strong></td></tr></table>';
    panelSendHtmlMail($recipient, 'Запрос смены тарифа ImagoPanel', panelMailShell('Запрос смены тарифа', 'Пользователь отправил запрос из своего профиля.', $content), 'Пользователь ' . ($profile['email'] ?? '') . ' просит сменить тариф с ' . ($currentTariff['name'] ?? '') . ' на ' . ($requestedTariff['name'] ?? ''));
}
