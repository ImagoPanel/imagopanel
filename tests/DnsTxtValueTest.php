<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/DnsTxtValue.php';
require_once dirname(__DIR__) . '/lib/HetznerDnsProvider.php';
require_once dirname(__DIR__) . '/lib/InternetBsDnsProvider.php';

function dnsTxtAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$dkim = 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmuAdl/N8zFHmHnvJrOePalFTjOhu7QPKCZCIO/wQfS1jsPNpzU8HrCCIsxVupcbX32sTR4GRuDejktqXsH/95rXfyoNRXexb+6MfBZc+iLyoQChKjQcRwqs9r8oqs/zdFSx9iemEtuf5DCJq6Mvpix9Arkw/+VmLXil/m0VvDV/ozKe6RcdBkSxqJthtiO7iinmv2e/qFfDP3PXqz6XzzeegfAMgizPdEzH0yPkmbPvFm31aJdfqJoI0RyatU4nCeQOYP+VvybrTkk8ra6wsJvVwZIUws72b7C+iJJPhzwC0yNJaHYTyvPPpu+bpmoGjC8ijHXZ36YDk1LFIvrLPJwIDAQAB';
$wire = DnsTxtValue::toPresentation($dkim);
$chunks = explode('" "', substr($wire, 1, -1));
$hetznerWireValue = new ReflectionMethod(HetznerDnsProvider::class, 'wireValue');
$hetznerWireValue->setAccessible(true);
$internetBsWireRecord = new ReflectionMethod(InternetBsDnsProvider::class, 'wireRecord');
$internetBsWireRecord->setAccessible(true);
$internetBsDisplayValue = new ReflectionMethod(InternetBsDnsProvider::class, 'displayValue');
$internetBsDisplayValue->setAccessible(true);

dnsTxtAssert(count($chunks) === 2, 'Long DKIM must be split into two TXT character-strings');
foreach ($chunks as $chunk) dnsTxtAssert(strlen($chunk) <= 255, 'TXT character-string exceeds 255 bytes');
dnsTxtAssert(DnsTxtValue::toDisplay($wire) === $dkim, 'Chunked DKIM must decode to the original value');
dnsTxtAssert($hetznerWireValue->invoke(null, 'TXT', $dkim) === $wire, 'Hetzner provider must use chunked TXT presentation');
$internetBsWire = $internetBsWireRecord->invoke(null, 'TXT', $dkim);
dnsTxtAssert(($internetBsWire['value'] ?? '') === $wire, 'Internet.bs provider must use chunked TXT presentation');
dnsTxtAssert($internetBsDisplayValue->invoke(null, 'TXT', $wire, 0) === $dkim, 'Internet.bs provider must display the logical TXT value');
dnsTxtAssert(DnsTxtValue::toPresentation('short value') === '"short value"', 'Short TXT value must remain one string');

$escaped = 'value with "quotes" and \\slashes';
dnsTxtAssert(DnsTxtValue::toDisplay(DnsTxtValue::toPresentation($escaped)) === $escaped, 'TXT escaping must round-trip');

$unicode = str_repeat('Ж', 200);
$unicodeWire = DnsTxtValue::toPresentation($unicode);
dnsTxtAssert(DnsTxtValue::toDisplay($unicodeWire) === $unicode, 'UTF-8 TXT chunks must round-trip');
foreach (explode('" "', substr($unicodeWire, 1, -1)) as $chunk) {
    dnsTxtAssert(strlen($chunk) <= 255 && preg_match('//u', $chunk) === 1, 'UTF-8 TXT chunk must be valid and at most 255 bytes');
}

echo "DnsTxtValue tests passed\n";
