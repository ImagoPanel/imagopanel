# Mail client autoconfiguration

`index.php` is the only request handler. It determines the domain from the
`emailaddress` query parameter, the Outlook `EMailAddress` POST value, or the
HTTP host, then returns a response for the requested URL:

- `/mail/config-v1.1.xml` — Mozilla/Thunderbird Autoconfig 1.1;
- `/.well-known/autoconfig/mail/config-v1.1.xml` — Mozilla well-known Autoconfig;
- `/autodiscover/autodiscover.xml` — Microsoft Outlook POX Autodiscover;
- `/config.xml` — the same compatible Mozilla Autoconfig 1.1 response;
- `/mail/apple.mobileconfig` — an Apple Mail profile using the protocol selected
  by `MAIL_CLIENT_APPLE_DEFAULT_PROTOCOL` (POP3 is preferred by default);
- `/mail/apple-pop3.mobileconfig` — an Apple Mail POP3S profile;
- `/mail/apple-imap.mobileconfig` — an Apple Mail IMAPS profile.

Physical nested directories are not required for these URLs. Every path is
mapped globally to the same PHP file by one exact Apache `AliasMatch`. Apple
profiles support interactive installation on iPhone, iPad, and macOS. The
mailbox address is supplied in the `email` parameter. The password is
intentionally omitted and is requested by the device during installation.

This directory does not need a local `.htaccess`. Access, PHP-FPM routing, and
response headers are configured once globally for all hosted domains.

## One-time configuration for every domain

1. Copy `apache-mailautoconfig.conf.example` to the global Apache configuration
   directory, for example `/etc/httpd/conf.d/imagopanel-mailautoconfig.conf`.
2. If ImagoPanel is not installed in `/var/www/imagopanel/public_html`, replace
   the path in `AliasMatch` and `<Directory>`.
3. Verify the PHP 7.4 socket in `SetHandler`. The example uses
   `/run/php-fpm/www.sock`; Remi installations commonly use
   `/var/opt/remi/php74/run/php-fpm/www.sock`.
4. Ensure that `mod_alias`, `mod_headers`, and `mod_proxy_fcgi` are loaded.
5. Run `httpd -t`. Reload Apache with `systemctl reload httpd` only after the
   result is `Syntax OK`.

These directives are global. Do not add them to `{USER}.conf` or to every
`<VirtualHost>`. Place the exact `AliasMatch` before any general Alias for
`/mail/`, `/.well-known/`, or `/autodiscover/`.

`index.php` and the global `<LocationMatch>` send `no-store` and `no-cache`
headers, preventing browsers and intermediate proxies from caching
configuration responses. PHP-FPM also disables error display for this handler
so errors cannot corrupt XML responses; errors remain available in the PHP
error log.

## Settings

Hosts and ports are read only from the root `config.php`:

- `MAIL_CLIENT_IMAP_HOST`, `MAIL_CLIENT_IMAP_PORT`;
- `MAIL_CLIENT_POP3_HOST`, `MAIL_CLIENT_POP3_PORT`;
- `MAIL_CLIENT_SMTP_HOST`, `MAIL_CLIENT_SMTP_PORT`;
- `MAIL_CLIENT_SMTP_STARTTLS_PORT`;
- `MAIL_CLIENT_AUTODISCOVER_HOST`, `MAIL_CLIENT_AUTODISCOVER_PORT`;
- `MAIL_CLIENT_APPLE_DEFAULT_PROTOCOL` — `POP3` or `IMAP` for the common Apple URL.

The same values generate the recommended DNS SRV records in
`DNS_API_RECOMMENDED_RECORDS`.

## Post-installation checks

```bash
curl -i 'https://example.com/mail/config-v1.1.xml?emailaddress=admin@example.com'
curl -i 'https://example.com/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=admin@example.com'
curl -i 'https://example.com/config.xml?emailaddress=admin@example.com'
curl -i -H 'Content-Type: text/xml' --data '<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>admin@example.com</EMailAddress></Request></Autodiscover>' 'https://mail.example.com/autodiscover/autodiscover.xml'
curl -i 'https://example.com/mail/apple.mobileconfig?email=admin@example.com'
curl -i 'https://example.com/mail/apple-pop3.mobileconfig?email=admin@example.com'
curl -i 'https://example.com/mail/apple-imap.mobileconfig?email=admin@example.com'

dig +short SRV _imaps._tcp.example.com
dig +short SRV _submissions._tcp.example.com
dig +short SRV _autodiscover._tcp.example.com
```

XML responses must use `Content-Type: text/xml`. Apple profiles must use
`Content-Type: application/x-apple-aspen-config` and a `.mobileconfig` filename.
Every response must include `Cache-Control: no-store, no-cache, ...`.

## Installing an Apple Mail profile

1. Open the mailbox **Mail connection settings** in ImagoPanel.
2. Select `Apple POP3` (preferred) or `Apple IMAP`.
3. On iPhone or iPad, open **Settings**, select **Profile Downloaded**, and
   confirm installation. On macOS, open the downloaded `.mobileconfig` and
   approve the profile in System Settings.
4. Enter the mailbox password when requested. One password is used for incoming
   and outgoing mail and is never included in the URL or profile.

The profile contains no password or certificate. It can be installed manually
without MDM. Fully automated enterprise deployment requires separately signing
the profile and distributing it through an MDM system.
