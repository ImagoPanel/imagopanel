<?php
declare(strict_types=1);

/**
 * DEDICATED PHP-FPM POOL FOR IMAGOPANEL
 *
 * Create an imagopanel pool running as the apache user, listening on
 * /run/php-fpm/imagopanel.sock, with open_basedir containing the panel directory,
 * /tmp, and the PHP session directory. Route panel PHP requests to this socket in Apache:
 * <FilesMatch \.(php|phar)$>
 *     SetHandler "proxy:unix:/run/php-fpm/imagopanel.sock|fcgi://localhost"
 * </FilesMatch>
 * After making changes, validate the configuration and restart PHP-FPM and Apache.
 */

/**
 * IMAGOPANEL CONFIGURATION EXAMPLE
 *
 * Copy this file to config.php and replace all CHANGE_ME values,
 * example.com domains, test IP addresses, and sample paths with your own values.
 * ImagoPanel does not use .env files: all settings are stored in config.php.
 *
 * Example installation in /srv/www/imagopanel/public_html:
 *
 * RedirectMatch 302 ^/imagopanel$ /imagopanel/
 * RedirectMatch 302 ^/panel$ /panel/
 * Alias /imagopanel/ "/srv/www/imagopanel/public_html/"
 * Alias /panel/ "/srv/www/imagopanel/public_html/"
 *
 * <Directory "/srv/www/imagopanel/public_html/">
 *     Options FollowSymLinks
 *     AllowOverride All
 *     DirectoryIndex index.php
 *     Require all granted
 * </Directory>
 *
 * Add tool aliases once to this global Apache file as well,
 * instead of adding them to every VirtualHost:
 * Alias "/phpmyadmin/" "/srv/www/imagopanel/public_html/phpmyadmin/"
 * Alias "/filemanager/" "/srv/www/imagopanel/public_html/filemanager/"
 * Alias "/fileeditor/" "/srv/www/imagopanel/public_html/fileeditor/"
 *
 * Do not add separate aliases for /panel/phpmyadmin/, /panel/filemanager/,
 * or /panel/fileeditor/: these URLs are already handled by the common /panel/ alias.
 *
 * Deny direct HTTP access to root/root.php through root/.htaccess:
 * Require all denied
 *
 * sudoers example (replace the installation path and, if necessary, the apache user):
 * Cmnd_Alias IMAGOPANEL_ROOT = \
 *     /usr/bin/php -d display_errors=stderr -d display_startup_errors=0 /srv/www/imagopanel/public_html/root/root.php --task, \
 *     /usr/bin/php -d display_errors=stderr -d display_startup_errors=0 /srv/www/imagopanel/public_html/root/root.php --prod
 * apache ALL=(root) NOPASSWD: IMAGOPANEL_ROOT
 *
 * Example hourly cron entry after completing the configuration:
 * 0 * * * * /usr/bin/php /srv/www/imagopanel/public_html/cron/collect_statuses.php --prod >> /var/log/imagopanel-statuses.log 2>&1
 */

/**
 * Environment detection. WIN and PROD are calculated automatically.
 * Replace the task.example.com literal in the TASK definition with the test server hostname.
 * This setting is required only when a separate TASK environment exists.
 */
define('WIN', strpos(strtoupper(php_uname('s')), 'WINDOWS') !== false ? true : false);
define('TASK', strpos((string) ($_SERVER['HTTP_HOST'] ?? ''), 'task.example.com') !== false ? true : false);
define('PROD', !WIN && !TASK);

/**
 * Main interface settings. PANEL_NAME and PANEL_TIMEZONE are required.
 * DEFAULT_LANGUAGE is the code of an existing JSON translation, such as ru, lv, or en.
 * Change ASSET_VERSION after updating custom CSS/JS to invalidate browser caches.
 * To import legacy mail, install imapsync and systemd-run and verify the
 * MAIL_MIGRATION_* paths. Jobs are stored in JSON; no database or migrations are required.
 * The worker and lib/MailMigration*.php must be owned by root and must not be writable
 * by the web user. The temporary credentials directory must have mode 0700.
 * Run the emergency secret cleanup as root every 5 minutes:
 * /usr/bin/php /var/www/imagopanel/public_html/cron/cleanup_mail_migrations.php --prod
 */
const PANEL_NAME = (WIN ? 'ImagoPanel' : (TASK ? 'ImagoPanel' : 'ImagoPanel'));
// Previous value before table-based DNS connection management: const ASSET_VERSION = (WIN ? '1.15.0' : (TASK ? '1.15.0' : '1.15.0'));
// Previous value before fixing DNS connection opening: const ASSET_VERSION = (WIN ? '1.15.1' : (TASK ? '1.15.1' : '1.15.1'));
// Previous value before making recommended DNS records collapsible: const ASSET_VERSION = (WIN ? '1.15.2' : (TASK ? '1.15.2' : '1.15.2'));
// Previous value before hiding incompatible DNS APIs: const ASSET_VERSION = (WIN ? '1.15.3' : (TASK ? '1.15.3' : '1.15.3'));
// Previous value before adding phpMyAdmin launch for the selected database: const ASSET_VERSION = (WIN ? '1.15.4' : (TASK ? '1.15.4' : '1.15.4'));
// Previous value before launching file tools from the domains table: const ASSET_VERSION = (WIN ? '1.15.5' : (TASK ? '1.15.5' : '1.15.5'));
// Previous value before temporary-access login through /panel/: const ASSET_VERSION = (WIN ? '1.15.6' : (TASK ? '1.15.6' : '1.15.6'));
// Previous value before fixing DataTables sorting and filters: const ASSET_VERSION = (WIN ? '1.15.7' : (TASK ? '1.15.7' : '1.15.7'));
// Previous value before adding creation timestamps to tables: const ASSET_VERSION = (WIN ? '1.15.8' : (TASK ? '1.15.8' : '1.15.8'));
// Previous value before adding the root timestamp migration: const ASSET_VERSION = (WIN ? '1.15.9' : (TASK ? '1.15.9' : '1.15.9'));
// Previous value before real domain A-record validation and MX recommendations: const ASSET_VERSION = (WIN ? '1.16.0' : (TASK ? '1.16.0' : '1.16.0'));
// Previous value before restoring DataTables sort arrows: const ASSET_VERSION = (WIN ? '1.16.1' : (TASK ? '1.16.1' : '1.16.1'));
// Previous value before persisting table sort order: const ASSET_VERSION = (WIN ? '1.16.2' : (TASK ? '1.16.2' : '1.16.2'));
// Previous value before persistent toast notifications: const ASSET_VERSION = (WIN ? '1.16.3' : (TASK ? '1.16.3' : '1.16.3'));
// Previous value before compact DataTables column widths: const ASSET_VERSION = (WIN ? '1.16.4' : (TASK ? '1.16.4' : '1.16.4'));
// Previous value before stretching compact tables to the container width: const ASSET_VERSION = (WIN ? '1.16.5' : (TASK ? '1.16.5' : '1.16.5'));
// Previous value before validating DNS prior to domain and mail creation: const ASSET_VERSION = (WIN ? '1.16.6' : (TASK ? '1.16.6' : '1.16.6'));
// Previous value before user and resource comments: const ASSET_VERSION = (WIN ? '1.16.7' : (TASK ? '1.16.7' : '1.16.7'));
// Previous value before the compact comments column: const ASSET_VERSION = (WIN ? '1.16.8' : (TASK ? '1.16.8' : '1.16.8'));
// Previous value before managing all DNS zones: const ASSET_VERSION = (WIN ? '1.16.9' : (TASK ? '1.16.9' : '1.16.9'));
// Previous value before the full zone list and DNS synchronization indicator: const ASSET_VERSION = (WIN ? '1.17.0' : (TASK ? '1.17.0' : '1.17.0'));
// Previous value before copying DNS records between zones: const ASSET_VERSION = (WIN ? '1.17.1' : (TASK ? '1.17.1' : '1.17.1'));
// Previous value before sequentially retrieving records from all DNS zones: const ASSET_VERSION = (WIN ? '1.17.2' : (TASK ? '1.17.2' : '1.17.2'));
// Previous value before adding REG.RU REG.API: const ASSET_VERSION = (WIN ? '1.17.3' : (TASK ? '1.17.3' : '1.17.3'));
// Previous value before adding the Namecheap DNS API: const ASSET_VERSION = (WIN ? '1.17.4' : (TASK ? '1.17.4' : '1.17.4'));
// Previous value before fixing Namecheap MX records: const ASSET_VERSION = (WIN ? '1.17.5' : (TASK ? '1.17.5' : '1.17.5'));
// Previous value before fixing Hetzner MX records: const ASSET_VERSION = (WIN ? '1.17.6' : (TASK ? '1.17.6' : '1.17.6'));
// Previous value before automatic CSRF token refresh: const ASSET_VERSION = (WIN ? '1.17.7' : (TASK ? '1.17.7' : '1.17.7'));
// Previous value before adding the Internet.bs DNS API: const ASSET_VERSION = (WIN ? '1.17.8' : (TASK ? '1.17.8' : '1.17.8'));
// Previous value before bulk ROOT validation and Apache vhost refresh: const ASSET_VERSION = (WIN ? '1.17.9' : (TASK ? '1.17.9' : '1.17.9'));
// Previous value before adding Apple Mail profiles: const ASSET_VERSION = (WIN ? '1.18.0' : (TASK ? '1.18.0' : '1.18.0'));
// Previous value before the collapsible ROOT migrations menu and bulk permission repair: const ASSET_VERSION = (WIN ? '1.18.1' : (TASK ? '1.18.1' : '1.18.1'));
// Previous value before moving DNS Management directly after Mail: const ASSET_VERSION = (WIN ? '1.18.2' : (TASK ? '1.18.2' : '1.18.2'));
// Previous value before the complete compact list of required DNS records: const ASSET_VERSION = (WIN ? '1.18.3' : (TASK ? '1.18.3' : '1.18.3'));
// Previous value before separate copying of DNS record names and values: const ASSET_VERSION = (WIN ? '1.18.4' : (TASK ? '1.18.4' : '1.18.4'));
// Previous value before restoring the common copy button and moving small buttons left: const ASSET_VERSION = (WIN ? '1.18.5' : (TASK ? '1.18.5' : '1.18.5'));
// Previous value before the three OpenDKIM management modes: const ASSET_VERSION = (WIN ? '1.18.6' : (TASK ? '1.18.6' : '1.18.6'));
// Previous value before read-only server diagnostics: const ASSET_VERSION = (WIN ? '1.18.7' : (TASK ? '1.18.7' : '1.18.7'));
// Value before preparing the public release: const ASSET_VERSION = (WIN ? '1.18.9' : (TASK ? '1.18.9' : '1.18.9'));
// Previous value before bulk DNS record changes: const ASSET_VERSION = (WIN ? '1.18.8' : (TASK ? '1.18.8' : '1.18.8'));
// Previous value before filtering DNS zones by domains hosted on this server: const ASSET_VERSION = (WIN ? '1.18.9' : (TASK ? '1.18.9' : '1.18.9'));
const ASSET_VERSION = (WIN ? '1.18.10' : (TASK ? '1.18.10' : '1.18.10'));
const DEFAULT_LANGUAGE = (WIN ? 'ru' : (TASK ? 'ru' : 'lv'));
const PANEL_TIMEZONE = (WIN ? 'Europe/Riga' : (TASK ? 'Europe/Riga' : 'Europe/Riga'));

/** Root email is required; specify a working administrator address. */
const ROOT_EMAIL = (WIN ? 'admin@example.com' : (TASK ? 'admin@example.com' : 'admin@example.com'));

/**
 * The root password hash is required. CHANGE_ME is not a valid hash.
 * Generate or replace the hash for PHP 7.4:
 * php -r "echo password_hash('NEW_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
 */
const ROOT_PASSWORD_HASH = (WIN
    ? 'CHANGE_ME_WITH_PASSWORD_HASH'
    : (TASK ? 'CHANGE_ME_WITH_PASSWORD_HASH' : 'CHANGE_ME_WITH_PASSWORD_HASH'));

/**
 * Optional restriction of root login to specific IP addresses or CIDR ranges.
 * An empty array permits login from any IP. Example: ['203.0.113.10', '2001:db8::/32'].
 */
const ROOT_ALLOWED_IPS = (WIN ? ['127.0.0.1'] : (TASK ? [] : []));

/**
 * Optional IP/CIDR ranges of trusted reverse proxies that forward X-Forwarded-For.
 * Leave [] when Apache/PHP is connected directly to the internet.
 */
const ROOT_TRUSTED_PROXY_IPS = (WIN ? [] : (TASK ? [] : []));

/** Optional: show the entered password to the root administrator in the user form. */
const SHOW_USER_PASSWORDS_TO_ADMIN = (WIN ? true : (TASK ? true : true));

/**
 * Recommended user password complexity. This produces a warning and does not block saving.
 * min_length must be at least 1; require_* values are booleans; special characters are supplied as a string.
 */
const USER_PASSWORD_POLICY = [
    'min_length' => 8,
    'require_uppercase' => true,
    'require_lowercase' => true,
    'require_number' => true,
    'require_special' => false,
    'special_characters' => '+-_)(?%#!,.',
];

/** Optional maximum number of individual IPv4/IPv6 addresses in a profile; CIDR is not supported. */
const USER_IP_ACCESS_MAX_ADDRESSES = (WIN ? 64 : (TASK ? 64 : 64));

/**
 * General limits. All values are required and must be positive integers.
 * Mail quotas are specified in MiB; the first quota is used by default.
 */
const STATS_REFRESH_MINUTES = (WIN ? 60 : (TASK ? 60 : 60));
const IMPORT_MAX_ROWS = (WIN ? 500 : (TASK ? 500 : 500));
const MAILBOX_QUOTA_OPTIONS_MB = (WIN
    ? [20, 50, 100, 1000, 2000]
    : (TASK ? [20, 50, 100, 1000, 2000] : [20, 50, 100, 1000, 2000]));
const IMPORT_MAIL_DEFAULT_QUOTA_MB = (WIN
    ? MAILBOX_QUOTA_OPTIONS_MB[0]
    : (TASK ? MAILBOX_QUOTA_OPTIONS_MB[0] : MAILBOX_QUOTA_OPTIONS_MB[0]));

/**
 * Sessions and Remember Me login. Lifetimes are required; the cookie name can be changed.
 * REMEMBER_LOGIN_SECRET is required and must be a unique random secret.
 * Generate a new secret: php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
 */
const SESSION_IDLE_TIMEOUT = (WIN ? 3600 : (TASK ? 3600 : 3600));
const REMEMBER_LOGIN_DAYS = (WIN ? 30 : (TASK ? 30 : 30));
const REMEMBER_LOGIN_COOKIE = (WIN ? 'IMAGOPANELREMEMBER' : (TASK ? 'IMAGOPANELREMEMBER' : 'IMAGOPANELREMEMBER'));
const REMEMBER_LOGIN_SECRET = (WIN
    ? 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET'
    : (TASK ? 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET' : 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET'));

/** Additional email verification for regular users after password login; root is unaffected. */
const USER_LOGIN_2FA_ENABLED = (WIN ? false : (TASK ? true : true));
/** Code/link lifetime in seconds and the permitted number of failed entry attempts. */
const USER_LOGIN_2FA_TTL_SECONDS = (WIN ? 600 : (TASK ? 600 : 600));
const USER_LOGIN_2FA_MAX_ATTEMPTS = (WIN ? 5 : (TASK ? 5 : 5));

/** System mail: transport accepts mail or smtp. SMTP fields are required only for smtp. */
const PANEL_MAIL_TRANSPORT = (WIN ? 'mail' : (TASK ? 'mail' : 'mail'));
const PANEL_MAIL_FROM = (WIN ? 'noreply@example.com' : (TASK ? 'noreply@example.com' : 'noreply@example.com'));
const PANEL_MAIL_FROM_NAME = (WIN ? 'ImagoPanel' : (TASK ? 'ImagoPanel' : 'ImagoPanel'));
const PANEL_SMTP_HOST = (WIN ? '' : (TASK ? '' : ''));
const PANEL_SMTP_PORT = (WIN ? 465 : (TASK ? 465 : 465));
const PANEL_SMTP_ENCRYPTION = (WIN ? 'ssl' : (TASK ? 'ssl' : 'ssl'));
const PANEL_SMTP_USERNAME = (WIN ? '' : (TASK ? '' : ''));
const PANEL_SMTP_PASSWORD = (WIN ? '' : (TASK ? '' : ''));

/**
 * Tariff limits. The string '0' means unlimited; per-resource sizes use strings with K, M, G, or T.
 * Integer and decimal values with a dot or comma are accepted: '100M', '7.40M', '7,40M', '2G'.
 */
const TARIFF_LIMITS_ENABLED = (WIN ? true : (TASK ? true : true));
const DEFAULT_USER_TARIFF = (WIN ? 'free' : (TASK ? 'free' : 'free'));
const USER_TARIFFS = (WIN ? [
    'free' => ['name' => 'Free', 'domain' => 5, 'db' => 5, 'mailbydomain' => 3, 'wwwsize' => '100M', 'mailsize' => '50M', 'dbsize' => '10M'],
] : (TASK ? [
    'free' => ['name' => 'Free', 'domain' => 5, 'db' => 5, 'mailbydomain' => 3, 'wwwsize' => '100M', 'mailsize' => '50M', 'dbsize' => '10M'],
] : [
    'free' => ['name' => 'Free', 'domain' => 5, 'db' => 5, 'mailbydomain' => 3, 'wwwsize' => '100M', 'mailsize' => '50M', 'dbsize' => '10M'],
]));

/**
 * Global UNIX accounts for all users. This setting is available only in config.php,
 * is neither displayed nor changed through the interface, and is disabled by default.
 * After changing the mode, save existing users as root/admin to refresh permissions.
 */
const UNIX_ACCOUNTS_ENABLED = (WIN ? false : (TASK ? false : false));
/** System quotas work only with UNIX_ACCOUNTS_ENABLED and are automatically skipped when unsupported. */
const SYSTEM_QUOTAS_ENABLED = (WIN ? false : (TASK ? false : false));
const SYSTEM_QUOTA_MOUNTPOINT = (WIN ? '/var/www' : (TASK ? '/var/www' : '/var/www'));

/** useradd: verify with `test -x /usr/sbin/useradd && rpm -q shadow-utils`; install with `dnf install -y shadow-utils`; minimum shadow-utils 4.6. */
const UNIX_USERADD_BINARY = (WIN ? '' : (TASK ? '/usr/sbin/useradd' : '/usr/sbin/useradd'));

/** userdel: verify with `test -x /usr/sbin/userdel && rpm -q shadow-utils`; install with `dnf install -y shadow-utils`; minimum shadow-utils 4.6. */
const UNIX_USERDEL_BINARY = (WIN ? '' : (TASK ? '/usr/sbin/userdel' : '/usr/sbin/userdel'));

/** id: verify with `/usr/bin/id --version`; install with `dnf install -y coreutils`; minimum GNU coreutils 8.30. */
const UNIX_ID_BINARY = (WIN ? '' : (TASK ? '/usr/bin/id' : '/usr/bin/id'));

/** nologin: verify with `test -x /sbin/nologin`; install with `dnf install -y util-linux`; minimum util-linux 2.32. */
const UNIX_NOLOGIN_SHELL = (WIN ? '/sbin/nologin' : (TASK ? '/sbin/nologin' : '/sbin/nologin'));

/** setquota: verify with `/usr/sbin/setquota -V`; install with `dnf install -y quota`; minimum quota-tools 4.04. */
const SYSTEM_SETQUOTA_BINARY = (WIN ? '' : (TASK ? '/usr/sbin/setquota' : '/usr/sbin/setquota'));

/**
 * Local project directories. Values based on __DIR__ normally do not need to be changed.
 * The panel process must be able to access the directories with the required write permissions.
 */
const DATA_DIRECTORY = (WIN ? __DIR__ . '/data' : (TASK ? __DIR__ . '/data' : __DIR__ . '/data'));
const STATS_CRON_LOCK_FILE = (WIN
    ? __DIR__ . '/storage/locks/statistics.lock'
    : (TASK ? __DIR__ . '/storage/locks/statistics.lock' : __DIR__ . '/storage/locks/statistics.lock'));
const STATUS_DIRECTORY = (WIN
    ? __DIR__ . '/storage/statuses'
    : (TASK ? __DIR__ . '/storage/statuses' : __DIR__ . '/storage/statuses'));

/**
 * Manual DNS checks. Limits and timeouts are required; Linux paths may be changed.
 * An empty DNS_DIG_BINARY is allowed only in a Windows environment without a system dig binary.
 */
const DNS_VERIFY_RATE_LIMIT = (WIN ? 5 : (TASK ? 5 : 5));
const DNS_VERIFY_RATE_WINDOW_SECONDS = (WIN ? 60 : (TASK ? 60 : 60));
const DNS_VERIFY_RATE_LIMIT_DIRECTORY = (WIN
    ? __DIR__ . '/data/.verify-rate-limits'
    : (TASK ? __DIR__ . '/data/.verify-rate-limits' : __DIR__ . '/data/.verify-rate-limits'));
/** dig: verify with `/usr/bin/dig -v`; install with `dnf install -y bind-utils`; minimum BIND utilities 9.11. */
const DNS_DIG_BINARY = (WIN ? '' : (TASK ? '/usr/bin/dig' : '/usr/bin/dig'));
const DNS_DIG_TIMEOUT_SECONDS = (WIN ? 2 : (TASK ? 2 : 2));
const DNS_DIG_TRIES = (WIN ? 1 : (TASK ? 1 : 1));
const DNS_AUTHORITATIVE_SERVER_LIMIT = (WIN ? 4 : (TASK ? 4 : 4));
const DNS_VERIFY_TOTAL_TIMEOUT_SECONDS = (WIN ? 15 : (TASK ? 15 : 15));
const DNS_DIG_PROCESS_TIMEOUT_SECONDS = (WIN ? 4 : (TASK ? 4 : 4));

/**
 * DNS providers available in profiles. enabled=true enables a working integration; planned=true
 * displays a future provider without allowing it to be selected.
 */
const DNS_API_PROVIDERS = [
    ['id' => 'hetzner', 'name' => 'Hetzner DNS / Console', 'enabled' => true, 'planned' => false],
    ['id' => 'joker', 'name' => 'Joker.com DMAPI', 'enabled' => true, 'planned' => false],
    ['id' => 'regru', 'name' => 'REG.RU REG.API', 'enabled' => true, 'planned' => false],
    ['id' => 'namecheap', 'name' => 'Namecheap DNS API', 'enabled' => true, 'planned' => false],
    ['id' => 'internetbs', 'name' => 'Internet.bs API', 'enabled' => true, 'planned' => false],
    ['id' => 'cloudflare', 'name' => 'Cloudflare DNS', 'enabled' => false, 'planned' => true],
    ['id' => 'digitalocean', 'name' => 'DigitalOcean DNS', 'enabled' => false, 'planned' => true],
    ['id' => 'route53', 'name' => 'Amazon Route 53', 'enabled' => false, 'planned' => true],
    ['id' => 'google-cloud-dns', 'name' => 'Google Cloud DNS', 'enabled' => false, 'planned' => true],
    ['id' => 'vultr', 'name' => 'Vultr DNS', 'enabled' => false, 'planned' => true],
];

/**
 * Display stored API keys and DNS connection passwords in the profile.
 * true displays values; false only allows replacing them with new values.
 */
const SHOW_DNS_PROVIDER_CREDENTIALS = (WIN ? true : (TASK ? true : true));

/** DNS provider for new profiles; an empty string means no provider is selected. */
const DNS_API_DEFAULT_PROVIDER = (WIN ? 'hetzner' : (TASK ? 'hetzner' : 'hetzner'));

/** Base HTTPS URL of the Hetzner Cloud API; the hostname must be api.hetzner.cloud. */
const DNS_HETZNER_API_URL = (WIN ? 'https://api.hetzner.cloud/v1' : (TASK ? 'https://api.hetzner.cloud/v1' : 'https://api.hetzner.cloud/v1'));

/** Required Hetzner API token with DNS permissions. Replace CHANGE_ME with your own key. */
const DNS_HETZNER_API_TOKEN = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/** Allowed hostnames for a user-supplied Hetzner API URL; protects against SSRF. */
const DNS_HETZNER_ALLOWED_API_HOSTS = ['api.hetzner.cloud'];

/** Official Joker.com DMAPI HTTPS URL; the hostname must be dmapi.joker.com. */
const DNS_JOKER_API_URL = (WIN ? 'https://dmapi.joker.com' : (TASK ? 'https://dmapi.joker.com' : 'https://dmapi.joker.com'));

/**
 * Required Joker.com API key with DNS permissions. Replace CHANGE_ME with your own key.
 * Official Joker recommendation: To use API keys in DMAPI instead of your user credentials,
 * please replace 'username=' and 'password=' with 'api-key=xxx' in your requests.
 */
const DNS_JOKER_API_TOKEN = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/** Allowed hostnames for a user-supplied Joker.com DMAPI URL; protects against SSRF. */
const DNS_JOKER_ALLOWED_API_HOSTS = ['dmapi.joker.com'];

/** Official Joker.com nameservers used to identify the domain's DNS provider. */
// Previous value before supporting current Joker nameservers: const DNS_JOKER_NAMESERVERS = ['a.ns.joker.com', 'b.ns.joker.com', 'c.ns.joker.com'];
const DNS_JOKER_NAMESERVERS = ['a.ns.joker.com', 'b.ns.joker.com', 'c.ns.joker.com', 'x.ns.joker.com', 'y.ns.joker.com', 'z.ns.joker.com'];

/** Official REG.API v2 HTTPS URL; the hostname must be api.reg.ru. */
const DNS_REGRU_API_URL = (WIN ? 'https://api.reg.ru/api/regru2' : (TASK ? 'https://api.reg.ru/api/regru2' : 'https://api.reg.ru/api/regru2'));

/** Required login for the REG.RU account that can access managed domains. */
const DNS_REGRU_API_USERNAME = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/**
 * Required dedicated REG.RU API password; do not use the ImagoPanel password here.
 * Allow the production server IP in the REG.RU account: Settings -> API access.
 */
const DNS_REGRU_API_PASSWORD = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/** Allowed hostnames for a user-supplied REG.API URL; protects against SSRF. */
const DNS_REGRU_ALLOWED_API_HOSTS = ['api.reg.ru'];

/** Known REG.RU nameservers used to identify the domain's DNS provider. */
const DNS_REGRU_NAMESERVERS = ['ns1.reg.ru', 'ns2.reg.ru', 'ns1.hosting.reg.ru', 'ns2.hosting.reg.ru', 'ns5.hosting.reg.ru', 'ns6.hosting.reg.ru'];

/**
 * Official Namecheap API HTTPS URL.
 * https://api.sandbox.namecheap.com/xml.response is allowed for sandbox use.
 */
const DNS_NAMECHEAP_API_URL = (WIN ? 'https://api.namecheap.com/xml.response' : (TASK ? 'https://api.namecheap.com/xml.response' : 'https://api.namecheap.com/xml.response'));

/**
 * Optional fallback Namecheap API username for root/admin.
 * Leave CHANGE_ME if connections will be configured only by users in their profiles.
 */
const DNS_NAMECHEAP_API_USERNAME = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/**
 * Optional fallback Namecheap API key for root/admin.
 * Obtain the key from Profile -> Tools -> Namecheap API Access; do not use the account password.
 */
const DNS_NAMECHEAP_API_KEY = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/**
 * Required public IPv4 address used for outbound ImagoPanel requests.
 * Replace 127.0.0.1 with the real IPv4 address and add it to the Namecheap API Access whitelist.
 */
const DNS_NAMECHEAP_CLIENT_IP = (WIN ? '127.0.0.1' : (TASK ? '127.0.0.1' : '127.0.0.1'));

/** Allowed hostnames for a user-supplied Namecheap API URL; protects against SSRF. */
const DNS_NAMECHEAP_ALLOWED_API_HOSTS = ['api.namecheap.com', 'api.sandbox.namecheap.com'];

/** Namecheap BasicDNS, PremiumDNS, FreeDNS, and EnterpriseDNS nameservers used for provider detection. */
const DNS_NAMECHEAP_NAMESERVERS = [
    'dns1.registrar-servers.com', 'dns2.registrar-servers.com',
    'pdns1.registrar-servers.com', 'pdns2.registrar-servers.com',
    'freedns1.registrar-servers.com', 'freedns2.registrar-servers.com', 'freedns3.registrar-servers.com',
    'freedns4.registrar-servers.com', 'freedns5.registrar-servers.com',
    'edns1.registrar-servers.com', 'edns2.registrar-servers.com',
];

/** Official Internet.bs API HTTPS URL; the hostname must be api.internet.bs. */
const DNS_INTERNETBS_API_URL = (WIN ? 'https://api.internet.bs' : (TASK ? 'https://api.internet.bs' : 'https://api.internet.bs'));

/** Internet.bs API key from My Account -> Get my API key. */
const DNS_INTERNETBS_API_KEY = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/**
 * Internet.bs API password. According to the activation email, this is the web-access password;
 * setting a separate API password in Account Security is recommended.
 */
const DNS_INTERNETBS_API_PASSWORD = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/** Allowed hostname for a user-supplied Internet.bs API URL; protects against SSRF. */
const DNS_INTERNETBS_ALLOWED_API_HOSTS = ['api.internet.bs'];

/** Official Internet.bs/TopDNS nameservers used to identify the domain's DNS provider. */
const DNS_INTERNETBS_NAMESERVERS = ['ns-uk.topdns.com', 'ns-usa.topdns.com', 'ns-canada.topdns.com'];

/** TTL for new DNS records in seconds; allowed range: 60 to 2147483647. */
const DNS_API_DEFAULT_TTL = (WIN ? 3600 : (TASK ? 3600 : 3600));

/** Required public hosting IPv4 address for recommended @, www, mail, and * A records. */
const DNS_API_RECOMMENDED_IPV4 = (WIN ? '127.0.0.1' : (TASK ? '127.0.0.1' : '127.0.0.1'));

/** Timeout for one HTTPS request to a DNS API, in seconds. */
const DNS_API_REQUEST_TIMEOUT_SECONDS = (WIN ? 15 : (TASK ? 15 : 15));

/**
 * Statistics collection. STATS_HOSTING_PUBLIC_IPS is required on TASK/PROD:
 * specify every public hosting IPv4 address; 127.0.0.1 below is only an example.
 */
const STATS_COMMAND_TIMEOUT_SECONDS = (WIN ? 15 : (TASK ? 15 : 15));
const STATS_HOSTING_PUBLIC_IPS = (WIN ? ['127.0.0.1'] : (TASK ? ['127.0.0.1'] : ['127.0.0.1']));

/**
 * Website storage. USER_WEB_ROOT_DIRECTORY, owner, and group are required.
 * An absolute Linux path is required; example root: /var/www/users.
 */
const USER_WEB_ROOT_DIRECTORY = (WIN ? '/var/www/users' : (TASK ? '/var/www/users' : '/var/www/users'));
const USER_PUBLIC_HTML_DIRECTORY = (WIN ? 'public_html' : (TASK ? 'public_html' : 'public_html'));
const USER_WEB_OWNER = (WIN ? 'apache' : (TASK ? 'apache' : 'apache'));
const USER_WEB_GROUP = (WIN ? 'apache' : (TASK ? 'apache' : 'apache'));
/** chown: verify with `/usr/bin/chown --version`; install with `dnf install -y coreutils`; minimum GNU coreutils 8.30. */
const FILESYSTEM_CHOWN_BINARY = (WIN ? '' : (TASK ? '/usr/bin/chown' : '/usr/bin/chown'));
const USER_ROOT_DIRECTORY_MODE = (WIN ? 0750 : (TASK ? 0750 : 0750));
const USER_PUBLIC_DIRECTORY_MODE = (WIN ? 0750 : (TASK ? 0750 : 0750));

/**
 * Domain logs. File names and limits are required; paths are built relative to the project.
 */
const USER_PHP_LOG_DIRECTORY = (WIN ? 'log' : (TASK ? 'log' : 'log'));
const USER_PHP_ERROR_LOG_FILE = (WIN ? 'php_error.log' : (TASK ? 'php_error.log' : 'php_error.log'));
const USER_APACHE_ACCESS_LOG_FILE = (WIN ? 'combine.log' : (TASK ? 'combine.log' : 'combine.log'));
const USER_APACHE_ERROR_LOG_FILE = (WIN ? 'error.log' : (TASK ? 'error.log' : 'error.log'));
const USER_PHP_LOG_DIRECTORY_MODE = (WIN ? 0750 : (TASK ? 0750 : 0750));
const DOMAIN_LOG_LINES_PER_PAGE = (WIN ? 100 : (TASK ? 100 : 100));
const DOMAIN_LOG_LINE_MAX_BYTES = (WIN ? 65536 : (TASK ? 65536 : 65536));

/**
 * Virtual mail storage. The path, owner, and numeric GID are required on PROD.
 * Example standard path: /var/vmail. Modes are specified as octal numbers.
 */
const MAIL_STORAGE_DIRECTORY = (WIN ? '/var/vmail' : (TASK ? '/var/vmail' : '/var/vmail'));
const MAIL_STORAGE_OWNER = (WIN ? 'vmail' : (TASK ? 'vmail' : 'vmail'));
const MAIL_STORAGE_GROUP = (WIN ? 2000 : (TASK ? 2000 : 2000));
const MAIL_STORAGE_ROOT_MODE = (WIN ? 0755 : (TASK ? 0755 : 0755));
const MAIL_STORAGE_MAILBOX_MODE = (WIN ? 0700 : (TASK ? 0700 : 0700));

/**
 * Calling privileged root/root.php. Linux paths are required on TASK/PROD.
 * The Windows PHP path is an optional local example; replace it or leave it empty.
 */
const ROOT_SCRIPT_PATH = (WIN
    ? __DIR__ . '/root/root.php'
    : (TASK ? __DIR__ . '/root/root.php' : __DIR__ . '/root/root.php'));
/** sudo: verify with `/usr/bin/sudo --version`; install with `dnf install -y sudo`; minimum sudo 1.8.29. */
const ROOT_SUDO_BINARY = (WIN ? '' : (TASK ? '/usr/bin/sudo' : '/usr/bin/sudo'));
/** PHP CLI: verify with `/usr/bin/php -v`; install `dnf install -y php-cli` from a PHP 7.4 repository; PHP 7.4.0-7.4.x is required. */
const ROOT_PHP_BINARY = (WIN ? 'C:/path/to/php-7.4/php.exe' : (TASK ? '/usr/bin/php' : '/usr/bin/php'));
/** Windows PHP CLI: verify with `C:\\path\\to\\php.exe -v`; install a PHP 7.4 archive from php.net; PHP 7.4.0-7.4.x is required. */
const ROOT_WINDOWS_PHP_BINARY = (WIN ? 'C:/path/to/php-7.4/php.exe' : (TASK ? '' : ''));
const ROOT_RESPONSE_MAX_BYTES = (WIN ? 1048576 : (TASK ? 1048576 : 1048576));
const ROOT_COMMAND_TIMEOUT_SECONDS = (WIN ? 120 : (TASK ? 120 : 120));
const ROOT_LOCK_DIRECTORY = (WIN
    ? __DIR__ . '/storage/locks/root'
    : (TASK ? __DIR__ . '/storage/locks/root' : '/var/lock/imagopanel'));
const ROOT_ALLOW_WINDOWS_DIRECT_CALL = (WIN ? true : (TASK ? false : false));

/**
 * Audit log for client calls to root.php. Parameters are optional to change,
 * but the directory must be writable. Retention is specified in days.
 */
const ROOT_LOG_ENABLED = (WIN ? true : (TASK ? true : true));
const ROOT_LOG_DIRECTORY = (WIN
    ? __DIR__ . '/storage/root-logs'
    : (TASK ? __DIR__ . '/storage/root-logs' : __DIR__ . '/storage/root-logs'));
const ROOT_LOG_RETENTION_DAYS = (WIN ? 180 : (TASK ? 180 : 180));
const ROOT_LOG_DEFAULT_DAYS = (WIN ? 30 : (TASK ? 30 : 30));
const ROOT_LOG_ENTRY_MAX_BYTES = (WIN ? 4194304 : (TASK ? 4194304 : 4194304));

/**
 * Permanent IP-based access to domain tools. Optional: [] disables it.
 * Only individual IPv4/IPv6 addresses without CIDR are allowed; 127.0.0.1 is a safe example.
 */
const DOMAIN_TOOL_TRUSTED_IPS = (WIN ? ['127.0.0.1'] : (TASK ? [] : []));

/**
 * Temporary tool access. Limits are required and must be integers.
 * DOMAIN_TOOL_AUTH_SECRET is required; generate 64 hexadecimal characters with:
 * php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
 */
const DOMAIN_TOOL_ACCESS_LIMIT = (WIN ? 50 : (TASK ? 50 : 50));
const DOMAIN_TOOL_ACCESS_HOURS = (WIN ? 24 : (TASK ? 24 : 24));
const DOMAIN_TOOL_SESSION_IDLE_SECONDS = (WIN ? 3600 : (TASK ? 3600 : 3600));

// Required lifetime of the one-time link that opens the selected database in phpMyAdmin, in seconds.
const PHPMYADMIN_DATABASE_LAUNCH_TTL_SECONDS = (WIN ? 60 : (TASK ? 60 : 600));

// Required lifetime of the one-time link that opens File Manager or PHP Editor, in seconds.
const DOMAIN_TOOL_PANEL_LAUNCH_TTL_SECONDS = (WIN ? 60 : (TASK ? 60 : 600));


const DOMAIN_TOOL_SESSION_NAME = (WIN ? 'IMAGOPANELTOOLSESSID' : (TASK ? 'IMAGOPANELTOOLSESSID' : 'IMAGOPANELTOOLSESSID'));
const DOMAIN_TOOL_AUTH_SECRET = (WIN
    ? 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET'
    : (TASK ? 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET' : 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET'));

/**
 * Storage and retention period for domain-tool logs. Directories must be writable.
 */
const DOMAIN_TOOL_LOG_DIRECTORY = (WIN
    ? __DIR__ . '/storage/domain-tool-logs'
    : (TASK ? __DIR__ . '/storage/domain-tool-logs' : __DIR__ . '/storage/domain-tool-logs'));
const DOMAIN_TOOL_STATE_DIRECTORY = (WIN
    ? __DIR__ . '/storage/domain-tool-state'
    : (TASK ? __DIR__ . '/storage/domain-tool-state' : __DIR__ . '/storage/domain-tool-state'));
const DOMAIN_TOOL_LOG_RETENTION_DAYS = (WIN ? 180 : (TASK ? 180 : 180));
const DOMAIN_TOOL_LOG_DEFAULT_DAYS = (WIN ? 30 : (TASK ? 30 : 30));
const DOMAIN_TOOL_LOG_ENTRY_MAX_BYTES = (WIN ? 4194304 : (TASK ? 4194304 : 4194304));

/**
 * Physical tool directories for the single global Apache configuration file.
 * User VirtualHosts do not contain these Alias and Directory blocks.
 */
const DOMAIN_TOOL_PHPMYADMIN_DIRECTORY = (WIN ? __DIR__ . '/phpmyadmin' : (TASK ? __DIR__ . '/phpmyadmin' : __DIR__ . '/phpmyadmin'));
const DOMAIN_TOOL_FILEMANAGER_DIRECTORY = (WIN ? __DIR__ . '/filemanager' : (TASK ? __DIR__ . '/filemanager' : __DIR__ . '/filemanager'));
const DOMAIN_TOOL_FILEEDITOR_DIRECTORY = (WIN ? __DIR__ . '/fileeditor' : (TASK ? __DIR__ . '/fileeditor' : __DIR__ . '/fileeditor'));
const DOMAIN_TOOL_APACHE_PUBLIC_DIRECTORY = (WIN
    ? '/srv/www/imagopanel/public_html'
    : (TASK ? __DIR__ : __DIR__));
const DOMAIN_TOOL_PHP_FPM_SOCKET = (WIN ? '/run/php-fpm/www.sock' : (TASK ? '/run/php-fpm/www.sock' : '/run/php-fpm/www.sock'));

/**
 * The phpMyAdmin cookie secret is required. Replace the placeholder with 64 random hexadecimal characters:
 * php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
 */
const DOMAIN_TOOL_PHPMYADMIN_BLOWFISH_SECRET = (WIN
    ? 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET'
    : (TASK ? 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET' : 'CHANGE_ME_WITH_RANDOM_64_HEX_SECRET'));

/**
 * Administrative MySQL/MariaDB connection. All four parameters are required.
 * The user must be allowed to create and modify databases and users.
 */
const MYSQL_ADMIN_HOST = (WIN ? '127.0.0.1' : (TASK ? '127.0.0.1' : '127.0.0.1'));
const MYSQL_ADMIN_PORT = (WIN ? 3306 : (TASK ? 3306 : 3306));
const MYSQL_ADMIN_USER = (WIN ? 'database_admin' : (TASK ? 'database_admin' : 'database_admin'));
const MYSQL_ADMIN_PASSWORD = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));

/**
 * Credentials for created client databases. The suffix and maximum length normally need no changes.
 * CONNECTION_HOST/PORT are the values shown to users for connecting.
 */
const MYSQL_CLIENT_USER_SUFFIX = (WIN ? '_user' : (TASK ? '_user' : '_user'));
const MYSQL_CLIENT_USER_HOST = (WIN ? 'localhost' : (TASK ? 'localhost' : 'localhost'));
const MYSQL_CLIENT_USER_MAX_LENGTH = (WIN ? 32 : (TASK ? 32 : 32));
const MYSQL_CLIENT_CONNECTION_HOST = (WIN ? 'localhost' : (TASK ? 'localhost' : 'localhost'));
const MYSQL_CLIENT_CONNECTION_PORT = (WIN ? 3306 : (TASK ? 3306 : 3306));

/**
 * Display stored database and mail passwords. Allowed values are true or false.
 * false permits replacing a password without revealing the stored value.
 */
const SHOW_DATABASE_PASSWORDS = (WIN ? true : (TASK ? true : true));
const SHOW_MAIL_PASSWORDS = (WIN ? true : (TASK ? true : true));

/**
 * Mail client settings. Hostnames are specified without a scheme or trailing dot;
 * hostnames and the webmail URL are required for display to users.
 * Standard SSL/TLS ports: IMAP 993, POP3 995, SMTP 465.
 */
const MAIL_CLIENT_IMAP_HOST = (WIN ? 'mail.example.com' : (TASK ? 'mail.example.com' : 'mail.example.com'));
const MAIL_CLIENT_IMAP_PORT = (WIN ? 993 : (TASK ? 993 : 993));
const MAIL_CLIENT_POP3_HOST = (WIN ? 'mail.example.com' : (TASK ? 'mail.example.com' : 'mail.example.com'));
const MAIL_CLIENT_POP3_PORT = (WIN ? 995 : (TASK ? 995 : 995));
const MAIL_CLIENT_SMTP_HOST = (WIN ? 'mail.example.com' : (TASK ? 'mail.example.com' : 'mail.example.com'));
const MAIL_CLIENT_SMTP_PORT = (WIN ? 465 : (TASK ? 465 : 465));
/** SMTP with mandatory STARTTLS; also used for the _submission SRV record. */
const MAIL_CLIENT_SMTP_STARTTLS_PORT = (WIN ? 587 : (TASK ? 587 : 587));
/** Outlook Autodiscover HTTPS server and port; specify the hostname without a scheme. */
const MAIL_CLIENT_AUTODISCOVER_HOST = (WIN ? 'mail.example.com' : (TASK ? 'mail.example.com' : 'mail.example.com'));
const MAIL_CLIENT_AUTODISCOVER_PORT = (WIN ? 443 : (TASK ? 443 : 443));
/** Default Apple profile protocol: POP3 (preferred) or IMAP. */
const MAIL_CLIENT_APPLE_DEFAULT_PROTOCOL = (WIN ? 'POP3' : (TASK ? 'POP3' : 'POP3'));
const MAIL_CLIENT_WEBMAIL_URL = (WIN ? 'https://mail.example.com' : (TASK ? 'https://mail.example.com' : 'https://mail.example.com'));
const MAIL_CLIENT_DOMAIN_WEBMAIL_TEMPLATE = (WIN ? 'https://{domain}/mail/' : (TASK ? 'https://{domain}/mail/' : 'https://{domain}/mail/'));

/** Enables legacy mail import through imapsync; false completely hides and blocks the feature. */
const MAIL_MIGRATION_ENABLED = (WIN ? false : (TASK ? false : true));

/**
 * imapsync: verify with `/usr/bin/imapsync --version`; minimum 2.185.
 * CentOS/AlmaLinux 8: `dnf install -y --enablerepo=powertools imapsync perl-Proc-ProcessTable`.
 * If the repository provides a version older than 2.185, update it using https://imapsync.lamiral.info/INSTALL.d/INSTALL.Centos.txt and verify the version again.
 */
const MAIL_MIGRATION_IMAPSYNC_BINARY = (WIN ? '' : (TASK ? '/usr/bin/imapsync' : '/usr/bin/imapsync'));

/** PHP CLI worker: verify with `/usr/bin/php -v`; install with `dnf install -y php-cli`; PHP 7.4.0-7.4.x is required. */
const MAIL_MIGRATION_PHP_BINARY = (WIN ? 'D:/path/to/php-7.4/php.exe' : (TASK ? '/usr/bin/php' : '/usr/bin/php'));

/** systemd-run: verify with `/usr/bin/systemd-run --version`; install with `dnf install -y systemd`; minimum systemd 239. */
const MAIL_MIGRATION_SYSTEMD_RUN_BINARY = (WIN ? '' : (TASK ? '/usr/bin/systemd-run' : '/usr/bin/systemd-run'));

/** ImagoPanel installation root; on PROD this is the directory above public_html. */
const IMAGOPANEL_INSTALL_DIRECTORY = (WIN ? __DIR__ : (TASK ? '/var/www/imagopanel' : '/var/www/imagopanel'));

/** Root service directory inside the ImagoPanel installation root but outside public_html. */
const MAIL_MIGRATION_RUNTIME_DIRECTORY = IMAGOPANEL_INSTALL_DIRECTORY . '/storage/mail-migrations';

/** Directory for individual job and history JSON files; no database is used. */
const MAIL_MIGRATION_JOB_DIRECTORY = MAIL_MIGRATION_RUNTIME_DIRECTORY . '/jobs';

/** Directory for temporary password files; root:root, mode 0700, with files using mode 0600. */
const MAIL_MIGRATION_CREDENTIAL_DIRECTORY = MAIL_MIGRATION_RUNTIME_DIRECTORY . '/credentials';

/** imapsync cache/PID directory; root:root, mode 0700. */
const MAIL_MIGRATION_TEMP_DIRECTORY = MAIL_MIGRATION_RUNTIME_DIRECTORY . '/tmp';

/** Log directory; owned by root, with read-only access for the web group. */
const MAIL_MIGRATION_LOG_DIRECTORY = MAIL_MIGRATION_RUNTIME_DIRECTORY . '/logs';

/** Directory for final secret-free JSON reports. */
const MAIL_MIGRATION_REPORT_DIRECTORY = MAIL_MIGRATION_RUNTIME_DIRECTORY . '/reports';

/** Allowed IMAP ports for legacy servers. */
const MAIL_MIGRATION_ALLOWED_PORTS = (WIN ? [143, 993] : (TASK ? [143, 993] : [143, 993]));

/** Allow private/reserved source addresses; false protects the internal network against SSRF. */
const MAIL_MIGRATION_ALLOW_PRIVATE_SOURCE_HOSTS = (WIN ? true : (TASK ? false : false));

/** Connection test timeout in seconds. */
const MAIL_MIGRATION_TEST_TIMEOUT_SECONDS = (WIN ? 180 : (TASK ? 180 : 180));

/** Maximum duration of one job in seconds. */
const MAIL_MIGRATION_MAX_RUNTIME_SECONDS = (WIN ? 86400 : (TASK ? 86400 : 86400));

/** Time without a heartbeat before cron performs emergency job cleanup; minimum 300 seconds. */
const MAIL_MIGRATION_STALE_SECONDS = (WIN ? 900 : (TASK ? 900 : 900));

/** Interface progress refresh interval in milliseconds. */
const MAIL_MIGRATION_POLL_INTERVAL_MS = (WIN ? 3000 : (TASK ? 3000 : 3000));

/** Log read limit used to calculate progress. */
const MAIL_MIGRATION_MAX_LOG_BYTES = (WIN ? 8388608 : (TASK ? 8388608 : 8388608));

/** Character set and collation for new databases; required standard MySQL/MariaDB values. */
const MYSQL_DATABASE_CHARSET = (WIN ? 'utf8mb4' : (TASK ? 'utf8mb4' : 'utf8mb4'));
const MYSQL_DATABASE_COLLATION = (WIN ? 'utf8mb4_unicode_ci' : (TASK ? 'utf8mb4_unicode_ci' : 'utf8mb4_unicode_ci'));

/**
 * PostfixAdmin database connection. Host, port, name, user, and password are required.
 * The table names below are standard; change them only when the schema differs.
 */
const POSTFIXADMIN_DB_HOST = (WIN ? '127.0.0.1' : (TASK ? '127.0.0.1' : '127.0.0.1'));
const POSTFIXADMIN_DB_PORT = (WIN ? 3306 : (TASK ? 3306 : 3306));
const POSTFIXADMIN_DB_NAME = (WIN ? 'database_name' : (TASK ? 'database_name' : 'database_name'));
const POSTFIXADMIN_DB_USER = (WIN ? 'database_user' : (TASK ? 'database_user' : 'database_user'));
const POSTFIXADMIN_DB_PASSWORD = (WIN ? 'CHANGE_ME' : (TASK ? 'CHANGE_ME' : 'CHANGE_ME'));
const POSTFIXADMIN_DOMAIN_TABLE = (WIN ? 'domain' : (TASK ? 'domain' : 'domain'));
const POSTFIXADMIN_MAILBOX_TABLE = (WIN ? 'mailbox' : (TASK ? 'mailbox' : 'mailbox'));
const POSTFIXADMIN_ALIAS_TABLE = (WIN ? 'alias' : (TASK ? 'alias' : 'alias'));

/**
 * PostfixAdmin/Dovecot hash format and new-domain limits.
 * The scheme is required and must be supported by Dovecot. Generate a test hash:
 * doveadm pw -s SHA512-CRYPT -p 'NEW_PASSWORD'
 */
const POSTFIXADMIN_PASSWORD_SCHEME = (WIN ? 'SHA512-CRYPT' : (TASK ? 'SHA512-CRYPT' : 'SHA512-CRYPT'));
const POSTFIXADMIN_QUOTA_DIVISOR = (WIN ? 1048576 : (TASK ? 1048576 : 1048576));
const POSTFIXADMIN_DOMAIN_ALIAS_LIMIT = (WIN ? 100 : (TASK ? 100 : 100));
const POSTFIXADMIN_DOMAIN_MAILBOX_LIMIT = (WIN ? 100 : (TASK ? 100 : 100));

/**
 * Required mail DNS records. DNS_DKIM_VALUE is the public key for both shared_key modes;
 * in per_domain_keys the value comes from the domain key. {domain} in DMARC is replaced with the current domain.
 */
const DNS_DKIM_SELECTOR = (WIN ? 'default' : (TASK ? 'default' : 'default'));
const DNS_DKIM_VALUE = (WIN
    ? 'v=DKIM1; k=rsa; p=CHANGE_ME'
    : (TASK ? 'v=DKIM1; k=rsa; p=CHANGE_ME' : 'v=DKIM1; k=rsa; p=CHANGE_ME'));
const DNS_SPF_VALUE = (WIN
    ? 'v=spf1 ip4:127.0.0.1 -all'
    : (TASK ? 'v=spf1 ip4:127.0.0.1 -all' : 'v=spf1 ip4:127.0.0.1 -all'));
const DNS_DMARC_VALUE = (WIN
    ? 'v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s'
    : (TASK
        ? 'v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s'
        : 'v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s'));

/**
 * Recommended DNS records displayed before applying them.
 * name is the relative record name; type is A/AAAA/CNAME/MX/TXT/CAA/SRV;
 * ttl ranges from 60 to 2147483647 seconds; values is an array of RRSet values.
 * The optional {domain} marker is replaced with the current domain.
 */
const DNS_API_RECOMMENDED_RECORDS = [
    ['name' => '@', 'type' => 'A', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_API_RECOMMENDED_IPV4]],
    ['name' => 'www', 'type' => 'A', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_API_RECOMMENDED_IPV4]],
    ['name' => 'mail', 'type' => 'A', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_API_RECOMMENDED_IPV4]],
    ['name' => '*', 'type' => 'A', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_API_RECOMMENDED_IPV4]],
    ['name' => '@', 'type' => 'MX', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['10 mail.{domain}']],
    ['name' => '@', 'type' => 'TXT', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_SPF_VALUE]],
    ['name' => DNS_DKIM_SELECTOR . '._domainkey', 'type' => 'TXT', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_DKIM_VALUE]],
    ['name' => '_dmarc', 'type' => 'TXT', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => [DNS_DMARC_VALUE]],
    ['name' => '_pop3s._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['0 0 ' . MAIL_CLIENT_POP3_PORT . ' ' . MAIL_CLIENT_POP3_HOST . '.']],
    ['name' => '_imaps._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['10 0 ' . MAIL_CLIENT_IMAP_PORT . ' ' . MAIL_CLIENT_IMAP_HOST . '.']],
    ['name' => '_submissions._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['10 0 ' . MAIL_CLIENT_SMTP_PORT . ' ' . MAIL_CLIENT_SMTP_HOST . '.']],
    ['name' => '_submission._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['0 0 ' . MAIL_CLIENT_SMTP_STARTTLS_PORT . ' ' . MAIL_CLIENT_SMTP_HOST . '.']],
    ['name' => '_pop3._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['0 0 0 .']],
    ['name' => '_imap._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['0 0 0 .']],
    ['name' => '_autodiscover._tcp', 'type' => 'SRV', 'ttl' => DNS_API_DEFAULT_TTL, 'values' => ['0 0 ' . MAIL_CLIENT_AUTODISCOVER_PORT . ' ' . MAIL_CLIENT_AUTODISCOVER_HOST . '.']],
];

/**
 * Apache vhosts and PHP-FPM. The vhost directory and existing include paths
 * are required on Linux. The selected version ID must exist in the array.
 */
const APACHE_VHOST_DIRECTORY = (WIN ? '' : (TASK ? '/etc/httpd/conf/vhosts' : '/etc/httpd/conf/vhosts'));
const APACHE_DEFAULT_PHP_VERSION = (WIN ? 'default' : (TASK ? 'default' : 'default'));
/** Complete fallback blocks are used only when the selected version's include value is empty. */
const APACHE_PHP_DEFAULT_FALLBACK = [
    'SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1',
    '<FilesMatch \.(php|phar)$>',
    '    SetHandler "proxy:unix:/var/opt/remi/php74/run/php-fpm/www.sock|fcgi://localhost"',
    '</FilesMatch>',
];
const APACHE_PHP56_FALLBACK = ['SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1', '<FilesMatch \.(php|phar)$>', '    SetHandler "proxy:unix:/var/opt/remi/php56/run/php-fpm/www.sock|fcgi://localhost"', '</FilesMatch>'];
const APACHE_PHP74_FALLBACK = ['SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1', '<FilesMatch \.(php|phar)$>', '    SetHandler "proxy:unix:/var/opt/remi/php74/run/php-fpm/www.sock|fcgi://localhost"', '</FilesMatch>'];
const APACHE_PHP81_FALLBACK = ['SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1', '<FilesMatch \.(php|phar)$>', '    SetHandler "proxy:unix:/var/opt/remi/php81/run/php-fpm/www.sock|fcgi://localhost"', '</FilesMatch>'];
const APACHE_PHP82_FALLBACK = ['SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1', '<FilesMatch \.(php|phar)$>', '    SetHandler "proxy:unix:/var/opt/remi/php82/run/php-fpm/www.sock|fcgi://localhost"', '</FilesMatch>'];
const APACHE_PHP83_FALLBACK = ['SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1', '<FilesMatch \.(php|phar)$>', '    SetHandler "proxy:unix:/var/opt/remi/php83/run/php-fpm/www.sock|fcgi://localhost"', '</FilesMatch>'];
/** include takes precedence; fallback is written to the vhost only when include is empty. */
const APACHE_PHP_VERSIONS = (WIN ? [
    ['id' => 'default', 'label' => 'PHP — default (7.4)', 'include' => '/etc/httpd/options/php74-php.conf', 'fallback' => APACHE_PHP_DEFAULT_FALLBACK],
    ['id' => '5.6', 'label' => 'PHP 5.6', 'include' => '/etc/httpd/options/php56-php.conf', 'fallback' => APACHE_PHP56_FALLBACK],
    ['id' => '7.4', 'label' => 'PHP 7.4', 'include' => '/etc/httpd/options/php74-php.conf', 'fallback' => APACHE_PHP74_FALLBACK],
    ['id' => '8.1', 'label' => 'PHP 8.1', 'include' => '/etc/httpd/options/php81-php.conf', 'fallback' => APACHE_PHP81_FALLBACK],
    ['id' => '8.2', 'label' => 'PHP 8.2', 'include' => '/etc/httpd/options/php82-php.conf', 'fallback' => APACHE_PHP82_FALLBACK],
    ['id' => '8.3', 'label' => 'PHP 8.3', 'include' => '/etc/httpd/options/php83-php.conf', 'fallback' => APACHE_PHP83_FALLBACK],
] : (TASK ? [
    ['id' => 'default', 'label' => 'PHP — default (7.4)', 'include' => '/etc/httpd/options/php74-php.conf', 'fallback' => APACHE_PHP_DEFAULT_FALLBACK],
    ['id' => '5.6', 'label' => 'PHP 5.6', 'include' => '/etc/httpd/options/php56-php.conf', 'fallback' => APACHE_PHP56_FALLBACK],
    ['id' => '7.4', 'label' => 'PHP 7.4', 'include' => '/etc/httpd/options/php74-php.conf', 'fallback' => APACHE_PHP74_FALLBACK],
    ['id' => '8.1', 'label' => 'PHP 8.1', 'include' => '/etc/httpd/options/php81-php.conf', 'fallback' => APACHE_PHP81_FALLBACK],
    ['id' => '8.2', 'label' => 'PHP 8.2', 'include' => '/etc/httpd/options/php82-php.conf', 'fallback' => APACHE_PHP82_FALLBACK],
    ['id' => '8.3', 'label' => 'PHP 8.3', 'include' => '/etc/httpd/options/php83-php.conf', 'fallback' => APACHE_PHP83_FALLBACK],
] : [
    ['id' => 'default', 'label' => 'PHP — default (7.4)', 'include' => '/etc/httpd/options/php74-php.conf', 'fallback' => APACHE_PHP_DEFAULT_FALLBACK],
    ['id' => '5.6', 'label' => 'PHP 5.6', 'include' => '/etc/httpd/options/php56-php.conf', 'fallback' => APACHE_PHP56_FALLBACK],
    ['id' => '7.4', 'label' => 'PHP 7.4', 'include' => '/etc/httpd/options/php74-php.conf', 'fallback' => APACHE_PHP74_FALLBACK],
    ['id' => '8.1', 'label' => 'PHP 8.1', 'include' => '/etc/httpd/options/php81-php.conf', 'fallback' => APACHE_PHP81_FALLBACK],
    ['id' => '8.2', 'label' => 'PHP 8.2', 'include' => '/etc/httpd/options/php82-php.conf', 'fallback' => APACHE_PHP82_FALLBACK],
    ['id' => '8.3', 'label' => 'PHP 8.3', 'include' => '/etc/httpd/options/php83-php.conf', 'fallback' => APACHE_PHP83_FALLBACK],
]));

/** systemctl: verify with `/usr/bin/systemctl --version`; install with `dnf install -y systemd`; minimum systemd 239. */
const APACHE_SYSTEMCTL_BINARY = (WIN ? '' : (TASK ? '/usr/bin/systemctl' : '/usr/bin/systemctl'));
/** httpd: verify with `/usr/sbin/httpd -v`; install with `dnf install -y httpd`; minimum Apache HTTP Server 2.4.37. */
const APACHE_HTTPD_BINARY = (WIN ? '' : (TASK ? '/usr/sbin/httpd' : '/usr/sbin/httpd'));
/** Apache service: verify with `/usr/bin/systemctl status httpd`; installed by `dnf install -y httpd`; minimum Apache 2.4.37. */
const APACHE_SERVICE_NAME = (WIN ? '' : (TASK ? 'httpd' : 'httpd'));
/**
 * Read-only root/admin diagnostics. Service names must match systemd unit names.
 * Set a value to an empty string only when that service is intentionally not used.
 */
const SERVER_DIAGNOSTICS_SERVICE_NAMES = [
    'apache' => 'httpd',
    'database' => 'mariadb',
    'postfix' => 'postfix',
    'dovecot' => 'dovecot',
    'opendkim' => 'opendkim',
];
/** Required extensions are checked in the same PHP CLI runtime that executes root/root.php. */
const SERVER_DIAGNOSTICS_REQUIRED_PHP_EXTENSIONS = ['curl', 'json', 'mbstring', 'openssl', 'PDO', 'pdo_mysql'];
/** Maximum time for one read-only diagnostic command or database connection, in seconds. */
const SERVER_DIAGNOSTICS_TIMEOUT_SECONDS = (WIN ? 8 : (TASK ? 8 : 8));
/** Certbot: verify with `/usr/bin/certbot --version`; install with `dnf install -y epel-release certbot`; minimum Certbot 1.0.0. */
const CERTBOT_BINARY = (WIN ? '' : (TASK ? '/usr/bin/certbot' : '/usr/bin/certbot'));
/** A real email address is required for Let's Encrypt registration and notifications. */
const CERTBOT_EMAIL = (WIN ? 'admin@example.com' : (TASK ? 'admin@example.com' : 'admin@example.com'));
const CERTBOT_DRY_RUN_FIRST = (WIN ? true : (TASK ? true : true));
/** OpenSSL: verify with `/usr/bin/openssl version`; install with `dnf install -y openssl`; minimum OpenSSL 1.1.1. */
const CERTBOT_OPENSSL_BINARY = (WIN ? '' : (TASK ? '/usr/bin/openssl' : '/usr/bin/openssl'));
const CERTBOT_REQUIRE_HOSTING_DNS = (WIN ? false : (TASK ? false : true));
/** OpenDKIM: verify with `opendkim -V` and `/usr/bin/systemctl status opendkim`; install with `dnf install -y epel-release opendkim`; minimum OpenDKIM 2.11.0. */
const OPENDKIM_SERVICE_NAME = (WIN ? '' : (TASK ? 'opendkim' : 'opendkim'));
/**
 * Mode: shared_key_all_domains, shared_key_managed_domains, or per_domain_keys.
 * The default is the current Domain * setup without modifying OpenDKIM files.
 * For shared_key_managed_domains: Domain file:/etc/opendkim/SigningDomains.
 * For per_domain_keys, remove Domain/Selector/KeyFile and enable KeyTable and SigningTable below.
 * ImagoPanel never modifies TrustedHosts. Cron entry for temporary-key cleanup:
 * 0,10,20,30,40,50 * * * * /usr/bin/php /var/www/imagopanel/public_html/cron/cleanup_opendkim_keys.php --prod
 */
const OPENDKIM_MANAGEMENT_MODE = (WIN ? 'shared_key_all_domains' : (TASK ? 'shared_key_all_domains' : 'shared_key_all_domains'));
/** In shared_key_managed_domains, add to opendkim.conf: Domain file:/etc/opendkim/SigningDomains. */
const OPENDKIM_SIGNING_DOMAINS_FILE = (WIN ? __DIR__ . '/storage/opendkim-test/SigningDomains' : (TASK ? '/etc/opendkim/SigningDomains' : '/etc/opendkim/SigningDomains'));
/** In per_domain_keys, add: KeyTable /etc/opendkim/KeyTable. */
const OPENDKIM_KEY_TABLE_FILE = (WIN ? __DIR__ . '/storage/opendkim-test/KeyTable' : (TASK ? '/etc/opendkim/KeyTable' : '/etc/opendkim/KeyTable'));
/** In per_domain_keys, add: SigningTable refile:/etc/opendkim/SigningTable. */
const OPENDKIM_SIGNING_TABLE_FILE = (WIN ? __DIR__ . '/storage/opendkim-test/SigningTable' : (TASK ? '/etc/opendkim/SigningTable' : '/etc/opendkim/SigningTable'));
/** Permanent key directory; ImagoPanel removes only directories carrying its marker. */
const OPENDKIM_KEYS_DIRECTORY = (WIN ? __DIR__ . '/storage/opendkim-test/keys' : (TASK ? '/etc/opendkim/keys' : '/etc/opendkim/keys'));
/** Temporary-key directory, automatically cleaned by cron after OPENDKIM_PENDING_KEY_TTL_SECONDS. */
const OPENDKIM_PENDING_KEYS_DIRECTORY = (WIN ? __DIR__ . '/storage/opendkim-pending' : (TASK ? '/var/lib/imagopanel/opendkim-pending' : '/var/lib/imagopanel/opendkim-pending'));
/** Global lock for DKIM changes across all users. */
const OPENDKIM_LOCK_FILE = (WIN ? ROOT_LOCK_DIRECTORY . '/opendkim.lock' : (TASK ? ROOT_LOCK_DIRECTORY . '/opendkim.lock' : ROOT_LOCK_DIRECTORY . '/opendkim.lock'));
/** PHP CLI: `php -m | grep openssl`; new RSA keys must be at least 2048 bits. */
const OPENDKIM_KEY_BITS = (WIN ? 2048 : (TASK ? 2048 : 2048));
/** Fallback OpenSSL: `/usr/bin/openssl version`; `dnf install -y openssl`; minimum 1.1.1. */
const OPENDKIM_OPENSSL_BINARY = (WIN ? '' : (TASK ? '/usr/bin/openssl' : '/usr/bin/openssl'));
/** Lifetime of an unused temporary key: 3600 seconds. */
const OPENDKIM_PENDING_KEY_TTL_SECONDS = (WIN ? 3600 : (TASK ? 3600 : 3600));
/** Owner of OpenDKIM files. */
const OPENDKIM_FILE_OWNER = (WIN ? '' : (TASK ? 'opendkim' : 'opendkim'));
/** Group of OpenDKIM files. */
const OPENDKIM_FILE_GROUP = (WIN ? '' : (TASK ? 'opendkim' : 'opendkim'));
/** OpenDKIM directory permissions. */
const OPENDKIM_DIRECTORY_MODE = 0750;
/** Private-key and metadata permissions. */
const OPENDKIM_PRIVATE_KEY_MODE = 0600;
/** OpenDKIM table-file permissions. */
const OPENDKIM_TABLE_FILE_MODE = 0640;
/** systemctl: `/usr/bin/systemctl --version`; systemd 239 or newer. */
const OPENDKIM_SYSTEMCTL_BINARY = (WIN ? '' : (TASK ? '/usr/bin/systemctl' : '/usr/bin/systemctl'));
/** After table or key changes, restart is used to guarantee that OpenDKIM reloads them. */
const OPENDKIM_SYSTEMCTL_ACTION = (WIN ? '' : (TASK ? 'restart' : 'restart'));

/**
 * Let's Encrypt file templates. Keep the standard Linux paths,
 * or replace them for a non-standard Certbot installation. The {domain} marker is required.
 */
const APACHE_SSL_CERTIFICATE_TEMPLATE = (WIN
    ? '/etc/letsencrypt/live/{domain}/fullchain.pem'
    : (TASK ? '/etc/letsencrypt/live/{domain}/fullchain.pem' : '/etc/letsencrypt/live/{domain}/fullchain.pem'));
const APACHE_SSL_KEY_TEMPLATE = (WIN
    ? '/etc/letsencrypt/live/{domain}/privkey.pem'
    : (TASK ? '/etc/letsencrypt/live/{domain}/privkey.pem' : '/etc/letsencrypt/live/{domain}/privkey.pem'));
const APACHE_SSL_OPTIONS_FILE = (WIN
    ? '/etc/letsencrypt/options-ssl-apache.conf'
    : (TASK ? '/etc/letsencrypt/options-ssl-apache.conf' : '/etc/letsencrypt/options-ssl-apache.conf'));

/** SSL validation uses OpenSSL: `/usr/bin/openssl version`; `dnf install -y openssl`; minimum 1.1.1. */
const STATS_SSL_CHECK_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/openssl', 's_client', '-connect', '{DOMAIN}:443', '-servername', '{DOMAIN}',
    '-verify_hostname', '{DOMAIN}', '-verify_return_error', '-brief',
] : [
    '/usr/bin/openssl', 's_client', '-connect', '{DOMAIN}:443', '-servername', '{DOMAIN}',
    '-verify_hostname', '{DOMAIN}', '-verify_return_error', '-brief',
]));
/** DNS A validation uses dig: `/usr/bin/dig -v`; `dnf install -y bind-utils`; minimum BIND utilities 9.11. */
const STATS_DOMAIN_DNS_CHECK_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'A', '{DOMAIN}',
] : [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'A', '{DOMAIN}',
]));
/** DKIM TXT validation uses dig: `/usr/bin/dig -v`; `dnf install -y bind-utils`; minimum BIND utilities 9.11. */
const STATS_DKIM_CHECK_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'TXT', '{DKIM_SELECTOR}._domainkey.{DOMAIN}',
] : [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'TXT', '{DKIM_SELECTOR}._domainkey.{DOMAIN}',
]));
/** SPF TXT validation uses dig: `/usr/bin/dig -v`; `dnf install -y bind-utils`; minimum BIND utilities 9.11. */
const STATS_SPF_CHECK_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'TXT', '{DOMAIN}',
] : [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'TXT', '{DOMAIN}',
]));
/** DMARC TXT validation uses dig: `/usr/bin/dig -v`; `dnf install -y bind-utils`; minimum BIND utilities 9.11. */
const STATS_DMARC_CHECK_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'TXT', '_dmarc.{DOMAIN}',
] : [
    '/usr/bin/dig', '+short', '+time=5', '+tries=1', 'TXT', '_dmarc.{DOMAIN}',
]));
/** mysql client: verify with `/usr/bin/mysql --version`; install with `dnf install -y mariadb`; minimum MariaDB client 10.3. */
const STATS_MYSQL_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/mysql', '--batch', '--skip-column-names', '--host={MYSQL_HOST}',
    '--port={MYSQL_PORT}', '--user={MYSQL_USER}', '--execute={SQL}',
] : [
    '/usr/bin/mysql', '--batch', '--skip-column-names', '--host={MYSQL_HOST}',
    '--port={MYSQL_PORT}', '--user={MYSQL_USER}', '--execute={SQL}',
]));
/** find: verify with `/usr/bin/find --version`; install with `dnf install -y findutils`; minimum GNU findutils 4.6.0. */
const STATS_MAILBOX_COUNT_COMMAND = (WIN ? [] : (TASK ? [
    '/usr/bin/find', '{MAIL_DOMAIN_PATH}', '-mindepth', '1', '-maxdepth', '1', '-type', 'd', '-print0',
] : [
    '/usr/bin/find', '{MAIL_DOMAIN_PATH}', '-mindepth', '1', '-maxdepth', '1', '-type', 'd', '-print0',
]));
/** Mailbox du: verify with `/usr/bin/du --version`; install with `dnf install -y coreutils`; minimum GNU coreutils 8.30. */
const STATS_MAILBOX_SIZE_COMMAND = (WIN ? [] : (TASK
    ? ['/usr/bin/du', '-sb', '--', '{MAILBOX_PATH}']
    : ['/usr/bin/du', '-sb', '--', '{MAILBOX_PATH}']));
/** Mail-domain du: verify with `/usr/bin/du --version`; install with `dnf install -y coreutils`; minimum GNU coreutils 8.30. */
const STATS_MAIL_DOMAIN_SIZE_COMMAND = (WIN ? [] : (TASK
    ? ['/usr/bin/du', '-sb', '--', '{MAIL_DOMAIN_PATH}']
    : ['/usr/bin/du', '-sb', '--', '{MAIL_DOMAIN_PATH}']));
/** public_html du: verify with `/usr/bin/du --version`; install with `dnf install -y coreutils`; minimum GNU coreutils 8.30. */
const STATS_DOMAIN_DIRECTORY_SIZE_COMMAND = (WIN ? [] : (TASK
    ? ['/usr/bin/du', '-sb', '--', '{DOMAIN_PUBLIC_PATH}']
    : ['/usr/bin/du', '-sb', '--', '{DOMAIN_PUBLIC_PATH}']));

/**
 * Statistics SQL. Templates are required; {DATABASE} is replaced with the validated database name.
 */
const STATS_DATABASE_SIZE_SQL = (WIN
    ? "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = '{DATABASE}';"
    : (TASK
        ? "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = '{DATABASE}';"
        : "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = '{DATABASE}';"));
const STATS_DATABASE_TABLE_COUNT_SQL = (WIN
    ? "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '{DATABASE}';"
    : (TASK
        ? "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '{DATABASE}';"
        : "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '{DATABASE}';"));

date_default_timezone_set(PANEL_TIMEZONE);
