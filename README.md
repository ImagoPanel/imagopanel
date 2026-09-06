# ImagoPanel

**Open Source Hosting Control Panel**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
![PHP 7.4](https://img.shields.io/badge/PHP-7.4-777BB4.svg)
![Open Source](https://img.shields.io/badge/Open%20Source-Yes-2ea44f.svg)

ImagoPanel is an open-source hosting control panel for managing websites, databases, mailboxes, DNS, and controlled access to common administration tools on an existing Linux hosting server.

Current release: **v1.18.8**

Developed and maintained by **SIA TASK.LV**.

Commercial support, installation, migration and custom development are available from SIA TASK.LV.

- Website: [imagopanel.com](https://imagopanel.com)
- Source: [github.com/ImagoPanel/ImagoPanel](https://github.com/ImagoPanel/ImagoPanel)
- Author: Vladimir / bmg1

## What makes ImagoPanel different

ImagoPanel does not require a control-panel database for its own operation. Its control and configuration architecture is based on PHP, JSON documents, and the actual server configuration and state. MySQL or MariaDB is managed as a hosting service, and an existing PostfixAdmin-compatible database can be used for mail provisioning, but neither is used as an internal ImagoPanel state database.

This design keeps the panel close to the services it manages and makes the on-disk state inspectable. It also means that installation must be completed carefully: service paths, permissions, the privileged helper, and every integration must match the target server.

## Main features

- Apache virtual-host management
- Multiple configurable PHP/PHP-FPM versions
- MariaDB/MySQL database and account management
- Postfix/Dovecot mailbox management through a PostfixAdmin-compatible schema
- OpenDKIM support with shared-key and per-domain-key modes
- DNS registrar and DNS hosting integrations, including Hetzner, Joker.com, REG.RU, Namecheap, and Internet.bs
- DNS zone retrieval, editing, synchronization, copying, and recommended record templates
- Secure, database-scoped phpMyAdmin access
- Secure, domain-directory-scoped File Manager and File Editor access
- Optional IP restrictions for ImagoPanel users
- Optional time-limited access to administrative tools
- Mail-client autoconfiguration endpoints and Apple configuration profiles
- Legacy IMAP mailbox migration through `imapsync`
- Root/admin server and configuration diagnostics
- JSON-based status collection and audit logs

Some capabilities are optional and appear only when their required services and configuration are enabled.

## Architecture

The browser interface uses locally bundled Bootstrap 5.3, Bootstrap Icons, jQuery, and DataTables assets. Requests are handled by `api/index.php`, which validates authentication, authorization, CSRF state, and resource ownership.

Normal panel state is stored in per-user JSON documents. Operations that require elevated server access are passed as structured JSON to the CLI-only `root/root.php` helper through a narrowly scoped `sudo` rule. The helper executes configured binaries without a shell, validates resource identifiers and paths, and writes only the server state required by the requested operation. Scheduled collectors store operational status in separate JSON files.

The root/admin diagnostics screen is read-only. It compares `config.php` with the host and checks configured executables, versions, systemd services, PHP extensions, PHP-FPM includes and sockets, Apache syntax, database connectivity, required paths and permissions, OpenDKIM mode files, and DNS provider endpoints. It never restarts services or returns configured credentials.

## Requirements

Production use is intended for a Linux server with:

- Apache HTTP Server 2.4.37 or newer
- PHP 7.4 CLI for ImagoPanel itself, with `curl`, `json`, `mbstring`, `openssl`, `PDO`, and `pdo_mysql`
- one or more configured PHP-FPM pools for hosted sites
- MariaDB or MySQL
- Postfix and Dovecot when mail management is enabled
- OpenDKIM when DKIM management or signing is enabled
- `systemd`, `sudo`, `dig`, `openssl`, and `chown`
- Certbot when automatic TLS certificate management is enabled
- `imapsync` 2.229 or newer when legacy mailbox migration is enabled

Exact binary paths, service names, directories, sockets, minimum versions, and optional feature switches are documented next to their settings in [`config.example.php`](config.example.php).

## Installation overview

ImagoPanel changes real web, database, mail, DNS, and filesystem configuration. Test the complete setup in a non-production environment before managing customer services.

1. Place the application in its final Apache-served directory.
2. Copy `config.example.php` to the private local file `config.php`.
3. Replace every `CHANGE_ME`, example hostname, test address, path, service name, and socket with a value for the target server.
4. Configure the global Apache aliases and access rules documented at the top of `config.example.php` and in `mailautoconfig/readme.md`.
5. Configure the exact passwordless `sudo` command for `root/root.php`. Do not grant the web server unrestricted sudo access.
6. Create the required runtime directories outside the public web root where the example configuration requires them, then apply the documented owners and modes.
7. Configure the status and cleanup cron jobs documented in `config.example.php`.
8. Validate PHP syntax and Apache configuration before opening the panel.
9. Sign in as root/admin and run **Server diagnostics**. Resolve every Error and review every Warning before enabling server mutations for users.

The example configuration is documentation, not a ready-to-run production configuration. Never deploy its placeholder credentials or example domains.

## Configuration

All local settings are defined in `config.php`; ImagoPanel does not use `.env` files. The repository contains only `config.example.php`.

- Keep `config.php` outside version control and restrict its filesystem permissions.
- Use password hashes and independently generated random secrets where documented.
- Keep production API credentials in `config.php` or in the panel's protected per-user JSON storage, never in public source files.
- Review the environment branches (`WIN`, `TASK`, and `PROD`) before deployment.
- Keep the PHP 7.4 CLI path for the panel separate from optional PHP-FPM versions offered to hosted sites.
- Treat changes to service paths, Apache includes, OpenDKIM files, and storage owners as server-administration changes.

## Security model

ImagoPanel applies role checks, per-user resource ownership, CSRF protection, session controls, optional email verification, optional IP allowlists, DNS API host allowlists, path validation, bounded command execution, and scoped tool-launch tokens. Privileged operations are isolated behind the CLI-only helper and an exact `sudoers` command.

The security of an installation still depends on correct Apache, PHP-FPM, filesystem, database, mail, DNS, and sudo configuration. Keep `config.php`, user JSON, logs, temporary credentials, and generated keys out of the public repository. Review [`SECURITY.md`](SECURITY.md) before reporting a vulnerability or operating a public instance.

## Project structure

| Path | Purpose |
| --- | --- |
| `index.php` | Panel entry point and authentication bootstrap |
| `api/` | Authenticated JSON API |
| `assets/` | Local UI assets, translations, and client code |
| `lib/` | Storage, service integrations, security helpers, and diagnostics |
| `root/` | CLI-only privileged helper and mail migration worker |
| `cron/` | Status and cleanup jobs |
| `data/` | Local per-user JSON data; never publish its runtime contents |
| `storage/` | Local status, locks, logs, temporary state, and reports |
| `filemanager/` | Restricted File Manager entry point |
| `fileeditor/` | Restricted File Editor entry point |
| `phpmyadmin/` | Bundled phpMyAdmin distribution and scoped entry configuration |
| `mailautoconfig/` | Shared mail-client autoconfiguration endpoints |
| `tests/` | Project checks and regression tests |

## Third-party software

ImagoPanel ships selected independent third-party tools and libraries as bundled example or preconfigured integrations. They are separate upstream projects, are not owned or relicensed by ImagoPanel or SIA TASK.LV, and each remains governed by its own license. The GNU AGPL-3.0 license covers original ImagoPanel code unless otherwise indicated.

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for exact versions, upstream projects, copyright holders, local paths, modification status, and retained license locations.

## Development and validation

Keep application changes compatible with PHP 7.4. Do not add remote CDN dependencies; browser libraries are served locally. Keep changes focused and validate every changed PHP file with `php -l`.

The repository validation workflow performs PHP 7.4 syntax checks and rejects accidentally tracked local/runtime files. It does not provision or modify a hosting server.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidelines and [`CHANGELOG.md`](CHANGELOG.md) for release notes.

## Support

Community support and reproducible bug reports belong in GitHub Issues. GitHub Discussions may be used when enabled for the repository.

Commercial installation, migration, troubleshooting, custom configuration, custom development, and support are available from **SIA TASK.LV**. See [`SUPPORT.md`](SUPPORT.md).

## License

ImagoPanel is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Copyright © 2026 SIA TASK.LV.

Planned separate repositories may use different licenses: `imagopanel/sdk` under MIT, `imagopanel/examples` under MIT, and `imagopanel/integrations` under Apache-2.0 or MIT as appropriate. Those plans do not change the license of this repository.
