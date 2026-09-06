# Security Policy

## Reporting a vulnerability

Do not report security vulnerabilities through public GitHub Issues, Discussions, pull requests, or public chat channels.

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.
4. Include the affected version or commit, impact, prerequisites, reproduction steps, and any safe proof of concept.

If private vulnerability reporting is unavailable, email **security@imagopanel.com**. Security reports must be sent privately and must not be opened as public Issues or Discussions.

Please allow the maintainers a reasonable opportunity to investigate and prepare a fix before disclosure. Do not access, modify, or retain data that does not belong to you, and do not test against third-party or production systems without explicit authorization.

## Supported versions

Security fixes are provided for the latest published ImagoPanel release and the current default development branch. Older deployments should be upgraded before requesting a backport.

## Sensitive information

Never commit or attach:

- `config.php`
- passwords or password hashes from real users
- API keys, access tokens, session secrets, or private keys
- SMTP, database, DNS provider, or registrar credentials
- per-user JSON files
- customer domains, email addresses, or access rules
- runtime logs, reports, lock files, backups, or temporary credentials

`config.example.php` is the public documented template. It must contain placeholders only. `config.php` is private, installation-specific, and excluded from version control.

If a secret was committed, removing it from the latest revision is not sufficient. Revoke or rotate it immediately and follow the hosting provider's process for removing it from repository history.

## Operational security

ImagoPanel controls real server services. Deployments should use a dedicated PHP-FPM pool, restrictive filesystem permissions, an exact `sudoers` command for the CLI-only helper, HTTPS, current service updates, protected runtime directories, and routine review of root/admin diagnostics and audit logs.
