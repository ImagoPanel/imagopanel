# Contributing to ImagoPanel

Thank you for helping improve ImagoPanel. Keep changes focused, reviewable, and compatible with the existing architecture.

## Issues and feature requests

- Search existing Issues before opening a new one.
- Use the provided bug or feature template.
- Include the ImagoPanel version, PHP version, server distribution, affected service versions, and exact reproduction steps when relevant.
- Remove credentials, customer data, private domains, and internal logs before attaching output.
- Keep one independently actionable problem or proposal per Issue.

Security vulnerabilities must follow [`SECURITY.md`](SECURITY.md) and must not be filed publicly.

## Pull requests

- Explain the problem, the chosen solution, and how the change was tested.
- Keep unrelated formatting, refactoring, and feature work out of the same pull request.
- Preserve the PHP and JSON architecture unless a proposal has been discussed first.
- Do not commit `config.php`, runtime data, logs, credentials, generated keys, IDE files, or backups.
- Update public English documentation when behavior or configuration changes.
- Add or update tests for behavior that can be checked without modifying a real server.

## Compatibility and style

- Keep core application code compatible with PHP 7.4.
- Use Bootstrap 5.3, Bootstrap Icons, jQuery, and the locally bundled browser libraries already used by the project.
- Do not add CDN dependencies for application assets.
- Keep configuration in `config.php` and document public settings in `config.example.php`.
- Keep `config.example.php` comments and all GitHub-facing documentation in English.
- Validate inputs, authorize resource ownership, use prepared database statements, and preserve CSRF checks for mutations.
- Privileged commands must avoid a shell and use explicit configured executable paths.

## Validation

At minimum:

1. Run `php -l` for every changed PHP file using PHP 7.4.
2. Validate changed JSON files with a strict parser.
3. Run the relevant scripts in `tests/`.
4. For server integrations, clearly distinguish static/local checks from tests performed on an actual server or provider account.

By submitting a contribution, you agree that it may be distributed under this repository's AGPL-3.0 license.
