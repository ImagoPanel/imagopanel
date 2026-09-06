# Changelog

All notable changes to ImagoPanel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases should use semantic versioning once public version tags are established.

## [Unreleased]

### Added

- Added sequential bulk DNS record changes with user/provider/domain filters, searchable multi-selection, per-zone provider verification, progress, and detailed failure reporting for users and root/admin.

### Fixed

- Split long Hetzner TXT values into DNS character-strings of at most 255 bytes while preserving one logical DKIM value.

### Security

- Isolated phpMyAdmin 5.2.2 from ImagoPanel AGPL application code through an original standalone MIT access adapter with one-time, host-bound and IP-bound launch state plus continuously revalidated server-side sessions.
- Removed Tiny File Manager's URL-upload user interface and server-side remote-fetch handler, eliminating the shipped `GHSA-wqww-g3x9-r7fw` / `CVE-2025-46651` SSRF path while retaining local uploads.
- Removed Pheditor's standalone/default/change-password authentication and terminal/shell execution functionality, addressing all six published advisories affecting the retained 2.0.1 code base without changing its reported base version.

## [1.18.8] - 2026-09-06

### Added

- Read-only root/admin diagnostics for configured executables, services, PHP extensions, PHP-FPM sockets, Apache syntax, database access, paths, permissions, OpenDKIM, and DNS provider endpoints.
- Localized server diagnostics, including actionable guidance for every warning and error, across all 43 interface languages.
- Public project documentation, contribution and support policies, security reporting guidance, Issue templates, a pull request template, and repository validation CI.
- Third-party software inventory, upstream attributions, modification status, and retained license locations.
- Project authorship and ownership information in `AUTHORS.md`.

### Changed

- Mail migration runtime data now stays under the configured ImagoPanel installation root instead of `/var/lib` and `/var/log`.
- Tiny File Manager and Pheditor browser dependencies are served from bundled local assets instead of runtime CDNs.
- PHPMailer and its Composer autoloader are shipped from the tracked `lib/vendor/` path instead of the excluded landing directory.
- Public release metadata and browser asset version are aligned to v1.18.8.
- PHP 7.4 CI lint covers ImagoPanel and bundled application code while excluding phpMyAdmin's upstream Composer vendor tree, which contains conditionally loaded PHP 8-only source files.

### Security

- Expanded ignore rules for private configuration, per-user JSON, runtime logs, locks, status files, temporary migration data, generated keys, backups, and common private-key formats.
- Replaced the security-contact placeholder with `security@imagopanel.com` and retained private reporting as the required channel.
- Removed disabled upstream sample tool credentials from the integrated File Manager and File Editor source.

### Notes

- Existing application behavior was intentionally preserved outside the server diagnostics feature.
- phpMyAdmin remains bundled at version 5.2.2 with the existing ImagoPanel integration; no automatic upstream replacement was performed.
