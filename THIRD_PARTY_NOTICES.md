# Third-party software notices

ImagoPanel includes selected independent third-party software as bundled example or preconfigured integrations for convenience. These components are not authored, owned, or relicensed by ImagoPanel or SIA TASK.LV. They remain subject to their respective upstream licenses and copyright notices. Inclusion does not imply affiliation with or endorsement by the upstream projects.

ImagoPanel is licensed under the GNU Affero General Public License v3.0. That license covers original ImagoPanel code unless otherwise indicated; it does not replace or relicense bundled third-party components.

The `Modified` column describes changes made for ImagoPanel integration. License texts and upstream notices are shipped beside the corresponding code. Copyright details below are transcribed from the shipped upstream notices; where a project identifies a team or contributors collectively, that upstream attribution is retained.

## Bundled applications

| Component | Version | License | Upstream and copyright | Local path | Modified | Original license or notice |
| --- | --- | --- | --- | --- | --- | --- |
| phpMyAdmin | 5.2.2 | GPL-2.0-only | [phpMyAdmin](https://github.com/phpmyadmin/phpmyadmin), Copyright © 1998 onwards — the phpMyAdmin team | `phpmyadmin/` | Modified only through `phpmyadmin/config.inc.php`, which calls the separately licensed standalone access adapter described below; the bundled upstream application was not upgraded | `phpmyadmin/LICENSE`, `phpmyadmin/README`, `phpmyadmin/composer.json`, and `phpmyadmin/doc/html/copyright.html` |
| Tiny File Manager | 2.6 | GNU GPL v3.0 (upstream identifier: GPL-3.0; no later-version grant is stated in the bundled notice) | [Tiny File Manager](https://github.com/prasathmani/tinyfilemanager), CCP Programmers / Prasath Mani and contributors | `filemanager/index.php` | Modified for integration with ImagoPanel — domain-scoped authorization, path restrictions, disabled standalone credentials, local asset URLs, and complete removal of URL upload/server-side remote fetching | `filemanager/LICENSE` and the upstream attribution header in `filemanager/index.php` |
| Pheditor | 2.0.1 | MIT | [Pheditor](https://github.com/pheditor/pheditor), Copyright © 2016 Hamid Samak | `fileeditor/index.php` | Modified ImagoPanel integration based on Pheditor 2.0.1. Standalone authentication and terminal functionality have been removed. Relevant upstream security fixes have been backported. Domain-scoped authorization and local browser assets are retained. | `fileeditor/LICENSE` and the upstream attribution header in `fileeditor/index.php` |

These applications are distributed as identifiable independent third-party example or preconfigured integrations with their original notices. phpMyAdmin is not relicensed under the ImagoPanel license. Tiny File Manager and Pheditor source modifications are shipped in source form together with their original notices.

### ImagoPanel phpMyAdmin access adapter — MIT exception

`phpmyadmin/imagopanel-access/Adapter.php` is original integration code authored by SIA TASK.LV and released separately under the MIT License. Its complete license is at `phpmyadmin/imagopanel-access/LICENSE`, and the source carries an SPDX identifier. This explicit exception applies only to that adapter and does not relicense other ImagoPanel code.

The adapter does not include, require, or execute `lib/DomainToolAccess.php`, `config.php`, or other AGPL application source. It communicates across a file-data boundary: read-only per-user JSON plus short-lived launch/settings/session JSON in the protected domain-tool state directory. The handoff contains access selection and public runtime settings only; no application signing secret or DNS, SMTP, root, or administrator credential is copied into phpMyAdmin. Database credentials are read only for the validated selected database and are supplied directly to phpMyAdmin's local configuration process.

The adapter validates the requested tool, active user/domain/database, one-time launch expiry, request host, client IP, temporary-access time window, IP allowlist, and phpMyAdmin permission. Its opaque server-side sessions are revalidated on every request and fail closed when state is absent, invalid, expired, moved to another host/IP, or no longer authorized.

## Shared ImagoPanel browser assets

| Component | Version | License | Upstream and copyright | Local path | Modified | Original license |
| --- | --- | --- | --- | --- | --- | --- |
| Bootstrap | 5.3.8 | MIT | [Bootstrap](https://github.com/twbs/bootstrap), Copyright © 2011–2025 The Bootstrap Authors | `assets/vendor/bootstrap/` | No | `assets/vendor/bootstrap/LICENSE` |
| Bootstrap Icons | 1.13.1 | MIT | [Bootstrap Icons](https://github.com/twbs/icons), Copyright © 2019–2024 The Bootstrap Authors | `assets/vendor/bootstrap-icons/` | No | `assets/vendor/bootstrap-icons/LICENSE` |
| jQuery | 3.7.1 | MIT | [jQuery](https://github.com/jquery/jquery), Copyright OpenJS Foundation and other contributors | `assets/vendor/jquery/` | No | `assets/vendor/jquery/LICENSE.txt` |
| DataTables | 3.0.2 | MIT | [DataTables](https://github.com/DataTables/DataTablesSrc), Copyright © 2008–present SpryMedia Ltd. | `assets/vendor/datatables/` | No | `assets/vendor/datatables/LICENSE.txt` |
| PHPMailer | 6.12.0 | LGPL-2.1-only | [PHPMailer](https://github.com/PHPMailer/PHPMailer), Copyright © 2012–2020 Marcus Bointon, 2010–2012 Jim Jagielski, 2004–2009 Andy Prevost, and the original founder Brent R. Matzelle | `lib/vendor/phpmailer/phpmailer/` | No | `lib/vendor/phpmailer/phpmailer/LICENSE` and source-file headers |
| Composer generated autoloader | 2.x generated runtime | MIT | [Composer](https://github.com/composer/composer), Copyright © Nils Adermann and Jordi Boggiano | `lib/vendor/composer/` | No | `lib/vendor/composer/LICENSE` |

## Tiny File Manager browser assets

| Component | Version | License | Upstream and copyright | Local path | Modified | Original license or notice |
| --- | --- | --- | --- | --- | --- | --- |
| Bootstrap | 5.3.3 | MIT | [Bootstrap](https://github.com/twbs/bootstrap), Copyright © 2011–2024 The Bootstrap Authors | `filemanager/assets/vendor/bootstrap/` | No | `filemanager/assets/vendor/bootstrap/LICENSE` |
| Popper (embedded in Bootstrap bundle) | 2.11.8 | MIT | [Popper](https://github.com/floating-ui/floating-ui), Copyright © 2019 Federico Zivolo | `filemanager/assets/vendor/bootstrap/js/bootstrap.bundle.min.js` | No | `filemanager/assets/vendor/bootstrap/POPPER-LICENSE.md` |
| Dropzone | 5.9.3 | MIT | [Dropzone](https://github.com/dropzone/dropzone), Copyright © 2021 Matias Meno | `filemanager/assets/vendor/dropzone/` | No | `filemanager/assets/vendor/dropzone/LICENSE` |
| Font Awesome | 4.7.0 | Font: SIL OFL 1.1; CSS/LESS/Sass: MIT; documentation: CC BY 3.0 | [Font Awesome](https://github.com/FortAwesome/Font-Awesome), Dave Gandy / Fonticons, Inc. and contributors | `filemanager/assets/vendor/font-awesome/` | No | `filemanager/assets/vendor/font-awesome/UPSTREAM-README.md` (the 4.7.0 upstream release carries its license statement in the README) |
| Highlight.js | 11.9.0 | BSD-3-Clause | [Highlight.js](https://github.com/highlightjs/highlight.js), Copyright © 2006 Ivan Sagalaev | `filemanager/assets/vendor/highlight.js/` | No | `filemanager/assets/vendor/highlight.js/LICENSE` |
| Ace | 1.32.2 | BSD-3-Clause | [Ace](https://github.com/ajaxorg/ace), Copyright © 2010 Ajax.org B.V. | `filemanager/assets/vendor/ace/` | No | `filemanager/assets/vendor/ace/LICENSE` |
| jQuery | 3.6.1 | MIT | [jQuery](https://github.com/jquery/jquery), Copyright OpenJS Foundation and other contributors | `filemanager/assets/vendor/jquery/` | No | `filemanager/assets/vendor/jquery/LICENSE.txt` |
| DataTables | 1.13.1 | MIT | [DataTables](https://github.com/DataTables/DataTablesSrc), Copyright © 2008–present SpryMedia Ltd. | `filemanager/assets/vendor/datatables/` | No | `filemanager/assets/vendor/datatables/LICENSE.txt` |

## Pheditor browser assets

| Component | Version | License | Upstream and copyright | Local path | Modified | Original license or notice |
| --- | --- | --- | --- | --- | --- | --- |
| Bootstrap | 5.3.3 | MIT | [Bootstrap](https://github.com/twbs/bootstrap), Copyright © 2011–2024 The Bootstrap Authors | `fileeditor/assets/vendor/bootstrap/` | No | `fileeditor/assets/vendor/bootstrap/LICENSE` |
| Popper (embedded in Bootstrap bundle) | 2.11.8 | MIT | [Popper](https://github.com/floating-ui/floating-ui), Copyright © 2019 Federico Zivolo | `fileeditor/assets/vendor/bootstrap/js/bootstrap.bundle.min.js` | No | `fileeditor/assets/vendor/bootstrap/POPPER-LICENSE.md` |
| jsTree | 3.3.17 | MIT | [jsTree](https://github.com/vakata/jstree), Copyright © 2014 Ivan Bozhanov | `fileeditor/assets/vendor/jstree/` | No | `fileeditor/assets/vendor/jstree/LICENSE-MIT` |
| CodeMirror 5 | 5.65.7 | MIT | [CodeMirror 5](https://github.com/codemirror/codemirror5), Copyright © 2017 Marijn Haverbeke and others | `fileeditor/assets/vendor/codemirror/` | No | `fileeditor/assets/vendor/codemirror/LICENSE` |
| JSHint | 2.13.6 | MIT | [JSHint](https://github.com/jshint/jshint), Copyright © 2012 Anton Kovalyov | `fileeditor/assets/vendor/jshint/` | No | `fileeditor/assets/vendor/jshint/LICENSE` |
| JSONLint | 1.6.0 | MIT | [JSONLint](https://github.com/zaach/jsonlint), Copyright © 2012 Zachary Carter | `fileeditor/assets/vendor/jsonlint/` | No | `fileeditor/assets/vendor/jsonlint/UPSTREAM-README.md` (the upstream release carries its MIT text in the README) |
| iziToast | 1.4.0 | Apache-2.0 | [iziToast](https://github.com/marcelodolza/iziToast), Marcelo Dolza and contributors | `fileeditor/assets/vendor/izitoast/` | No | `fileeditor/assets/vendor/izitoast/LICENSE` |
| Font Awesome Free | 6.7.2 | Icons: CC BY 4.0; fonts: SIL OFL 1.1; code: MIT | [Font Awesome](https://github.com/FortAwesome/Font-Awesome), Fonticons, Inc. and contributors | `fileeditor/assets/vendor/font-awesome/` | No | `fileeditor/assets/vendor/font-awesome/LICENSE.txt` |
| jQuery | 3.7.1 | MIT | [jQuery](https://github.com/jquery/jquery), Copyright OpenJS Foundation and other contributors | `fileeditor/assets/vendor/jquery/` | No | `fileeditor/assets/vendor/jquery/LICENSE.txt` |
| js-sha512 | 0.9.0 | MIT | [js-sha512](https://github.com/emn178/js-sha512), Copyright © 2014–2024 Chen, Yi-Cyuan | `fileeditor/assets/vendor/js-sha512/` | No | `fileeditor/assets/vendor/js-sha512/LICENSE.txt` |

## phpMyAdmin dependency inventory

phpMyAdmin 5.2.2 is kept as the upstream all-languages distribution with its installed Composer dependencies. Their exact package names, versions, source URLs, and SPDX license identifiers are retained in `phpmyadmin/vendor/composer/installed.json` and `phpmyadmin/composer.lock`. Individual license texts remain in each `phpmyadmin/vendor/<vendor>/<package>/LICENSE*` file. The installed license set is:

- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- GPL-2.0-or-later
- ISC
- LGPL-3.0-or-later
- MIT
- MPL-2.0

phpMyAdmin's own documentation also lists its JavaScript, CSS, icon, font, and other embedded third-party notices at `phpmyadmin/doc/html/copyright.html#third-party-licenses`. Those nested dependencies are unmodified by ImagoPanel.

### phpMyAdmin 5.2.2 dependency audit notes

A Composer advisory audit on 2026-09-06 reports affected-version matches in the unchanged phpMyAdmin 5.2.2 lock file. The distribution and lock file were not upgraded, replaced, downloaded, or selectively merged because this release intentionally retains the exact bundled 5.2.2 distribution.

- `paragonie/sodium_compat` 1.21.1 matches current Ed25519 validation advisories. The standalone ImagoPanel access adapter does not call the native `sodium` extension or this compatibility package. The package remains part of the unchanged phpMyAdmin distribution, so deployments using phpMyAdmin features that invoke its Ed25519 compatibility path must treat the advisory as unresolved.
- `symfony/cache` 5.4.46 and `symfony/process` 5.4.47 match current advisories for `PdoAdapter::doClear()` and MSYS2/Git Bash command escaping respectively. No phpMyAdmin application source in this distribution imports or instantiates Symfony Cache or Symfony Process; the deployment target is Linux, not MSYS2/Git Bash.
- `twig/twig` 3.11.3 matches current sandbox and untrusted-template compilation advisories. The shipped phpMyAdmin integration uses a `FilesystemLoader` restricted to the bundled local `phpmyadmin/templates` directory, does not install Twig's `SandboxExtension`, and has no runtime user-template source or writable template directory exposed through ImagoPanel's domain-scoped file tools. These advisory prerequisites are not present in the supported deployment. Any future addition of user-controlled Twig templates, Twig sandboxing, or write access to the phpMyAdmin application/template tree requires a new review.

These are deployment-context dispositions, not claims that the unchanged dependency versions are patched. Generic dependency scanners will continue to report the version matches. Operators must keep the phpMyAdmin application directory read-only to domain users and separately review any phpMyAdmin feature that activates an affected dependency path.

## Distribution notes

- Keep this file and every referenced license/notice file when redistributing ImagoPanel.
- Preserve copyright and attribution notices in modified third-party source files.
- Source for the modified Tiny File Manager and Pheditor integrations is included in this repository.
- The repository-level `LICENSE` remains the unmodified GNU Affero General Public License v3.0 text for ImagoPanel itself.
- This notice is an attribution and inventory document, not legal advice.

## Security advisory disposition for bundled modified applications

- Tiny File Manager `GHSA-wqww-g3x9-r7fw` / `CVE-2025-46651` (URL-upload SSRF): not applicable to the shipped integration because the URL-upload form, JavaScript, request parameters, server handler, cURL path, and stream/copy remote-fetch path have been physically removed. Ordinary local multipart upload remains available.
- Pheditor `GHSA-f25v-x6vr-962g` and `GHSA-p4h7-p9rj-2pq2` / `CVE-2026-55579` (standalone/default/change-password authentication): not applicable to the shipped integration because all standalone password constants, login handling, password-change action and UI, attempt log, and default-password warning have been physically removed. Access is exclusively provided by ImagoPanel's domain-scoped authorization before Pheditor starts.
- Pheditor `GHSA-g3hq-hphg-8fhh`, `GHSA-wg4w-wr5q-6vjc` / `CVE-2026-55578`, `GHSA-9643-6xjp-vx57` / `CVE-2026-54540`, and `GHSA-jvc5-6g7q-c843` / `CVE-2026-48030` (terminal command injection/allowlist bypass): not applicable to the shipped integration because the terminal action, command allowlist, `shell_exec` call, JavaScript, UI, styles, persisted terminal state, and terminal keyboard shortcuts have been physically removed.

Pheditor's reported base version remains 2.0.1 to identify the upstream code base accurately. Reintroducing standalone authentication, password management, terminal execution, or URL upload would invalidate these dispositions and requires a new security review.
