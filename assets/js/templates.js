(function (window, $) {
  "use strict";

  function esc(value) {
    return $("<div>").text(value == null ? "" : String(value)).html();
  }

  function tr(key, tag, className) {
    const target = tag || "span";
    const classAttr = className ? ` class="${esc(className)}"` : "";
    return `<${target}${classAttr} translate="${esc(key)}"></${target}>`;
  }

  function brand(dark) {
    return `<a class="brand${dark ? " text-white" : ""}" href="#overview" data-route="overview">
      <span class="brand-mark"><i class="bi bi-layers-half"></i></span>
      <span>ImagoPanel${dark ? "<small>hosting control</small>" : ""}</span>
    </a>`;
  }

  function languageMenu() {
    return `<button class="btn btn-light language-switcher" type="button" data-language-picker translate="common.language" translate-attr="aria-label">
      <i class="bi bi-globe2"></i><span data-current-language></span><i class="bi bi-chevron-down language-chevron"></i>
    </button>`;
  }

  function login(config) {
    const error = config.loginError ? `<div class="alert alert-danger py-2 small mb-3" role="alert" translate="login.${esc(config.loginError)}"></div>` : "";
    const portal = config.toolPortal && typeof config.toolPortal === "object" ? config.toolPortal : null;
    const portalTool = function (tool, icon, title, commentKey) {
      const allowed = !!(portal && portal.tools && portal.tools[tool]);
      return `<form method="post" action="./" target="_blank" class="tool-portal-card${allowed ? "" : " is-disabled"}">
        <input type="hidden" name="_action" value="launchTemporaryTool">
        <input type="hidden" name="_csrf" value="${esc(config.csrfToken)}">
        <input type="hidden" name="tool" value="${esc(tool)}">
        <span class="tool-portal-icon"><i class="bi ${esc(icon)}"></i></span>
        <span class="tool-portal-copy"><strong>${esc(title)}</strong><small translate="${esc(commentKey)}"></small></span>
        <button class="btn btn-sm ${allowed ? "btn-primary" : "btn-outline-secondary"}" type="submit"${allowed ? "" : " disabled"} translate="login.toolOpen"></button>
      </form>`;
    };
    let loginForm;
    if (portal) {
      const expires = portal.expiresAt ? new Date(portal.expiresAt) : null;
      const expiresText = expires && !Number.isNaN(expires.getTime()) ? expires.toLocaleString() : "—";
      loginForm = `${tr("login.toolPortalTitle", "h1")}
        <p><span translate="login.toolPortalSubtitle"></span> <strong>${esc(portal.domain || "")}</strong></p>
        ${error}
        <div class="tool-portal-meta"><span><i class="bi bi-person-badge"></i>${esc(portal.name || portal.login || "")}</span><span><i class="bi bi-clock"></i><span translate="login.toolAccessUntil"></span>: ${esc(expiresText)}</span></div>
        <div class="tool-portal-list">
          ${portalTool("phpmyadmin", "bi-database-gear", "phpMyAdmin", "login.toolPhpMyAdminComment")}
          ${portalTool("filemanager", "bi-folder2-open", "File Manager", "login.toolFileManagerComment")}
          ${portalTool("fileeditor", "bi-code-slash", "PHP Editor", "login.toolFileEditorComment")}
        </div>
        <form method="post" action="./" class="mt-4"><input type="hidden" name="_action" value="logout"><input type="hidden" name="_csrf" value="${esc(config.csrfToken)}"><button class="btn btn-outline-secondary w-100" type="submit"><i class="bi bi-box-arrow-left me-2"></i><span translate="common.logout"></span></button></form>`;
    } else if (config.twoFactorPending) {
      loginForm = `${tr("login.twoFactorTitle", "h1")}
          <p><span translate="login.twoFactorSubtitle"></span> <strong>${esc(config.twoFactorEmail || "")}</strong></p>
          ${error}
          <form method="post" action="./" autocomplete="one-time-code">
            <input type="hidden" name="_action" value="verify2fa">
            <input type="hidden" name="_csrf" value="${esc(config.csrfToken)}">
            <div class="mb-4">
              <label class="form-label" for="login-code" translate="login.twoFactorCode"></label>
              <div class="input-group">
                <span class="input-group-text"><i class="bi bi-shield-check"></i></span>
                <input class="form-control form-control-lg text-center font-monospace" id="login-code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required autofocus placeholder="000000">
              </div>
            </div>
            <button class="btn btn-primary btn-lg w-100" type="submit"><span translate="login.twoFactorSubmit"></span><i class="bi bi-arrow-right ms-2"></i></button>
          </form>
          <form method="post" action="./" class="mt-3">
            <input type="hidden" name="_action" value="cancel2fa"><input type="hidden" name="_csrf" value="${esc(config.csrfToken)}">
            <button class="btn btn-link w-100 text-secondary" type="submit" translate="login.twoFactorCancel"></button>
          </form>`;
    } else {
      loginForm = `${tr("login.title", "h1")}
          ${tr("login.subtitle", "p")}
          ${error}
          <form method="post" action="./" autocomplete="on">
            <input type="hidden" name="_action" value="login">
            <input type="hidden" name="_csrf" value="${esc(config.csrfToken)}">
            <div class="mb-3">
              <label class="form-label" for="login-identifier" translate="login.identifier"></label>
              <div class="input-group">
                <span class="input-group-text"><i class="bi bi-person-badge"></i></span>
                <input class="form-control" id="login-identifier" name="identifier" type="text" autocomplete="username" required translate="login.identifierPlaceholder" translate-attr="placeholder">
              </div>
            </div>
            <div class="mb-3">
              <label class="form-label" for="login-password" translate="login.password"></label>
              <div class="input-group">
                <span class="input-group-text"><i class="bi bi-shield-lock"></i></span>
                <input class="form-control" id="login-password" name="password" type="password" autocomplete="current-password" required translate="login.passwordPlaceholder" translate-attr="placeholder">
                <button class="btn btn-outline-secondary password-toggle" type="button" data-password-toggle="#login-password" aria-label="Show password"><i class="bi bi-eye"></i></button>
              </div>
            </div>
            <div class="form-check mb-4">
              <input class="form-check-input" type="checkbox" id="remember-session" name="remember" value="1">
              <label class="form-check-label" for="remember-session" translate="login.remember"></label>
            </div>
            <button class="btn btn-primary btn-lg w-100" type="submit"><span translate="login.submit"></span><i class="bi bi-arrow-right ms-2"></i></button>
          </form>`;
    }
    return `<main class="login-page">
      <section class="login-panel">
        <div class="d-flex justify-content-between align-items-center">${brand(false)}${languageMenu()}</div>
        <div class="login-card">
          ${loginForm}
        </div>
      </section>
      <aside class="login-visual">
        <div class="visual-content">
          <div class="visual-copy">
            <span class="visual-kicker"><i class="bi bi-activity"></i>${tr("login.visualKicker")}</span>
            ${tr("login.visualTitle", "h2")}
            ${tr("login.visualText", "p")}
          </div>
          <div class="visual-stats">
            <div class="visual-stat"><i class="bi bi-globe2"></i><strong>8</strong>${tr("login.domainStat", "small")}</div>
            <div class="visual-stat"><i class="bi bi-database"></i><strong>6</strong>${tr("login.databaseStat", "small")}</div>
            <div class="visual-stat"><i class="bi bi-envelope-paper"></i><strong>9</strong>${tr("login.mailStat", "small")}</div>
          </div>
        </div>
      </aside>
    </main>
    <div id="modal-root"></div>`;
  }

  function sidebarGroupOpen(name) {
    try {
      return window.localStorage.getItem(`imago_sidebar_group_${name}`) === "1";
    } catch (error) {
      return false;
    }
  }

  function navItems(isRoot, dnsManagementEnabled) {
    const items = [
      ["overview", "bi-grid-1x2", "nav.overview"],
      ["users", "bi-people", "nav.users", true],
      ["domains", "bi-globe2", "nav.domains"],
      ["databases", "bi-database", "nav.databases"],
      ["mail", "bi-envelope-paper", "nav.mail"],
      ["dnsManagement", "bi-cloud-arrow-up", "dns.domainTitle", false, true],
      ["logs", "bi-journal-code", "Журнал root.php", true],
      ["toolLogs", "bi-shield-lock", "Доступы к инструментам", true],
      ["diagnostics", "bi-activity", "diagnostics.menu", true]
    ];
    const links = items.filter(function (item) { return (!item[3] || isRoot) && (!item[4] || dnsManagementEnabled); }).map(function (item) {
      const label = ["logs", "toolLogs"].includes(item[0]) ? `<span>${esc(item[2])}</span>` : `<span translate="${item[2]}"></span>`;
      return `<a class="nav-link" href="#${item[0]}" data-route="${item[0]}"><i class="bi ${item[1]}"></i>${label}</a>`;
    }).join("");
    const migrationOpen = sidebarGroupOpen("migration");
    const migration = !isRoot ? "" : `<div class="sidebar-nav-group${migrationOpen ? " is-open" : ""}" data-sidebar-group="migration">
      <button class="nav-link sidebar-nav-toggle" type="button" data-sidebar-group-toggle="migration" aria-expanded="${migrationOpen ? "true" : "false"}"><i class="bi bi-arrow-repeat"></i><span>Миграции</span><i class="bi bi-chevron-down sidebar-nav-chevron"></i></button>
      <div class="sidebar-nav-submenu${migrationOpen ? "" : " d-none"}" data-sidebar-group-content="migration">
        <a class="nav-link nav-sub-link" href="#migration?section=dates" data-route="migration" data-migration-section="dates"><i class="bi bi-calendar-check"></i><span>Выставить всем даты</span></a>
        <a class="nav-link nav-sub-link" href="#migration?section=apache" data-route="migration" data-migration-section="apache"><i class="bi bi-server"></i><span>Обновить Apache</span></a>
        <a class="nav-link nav-sub-link" href="#migration?section=permissions" data-route="migration" data-migration-section="permissions"><i class="bi bi-shield-check"></i><span>Выставить права</span></a>
      </div>
    </div>`;
    return `${links}${migration}`;
  }

  function sidebar(config, mobile) {
    return `<aside class="sidebar${mobile ? " p-3" : ""}">
      ${brand(true)}
      <nav class="sidebar-nav">${navItems(config.role === "root", !!config.dnsManagementEnabled)}</nav>
      ${config.role === "root" ? `<div class="sidebar-footer">
        <div><span class="pulse-dot"></span><span translate="common.comingFromCron"></span></div>
        <small translate="common.noSystemChanges"></small>
      </div>` : ""}
    </aside>`;
  }

  function shell(config) {
    const initials = String(config.name || config.email || "IP").split(/\s|@/).filter(Boolean).slice(0, 2).map(function (part) { return part.charAt(0).toUpperCase(); }).join("");
    const roleKey = config.role === "root" ? "common.root" : "common.user";
    return `<div class="app-shell">
      ${sidebar(config, false)}
      <div class="offcanvas offcanvas-start" tabindex="-1" id="mobile-navigation"><div class="offcanvas-body p-0">${sidebar(config, true)}</div></div>
      <section class="main-shell">
        <header class="topbar">
          <button class="btn btn-light btn-icon mobile-menu me-3" type="button" data-bs-toggle="offcanvas" data-bs-target="#mobile-navigation"><i class="bi bi-list"></i></button>
          <div class="topbar-title"><h1 id="topbar-title"></h1>${config.role === "root" ? '<p translate="common.noSystemChanges"></p>' : ""}</div>
          <div class="topbar-actions">
            ${languageMenu()}
            <div class="dropdown">
              <button class="user-menu dropdown-toggle" type="button" data-bs-toggle="dropdown">
                <span class="avatar">${esc(initials)}</span>
                <span class="user-meta"><strong>${esc(config.email)}</strong><small translate="${roleKey}"></small></span>
                <i class="bi bi-chevron-down small text-secondary"></i>
              </button>
              <ul class="dropdown-menu dropdown-menu-end">
                <li><div class="dropdown-item-text small text-secondary">${esc(config.name || config.email)}</div></li>
                <li><hr class="dropdown-divider"></li>
                ${config.role === "user" ? '<li><button class="dropdown-item" type="button" data-open-profile><i class="bi bi-person-gear me-2"></i><span translate="profile.open"></span></button></li>' : ""}
                ${config.role === "user" ? '<li><hr class="dropdown-divider"></li>' : ""}
                <li><form method="post" action="./"><input type="hidden" name="_action" value="logout"><input type="hidden" name="_csrf" value="${esc(config.csrfToken)}"><button class="dropdown-item text-danger" type="submit"><i class="bi bi-box-arrow-right me-2"></i><span translate="common.logout"></span></button></form></li>
              </ul>
            </div>
          </div>
        </header>
        <main id="main-content" class="main-content"></main>
      </section>
      <div id="modal-root"></div>
      <div id="app-toast-container" class="toast-container position-fixed bottom-0 end-0 p-3" aria-live="polite" aria-atomic="false"></div>
    </div>`;
  }

  function pageHeading(route, hasAdd, isRoot) {
    const icon = { users: "bi-person-plus", domains: "bi-plus-circle", databases: "bi-database-add", mail: "bi-envelope-plus" }[route] || "bi-plus";
    const importButton = ["domains", "mail"].includes(route) ? `<button class="btn btn-outline-primary" type="button" data-import="${route}"><i class="bi bi-upload me-2"></i><span translate="common.import"></span></button>` : "";
    const exportButton = route === "domains" ? `<button class="btn btn-outline-primary" type="button" data-export-domains><i class="bi bi-download me-2"></i><span translate="common.exportCsv"></span></button>` : "";
    const isLogRoute = ["logs", "toolLogs"].includes(route);
    const title = route === "logs" ? "<h2>Журнал действий клиентов</h2>" : (route === "toolLogs" ? "<h2>Доступы к инструментам доменов</h2>" : `<h2 translate="page.${route}Title"></h2>`);
    const subtitle = route === "logs" ? "<p>Только действия users, выполненные через root.php за последние 30 дней.</p>" : (route === "toolLogs" ? "<p>Входы, отказы и запросы phpMyAdmin, File Manager и PHP Editor за последние 30 дней.</p>" : `<p translate="page.${route}Subtitle"></p>`);
    if (route === "dnsManagement") {
      return `<div class="page-heading"><div><h2 translate="dns.domainTitle"></h2><p translate="dns.managementSubtitle"></p></div><div class="heading-actions"><button class="btn btn-outline-primary" type="button" data-open-dns-bulk-change><i class="bi bi-pencil-square me-2"></i><span translate="dns.bulkChange"></span></button><button class="btn btn-outline-primary" type="button" data-refresh-dns-zones><i class="bi bi-cloud-download me-2"></i><span translate="dns.refreshZones"></span></button><button class="btn btn-primary" type="button" data-refresh-all-dns-records><i class="bi bi-arrow-repeat me-2"></i><span translate="dns.fetchAllRecords"></span></button></div></div>`;
    }
    return `<div class="page-heading">
      <div>${title}${subtitle}</div>
      ${hasAdd && !isLogRoute ? `<div class="heading-actions"><button class="btn btn-outline-secondary" type="button" data-preview-action="refresh"><i class="bi bi-arrow-clockwise me-2"></i><span translate="common.check"></span></button>${exportButton}${importButton}<button class="btn btn-primary" type="button" data-add="${route}"><i class="bi ${icon} me-2"></i><span translate="common.add"></span></button></div>` : ""}
    </div>`;
  }

  function metricCard(icon, color, labelKey, value, detail, percent) {
    return `<article class="metric-card ${color}">
      <div class="metric-top"><span translate="${labelKey}"></span><span class="metric-icon"><i class="bi ${icon}"></i></span></div>
      <strong>${esc(value)}</strong>
      <div class="usage-row"><span>${esc(detail)}</span><span>${esc(percent)}%</span></div>
      <div class="progress"><div class="progress-bar" style="width:${Math.min(100, Number(percent))}%"></div></div>
    </article>`;
  }

  function tariffCount(value) {
    return Number(value || 0) > 0 ? String(value) : "∞";
  }

  function tariffSize(value) {
    const bytes = Number(value || 0);
    if (!bytes) return "∞";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const amount = bytes / Math.pow(1024, index);
    return `${Math.round(amount * 100) / 100} ${units[index]}`;
  }

  function tariffUsage(labelKey, icon, used, limit) {
    const numericLimit = Number(limit || 0);
    const progress = numericLimit > 0 ? Math.min(100, Math.round(Number(used || 0) / numericLimit * 100)) : 0;
    return `<div class="tariff-usage">
      <div class="tariff-usage-title"><span><i class="bi ${icon}"></i><span translate="${labelKey}"></span></span><strong>${esc(used)} / ${esc(tariffCount(limit))}</strong></div>
      <div class="progress"><div class="progress-bar" style="width:${progress}%"></div></div>
    </div>`;
  }

  function tariffOverview(summary) {
    const tariff = summary.tariff || {};
    return `<aside class="tariff-box">
      <header class="tariff-box-header">
        <span class="tariff-box-icon"><i class="bi bi-stars"></i></span>
        <div><small translate="profile.tariff"></small><h3>${esc(summary.tariffName || tariff.name || tariff.key || "—")}</h3></div>
      </header>
      <div class="tariff-usage-list">
        ${tariffUsage("profile.tariffDomains", "bi-globe2", summary.domains, tariff.domain)}
        ${tariffUsage("profile.tariffDatabases", "bi-database", summary.databases, tariff.db)}
      </div>
      <div class="tariff-limit-grid">
        <div><i class="bi bi-envelope-at"></i><span translate="profile.tariffMailPerDomain"></span><strong>${esc(tariffCount(tariff.mailbydomain))}</strong></div>
        <div><i class="bi bi-folder2-open"></i><span translate="profile.tariffWebsiteSize"></span><strong>${esc(tariffSize(tariff.wwwsize))}</strong></div>
        <div><i class="bi bi-database-check"></i><span translate="profile.tariffDatabaseSize"></span><strong>${esc(tariffSize(tariff.dbsize))}</strong></div>
        <div><i class="bi bi-envelope-paper"></i><span translate="profile.tariffMailboxSize"></span><strong>${esc(tariffSize(tariff.mailsize))}</strong></div>
      </div>
    </aside>`;
  }

  function overview(summary, isRoot, warnings) {
    const first = isRoot
      ? metricCard("bi-people", "violet", "metrics.users", summary.activeUsers + " / " + summary.users, "", Math.round(summary.activeUsers / summary.users * 100))
      : metricCard("bi-globe2", "violet", "metrics.domains", summary.activeDomains + " / " + summary.domains, "", Math.round(summary.activeDomains / summary.domains * 100));
    const warningMarkup = isRoot && Array.isArray(warnings) ? warnings.map(function (warning) { return `<div class="alert alert-warning"><i class="bi bi-exclamation-triangle me-2"></i>${esc(warning)}</div>`; }).join("") : "";
    return `${pageHeading("overview", false)}${warningMarkup}
      <section class="metric-grid">
        ${first}
        ${metricCard("bi-folder2-open", "cyan", "metrics.storage", summary.siteUsed, summary.siteUsed + " / " + summary.siteQuota, summary.sitePercent)}
        ${metricCard("bi-database", "green", "metrics.databases", summary.databaseUsed, summary.databases + " databases", summary.databasePercent)}
        ${metricCard("bi-envelope-paper", "amber", "metrics.mail", summary.mailUsed, summary.mailAccounts + " accounts", summary.mailPercent)}
      </section>
      <section class="dashboard-grid">
        <article class="panel-card">
          <header class="panel-header"><div><h3 translate="dashboard.healthTitle"></h3><p translate="dashboard.healthSubtitle"></p></div><span class="status-pill success" translate="dashboard.allGood"></span></header>
          <div class="panel-body service-list">
            <div class="service-row"><i class="bi bi-diagram-3"></i><div><strong translate="dashboard.dns"></strong><small>${summary.boundDomains}/${summary.domains}</small></div><span class="status-pill ${summary.boundDomains === summary.domains ? "success" : "warning"}" translate="${summary.boundDomains === summary.domains ? "dashboard.allGood" : "dashboard.attention"}"></span></div>
            <div class="service-row"><i class="bi bi-shield-check"></i><div><strong translate="dashboard.ssl"></strong><small>${summary.sslDomains}/${summary.domains}</small></div><span class="status-pill ${summary.sslDomains === summary.domains ? "success" : "warning"}" translate="${summary.sslDomains === summary.domains ? "dashboard.allGood" : "dashboard.attention"}"></span></div>
            <div class="service-row"><i class="bi bi-database-check"></i><div><strong translate="dashboard.database"></strong><small>${summary.databases}</small></div><span class="status-pill success" translate="dashboard.allGood"></span></div>
            <div class="service-row"><i class="bi bi-envelope-check"></i><div><strong translate="dashboard.mail"></strong><small>${summary.secureMail}/${summary.mailAccounts}</small></div><span class="status-pill ${summary.secureMail === summary.mailAccounts ? "success" : "warning"}" translate="${summary.secureMail === summary.mailAccounts ? "dashboard.allGood" : "dashboard.attention"}"></span></div>
          </div>
        </article>
        ${isRoot ? `<aside class="sync-box">
          <span class="sync-icon"><i class="bi bi-clock-history"></i></span>
          <h3 translate="dashboard.syncTitle"></h3><p translate="dashboard.syncText"></p>
          <div class="sync-meta"><div><span translate="dashboard.lastSync"></span>${summary.lastSync ? `<strong>${esc(summary.lastSync)}</strong>` : '<strong translate="dashboard.notConnected"></strong>'}</div><div><span translate="dashboard.nextSync"></span>${summary.nextSync ? `<strong>${esc(summary.nextSync)}</strong>` : '<strong translate="dashboard.afterHour"></strong>'}</div><div><span translate="dashboard.duration"></span>${summary.syncDuration ? `<strong>${esc(summary.syncDuration)}</strong>` : '<strong translate="dashboard.notAvailable"></strong>'}</div></div>
        </aside>` : tariffOverview(summary)}
      </section>`;
  }

  function filterRow(headers, skipFirst) {
    const cells = headers.map(function (key, index) {
      if (skipFirst && index === 0) return "<th></th>";
      if (key === "common.comment") {
        return '<th class="comment-column"><input class="column-filter comment-column-filter" type="search" translate="common.comment" translate-attr="title aria-label"></th>';
      }
      return '<th><input class="column-filter" type="search" translate="tables.filter" translate-attr="placeholder"></th>';
    }).join("");
    return `<tr class="filter-row" data-dt-order="disable">${cells}</tr>`;
  }

  const definitions = {
    users: ["common.actions", "columns.email", "common.comment", "columns.prefix", "columns.tariff", "columns.rootPath", "columns.domains", "columns.sites", "columns.databases", "columns.mail", "columns.vhosts", "columns.status", "columns.createdAt"],
    domains: ["common.actions", "columns.domain", "common.comment", "columns.binding", "columns.ssl", "columns.redirects", "columns.folderSize", "columns.database", "columns.tools", "columns.mailAccounts", "columns.dns", "columns.status", "columns.createdAt"],
    databases: ["common.actions", "columns.databaseName", "common.comment", "columns.size", "columns.tablesCount", "columns.linkedDomain", "columns.status", "columns.createdAt"],
    mail: ["common.actions", "columns.mailDomain", "columns.address", "common.comment", "columns.catchAll", "columns.forwardTo", "columns.usage", "columns.status", "columns.createdAt"],
    dnsManagement: ["common.actions", "columns.domain", "dns.provider", "dns.connectionName", "dns.recordsCount", "columns.status", "dns.changedAt"],
    logs: ["Подробности", "Дата и время", "User / префикс", "Статус", "IP", "Операция", "Длительность", "Ошибка"],
    toolLogs: ["Подробности", "Дата и время", "User / префикс", "Статус", "IP", "Операция", "Длительность", "Ошибка"]
  };

  function tablePage(route, isRoot) {
    let headers = definitions[route].slice();
    if (isRoot && route !== "users" && !["logs", "toolLogs"].includes(route)) headers.splice(1, 0, "columns.user");
    const isLogs = ["logs", "toolLogs"].includes(route);
    const headerMarkup = headers.map(function (key) {
        if (isLogs) return `<th>${esc(key)}</th>`;
        if (key === "common.comment") return '<th class="comment-column" translate="common.comment" translate-attr="title aria-label"><i class="bi bi-chat-left-text-fill"></i><span class="visually-hidden" translate="common.comment"></span></th>';
        return `<th><span translate="${key}"></span></th>`;
    }).join("");
    const dnsProgress = route !== "dnsManagement" ? "" : `<section class="dns-bulk-progress d-none" data-dns-records-progress aria-live="polite">
      <div class="dns-bulk-progress-head"><div><span class="spinner-border spinner-border-sm text-primary" data-dns-progress-icon></span><strong translate="dns.fetchingAllRecords"></strong></div><strong><span data-dns-progress-processed>0</span>/<span data-dns-progress-total>0</span></strong></div>
      <div class="dns-bulk-progress-domain"><span translate="dns.currentDomain"></span><strong data-dns-progress-current>—</strong></div>
      <div class="dns-bulk-progress-meta"><span><span translate="dns.processedDomains"></span>: <strong data-dns-progress-processed-copy>0</strong></span><span><span translate="dns.remainingDomains"></span>: <strong data-dns-progress-remaining>0</strong></span><span><span translate="dns.failedDomains"></span>: <strong data-dns-progress-errors>0</strong></span></div>
      <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="progress-bar progress-bar-striped progress-bar-animated" data-dns-progress-bar style="width:0%"></div></div>
      <div class="dns-bulk-progress-errors d-none" data-dns-progress-error-list></div>
    </section>`;
    return `${pageHeading(route, !isLogs && route !== "dnsManagement", isRoot)}${dnsProgress}
      <section class="panel-card table-panel">
        <header class="panel-header"><div>${isLogs ? (route === "toolLogs" ? "<h3>Журнал инструментов доменов</h3><p>Запросы, успешные входы и отказы</p>" : "<h3>Журнал действий клиентов</h3><p>Запросы и ответы root.php</p>") : `<h3 translate="page.${route}Title"></h3>${isRoot ? '<p translate="common.comingFromCron"></p>' : ""}`}</div>${isRoot ? `<span class="preview-badge"><i class="bi ${isLogs ? "bi-shield-lock" : "bi-eye"}"></i>${isLogs ? "<span>Только root/admin</span>" : '<span translate="common.preview"></span>'}</span>` : ""}</header>
        <div class="panel-body"><div class="table-wrap"><table id="${route}-table" class="table align-middle"><thead><tr>${headerMarkup}</tr>${filterRow(headers, true)}</thead><tbody></tbody></table></div></div>
      </section>`;
  }

  function migrationPage() {
    return `<div class="page-heading"><div><h2>Миграции</h2><p>Служебные операции ROOT для пользовательских данных, каталогов и Apache.</p></div></div>
      <div class="d-grid gap-3">
      <section class="panel-card" data-migration-card="dates">
        <div class="panel-header"><div><h3>Выставить всем даты</h3><p>Заполняет даты создания пользователей, доменов, баз данных и почтовых адресов.</p></div><i class="bi bi-calendar-check fs-4 text-primary"></i></div>
        <div class="panel-body">
          <p class="text-secondary mb-3">Если дата создания отсутствует, будет использована дата последнего изменения. Если нет и её — текущее время.</p>
          <button class="btn btn-primary" type="button" data-migrate-created-at><i class="bi bi-play-fill me-2"></i>Выставить всем даты</button>
          <div class="alert mt-3 mb-0 d-none" role="status" data-migrate-created-at-result></div>
        </div>
      </section>
      <section class="panel-card" data-migration-card="apache">
        <div class="panel-header"><div><h3>Обновить Apache</h3><p>Проверяет текущую конфигурацию, пересоздаёт пользовательские vhost и перезагружает Apache только после успешного <code>httpd -t</code>.</p></div><i class="bi bi-server fs-4 text-primary"></i></div>
        <div class="panel-body">
          <p class="text-secondary mb-3">Если найдены ошибочные домены, отчёт покажет причину и позволит отключить их перед повторной проверкой.</p>
          <button class="btn btn-primary" type="button" data-apache-vhosts-refresh><i class="bi bi-arrow-repeat me-2"></i>Обновить Apache</button>
        </div>
      </section>
      <section class="panel-card" data-migration-card="permissions">
        <div class="panel-header"><div><h3>Выставить права</h3><p>Обходит доменные папки всех пользователей и применяет те же владельца и группу, что и одиночная кнопка в таблице доменов.</p></div><i class="bi bi-shield-check fs-4 text-primary"></i></div>
        <div class="panel-body">
          <p class="text-secondary mb-3">Обрабатываются активные и отключённые домены. Общие папки нескольких доменов изменяются только один раз.</p>
          <button class="btn btn-primary" type="button" data-all-domain-permissions><i class="bi bi-shield-check me-2"></i>Выставить права всем</button>
          <div class="alert mt-3 mb-0 d-none" role="status" data-all-domain-permissions-result></div>
        </div>
      </section>
      </div>`;
  }

  function serverDiagnosticsPage() {
    return `<div class="page-heading"><div><h2 translate="diagnostics.title"></h2><p translate="diagnostics.subtitle"></p></div><button class="btn btn-outline-primary" type="button" data-server-diagnostics-refresh><i class="bi bi-arrow-repeat me-2"></i><span translate="diagnostics.refresh"></span></button></div>
      <div class="alert alert-info d-flex align-items-start gap-2"><i class="bi bi-shield-check fs-5"></i><div><strong translate="diagnostics.readOnlyTitle"></strong><div class="small mt-1" translate="diagnostics.readOnlyText"></div></div></div>
      <div data-server-diagnostics-result><div class="panel-card"><div class="panel-body py-5 text-center"><span class="spinner-border text-primary" role="status"></span><div class="mt-3 text-secondary" translate="diagnostics.running"></div></div></div></div>`;
  }

  function apacheRefreshModal() {
    return `<div class="modal fade" id="apache-refresh-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h2 class="modal-title"><i class="bi bi-server me-2"></i>Обновление Apache</h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body" data-apache-refresh-report></div>
      <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal">Закрыть</button><button type="button" class="btn btn-outline-primary" data-apache-refresh-rerun><i class="bi bi-arrow-repeat me-2"></i>Проверить ещё раз</button></div>
    </div></div></div>`;
  }

  function logJsonBlock(label, value) {
    const json = JSON.stringify(value === undefined ? null : value, null, 2);
    return `<section class="log-json-block"><h4>${esc(label)}</h4><pre>${esc(json)}</pre></section>`;
  }

  function logDetailsModal(record) {
    const user = record && record.user && typeof record.user === "object" ? record.user : {};
    const duration = record && record.durationMs != null ? String(record.durationMs) + " ms" : "—";
    const status = record && ["success", "error", "nofinished"].includes(record.status) ? record.status : "nofinished";
    return `<div class="modal fade" id="log-details-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><div><h2 class="modal-title">Подробности операции</h2><small class="font-monospace text-secondary">${esc(record && record.requestId || "")}</small></div><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <div class="log-detail-grid">
          <div><span>Дата и время</span><strong>${esc(record && record.startedTimestamp || "—")}</strong></div>
          <div><span>User / префикс</span><strong>${esc(user.email || "—")}<small>${esc(user.prefix || "")}</small></strong></div>
          <div><span>Статус</span><strong>${esc(status)}</strong></div>
          <div><span>IP</span><strong>${esc(record && record.ip || "—")}</strong></div>
          <div><span>Операция</span><strong class="font-monospace">${esc(record && record.action || "—")}</strong></div>
          <div><span>Длительность</span><strong>${esc(duration)}</strong></div>
          <div><span>Среда</span><strong>${esc(record && record.environment || "—")}</strong></div>
          <div><span>Завершено</span><strong>${esc(record && record.finishedTimestamp || "—")}</strong></div>
        </div>
        ${logJsonBlock("JSON запроса", record ? record.request : null)}
        ${logJsonBlock("JSON ответа", record ? record.response : null)}
        ${logJsonBlock("JSON ошибки", record ? record.error : null)}
        ${logJsonBlock("Все записанные данные", record || null)}
      </div>
      <div class="modal-footer"><button type="button" class="btn btn-primary" data-bs-dismiss="modal" translate="common.close"></button></div>
    </div></div></div>`;
  }

  function field(label, input, width) {
    return `<div class="${width || "col-md-6"}"><label class="form-label" translate="${label}"></label>${input}</div>`;
  }

  function userOptions(users, selected) {
    return users.map(function (user) { return `<option value="${user.id}"${Number(selected) === user.id ? " selected" : ""}>${esc(user.email)}</option>`; }).join("");
  }

  function domainOptions(domains, selected) {
    return `<option value="" translate="forms.selectNone"></option>` + domains.map(function (domain) { return `<option value="${esc(domain.domain)}"${selected === domain.domain ? " selected" : ""}>${esc(domain.domain)}</option>`; }).join("");
  }

  function phpVersionOptions(versions, selected) {
    const available = Array.isArray(versions) ? versions : [];
    const fallback = (available.find(function (version) { return version.default; }) || available[0] || {}).id || "default";
    const value = selected || fallback;
    return available.map(function (version) {
      return `<option value="${esc(version.id)}"${String(version.id) === String(value) ? " selected" : ""}>${esc(version.label)}</option>`;
    }).join("");
  }

  function projectPaths(domains, userId, isRoot) {
    const seen = {};
    return (domains || []).filter(function (domain) {
      return !isRoot || Number(domain.userId) === Number(userId);
    }).map(function (domain) {
      return domain.path || "";
    }).filter(function (path) {
      if (!path || seen[path]) return false;
      seen[path] = true;
      return true;
    });
  }

  function projectPathOptions(paths) {
    return paths.map(function (path) {
      return `<option value="${esc(path)}">${esc(path)}</option>`;
    }).join("");
  }

  function localDateTime(value) {
    const date = value ? new Date(value) : new Date();
    if (Number.isNaN(date.getTime())) return "";
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }

  function domainToolAccessRow(access, index) {
    const item = access || {};
    const permissions = item.permissions || { phpmyadmin: true, filemanager: true, fileeditor: true };
    const ips = Array.isArray(item.ips) ? item.ips : String(item.ips || "").split(/[\s,;]+/).filter(Boolean);
    const startsAt = localDateTime(item.startsAt).replace("T", " ") || "—";
    const expiresAt = localDateTime(item.expiresAt).replace("T", " ") || "—";
    return `<tr data-tool-access data-access-id="${esc(item.id || "")}"${item.active === false ? ' class="table-secondary"' : ""}>
      <td><strong data-tool-row-number>${index + 1}</strong>
        <input data-tool-field="name" type="hidden" value="${esc(item.name || "")}">
        <input data-tool-field="login" type="hidden" value="${esc(item.login || "")}">
        <input data-tool-field="password" type="hidden" value="${esc(item.password || "")}">
        <input data-tool-field="ips" type="hidden" value="${esc(ips.join("\n"))}">
        <input data-tool-field="startsAt" type="hidden" value="${esc(item.startsAt || "")}">
        <input data-tool-field="expiresAt" type="hidden" value="${esc(item.expiresAt || "")}">
        <input data-tool-field="active" type="hidden" value="${item.active === false ? "0" : "1"}">
        <input data-tool-permission="phpmyadmin" type="hidden" value="${permissions.phpmyadmin !== false ? "1" : "0"}">
        <input data-tool-permission="filemanager" type="hidden" value="${permissions.filemanager !== false ? "1" : "0"}">
        <input data-tool-permission="fileeditor" type="hidden" value="${permissions.fileeditor !== false ? "1" : "0"}">
      </td>
      <td><strong>${esc(item.login || "—")}</strong>${item.name ? `<div class="form-text">${esc(item.name)}</div>` : ""}<span class="badge ${item.active === false ? "text-bg-secondary" : "text-bg-success"}">${item.active === false ? "Неактивен" : "Активен"}</span></td>
      <td class="text-nowrap">${esc(startsAt)}</td>
      <td class="text-nowrap">${esc(expiresAt)}</td>
      <td>${ips.length ? ips.map(function (ip) { return `<code class="d-block">${esc(ip)}</code>`; }).join("") : "—"}</td>
      <td><div class="btn-group btn-group-sm" role="group">
        <button class="btn btn-sm btn-outline-primary text-nowrap" type="button" data-tool-extend title="Продлить на 24 часа"><i class="bi bi-clock-history me-1"></i>+24</button>
        <button class="btn btn-sm btn-outline-primary text-nowrap" type="button" data-tool-edit><i class="bi bi-pencil me-1"></i>Редактировать</button>
        <button class="btn btn-sm btn-outline-secondary text-nowrap" type="button" data-tool-toggle><i class="bi ${item.active === false ? "bi-play" : "bi-pause"} me-1"></i>${item.active === false ? "Активировать" : "Деактивировать"}</button>
        <button class="btn btn-sm btn-outline-danger text-nowrap" type="button" data-tool-remove><i class="bi bi-trash3 me-1"></i>Удалить</button>
      </div></td>
    </tr>`;
  }

  function domainToolAccessEditor(access, index, domain) {
    const item = access || {};
    const editing = index >= 0;
    const permissions = item.permissions || { phpmyadmin: true, filemanager: true, fileeditor: true };
    const token = `tool-access-editor-${index}`;
    const startsAt = localDateTime(item.startsAt || new Date().toISOString());
    const expiresAt = localDateTime(item.expiresAt || new Date(Date.now() + 86400000).toISOString());
    const scheduled = !!item.startsAt && new Date(item.startsAt).getTime() > Date.now() + 60000;
    const ips = Array.isArray(item.ips) ? item.ips.join("\n") : String(item.ips || "");
    return `<article class="domain-tool-access border rounded-3 p-3 mt-3" data-tool-editor-form data-edit-index="${index}" data-access-id="${esc(item.id || "")}">
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
        <div><strong data-access-summary>${editing ? "Редактирование доступа" : "Новый доступ"}</strong><div class="form-text">Заполните поля и примените запись — после этого она появится в таблице.</div></div>
        <button class="btn-close" type="button" data-tool-editor-cancel aria-label="Закрыть"></button>
      </div>
      <div class="row g-3">
        <div class="col-md-4"><label class="form-label">Название</label><input class="form-control" data-tool-field="name" maxlength="100" required value="${esc(item.name || "")}"><div class="form-text">Для кого или для какой работы создан доступ.</div></div>
        <div class="col-md-4"><label class="form-label">Логин</label><input class="form-control" data-tool-field="login" pattern="[A-Za-z0-9_.@-]{2,64}" maxlength="64" required value="${esc(item.login || "")}"><div class="form-text">Отдельный логин, не связанный с Linux.</div></div>
        <div class="col-md-4"><label class="form-label">Пароль</label><div class="input-group"><input class="form-control font-monospace" data-tool-field="password" type="text" minlength="8" maxlength="128" required value="${esc(item.password || "")}"><button class="btn btn-outline-primary" type="button" data-tool-password title="Сгенерировать"><i class="bi bi-arrow-repeat"></i></button></div><div class="form-text">Минимум 8 символов: большие и маленькие буквы, цифра и спецсимвол.</div></div>
        <div class="col-12"><label class="form-label">Разрешённые IP</label><div class="input-group"><textarea class="form-control font-monospace" data-tool-field="ips" rows="2" required>${esc(ips)}</textarea><button class="btn btn-outline-primary" type="button" data-tool-current-ip>Использовать мой IP</button></div><div class="form-text">Отдельные IPv4/IPv6, по одному на строку либо через запятую или точку с запятой. Подсети не разрешены.</div></div>
        <div class="col-12"><label class="form-label d-block">Доступные инструменты</label><div class="d-flex flex-wrap gap-3">
          <div class="form-check"><input class="form-check-input" data-tool-permission="phpmyadmin" type="checkbox" id="${token}-pma"${permissions.phpmyadmin !== false ? " checked" : ""}><label class="form-check-label" for="${token}-pma">phpMyAdmin</label></div>
          <div class="form-check"><input class="form-check-input" data-tool-permission="filemanager" type="checkbox" id="${token}-fm"${permissions.filemanager !== false ? " checked" : ""}><label class="form-check-label" for="${token}-fm">File Manager</label></div>
          <div class="form-check"><input class="form-check-input" data-tool-permission="fileeditor" type="checkbox" id="${token}-fe"${permissions.fileeditor !== false ? " checked" : ""}><label class="form-check-label" for="${token}-fe">PHP Editor</label></div>
        </div><div class="form-text">По умолчанию разрешены все три инструмента.</div></div>
        <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" data-tool-active-switch type="checkbox" id="${token}-active"${item.active === false ? "" : " checked"}><label class="form-check-label" for="${token}-active">Доступ активен</label></div><div class="form-text">Отключённый доступ сохраняется, но авторизация по нему запрещена.</div></div>
        <div class="col-md-6"><label class="form-label d-block">Начало 24-часовой сессии</label><div class="d-flex flex-wrap gap-3 mb-2"><div class="form-check"><input class="form-check-input" data-tool-start-mode type="radio" name="${token}-start" value="now" id="${token}-now"${scheduled ? "" : " checked"}><label class="form-check-label" for="${token}-now">Сейчас</label></div><div class="form-check"><input class="form-check-input" data-tool-start-mode type="radio" name="${token}-start" value="scheduled" id="${token}-scheduled"${scheduled ? " checked" : ""}><label class="form-check-label" for="${token}-scheduled">Задать время начала</label></div></div><input class="form-control" data-tool-field="startsAt" type="datetime-local" required value="${esc(startsAt)}"${scheduled ? "" : " readonly"}><div class="form-text">До указанного времени войти нельзя.</div></div>
        <div class="col-md-6"><label class="form-label">Доступ действует до</label><input class="form-control" data-tool-field="expiresAt" type="datetime-local" readonly value="${esc(expiresAt)}"><div class="form-text">Новый доступ действует 24 часа; кнопка +24 продлевает срок.</div></div>
        <input data-tool-field="active" type="hidden" value="${item.active === false ? "0" : "1"}">
      </div>
      <details class="mt-3"><summary class="btn btn-sm btn-light">Пути и реквизиты входа</summary><div class="bg-light rounded-3 p-3 mt-2 small font-monospace">
        <div>https://${esc(domain)}/phpmyadmin/ &nbsp; | &nbsp; https://${esc(domain)}/panel/phpmyadmin/</div>
        <div>https://${esc(domain)}/filemanager/ &nbsp; | &nbsp; https://${esc(domain)}/panel/filemanager/</div>
        <div>https://${esc(domain)}/fileeditor/ &nbsp; | &nbsp; https://${esc(domain)}/panel/fileeditor/</div>
        <div class="mt-2">LOGIN: <span data-access-login-preview>${esc(item.login || "")}</span></div><div>PASSWORD: <span data-access-password-preview>${esc(item.password || "")}</span></div><div>IP: <span data-access-ip-preview>${esc(ips.replace(/\n/g, ", "))}</span></div>
      </div></details>
      <div class="d-flex justify-content-end gap-2 mt-3"><button class="btn btn-light" type="button" data-tool-editor-cancel>Отмена</button><button class="btn btn-primary" type="button" data-tool-editor-save><i class="bi bi-check2 me-2"></i>${editing ? "Сохранить изменения" : "Добавить доступ"}</button></div>
    </article>`;
  }

  function domainToolAccessSection(item) {
    const accesses = Array.isArray(item.toolAccesses) ? item.toolAccesses : [];
    const domain = item.domain || "domain.example";
    return `<section class="form-section"><div class="form-section-title"><i class="bi bi-tools"></i><span>Временные доступы к инструментам</span></div>
      <p class="form-text mb-3">Каждый запрос проверяет домен, IP, состояние доступа, срок и разрешённый инструмент. File Manager и PHP Editor ограничены папкой public_html этого домена; phpMyAdmin — привязанной базой.</p>
      <div class="d-flex justify-content-end mb-3"><button class="btn btn-outline-primary" type="button" data-tool-add><i class="bi bi-plus-lg me-2"></i>Добавить</button></div>
      <div class="table-responsive border rounded-3"><table class="table table-hover align-middle mb-0"><thead class="table-light"><tr><th>№</th><th>Логин</th><th>Начало</th><th>Окончание</th><th>IP-адреса</th><th>Действия</th></tr></thead>
        <tbody data-tool-access-list>${accesses.map(function (access, index) { return domainToolAccessRow(access, index); }).join("")}<tr data-tool-access-empty${accesses.length ? ' class="d-none"' : ""}><td class="text-center text-secondary py-4" colspan="6">Доступы ещё не добавлены</td></tr></tbody>
      </table></div>
      <div data-tool-editor-host></div>
    </section>`;
  }

  function commonModal(titleKey, type, body, wide, showTechnicalNotice) {
    const technicalNotice = showTechnicalNotice ? '<div class="notice-strip mb-4"><i class="bi bi-info-circle"></i><span translate="forms.previewNotice"></span></div>' : "";
    return `<div class="modal fade" id="entity-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-dialog-centered modal-dialog-scrollable ${wide ? "modal-xl" : "modal-lg"}"><div class="modal-content">
      <form id="entity-form" data-entity="${esc(type)}"><div class="modal-header"><h2 class="modal-title" translate="${titleKey}"></h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">${technicalNotice}${body}</div>
      <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" translate="common.cancel"></button><button type="submit" class="btn btn-primary"><i class="bi bi-check2 me-2"></i><span translate="common.save"></span></button></div></form>
    </div></div></div>`;
  }

  function tariffOptions(tariffs, selected) {
    return (tariffs || []).map(function (tariff) { return `<option value="${esc(tariff.key)}"${String(selected || "") === String(tariff.key) ? " selected" : ""}>${esc(tariff.name)}</option>`; }).join("");
  }

  function tariffSummary(tariff) {
    if (!tariff) return "";
    return `<span translate="profile.tariffDomains"></span>: ${tariffCount(tariff.domain)} · <span translate="profile.tariffDatabases"></span>: ${tariffCount(tariff.db)} · <span translate="profile.tariffMailPerDomain"></span>: ${tariffCount(tariff.mailbydomain)} · <span translate="profile.tariffWebsiteSize"></span>: ${tariffSize(tariff.wwwsize)} · <span translate="profile.tariffMailboxSize"></span>: ${tariffSize(tariff.mailsize)} · <span translate="profile.tariffDatabaseSize"></span>: ${tariffSize(tariff.dbsize)}`;
  }

  function userIpAccessSection(item, idPrefix) {
    const ips = Array.isArray(item.allowedIps) ? item.allowedIps.join("\n") : String(item.allowedIps || "");
    const switchId = `${idPrefix}-ip-access-enabled`;
    return `<section class="form-section" data-profile-ip-access><div class="form-section-title"><i class="bi bi-shield-lock"></i><span translate="profile.ipAccessTitle"></span></div><div class="row g-3">
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" id="${esc(switchId)}" name="ipAccessEnabled" type="checkbox"${item.ipAccessEnabled ? " checked" : ""}><label class="form-check-label" for="${esc(switchId)}" translate="profile.ipAccessEnabled"></label></div><div class="form-text" translate="profile.ipAccessWarning"></div></div>
      <div class="col-12"><label class="form-label" translate="profile.allowedIps"></label><div class="input-group"><textarea class="form-control font-monospace" name="allowedIps" rows="3" data-profile-allowed-ips>${esc(ips)}</textarea><button class="btn btn-outline-primary" type="button" data-profile-current-ip><i class="bi bi-crosshair me-1"></i><span translate="profile.addCurrentIp"></span></button></div><div class="form-text" translate="profile.allowedIpsHint"></div></div>
    </div></section>`;
  }

  function userModal(record, webRootDirectory, tariffs, defaultTariff, showPassword) {
    const edit = !!record;
    const item = record || {};
    const emailList = function (value) { return Array.isArray(value) ? value.join("\n") : String(value || ""); };
    const basePath = String(webRootDirectory || "/var/www").replace(/\/$/, "");
    const rootPath = item.rootPath || `${basePath}/${item.prefix || "{USER_PREFIX}"}`;
    const selectedTariff = item.tariff || defaultTariff || ((tariffs || [])[0] && tariffs[0].key) || "";
    const selectedDefinition = (tariffs || []).find(function (tariff) { return tariff.key === selectedTariff; });
    const passwordType = showPassword ? "text" : "password";
    const body = `<section class="form-section"><div class="form-section-title"><i class="bi bi-person"></i><span translate="forms.general"></span></div><div class="row g-3">
      ${field("forms.name", `<input class="form-control" name="name" required value="${esc(item.name)}">`)}
      ${field("forms.email", `<input class="form-control" name="email" type="email" required value="${esc(item.email)}">`)}
      ${field("forms.newPassword", `<input class="form-control" name="password" type="${passwordType}" maxlength="4096" autocomplete="new-password" data-user-password${edit ? "" : " required"}><div class="form-text" data-user-password-feedback data-password-required="${edit ? "0" : "1"}"></div>`)}
      ${field("forms.prefix", `<input class="form-control" name="prefix" pattern="[a-z][a-z0-9_]{1,31}" maxlength="32" required value="${esc(item.prefix)}"${edit ? " readonly" : ""}><div class="form-text" translate="forms.prefixHint"></div>`)}
      ${field("forms.rootPath", `<input class="form-control" name="rootPath" data-user-root-path data-web-root="${esc(basePath)}" readonly value="${esc(rootPath)}"><div class="form-text" translate="forms.rootPathHint"></div>`, "col-12")}
      ${field("common.comment", `<textarea class="form-control" name="comment" rows="3" maxlength="2000">${esc(item.comment || "")}</textarea>`, "col-12")}
    </div></section>
    ${userIpAccessSection(item, "user")}
    <section class="form-section"><div class="form-section-title"><i class="bi bi-speedometer2"></i><span translate="forms.quotas"></span></div><div class="row g-3">
      ${field("profile.tariff", `<select class="form-select" name="tariff" data-tariff-select>${tariffOptions(tariffs, selectedTariff)}</select>`, "col-12")}
      <div class="col-12"><div class="alert alert-light border mb-0" data-tariff-summary>${tariffSummary(selectedDefinition)}</div></div>
      ${item.tariffRequest ? `<div class="col-12"><div class="alert alert-info mb-0"><strong translate="profile.tariffRequested"></strong> ${esc(item.tariffRequest.name || item.tariffRequest.key || "")}</div></div>` : ""}
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-bell"></i><span translate="profile.notifications"></span></div><div class="row g-3">
      ${field("profile.billingEmails", `<textarea class="form-control" name="billingEmails" rows="2">${esc(emailList(item.billingEmails))}</textarea><div class="form-text" translate="profile.emailListHint"></div>`)}
      ${field("profile.technicalEmails", `<textarea class="form-control" name="technicalEmails" rows="2">${esc(emailList(item.technicalEmails))}</textarea><div class="form-text" translate="profile.emailListHint"></div>`)}
      ${field("profile.limitEmails", `<textarea class="form-control" name="limitEmails" rows="2">${esc(emailList(item.limitEmails))}</textarea><div class="form-text" translate="profile.emailListHint"></div>`)}
      ${field("profile.phone", `<input class="form-control" name="contactPhone" type="tel" maxlength="64" value="${esc(item.contactPhone || "")}">`)}
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-building"></i><span translate="profile.company"></span></div><div class="row g-3">
      ${field("profile.companyName", `<input class="form-control" name="companyName" maxlength="160" value="${esc(item.companyName || "")}">`)}
      ${field("profile.registrationNumber", `<input class="form-control" name="companyRegistrationNumber" maxlength="80" value="${esc(item.companyRegistrationNumber || "")}">`)}
      ${field("profile.companyAddress", `<textarea class="form-control" name="companyAddress" rows="2" maxlength="500">${esc(item.companyAddress || "")}</textarea>`, "col-12")}
    </div></section>`;
    return commonModal(edit ? "forms.userEdit" : "forms.userAdd", "users", `<input type="hidden" name="id" value="${esc(item.id || "")}">${body}`, true, true);
  }

  function dnsProviderOptions(providers, selected) {
    const empty = `<option value=""${selected ? "" : " selected"}>—</option>`;
    return empty + (providers || []).map(function (provider) {
      const planned = !provider.enabled || provider.planned;
      const label = `${provider.name}${planned ? " — planned" : ""}`;
      return `<option value="${esc(provider.id)}" data-provider-name="${esc(provider.name)}" data-api-url="${esc(provider.apiUrl || "")}"${planned ? " data-dns-planned" : ""}${String(selected || "") === String(provider.id) ? " selected" : ""}${planned ? " disabled" : ""}>${esc(label)}</option>`;
    }).join("");
  }

  function dnsConnectionRow(connection, providers, showCredentials) {
    const item = connection || {};
    const id = item.id || `dns-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const provider = item.provider || "hetzner";
    const authType = provider === "internetbs"
      ? "api_key_password"
      : (["regru", "namecheap"].includes(provider)
      ? "login_password"
      : (provider === "joker" && item.authType === "login_password" ? "login_password" : "api_key"));
    const secretType = showCredentials ? "text" : "password";
    return `<div class="border rounded-3 p-3" data-dns-connection-editor data-dns-connection-id="${esc(id)}" data-dns-active="${item.active === false ? "0" : "1"}" data-dns-created-at="${esc(item.createdAt || "")}" data-dns-updated-at="${esc(item.updatedAt || "")}">
      <div class="d-flex align-items-center justify-content-between gap-2 mb-3"><strong data-dns-connection-title>${esc(item.name || "DNS")}</strong><button class="btn btn-sm btn-outline-secondary" type="button" data-cancel-dns-connection><i class="bi bi-x-lg me-1"></i><span translate="common.cancel"></span></button></div>
      <div class="row g-3">
        ${field("dns.connectionName", `<input class="form-control" data-dns-connection-field="name" maxlength="120" required value="${esc(item.name || "")}">`)}
        ${field("dns.provider", `<select class="form-select" data-dns-connection-field="provider" data-dns-provider>${dnsProviderOptions(providers, provider)}</select>`)}
        ${field("dns.apiUrl", `<input class="form-control font-monospace" data-dns-connection-field="apiUrl" type="url" maxlength="500" value="${esc(item.apiUrl || "")}">`, "col-12")}
        <div class="col-12" data-dns-auth-wrap><label class="form-label" translate="dns.authType"></label><select class="form-select" data-dns-connection-field="authType"><option value="api_key"${authType === "api_key" ? " selected" : ""} translate="dns.apiKeyAuth"></option><option value="login_password"${authType === "login_password" ? " selected" : ""} translate="dns.loginPasswordAuth"></option><option value="api_key_password"${authType === "api_key_password" ? " selected" : ""}>API key + password</option></select></div>
        <div class="col-12" data-dns-api-key-wrap>${field("dns.apiToken", `<div class="input-group"><input class="form-control font-monospace" data-dns-connection-field="apiToken" type="${secretType}" maxlength="4096" autocomplete="new-password" value="${showCredentials ? esc(item.apiToken || "") : ""}" placeholder="${item.apiTokenConfigured ? "••••••••••••" : ""}"><button class="btn btn-outline-secondary" type="button" data-toggle-dns-secret><i class="bi bi-eye"></i></button></div>`, "col-12")}</div>
        <div class="col-md-6" data-dns-login-wrap data-dns-username-wrap>${field("dns.username", `<input class="form-control" data-dns-connection-field="username" maxlength="4096" autocomplete="username" value="${showCredentials ? esc(item.username || "") : ""}" placeholder="${item.usernameConfigured ? "••••••••" : ""}">`, "col-12")}</div>
        <div class="col-md-6" data-dns-login-wrap data-dns-password-wrap>${field("dns.password", `<div class="input-group"><input class="form-control" data-dns-connection-field="password" type="${secretType}" maxlength="4096" autocomplete="new-password" value="${showCredentials ? esc(item.password || "") : ""}" placeholder="${item.passwordConfigured ? "••••••••" : ""}"><button class="btn btn-outline-secondary" type="button" data-toggle-dns-secret><i class="bi bi-eye"></i></button></div>`, "col-12")}</div>
        <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns-manage-all-${esc(id)}" data-dns-connection-field="manageAllDomains"${item.manageAllDomains ? " checked" : ""}><label class="form-check-label" for="dns-manage-all-${esc(id)}" translate="dns.manageAllDomains"></label></div><div class="form-text" translate="dns.manageAllDomainsHint"></div></div>
        <div class="col-12"><div class="form-text d-none" data-dns-provider-guidance></div><div class="d-flex flex-wrap gap-2 mt-2"><button class="btn btn-sm btn-outline-primary" type="button" data-test-dns-provider><i class="bi bi-plug me-1"></i><span translate="dns.testConnection"></span></button><button class="btn btn-sm btn-success" type="button" data-save-dns-connection><i class="bi bi-check-lg me-1"></i><span translate="common.save"></span></button></div><div class="mt-2 d-none" data-dns-profile-result></div></div>
      </div>
    </div>`;
  }

  function dnsConnectionTableRow(connection, index) {
    const item = connection || {};
    const active = item.active !== false;
    const date = String(item.updatedAt || item.createdAt || "").replace("T", " ").replace(/\.\d+Z$/, "").replace(/Z$/, "");
    return `<tr data-dns-connection-row data-dns-connection-json="${esc(encodeURIComponent(JSON.stringify(item)))}">
      <td class="text-center" data-dns-connection-number>${index + 1}</td>
      <td><span class="text-nowrap">${esc(date || "—")}</span></td>
      <td><strong>${esc(item.name || "DNS")}</strong>${item.manageAllDomains ? '<i class="bi bi-globe2 text-primary ms-2" translate="dns.manageAllDomains" translate-attr="title aria-label"></i>' : ""}<div class="small text-secondary">${esc(String(item.provider || "").toUpperCase())}</div></td>
      <td><span class="badge ${active ? "text-bg-success" : "text-bg-secondary"}" translate="dns.${active ? "active" : "inactive"}"></span></td>
      <td class="text-nowrap"><div class="d-flex gap-1">
        <button class="btn btn-sm btn-outline-primary" type="button" data-edit-dns-connection translate="common.edit" translate-attr="title aria-label"><i class="bi bi-pencil"></i></button>
        <button class="btn btn-sm ${active ? "btn-outline-warning" : "btn-outline-success"}" type="button" data-toggle-dns-connection translate="dns.${active ? "deactivate" : "activate"}" translate-attr="title aria-label"><i class="bi bi-${active ? "pause" : "play"}"></i></button>
        <button class="btn btn-sm btn-outline-danger" type="button" data-delete-dns-connection translate="common.delete" translate-attr="title aria-label"><i class="bi bi-trash"></i></button>
      </div></td>
    </tr>`;
  }

  function profileModal(record, tariffs, dnsProviders, dnsDefaultProvider, showCredentials) {
    const item = record || {};
    const emailList = function (value) { return Array.isArray(value) ? value.join("\n") : String(value || ""); };
    const currentTariff = item.tariffLimits || (tariffs || []).find(function (tariff) { return tariff.key === item.tariff; });
    const requestOptions = (tariffs || []).filter(function (tariff) { return tariff.key !== item.tariff; });
    const body = `<section class="form-section"><div class="form-section-title"><i class="bi bi-person"></i><span translate="profile.account"></span></div><div class="row g-3">
      ${field("forms.name", `<input class="form-control" name="name" required maxlength="120" value="${esc(item.name || "")}">`)}
      ${field("profile.primaryEmail", `<input class="form-control" name="email" type="email" readonly value="${esc(item.email || "")}"><div class="form-text" translate="profile.primaryEmailHint"></div>`)}
      ${field("forms.newPassword", `<input class="form-control" name="password" type="password" maxlength="4096" autocomplete="new-password" data-user-password><div class="form-text" data-user-password-feedback data-password-required="0"></div>`)}
      ${field("profile.passwordConfirmation", `<input class="form-control" name="passwordConfirmation" type="password" maxlength="4096" autocomplete="new-password">`)}
    </div></section>
    ${userIpAccessSection(item, "profile")}
    <section class="form-section"><div class="form-section-title"><i class="bi bi-speedometer2"></i><span translate="profile.tariff"></span></div><div class="row g-3">
      <div class="col-12"><div class="alert alert-light border mb-0"><strong>${esc(item.tariffName || (currentTariff && currentTariff.name) || item.tariff || "")}</strong><div class="small mt-2">${tariffSummary(currentTariff)}</div></div></div>
      ${item.tariffRequest ? `<div class="col-12"><div class="alert alert-info mb-0"><strong translate="profile.tariffRequested"></strong> ${esc(item.tariffRequest.name || item.tariffRequest.key || "")}</div></div>` : ""}
      ${requestOptions.length ? `<div class="col-md-8"><label class="form-label" translate="profile.requestTariff"></label><select class="form-select" data-tariff-request>${tariffOptions(requestOptions, requestOptions[0].key)}</select></div><div class="col-md-4 d-flex align-items-end"><button class="btn btn-outline-primary w-100" type="button" data-request-tariff translate="profile.requestTariffButton"></button></div>` : ""}
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-bell"></i><span translate="profile.notifications"></span></div><div class="row g-3">
      ${field("profile.billingEmails", `<textarea class="form-control" name="billingEmails" rows="3">${esc(emailList(item.billingEmails))}</textarea><div class="form-text" translate="profile.emailListHint"></div>`)}
      ${field("profile.technicalEmails", `<textarea class="form-control" name="technicalEmails" rows="3">${esc(emailList(item.technicalEmails))}</textarea><div class="form-text" translate="profile.emailListHint"></div>`)}
      ${field("profile.limitEmails", `<textarea class="form-control" name="limitEmails" rows="3">${esc(emailList(item.limitEmails))}</textarea><div class="form-text" translate="profile.emailListHint"></div>`)}
      ${field("profile.phone", `<input class="form-control" name="contactPhone" type="tel" maxlength="64" value="${esc(item.contactPhone || "")}">`)}
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-building"></i><span translate="profile.company"></span></div><div class="row g-3">
      ${field("profile.companyName", `<input class="form-control" name="companyName" maxlength="160" value="${esc(item.companyName || "")}">`)}
      ${field("profile.registrationNumber", `<input class="form-control" name="companyRegistrationNumber" maxlength="80" value="${esc(item.companyRegistrationNumber || "")}">`)}
      ${field("profile.companyAddress", `<textarea class="form-control" name="companyAddress" rows="3" maxlength="500">${esc(item.companyAddress || "")}</textarea>`, "col-12")}
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-envelope-at"></i><span translate="profile.defaultForwarding"></span></div><div class="row g-3">
      ${field("profile.defaultForwardEmail", `<input class="form-control font-monospace" name="defaultForwardEmail" type="text" maxlength="254" placeholder="{DOMAIN}@example.com" value="${esc(item.defaultForwardEmail || "")}"><div class="form-text" translate="profile.defaultForwardEmailHint"></div>`, "col-12")}
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" id="profile-forward-new" name="mailForwardNewDomains" type="checkbox"${item.mailForwardNewDomains ? " checked" : ""}><label class="form-check-label" for="profile-forward-new" translate="profile.forwardNewDomains"></label></div></div>
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" id="profile-forward-whole" name="mailForwardWholeDomain" type="checkbox"${item.mailForwardWholeDomain ? " checked" : ""}><label class="form-check-label" for="profile-forward-whole" translate="profile.forwardWholeDomain"></label><div class="form-text" translate="profile.forwardWholeDomainHint"></div></div></div>
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" id="profile-catch-info" name="mailCatchAllToInfo" type="checkbox"${item.mailCatchAllToInfo !== false ? " checked" : ""}><label class="form-check-label" for="profile-catch-info" translate="profile.catchAllToInfo"></label><div class="form-text" translate="profile.catchAllToInfoHint"></div></div></div>
    </div></section>
    <section class="form-section" data-dns-profile><div class="form-section-title"><i class="bi bi-diagram-3"></i><span translate="dns.profileTitle"></span></div><div class="form-text mb-3" translate="dns.connectionsHint"></div><button class="btn btn-sm btn-primary mb-3" type="button" data-add-dns-connection><i class="bi bi-plus-lg me-1"></i><span translate="dns.addConnection"></span></button><div class="table-responsive"><table class="table table-sm table-hover align-middle mb-0"><thead><tr><th class="text-center">#</th><th translate="dns.changedAt"></th><th translate="dns.connectionName"></th><th translate="columns.status"></th><th translate="common.actions"></th></tr></thead><tbody data-dns-connections>${(item.dnsConnections || []).map(dnsConnectionTableRow).join("")}</tbody></table></div><div class="d-none py-3 text-secondary" data-dns-connections-empty translate="dns.noConnections"></div><div class="mt-3" data-dns-connection-editor-root></div></section>`;
    return commonModal("profile.title", "profile", body, true, false);
  }

  function dnsRequirements(records) {
    return `<div class="dns-requirements">
      <div class="dns-requirements-actions">
        <button class="btn btn-sm btn-outline-primary dns-requirements-toggle" type="button" data-bs-toggle="collapse" data-bs-target="#required-dns-records" aria-expanded="false" aria-controls="required-dns-records">
          <span><i class="bi bi-diagram-3 me-1"></i><strong translate="forms.requiredDnsTitle"></strong></span><i class="bi bi-chevron-down dns-requirements-chevron"></i>
        </button>
        <button class="btn btn-sm btn-outline-secondary dns-requirements-toggle" type="button" data-toggle-all-required-dns aria-expanded="false">
          <span><i class="bi bi-list-check me-1"></i><strong translate="forms.showAllDnsRecords"></strong></span><i class="bi bi-chevron-down dns-requirements-chevron"></i>
        </button>
      </div>
      <div class="collapse" id="required-dns-records"><div class="dns-requirements-content">
        <p class="form-text mb-0" translate="forms.requiredDnsText"></p>
        ${(records || []).map(function (record, index) { return `<div class="dns-record" data-dns-record="${index}">
          <div class="dns-record-heading"><strong>${esc(record.label)}</strong><span class="badge text-bg-light">${esc(record.type)}</span></div>
          <div class="dns-record-line">
            <small translate="forms.recordName"></small><code data-dns-name></code>
            <button class="btn btn-outline-secondary btn-sm dns-copy-button" type="button" data-copy-dns="name" translate="forms.recordName" translate-attr="title aria-label"><i class="bi bi-copy"></i></button>
          </div>
          <div class="dns-record-line">
            <small translate="forms.recordValue"></small><code data-dns-value></code>
            <button class="btn btn-outline-secondary btn-sm dns-copy-button" type="button" data-copy-dns="value" translate="forms.recordValue" translate-attr="title aria-label"><i class="bi bi-copy"></i></button>
          </div>
        </div>`; }).join("")}
      </div></div>
      <div class="dns-all-required d-none" data-all-required-dns>
        <p class="form-text mb-1" translate="forms.allDnsRecordsText"></p>
        <div class="dns-all-required-records" data-all-required-dns-records></div>
      </div>
    </div>`;
  }

  function dnsRecordRow(record, types, isNew) {
    const item = record || {};
    const editable = isNew || item.editable;
    const options = (types || ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"]).map(function (type) {
      return `<option value="${esc(type)}"${String(item.type || "A") === type ? " selected" : ""}>${esc(type)}</option>`;
    }).join("");
    const values = Array.isArray(item.values) ? item.values.join("\n") : String(item.values || "");
    return `<div class="dns-api-record${isNew ? " is-new" : ""}" data-dns-api-record data-dns-original-name="${esc(item.name || "")}" data-dns-original-type="${esc(item.type || "")}">
      <div class="dns-api-record-grid">
        <div><label class="form-label" translate="forms.recordName"></label><input class="form-control font-monospace" data-dns-field="name" maxlength="253" value="${esc(item.name || "@")}"${editable && isNew ? "" : " readonly"}></div>
        <div><label class="form-label" translate="dns.recordType"></label><select class="form-select" data-dns-field="type"${editable && isNew ? "" : " disabled"}>${options}</select></div>
        <div><label class="form-label">TTL</label><input class="form-control font-monospace" data-dns-field="ttl" type="number" min="60" max="2147483647" value="${esc(item.ttl || 3600)}"${editable ? "" : " readonly"}></div>
        <div class="dns-api-values"><label class="form-label" translate="dns.recordValues"></label><textarea class="form-control font-monospace" data-dns-field="values" rows="2"${editable ? "" : " readonly"}>${esc(values)}</textarea></div>
        <div class="dns-api-actions">${editable ? `<button class="btn btn-sm btn-outline-success" type="button" data-save-dns-record translate="common.save" translate-attr="title aria-label"><i class="bi bi-check-lg"></i></button><button class="btn btn-sm btn-outline-danger" type="button" ${isNew ? "data-cancel-dns-record" : "data-delete-dns-record"} translate="common.${isNew ? "cancel" : "delete"}" translate-attr="title aria-label"><i class="bi bi-${isNew ? "x-lg" : "trash"}"></i></button>` : '<span class="badge text-bg-light"><i class="bi bi-lock"></i></span>'}</div>
      </div>
    </div>`;
  }

  function dnsManagedRecordRow(record, types, readOnly) {
    const item = record || {};
    const options = (types || ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"]).map(function (type) {
      return `<option value="${esc(type)}"${String(item.type || "A") === type ? " selected" : ""}>${esc(type)}</option>`;
    }).join("");
    const values = Array.isArray(item.values) ? item.values.join("\n") : String(item.values || "");
    return `<div class="dns-api-record" data-managed-dns-record>
      <div class="dns-api-record-grid">
        <div><label class="form-label" translate="forms.recordName"></label><input class="form-control font-monospace" data-dns-field="name" maxlength="253" value="${esc(item.name || "@")}"${readOnly ? " readonly" : ""}></div>
        <div><label class="form-label" translate="dns.recordType"></label><select class="form-select" data-dns-field="type"${readOnly ? " disabled" : ""}>${options}</select></div>
        <div><label class="form-label">TTL</label><input class="form-control font-monospace" data-dns-field="ttl" type="number" min="60" max="2147483647" value="${esc(item.ttl || 3600)}"${readOnly ? " readonly" : ""}></div>
        <div class="dns-api-values"><label class="form-label" translate="dns.recordValues"></label><textarea class="form-control font-monospace" data-dns-field="values" rows="2"${readOnly ? " readonly" : ""}>${esc(values)}</textarea></div>
        <div class="dns-api-actions">${readOnly ? '<span class="badge text-bg-light"><i class="bi bi-eye"></i></span>' : '<button class="btn btn-sm btn-outline-danger" type="button" data-remove-managed-dns-record translate="common.delete" translate-attr="title aria-label"><i class="bi bi-trash"></i></button>'}</div>
      </div>
    </div>`;
  }

  function dnsManagedRecordsText(records) {
    const lines = [];
    (Array.isArray(records) ? records : []).forEach(function (record) {
      const name = String(record && record.name || "@");
      const type = String(record && record.type || "").toUpperCase();
      const ttl = Number(record && record.ttl || 0) || 3600;
      let values = Array.isArray(record && record.values) ? record.values : [];
      if (!values.length && Array.isArray(record && record.records)) {
        values = record.records.map(function (value) { return value && typeof value === "object" ? value.value : value; });
      }
      values.filter(function (value) { return value !== undefined && value !== null && String(value) !== ""; }).forEach(function (value) {
        lines.push(`${name}\t${ttl}\t${type}\t${String(value)}`);
      });
    });
    return lines.join("\n");
  }

  function dnsManagedCopyPanel(targets, sourceDomain) {
    const rows = (Array.isArray(targets) ? targets : []).map(function (target, index) {
      const details = [target.provider && String(target.provider).toUpperCase(), target.connectionName, target.prefix].filter(Boolean).join(" · ");
      const search = [target.domain, target.provider, target.connectionName, target.user, target.prefix].filter(Boolean).join(" ").toLowerCase();
      return `<label class="dns-copy-zone" data-dns-copy-zone data-search="${esc(search)}" for="dns-copy-target-${index}"><input class="form-check-input" type="checkbox" id="dns-copy-target-${index}" value="${esc(target.id || "")}" data-dns-copy-target><span><strong>${esc(target.domain || "")}</strong><small>${esc(details)}</small></span></label>`;
    }).join("");
    return `<section class="dns-copy-panel d-none" data-dns-copy-panel data-source-domain="${esc(sourceDomain || "")}">
      <div class="input-group input-group-sm mb-2"><span class="input-group-text"><i class="bi bi-search"></i></span><input class="form-control" type="search" data-dns-copy-search translate="dns.copyZoneSearch" translate-attr="placeholder aria-label"></div>
      <div class="dns-copy-zone-list" data-dns-copy-zone-list>${rows || '<div class="text-secondary small py-3" translate="dns.noCopyTargets"></div>'}</div>
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mt-3"><div class="form-text m-0" translate="dns.copyZoneHint"></div><button class="btn btn-sm btn-primary" type="button" data-dns-copy-submit${rows ? "" : " disabled"}><i class="bi bi-copy me-1"></i><span translate="dns.copySelectedZones"></span></button></div>
      <div class="dns-copy-results mt-3 d-none" data-dns-copy-results></div>
    </section>`;
  }

  function dnsManagedZoneModal(data, readOnly) {
    const payload = data || {};
    const zone = payload.zone || {};
    const types = payload.types || ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"];
    const records = Array.isArray(zone.records) ? zone.records : (Array.isArray(payload.records) ? payload.records : []);
    const recommended = Array.isArray(payload.recommended) ? payload.recommended : [];
    const copyTargets = Array.isArray(payload.copyTargets) ? payload.copyTargets : [];
    const textRecords = dnsManagedRecordsText(records);
    const body = `<input type="hidden" name="id" value="${esc(zone.id || "")}">
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3"><div><strong class="fs-5">${esc(zone.domain || payload.zone || "")}</strong><div class="text-secondary small">${esc(zone.connectionName || payload.provider || "")}</div></div><span class="badge text-bg-light">${esc(String(zone.provider || payload.provider || "").toUpperCase())}</span></div>
      ${readOnly
        ? (textRecords ? `<pre class="dns-current-records">${esc(textRecords)}</pre>` : `<div class="text-secondary small py-3" translate="dns.noRecords"></div>`)
        : `<div class="d-flex flex-wrap gap-2 mb-3"><button class="btn btn-sm btn-outline-primary" type="button" data-add-managed-dns-record><i class="bi bi-plus-lg me-1"></i><span translate="dns.addRecord"></span></button><button class="btn btn-sm btn-outline-success" type="button" data-add-managed-dns-template><i class="bi bi-magic me-1"></i><span translate="dns.addHostingTemplate"></span></button><button class="btn btn-sm btn-outline-info" type="button" data-toggle-managed-dns-copy${copyTargets.length ? "" : " disabled"}><i class="bi bi-copy me-1"></i><span translate="dns.copyToZone"></span></button></div>${dnsManagedCopyPanel(copyTargets, zone.domain || "")}<div data-managed-dns-records data-dns-types="${esc(encodeURIComponent(JSON.stringify(types)))}" data-dns-template="${esc(encodeURIComponent(JSON.stringify(recommended)))}">${records.length ? records.map(function (record) { return dnsManagedRecordRow(record, types, false); }).join("") : `<div class="text-secondary small py-3" data-managed-dns-empty translate="dns.noRecords"></div>`}</div>`}`;
    return `<div class="modal fade" id="dns-managed-zone-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable"><div class="modal-content"><form id="dns-managed-zone-form" data-read-only="${readOnly ? "1" : "0"}"><div class="modal-header"><h2 class="modal-title" translate="${readOnly ? "dns.currentRecords" : "dns.editZone"}"></h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body">${body}</div><div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" translate="common.${readOnly ? "close" : "cancel"}"></button>${readOnly ? "" : '<button type="submit" class="btn btn-primary"><i class="bi bi-check2 me-2"></i><span translate="common.save"></span></button>'}</div></form></div></div></div>`;
  }

  function dnsBulkChangeModal(data, isRoot, defaultTtl) {
    const payload = data || {};
    const zones = Array.isArray(payload.zones) ? payload.zones : [];
    const users = Array.isArray(payload.users) ? payload.users : [];
    const providers = Array.isArray(payload.providers) ? payload.providers : [];
    const types = Array.isArray(payload.types) && payload.types.length ? payload.types : ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"];
    const userOptions = users.map(function (user) {
      const label = [user.email, user.prefix].filter(Boolean).join(" · ");
      return `<option value="${esc(user.id)}">${esc(label)}</option>`;
    }).join("");
    const providerOptions = providers.map(function (provider) {
      return `<option value="${esc(provider.id)}">${esc(provider.name || String(provider.id || "").toUpperCase())}</option>`;
    }).join("");
    const typeOptions = types.map(function (type) { return `<option value="${esc(type)}">${esc(type)}</option>`; }).join("");
    const zoneRows = zones.map(function (zone, index) {
      const details = [String(zone.provider || "").toUpperCase(), zone.connectionName, isRoot ? (zone.user || zone.prefix) : ""].filter(Boolean).join(" · ");
      const search = [zone.domain, zone.provider, zone.connectionName, zone.user, zone.prefix].filter(Boolean).join(" ").toLowerCase();
      return `<label class="dns-copy-zone" data-dns-bulk-zone data-search="${esc(search)}" data-user-id="${esc(zone.userId || "")}" data-provider="${esc(zone.provider || "")}" data-on-server="${zone.onServer ? "1" : "0"}" for="dns-bulk-zone-${index}"><input class="form-check-input" type="checkbox" id="dns-bulk-zone-${index}" value="${esc(zone.id || "")}" data-dns-bulk-target data-domain="${esc(zone.domain || "")}"><span><strong>${esc(zone.domain || "")}</strong><small>${esc(details)}</small></span></label>`;
    }).join("");
    return `<div class="modal fade" id="dns-bulk-change-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable"><div class="modal-content"><form id="dns-bulk-change-form"><div class="modal-header"><div><h2 class="modal-title" translate="dns.bulkChangeTitle"></h2><div class="text-secondary small" translate="dns.bulkChangeHint"></div></div><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body">
      <section class="form-section"><div class="form-section-title"><i class="bi bi-check2-square"></i><span translate="dns.domainSelection"></span></div>
        <div class="row g-3 mb-3">${isRoot ? `<div class="col-md-6"><label class="form-label" translate="dns.userLabel"></label><select class="form-select" data-dns-bulk-user><option value="" translate="dns.allUsers"></option>${userOptions}</select></div>` : ""}<div class="${isRoot ? "col-md-6" : "col-12"}"><label class="form-label" translate="dns.providerFilter"></label><select class="form-select" data-dns-bulk-provider><option value="" translate="dns.allProviders"></option>${providerOptions}</select></div></div>
        <div class="form-check mb-1"><input class="form-check-input" type="checkbox" id="dns-bulk-server-only" data-dns-bulk-server-only><label class="form-check-label fw-semibold" for="dns-bulk-server-only" translate="dns.serverDomainsOnly"></label></div>
        <div class="form-text mb-3" translate="dns.serverDomainsOnlyHint"></div>
        <div class="input-group input-group-sm mb-2"><span class="input-group-text"><i class="bi bi-search"></i></span><input class="form-control" type="search" data-dns-bulk-search translate="dns.searchDomains" translate-attr="placeholder aria-label"><button class="btn btn-outline-primary" type="button" data-dns-bulk-select-all><i class="bi bi-check2-all me-1"></i><span translate="dns.allDomains"></span></button><button class="btn btn-outline-secondary" type="button" data-dns-bulk-clear><i class="bi bi-x-lg me-1"></i><span translate="dns.clearSelection"></span></button></div>
        <div class="dns-copy-zone-list" data-dns-bulk-zone-list>${zoneRows || '<div class="text-secondary small p-3" translate="dns.noManagedZones"></div>'}</div>
        <div class="form-text mt-2"><span translate="dns.selectedDomains"></span>: <strong data-dns-bulk-selected>0</strong></div>
      </section>
      <section class="form-section mt-3"><div class="form-section-title"><i class="bi bi-record-circle"></i><span translate="dns.recordSettings"></span></div><div class="row g-3">
        <div class="col-md-3"><label class="form-label" translate="dns.recordType"></label><select class="form-select" name="type" required>${typeOptions}</select></div>
        <div class="col-md-6"><label class="form-label" translate="dns.recordNameLabel"></label><div class="input-group"><input class="form-control font-monospace" name="name" maxlength="253" placeholder="@"><span class="input-group-text font-monospace" data-dns-bulk-name-suffix>.domain</span></div><div class="form-text" translate="dns.recordNameHint"></div></div>
        <div class="col-md-3"><label class="form-label">TTL</label><input class="form-control" name="ttl" type="number" min="60" max="2147483647" value="${esc(defaultTtl || 3600)}" required></div>
        <div class="col-12"><label class="form-label" translate="dns.recordValue"></label><textarea class="form-control font-monospace" name="values" rows="3" required></textarea><div class="form-text" translate="dns.recordValueHint"></div></div>
      </div></section>
      <section class="dns-bulk-progress d-none mt-3" data-dns-bulk-change-progress aria-live="polite"><div class="dns-bulk-progress-head"><div><span class="spinner-border spinner-border-sm text-primary" data-dns-bulk-change-spinner></span><strong translate="dns.applyingBulkChange"></strong></div><strong><span data-dns-bulk-processed>0</span>/<span data-dns-bulk-total>0</span></strong></div><div class="dns-bulk-progress-domain"><span translate="dns.currentTarget"></span><strong data-dns-bulk-current>—</strong></div><div class="dns-bulk-progress-meta"><span><span translate="dns.successfulDomains"></span>: <strong data-dns-bulk-success>0</strong></span><span><span translate="dns.failedDomains"></span>: <strong data-dns-bulk-failed>0</strong></span></div><div class="progress"><div class="progress-bar progress-bar-striped progress-bar-animated" data-dns-bulk-bar style="width:0%"></div></div><div class="dns-bulk-progress-errors d-none" data-dns-bulk-results></div></section>
    </div><div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" translate="common.close"></button><button type="submit" class="btn btn-primary"${zones.length ? "" : " disabled"}><i class="bi bi-cloud-upload me-2"></i><span translate="dns.saveAndSend"></span></button></div></form></div></div></div>`;
  }

  function dnsManagementSection(item, defaultTtl) {
    const edit = !!item.id;
    return `<section class="form-section d-none" data-dns-management data-domain-id="${esc(item.id || "")}" data-dns-default-ttl="${esc(defaultTtl || 3600)}">
      <div class="form-section-title"><i class="bi bi-cloud-check"></i><span translate="dns.domainTitle"></span></div>
      <div class="check-card"><div class="check-card-head"><div><strong translate="dns.providerStatus"></strong><div class="form-text" translate="dns.providerStatusHint"></div></div><button class="btn btn-sm btn-outline-primary" type="button" data-detect-dns-provider><i class="bi bi-search me-1"></i><span translate="common.check"></span></button></div><div class="mt-3 d-none" data-dns-provider-result></div><div class="row g-2 align-items-end mt-2 d-none" data-dns-connection-picker><div class="col-md-8"><label class="form-label" translate="dns.selectConnection"></label><select class="form-select" name="dnsConnectionId" data-domain-dns-connection data-saved-value="${esc(item.dnsConnectionId || "")}"></select></div><div class="col-md-4"><button class="btn btn-outline-primary w-100" type="button" data-verify-dns-access><i class="bi bi-shield-check me-1"></i><span translate="dns.checkApiAccess"></span></button></div></div><button class="btn btn-sm btn-outline-secondary mt-3" type="button" data-toggle-recommended-dns aria-expanded="false"><i class="bi bi-chevron-down me-1"></i><span translate="dns.recommendedPreviewTitle"></span></button><div class="dns-recommended-preview d-none" data-dns-recommended-preview><div class="dns-recommended-heading"><div><div class="form-text" translate="dns.recommendedPreviewHint"></div></div></div><div class="dns-recommended-records" data-dns-recommended-records></div></div><button class="btn btn-primary btn-sm mt-3 d-none" type="button" data-apply-recommended-dns disabled><i class="bi bi-magic me-1"></i><span translate="dns.applyRecommended"></span></button></div>
      ${edit ? `<div class="dns-api-editor mt-3"><div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2"><div><strong translate="dns.recordsTitle"></strong><div class="form-text" translate="dns.recordsHint"></div></div><button class="btn btn-sm btn-outline-primary" type="button" data-add-dns-record disabled><i class="bi bi-plus-lg me-1"></i><span translate="dns.addRecord"></span></button></div><div class="dns-api-loading d-none" data-dns-api-loading><span class="spinner-border spinner-border-sm"></span><span translate="dns.loadingRecords"></span></div><div class="dns-api-records" data-dns-api-records></div></div>` : ""}
    </section>`;
  }

  function domainModal(record, users, domains, isRoot, dnsRecords, publicHtmlDirectory, phpVersions, dnsDefaultTtl) {
    const edit = !!record;
    const item = record || {};
    const selectedUserId = item.userId || (users[0] && users[0].id);
    const paths = projectPaths(domains, selectedUserId, isRoot);
    const currentPath = item.path || "";
    if (currentPath && !paths.includes(currentPath)) paths.push(currentPath);
    const useExisting = !!currentPath && paths.length > 0;
    const selectedExistingPath = currentPath || paths[0] || "";
    const publicDirectory = publicHtmlDirectory || "public_html";
    const defaultFolder = item.domain || "";
    const owner = isRoot ? field("forms.selectUser", `<select class="form-select" name="userId" data-domain-owner${edit ? " disabled" : ""}>${userOptions(users, selectedUserId)}</select>`) : "";
    const body = `<section class="form-section"><div class="form-section-title"><i class="bi bi-globe2"></i><span translate="forms.general"></span></div><div class="row g-3">
      ${owner}
      ${field("forms.domain", `<div class="input-group"><span class="input-group-text">https://</span><input class="form-control" name="domain" required value="${esc(item.domain)}" translate="forms.domainPlaceholder" translate-attr="placeholder"></div>`)}
      <div class="col-md-6"><label class="form-label">PHP</label><select class="form-select" name="phpVersion" required>${phpVersionOptions(phpVersions, item.phpVersion)}</select></div>
      ${field("common.comment", `<textarea class="form-control" name="comment" rows="3" maxlength="2000">${esc(item.comment || "")}</textarea>`, "col-12")}
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-folder2-open"></i><span translate="forms.projectDirectory"></span></div>
      <div class="row g-3">
        <div class="col-12"><div class="project-mode-selector">
          <div class="form-check"><input class="form-check-input" name="projectPathMode" value="existing" type="radio" id="project-existing" ${useExisting ? "checked" : ""}${paths.length ? "" : " disabled"}><label class="form-check-label" for="project-existing" translate="forms.useExistingProject"></label></div>
          <div class="form-check"><input class="form-check-input" name="projectPathMode" value="new" type="radio" id="project-new" ${useExisting ? "" : "checked"}><label class="form-check-label" for="project-new" translate="forms.createProjectDirectory"></label></div>
        </div></div>
        ${field("forms.existingProject", `<div class="input-group"><span class="input-group-text"><i class="bi bi-search"></i></span><input class="form-control" type="search" name="existingPath" data-existing-project data-current-path="${esc(currentPath)}" list="domain-existing-project-options" value="${esc(selectedExistingPath)}" autocomplete="off" translate="forms.searchExistingProject" translate-attr="placeholder aria-label"></div><datalist id="domain-existing-project-options" data-existing-project-options>${projectPathOptions(paths)}</datalist>`, "col-12 project-existing-group")}
        ${field("forms.projectFolder", `<div class="input-group"><span class="input-group-text">~/</span><input class="form-control" name="projectFolder" data-project-folder pattern="[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?" value="${esc(defaultFolder)}"><span class="input-group-text">/${esc(publicDirectory)}</span></div><div class="form-text" translate="forms.projectDirectoryHint"></div>`, "col-12 project-new-group")}
        <div class="col-12"><div class="project-path-preview"><span translate="forms.absolutePath"></span><code data-project-absolute></code></div></div>
        ${edit ? `<div class="col-12"><div class="d-flex flex-wrap align-items-center justify-content-between gap-3 border rounded-3 p-3"><div><strong>Права файлов и папок</strong><div class="form-text">Исправляет доступ к файлам и папкам этого сайта.</div></div><button class="btn btn-outline-primary" type="button" data-domain-permissions="${esc(item.id)}"><i class="bi bi-shield-check me-2"></i>Выставить права</button></div></div>` : ""}
      </div>
    </section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-sliders"></i><span translate="forms.services"></span></div><div class="row g-3">
      <div class="col-md-6"><div class="form-check form-switch"><input class="form-check-input" name="useSsl" type="checkbox" id="use-ssl" ${item.ssl !== false ? "checked" : ""}><label class="form-check-label" for="use-ssl" translate="forms.useSsl"></label></div></div>
      <div class="col-md-6"><div class="form-check form-switch"><input class="form-check-input" name="redirectHttp" type="checkbox" id="redirect-http" ${item.redirectHttp !== false ? "checked" : ""}><label class="form-check-label" for="redirect-http" translate="forms.redirectHttp"></label></div></div>
      <div class="col-md-6"><div class="form-check form-switch"><input class="form-check-input" name="redirectWww" type="checkbox" id="redirect-www" ${item.redirectWww !== false ? "checked" : ""}><label class="form-check-label" for="redirect-www" translate="forms.redirectWww"></label></div></div>
      <div class="col-md-6"><div class="form-check form-switch"><input class="form-check-input" name="createDatabase" type="checkbox" id="create-db" ${item.database ? "checked" : ""}${edit ? " disabled" : ""}><label class="form-check-label" for="create-db" translate="forms.createDatabase"></label></div></div>
      <div class="col-md-6"><div class="form-check form-switch"><input class="form-check-input" name="createMail" type="checkbox" id="create-mail" ${item.mailEnabled || item.mailAccounts ? "checked" : ""}${edit ? " disabled" : ""}><label class="form-check-label" for="create-mail" translate="forms.createMail"></label></div></div>
    </div></section>
    <section class="form-section"><div class="form-section-title"><i class="bi bi-shield-check"></i><span translate="forms.verification"></span></div>
      <div class="check-card"><div class="check-card-head"><strong translate="forms.checkDomain"></strong><button class="btn btn-outline-primary btn-sm" type="button" data-verify="domain"><i class="bi bi-radar me-1"></i><span translate="common.check"></span></button></div><div class="verification-results d-none" data-verification-results="domain"></div></div>
      <div class="check-card mt-3"><div class="check-card-head"><strong translate="forms.checkMailDns"></strong><button class="btn btn-outline-primary btn-sm" type="button" data-verify="mail"><i class="bi bi-radar me-1"></i><span translate="common.check"></span></button></div><div class="verification-results d-none" data-verification-results="mail"></div></div>
      <div class="mt-3">${dnsRequirements(dnsRecords)}</div>
    </section>
    ${dnsManagementSection(item, dnsDefaultTtl)}
    ${edit ? domainToolAccessSection(item) : ""}`;
    return commonModal(edit ? "forms.domainEdit" : "forms.domainAdd", "domains", `<input type="hidden" name="id" value="${esc(item.id || "")}">${body}`, true, isRoot);
  }

  function databaseModal(record, users, domains, isRoot, currentPrefix, connectionHost, connectionPort, showPasswords) {
    const edit = !!record;
    const item = record || {};
    const selectedUserId = item.userId || (users[0] && users[0].id) || "";
    const selectedUser = users.find(function (user) { return Number(user.id) === Number(selectedUserId); });
    const prefix = item.prefix || (selectedUser && selectedUser.prefix) || currentPrefix || "prefix";
    const username = item.username || item.name || "";
    const password = showPasswords ? (item.password || "") : "";
    const host = item.host || connectionHost || "localhost";
    const port = item.port || connectionPort || 3306;
    const owner = isRoot ? field("forms.selectUser", `<select class="form-select" name="userId" data-database-owner${edit ? " disabled" : ""}>${userOptions(users, selectedUserId)}</select>`) : "";
    const passwordField = `<div class="input-group">
      <input class="form-control font-monospace" name="password" type="${showPasswords ? "text" : "password"}" minlength="8" maxlength="128"${edit && !showPasswords ? "" : " required"} value="${esc(password)}" autocomplete="new-password">
      ${showPasswords ? '<button class="btn btn-outline-primary" type="button" data-generate-database-password translate="forms.generatePassword" translate-attr="title aria-label"><i class="bi bi-arrow-repeat"></i></button>' : ""}
    </div><div class="form-text" translate="forms.databasePasswordHint"></div>`;
    const credentials = edit ? `<section class="form-section"><div class="form-section-title"><i class="bi bi-plug"></i><span translate="forms.databaseConnection"></span></div>
      ${item.credentialsPending ? '<div class="notice-strip mb-3"><i class="bi bi-exclamation-triangle"></i><span translate="forms.databasePasswordPending"></span></div>' : ""}
      <textarea class="form-control font-monospace" rows="6" readonly data-database-credentials data-database-host="${esc(host)}" data-database-port="${esc(port)}" data-database-username="${esc(username)}"></textarea>
    </section>` : "";
    const body = `<section class="form-section"><div class="form-section-title"><i class="bi bi-database"></i><span translate="forms.general"></span></div><div class="row g-3">
      ${owner}
      ${field("forms.databaseName", `<div class="input-group"><span class="input-group-text" data-database-prefix>${esc(prefix)}_</span><input class="form-control" name="name" required pattern="[a-z0-9_]{1,48}" value="${esc(item.name ? item.name.substring(prefix.length + 1) : "")}"${edit ? " readonly" : ""}></div>`)}
      ${field("forms.linkedDomain", `<select class="form-select" name="domain">${domainOptions(domains, item.domain)}</select>`, "col-12")}
      ${field("common.comment", `<textarea class="form-control" name="comment" rows="3" maxlength="2000">${esc(item.comment || "")}</textarea>`, "col-12")}
      ${field("forms.databasePassword", passwordField, "col-12")}
    </div></section>${credentials}`;
    return commonModal(edit ? "forms.databaseEdit" : "forms.databaseAdd", "databases", `<input type="hidden" name="id" value="${esc(item.id || "")}">${body}`, false, isRoot);
  }

  function databaseConfigurationModal(record, configuration) {
    const item = record || {};
    return `<div class="modal fade" id="database-configuration-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h2 class="modal-title"><span translate="forms.databaseConnection"></span> · ${esc(item.name || "")}</h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body"><textarea class="form-control font-monospace" rows="6" readonly>${esc(configuration || "")}</textarea></div>
      <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" translate="common.close"></button></div>
    </div></div></div>`;
  }

  function mailAliasRow(value, domain) {
    return `<div class="input-group mb-2" data-mail-alias-row>
      <input class="form-control font-monospace" name="aliases[]" data-mail-alias-input pattern="[A-Za-z0-9][A-Za-z0-9._+-]{0,63}" maxlength="64" value="${esc(value || "")}" translate="forms.mailAliasesPlaceholder" translate-attr="placeholder">
      <span class="input-group-text" data-mail-domain-suffix>@${esc(domain || "domain")}</span>
      <button class="btn btn-outline-danger" type="button" data-remove-mail-alias translate="forms.removeAlias" translate-attr="title aria-label"><i class="bi bi-dash-lg"></i></button>
    </div>`;
  }

  function mailMigrationSection(item, allowedPorts) {
    const ports = (Array.isArray(allowedPorts) && allowedPorts.length ? allowedPorts : [143, 993]).map(Number);
    const defaultPort = ports.indexOf(993) !== -1 ? 993 : ports[0];
    return `<section class="form-section" data-mail-migration data-mailbox-id="${esc(item.id || "")}">
      <div class="form-section-title"><i class="bi bi-cloud-arrow-down"></i><span translate="mailMigration.title"></span></div>
      <div class="mail-migration-loading" data-mail-migration-loading><span class="spinner-border spinner-border-sm"></span><span translate="mailMigration.loading"></span></div>
      <div class="d-none" data-mail-migration-content>
        <div data-mail-migration-current></div>
        <div class="mail-migration-form" data-mail-migration-form>
          <p class="text-secondary small mb-3" translate="mailMigration.description"></p>
          <div class="row g-3">
            <div class="col-md-6"><label class="form-label" translate="mailMigration.host"></label><input class="form-control" type="text" data-migration-field="sourceHost" maxlength="253" autocomplete="off"></div>
            <div class="col-md-3"><label class="form-label" translate="mailMigration.port"></label><select class="form-select" data-migration-field="sourcePort">${ports.map(function (port) { return `<option value="${esc(port)}"${port === defaultPort ? " selected" : ""}>${esc(port)}</option>`; }).join("")}</select></div>
            <div class="col-md-3"><label class="form-label" translate="mailMigration.security"></label><select class="form-select" data-migration-field="sourceSecurity"><option value="ssl" translate="mailMigration.ssl"></option><option value="starttls">STARTTLS</option><option value="none" translate="mailMigration.none"></option></select></div>
            <div class="col-md-6"><label class="form-label" translate="mailMigration.login"></label><input class="form-control" type="text" data-migration-field="sourceLogin" maxlength="254" autocomplete="username"></div>
            <div class="col-md-6"><label class="form-label" translate="mailMigration.password"></label><input class="form-control" type="password" data-migration-field="sourcePassword" maxlength="4096" autocomplete="current-password"></div>
          </div>
          <div class="mail-migration-stages d-none mt-3" data-mail-migration-stages aria-live="polite"></div>
          <div class="mail-migration-test-result d-none mt-3" data-mail-migration-test-result></div>
          <div class="d-flex flex-wrap gap-2 mt-3">
            <button class="btn btn-outline-primary" type="button" data-mail-migration-test><i class="bi bi-plug me-1"></i><span translate="mailMigration.test"></span></button>
            <button class="btn btn-primary d-none" type="button" data-mail-migration-start><i class="bi bi-play-fill me-1"></i><span translate="mailMigration.start"></span></button>
          </div>
        </div>
        <div class="mail-migration-report d-none mt-3" data-mail-migration-report></div>
        <div class="mail-migration-history mt-4 d-none" data-mail-migration-history-wrap><h3 class="h6" translate="mailMigration.previous"></h3><div data-mail-migration-history></div></div>
      </div>
    </section>`;
  }

  function mailModal(record, users, domains, isRoot, showPasswords, mailConnection, quotaOptionsMb, defaultQuotaMb, migrationEnabled, migrationPorts) {
    const edit = !!record;
    const item = record || {};
    const selectedUserId = item.userId || (users[0] && users[0].id) || "";
    const owner = isRoot ? field("forms.selectUser", `<select class="form-select" name="userId"${edit ? " disabled" : ""}>${userOptions(users, selectedUserId)}</select>`) : "";
    const password = showPasswords ? (item.password || "") : "";
    const selectedDomain = item.domain || (domains[0] && domains[0].domain) || "domain";
    const selectedDomainRow = (domains || []).find(function (domain) { return domain.domain === selectedDomain; }) || {};
    const canCreateInfoCatchAll = !edit && Number(selectedDomainRow.mailAccounts || 0) === 0 && selectedDomainRow.mailMode !== "domain_forward";
    const aliases = (Array.isArray(item.aliases) && item.aliases.length ? item.aliases : [""]).map(function (alias) {
      const suffix = `@${selectedDomain}`;
      return alias && alias.slice(-suffix.length).toLowerCase() === suffix.toLowerCase() ? alias.slice(0, -suffix.length) : alias;
    });
    const aliasRows = aliases.map(function (alias) { return mailAliasRow(alias, selectedDomain); }).join("");
    const forwardTo = Array.isArray(item.forwardTo) ? item.forwardTo.join("\n") : "";
    const quota = item.quotaBytes ? Math.round(item.quotaBytes / 1048576) : Number(defaultQuotaMb || 20);
    const configuredQuotas = (Array.isArray(quotaOptionsMb) ? quotaOptionsMb : []).map(Number).filter(function (value, index, values) {
      return Number.isInteger(value) && value > 0 && values.indexOf(value) === index;
    });
    if (configuredQuotas.indexOf(quota) === -1) configuredQuotas.push(quota);
    const quotaOptions = configuredQuotas.map(function (value) {
      return `<option value="${esc(value)}"${value === quota ? " selected" : ""}>${esc(value)} MB</option>`;
    }).join("");
    const passwordField = `<div class="input-group">
      <input class="form-control font-monospace" name="password" type="${showPasswords ? "text" : "password"}" minlength="8" maxlength="128"${edit && !showPasswords ? "" : " required"} value="${esc(password)}" autocomplete="new-password">
      ${showPasswords ? '<button class="btn btn-outline-primary" type="button" data-generate-mail-password translate="forms.generatePassword" translate-attr="title aria-label"><i class="bi bi-arrow-repeat"></i></button>' : ""}
    </div><div class="form-text" translate="${showPasswords ? "forms.mailPasswordHint" : "forms.passwordHint"}"></div>`;
    const credentials = `<section class="form-section"><div class="form-section-title"><i class="bi bi-plug"></i><span translate="forms.mailConnection"></span></div>
      ${item.credentialsPending ? '<div class="notice-strip mb-3"><i class="bi bi-exclamation-triangle"></i><span translate="forms.mailPasswordPending"></span></div>' : ""}
      <textarea class="form-control font-monospace" rows="18" readonly data-mail-credentials></textarea>
    </section>`;
    const body = `<section class="form-section"><div class="form-section-title"><i class="bi bi-envelope"></i><span translate="forms.general"></span></div><div class="row g-3">
      ${owner}
      ${field("forms.mailDomain", `<select class="form-select" name="domain" required>${domainOptions(domains, item.domain)}</select>`)}
      ${field("forms.mailbox", `<div class="input-group"><input class="form-control" name="mailbox" required value="${esc(item.address ? item.address.split("@")[0] : "")}"><span class="input-group-text" data-mail-domain-suffix>@${esc(selectedDomain)}</span></div>`)}
      ${field("common.comment", `<textarea class="form-control" name="comment" rows="3" maxlength="2000">${esc(item.comment || "")}</textarea>`, "col-12")}
      ${!edit ? `<div class="col-12${canCreateInfoCatchAll ? "" : " d-none"}" data-mail-info-catchall-wrap><button class="btn btn-outline-primary" type="button" data-mail-info-catchall><i class="bi bi-envelope-check me-2"></i><span translate="profile.catchAllInfoButton"></span></button><div class="form-text" translate="profile.catchAllInfoButtonHint"></div></div>` : ""}
      ${field("forms.mailAliases", `<div data-mail-alias-list>${aliasRows}</div><button class="btn btn-sm btn-outline-primary mt-1" type="button" data-add-mail-alias><i class="bi bi-plus-lg me-1"></i><span translate="forms.addAlias"></span></button><div class="form-text" translate="forms.mailAliasesHint"></div>`, "col-12")}
      ${field("forms.mailForwardTo", `<textarea class="form-control font-monospace" name="forwardTo" rows="4" translate="forms.mailForwardToPlaceholder" translate-attr="placeholder">${esc(forwardTo)}</textarea><div class="form-text" translate="forms.mailForwardToHint"></div>`, "col-12")}
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" id="mail-catch-all" name="catchAll" type="checkbox"${item.catchAll ? " checked" : ""}><label class="form-check-label" for="mail-catch-all" translate="forms.mailCatchAll"></label></div><div class="form-text" translate="forms.mailCatchAllHint"></div></div>
      ${field("forms.quotaMb", `<select class="form-select" name="quota" required>${quotaOptions}</select>`)}
      ${field("forms.mailPassword", passwordField, "col-12")}
    </div></section>${credentials}${edit && migrationEnabled ? mailMigrationSection(item, migrationPorts) : ""}`;
    return commonModal(edit ? "forms.mailEdit" : "forms.mailAdd", "mail", `<input type="hidden" name="id" value="${esc(item.id || "")}">${body}`, true, isRoot);
  }

  function mailConfigurationModal(record, configuration, mailConnection) {
    const item = record || {};
    const settings = mailConnection || {};
    const email = encodeURIComponent(String(item.address || ""));
    const profileUrl = function (path) {
      const separator = String(path || "").indexOf("?") === -1 ? "?" : "&";
      return `${String(path || "")}${separator}email=${email}`;
    };
    const appleProfiles = `<div class="notice-strip mb-3 align-items-center">
      <i class="bi bi-apple fs-4"></i>
      <div class="flex-grow-1"><strong>Apple Mail</strong><div class="small text-muted">iPhone · iPad · macOS</div></div>
      <div class="d-flex flex-wrap gap-2">
        <a class="btn btn-sm btn-primary" href="${esc(profileUrl(settings.applePop3ProfilePath || settings.appleProfilePath || "/mail/apple.mobileconfig"))}" target="_blank" rel="noopener"><i class="bi bi-download me-1"></i>Apple POP3</a>
        <a class="btn btn-sm btn-outline-primary" href="${esc(profileUrl(settings.appleImapProfilePath || "/mail/apple-imap.mobileconfig"))}" target="_blank" rel="noopener"><i class="bi bi-download me-1"></i>Apple IMAP</a>
      </div>
    </div>`;
    return `<div class="modal fade" id="mail-configuration-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h2 class="modal-title"><span translate="forms.mailConnection"></span> · ${esc(item.address || "")}</h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">${appleProfiles}<textarea class="form-control font-monospace" rows="21" readonly>${esc(configuration || "")}</textarea></div>
      <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" translate="common.close"></button></div>
    </div></div></div>`;
  }

  function domainLogsModal(domain, files) {
    const available = Array.isArray(files) ? files : [];
    return `<div class="modal fade" id="domain-logs-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h2 class="modal-title"><span translate="domainLogs.title"></span> · ${esc(domain)}</h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <div class="domain-log-tabs" role="tablist">${available.map(function (file, index) { return `<button class="btn btn-sm ${index === 0 ? "btn-primary active" : "btn-outline-primary"}" type="button" data-domain-log-file="${esc(file)}">${esc(file)}</button>`; }).join("")}</div>
        <div class="domain-log-loading d-none" data-domain-log-loading><span class="spinner-border spinner-border-sm"></span><span translate="domainLogs.loading"></span></div>
        <pre class="domain-log-viewer mt-3" data-domain-log-viewer tabindex="0"></pre>
        <div class="domain-log-empty d-none" data-domain-log-empty><i class="bi bi-file-earmark-text"></i><span translate="domainLogs.empty"></span></div>
      </div>
      <div class="modal-footer domain-log-footer">
        <div class="domain-log-pager">
          <button class="btn btn-outline-secondary" type="button" data-domain-log-newer><i class="bi bi-chevron-left me-1"></i><span translate="domainLogs.newer"></span></button>
          <span class="domain-log-page" data-domain-log-page></span>
          <button class="btn btn-outline-secondary" type="button" data-domain-log-older><span translate="domainLogs.older"></span><i class="bi bi-chevron-right ms-1"></i></button>
        </div>
        <div class="d-flex gap-2">
          <a class="btn btn-outline-primary disabled" data-domain-log-download aria-disabled="true"><i class="bi bi-download me-1"></i><span translate="domainLogs.download"></span></a>
          <button type="button" class="btn btn-primary" data-bs-dismiss="modal" translate="common.close"></button>
        </div>
      </div>
    </div></div></div>`;
  }

  function importModal(type, users, isRoot) {
    const domainImport = type === "domains";
    const example = domainImport
      ? "domain1.com project-one/public_html ssl www\ndomain2.com shared/public_html ssl www\ndomain3.com shared/public_html ssl"
      : "admin@example.com\tPassword+1\tsupport,help\tuser@example.com\tyes\nuser@example.com\t\tuser\t\tno\nuser@example.com Password+2";
    const owner = isRoot ? `<div class="mb-3"><label class="form-label" translate="forms.selectUser"></label><select class="form-select" data-import-owner>${userOptions(users, users[0] && users[0].id)}</select></div>` : "";
    const credentials = domainImport ? "" : `<section class="mt-4 d-none" data-import-credentials-section><label class="form-label" translate="forms.mailCredentials"></label><textarea class="form-control font-monospace import-credentials" data-import-credentials rows="6" readonly></textarea><div class="form-text" translate="forms.mailCredentialsHint"></div><button class="btn btn-outline-secondary btn-sm mt-2" type="button" data-copy-import-credentials><i class="bi bi-copy me-1"></i><span translate="common.copy"></span></button></section>`;
    return `<div class="modal fade" id="import-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h2 class="modal-title" translate="forms.${domainImport ? "domainImport" : "mailImport"}"></h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body" data-import-type="${esc(type)}">
        ${owner}
        <label class="form-label" translate="forms.importSource"></label>
        <textarea class="form-control font-monospace import-source" data-import-source rows="7" placeholder="${esc(example)}"></textarea>
        <div class="form-text mt-2" translate="forms.${domainImport ? "domainImportHint" : "mailImportHint"}"></div>
        <section class="mt-4 d-none" data-import-preview-section>
          <div class="d-flex align-items-center justify-content-between gap-3 mb-2"><label class="form-label mb-0" translate="forms.importPreview"></label><span class="badge text-bg-light" data-import-count></span></div>
          <div class="import-preview" data-import-preview></div>
        </section>
        ${credentials}
      </div>
      <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" translate="common.cancel"></button><button type="button" class="btn btn-outline-primary" data-parse-import><i class="bi bi-list-check me-2"></i><span translate="common.previewImport"></span></button><button type="button" class="btn btn-primary d-none" data-accept-import><i class="bi bi-check2-circle me-2"></i><span translate="common.accept"></span></button></div>
    </div></div></div>`;
  }

  function domainImportRows(records) {
    return `<div class="import-grid import-domain-grid"><div class="import-grid-head"><span>#</span><span translate="forms.domain"></span><span translate="forms.relativePath"></span><span>SSL</span><span>WWW</span><span translate="columns.status"></span></div>${records.map(function (record, index) {
      return `<div class="import-grid-row" data-import-row="${index}"><span class="import-index">${index + 1}</span><input class="form-control" data-import-field="domain" value="${esc(record.domain)}"><input class="form-control font-monospace" data-import-field="path" value="${esc(record.path)}"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" data-import-field="ssl"${record.ssl ? " checked" : ""}></div><div class="form-check form-switch"><input class="form-check-input" type="checkbox" data-import-field="www"${record.www ? " checked" : ""}></div><span class="import-row-status"></span></div>`;
    }).join("")}</div>`;
  }

  function mailImportRows(records) {
    return `<div class="import-mail-cards">${records.map(function (record, index) {
      return `<div class="import-mail-card" data-import-row="${index}">
        <div class="import-mail-card-head"><strong>#${index + 1}</strong><span class="import-row-status"></span></div>
        <div class="row g-3">
          <div class="col-md-6"><label class="form-label" translate="forms.email"></label><input class="form-control" type="email" data-import-field="email" value="${esc(record.email)}"></div>
          <div class="col-md-6"><label class="form-label" translate="forms.newPassword"></label><div class="input-group"><input class="form-control font-monospace" type="text" data-import-field="password" value="${esc(record.password)}"><button class="btn btn-outline-secondary" type="button" data-regenerate-import-password translate="forms.generatePassword" translate-attr="title aria-label"><i class="bi bi-arrow-repeat"></i></button></div></div>
          <div class="col-md-6"><label class="form-label" translate="forms.mailAliases"></label><textarea class="form-control font-monospace" rows="2" data-import-field="aliases">${esc((record.aliases || []).join(", "))}</textarea><div class="form-text" translate="forms.importAliasesHint"></div></div>
          <div class="col-md-6"><label class="form-label" translate="forms.mailForwardTo"></label><textarea class="form-control font-monospace" rows="2" data-import-field="forwardTo">${esc((record.forwardTo || []).join(", "))}</textarea><div class="form-text" translate="forms.importForwardHint"></div></div>
          <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="import-catch-all-${index}" data-import-field="catchAll"${record.catchAll ? " checked" : ""}><label class="form-check-label" for="import-catch-all-${index}" translate="forms.mailCatchAll"></label></div></div>
        </div>
      </div>`;
    }).join("")}</div>`;
  }

  function languageModal(languages, currentLanguage) {
    return `<div class="modal fade" id="language-modal" tabindex="-1" aria-hidden="true"><div class="modal-dialog modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h2 class="modal-title" translate="languagePicker.title"></h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <div class="input-group language-search"><span class="input-group-text"><i class="bi bi-search"></i></span><input class="form-control" type="search" data-language-search translate="languagePicker.search" translate-attr="placeholder aria-label" autocomplete="off"></div>
        <div class="language-list mt-3" data-language-list>${(languages || []).map(function (language) {
          const selected = language.code === currentLanguage;
          return `<button class="language-option${selected ? " active" : ""}" type="button" data-language="${esc(language.code)}" data-language-name="${esc(String(language.name).toLowerCase())}" data-language-code="${esc(language.code)}"><span class="language-code">${esc(language.code.toUpperCase())}</span><strong>${esc(language.name)}</strong>${selected ? '<i class="bi bi-check-circle-fill"></i>' : ""}</button>`;
        }).join("")}</div>
        <div class="language-empty d-none" data-language-empty><i class="bi bi-search"></i><span translate="languagePicker.noResults"></span></div>
      </div>
    </div></div></div>`;
  }

  window.ImagoTemplates = {
    login: login,
    shell: shell,
    overview: overview,
    tablePage: tablePage,
    migrationPage: migrationPage,
    serverDiagnosticsPage: serverDiagnosticsPage,
    apacheRefreshModal: apacheRefreshModal,
    userModal: userModal,
    profileModal: profileModal,
    dnsConnectionRow: dnsConnectionRow,
    dnsConnectionTableRow: dnsConnectionTableRow,
    domainModal: domainModal,
    dnsRecordRow: dnsRecordRow,
    dnsManagedRecordRow: dnsManagedRecordRow,
    dnsManagedZoneModal: dnsManagedZoneModal,
    dnsBulkChangeModal: dnsBulkChangeModal,
    databaseModal: databaseModal,
    databaseConfigurationModal: databaseConfigurationModal,
    mailModal: mailModal,
    mailConfigurationModal: mailConfigurationModal,
    mailAliasRow: mailAliasRow,
    domainToolAccessRow: domainToolAccessRow,
    domainToolAccessEditor: domainToolAccessEditor,
    domainLogsModal: domainLogsModal,
    importModal: importModal,
    domainImportRows: domainImportRows,
    mailImportRows: mailImportRows,
    languageModal: languageModal,
    logDetailsModal: logDetailsModal,
    esc: esc
  };
})(window, jQuery);
