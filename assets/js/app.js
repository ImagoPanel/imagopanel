(function (window, $) {
  "use strict";

  const config = window.IMAGO_CONFIG || {};
  const templates = window.ImagoTemplates;
  let csrfRefreshRequest = null;
  let sessionReloading = false;
  let pageHiddenAt = 0;
  const state = {
    language: localStorage.getItem("imago_language") || config.defaultLanguage || "ru",
    translations: {},
    translationRequests: {},
    languages: [],
    data: { users: [], domains: [], databases: [], mail: [], dnsManagementEnabled: false },
    route: "overview",
    table: null,
    modal: null,
    importRecords: [],
    domainLog: null,
    mailMigrationTimer: null,
    mailMigrationStageTimer: null,
    dnsRecordsRefreshRunning: false,
    dkimValues: {}
  };

  function valueAt(object, path) {
    return String(path || "").split(".").reduce(function (value, key) {
      return value && Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined;
    }, object);
  }

  function text(key) {
    const dictionary = state.translations[state.language] || {};
    const value = valueAt(dictionary, key);
    const fallback = valueAt(state.translations.en || {}, key);
    return value == null || typeof value === "object" ? (fallback == null || typeof fallback === "object" ? key : String(fallback)) : String(value);
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (character) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;" }[character];
    });
  }

  function translatePage(scope) {
    const $scope = scope ? $(scope) : $(document);
    const dictionary = state.translations[state.language] || {};
    const fallbackDictionary = state.translations.en || {};
    $scope.find("[translate]").addBack("[translate]").each(function () {
      const $element = $(this);
      let value = valueAt(dictionary, $element.attr("translate"));
      if (value === undefined || value === null || typeof value === "object") value = valueAt(fallbackDictionary, $element.attr("translate"));
      if (value === undefined || value === null || typeof value === "object") return;
      const attributes = String($element.attr("translate-attr") || "").trim().split(/\s+/).filter(Boolean);
      if (attributes.length) {
        attributes.forEach(function (attribute) { $element.attr(attribute, value); });
      } else {
        $element.text(value);
      }
    });
    document.documentElement.lang = state.language;
    const language = state.languages.find(function (item) { return item.code === state.language; });
    document.documentElement.dir = language && language.dir === "rtl" ? "rtl" : "ltr";
  }

  function showLanguageLoading(show) {
    $("#language-loader").toggleClass("is-visible", !!show).attr("aria-hidden", show ? "false" : "true");
  }

  function loadTranslation(language) {
    if (state.translations[language]) return $.Deferred().resolve(state.translations[language]).promise();
    if (state.translationRequests[language]) return state.translationRequests[language];
    state.translationRequests[language] = $.getJSON(`assets/data/translations/${encodeURIComponent(language)}.json?v=${encodeURIComponent(config.assetVersion || "1")}`).then(function (dictionary) {
      state.translations[language] = dictionary;
      return dictionary;
    }).always(function () { delete state.translationRequests[language]; });
    return state.translationRequests[language];
  }

  function currentLanguageName() {
    const language = state.languages.find(function (item) { return item.code === state.language; });
    return language ? language.name : state.language.toUpperCase();
  }

  function updateLanguageButton() {
    $("[data-current-language]").text(currentLanguageName());
  }

  function setLanguage(language) {
    if (!state.languages.some(function (item) { return item.code === language; })) return;
    const modalElement = document.getElementById("language-modal");
    const modal = modalElement ? bootstrap.Modal.getInstance(modalElement) : null;
    if (modal) modal.hide();
    showLanguageLoading(true);
    $.when(loadTranslation("en"), loadTranslation(language)).done(function () {
      state.language = language;
      localStorage.setItem("imago_language", language);
      if (config.isAuthenticated) renderRoute(state.route);
      else translatePage(document);
      updateLanguageButton();
    }).fail(function () {
      showError(text("toast.error"));
    }).always(function () {
      window.setTimeout(function () { showLanguageLoading(false); }, 120);
    });
  }

  function updateCsrfToken(token) {
    const value = String(token || "");
    if (!value) return false;
    config.csrfToken = value;
    $('input[name="_csrf"]').val(value);
    return true;
  }

  function reloadExpiredSession() {
    if (sessionReloading) return;
    sessionReloading = true;
    window.location.reload();
  }

  function rawApiRequest(payload, method, options) {
    const verb = method || "POST";
    const requestOptions = $.extend({}, options || {});
    requestOptions.headers = $.extend({}, requestOptions.headers || {}, {
      "X-CSRF-Token": config.csrfToken || ""
    });
    return $.ajax($.extend({
      url: "api/index.php",
      method: verb,
      dataType: "json",
      contentType: verb === "GET" ? "application/x-www-form-urlencoded; charset=UTF-8" : "application/json; charset=UTF-8",
      data: verb === "GET" ? payload : JSON.stringify(payload || {}),
      cache: false
    }, requestOptions));
  }

  function refreshCsrfToken() {
    if (csrfRefreshRequest) return csrfRefreshRequest;

    const deferred = $.Deferred();
    csrfRefreshRequest = deferred.promise();
    $.ajax({
      url: "api/index.php",
      method: "GET",
      dataType: "json",
      data: { action: "sessionCsrf" },
      cache: false
    }).done(function (response) {
      if (response && response.ok && response.data && updateCsrfToken(response.data.csrfToken)) {
        deferred.resolve(response.data.csrfToken);
        return;
      }
      deferred.reject({
        status: 500,
        responseJSON: { error: response && response.error ? response.error : "Invalid CSRF refresh response" }
      });
    }).fail(function (xhr, status, error) {
      deferred.reject(xhr, status, error);
    }).always(function () {
      csrfRefreshRequest = null;
    });

    return deferred.promise();
  }

  function invalidCsrfResponse(xhr) {
    return xhr && Number(xhr.status) === 403
      && String((xhr.responseJSON || {}).error || "") === "Invalid CSRF token";
  }

  function apiRequest(payload, method, options) {
    const deferred = $.Deferred();

    function send(retried) {
      rawApiRequest(payload, method, options).done(function () {
        deferred.resolveWith(this, arguments);
      }).fail(function (xhr) {
        const originalFailure = arguments;
        const originalContext = this;
        if (!retried && invalidCsrfResponse(xhr)) {
          refreshCsrfToken().done(function () {
            send(true);
          }).fail(function (refreshXhr) {
            if (refreshXhr && Number(refreshXhr.status) === 401) reloadExpiredSession();
            deferred.rejectWith(originalContext, originalFailure);
          });
          return;
        }
        if (xhr && Number(xhr.status) === 401) reloadExpiredSession();
        deferred.rejectWith(originalContext, originalFailure);
      });
    }

    send(false);
    return deferred.promise();
  }

  function refreshData() {
    return apiRequest({ action: "bootstrap" }, "GET").then(function (response) {
      if (!response || !response.ok || !response.data) throw new Error(response && response.error || "Invalid API response");
      state.data = response.data;
      config.dnsManagementEnabled = !!response.data.dnsManagementEnabled;
      return response.data;
    });
  }

  function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    const units = ["B", "KB", "MB", "GB", "TB"];
    if (!value) return "0 B";
    const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
    const number = value / Math.pow(1024, index);
    return `${number >= 10 || index === 0 ? number.toFixed(0) : number.toFixed(1)} ${units[index]}`;
  }

  function percent(used, quota) {
    return quota ? Math.round((Number(used) / Number(quota)) * 100) : 0;
  }

  function scopedData(type) {
    const rows = state.data[type] || [];
    if (config.role === "root" || type === "users") return rows.slice();
    return rows.filter(function (row) { return Number(row.userId || row.id) === Number(config.userId); });
  }

  function summary() {
    const users = config.role === "root" ? state.data.users.slice() : state.data.users.filter(function (user) { return user.id === Number(config.userId); });
    const currentUser = config.role === "root" ? null : (users[0] || null);
    const configuredTariff = currentUser && currentUser.tariffLimits ? currentUser.tariffLimits : {};
    const tariff = config.tariffLimitsEnabled ? configuredTariff : $.extend({}, configuredTariff, {
      domain: 0,
      db: 0,
      mailbydomain: 0,
      wwwsize: 0,
      mailsize: 0,
      dbsize: 0
    });
    const domains = scopedData("domains");
    const databases = scopedData("databases");
    const mail = scopedData("mail");
    const sum = function (rows, key) { return rows.reduce(function (total, item) { return total + (Number(item[key]) || 0); }, 0); };
    const siteUsed = sum(users, "siteBytes");
    const siteQuota = sum(users, "siteQuotaBytes");
    const databaseUsed = sum(users, "databaseBytes");
    const databaseQuota = sum(users, "databaseQuotaBytes");
    const mailUsed = sum(users, "mailBytes");
    const mailQuota = sum(users, "mailQuotaBytes");
    const latestStatus = users.filter(function (row) { return row.statusCollectedAt; }).sort(function (left, right) {
      return String(right.statusCollectedAt).localeCompare(String(left.statusCollectedAt));
    })[0] || null;
    const statusDate = latestStatus ? new Date(latestStatus.statusCollectedAt) : null;
    const nextStatusDate = statusDate ? new Date(statusDate.getTime() + Number(config.refreshMinutes || 60) * 60000) : null;
    return {
      users: users.length,
      activeUsers: users.filter(function (row) { return row.active; }).length,
      domains: domains.length,
      activeDomains: domains.filter(function (row) { return row.active; }).length,
      boundDomains: domains.filter(function (row) { return row.bound; }).length,
      sslDomains: domains.filter(function (row) { return row.sslValid === undefined ? row.ssl : row.sslValid; }).length,
      databases: databases.length,
      mailAccounts: mail.length,
      secureMail: mail.filter(function (row) { return row.dkim && row.spf && row.dmarc; }).length,
      siteUsed: formatBytes(siteUsed),
      siteQuota: formatBytes(siteQuota),
      sitePercent: percent(siteUsed, siteQuota),
      databaseUsed: formatBytes(databaseUsed),
      databasePercent: percent(databaseUsed, databaseQuota),
      mailUsed: formatBytes(mailUsed),
      mailPercent: percent(mailUsed, mailQuota),
      tariff: tariff,
      tariffName: currentUser ? (currentUser.tariffName || currentUser.tariff || "") : "",
      lastSync: statusDate && !isNaN(statusDate.getTime()) ? statusDate.toLocaleString(state.language) : "",
      nextSync: nextStatusDate && !isNaN(nextStatusDate.getTime()) ? nextStatusDate.toLocaleString(state.language) : "",
      syncDuration: latestStatus ? `${(Number(latestStatus.statusDurationMs || 0) / 1000).toFixed(1)} s` : ""
    };
  }

  function statusPill(active) {
    return `<span class="status-pill ${active ? "success" : "neutral"}" translate="common.${active ? "active" : "inactive"}"></span>`;
  }

  function boolPill(value, positiveKey, negativeKey) {
    return `<span class="status-pill ${value ? "success" : "warning"}" translate="${value ? positiveKey : negativeKey}"></span>`;
  }

  function userChip(email) {
    const initials = String(email || "U").charAt(0).toUpperCase();
    return `<span class="user-chip"><span>${templates.esc(initials)}</span>${templates.esc(email)}</span>`;
  }

  function actions(type, row) {
    const toggleIcon = row.active ? "bi-pause" : "bi-play";
    const toggleKey = row.active ? "common.disable" : "common.enable";
    return `<div class="actions">
      <button class="btn btn-sm btn-outline-primary" type="button" data-edit="${type}" data-id="${row.id}" translate="common.edit" translate-attr="title aria-label"><i class="bi bi-pencil"></i></button>
      ${type === "domains" ? `<button class="btn btn-sm btn-outline-info" type="button" data-domain-logs="${row.id}" translate="domainLogs.open" translate-attr="title aria-label"><i class="bi bi-file-earmark-text"></i></button>` : ""}
      ${type === "domains" ? `<button class="btn btn-sm btn-outline-success" type="button" data-domain-permissions="${row.id}" data-icon-only title="Выставить права" aria-label="Выставить права"><i class="bi bi-shield-check"></i></button>` : ""}
      ${type === "domains" ? `<button class="btn btn-sm btn-outline-info" type="button" data-domain-panel-tool="filemanager" data-id="${row.id}" translate="forms.openFileManager" translate-attr="title aria-label"><i class="bi bi-folder2-open"></i></button>` : ""}
      ${type === "domains" ? `<button class="btn btn-sm btn-outline-secondary" type="button" data-domain-panel-tool="fileeditor" data-id="${row.id}" translate="forms.openFileEditor" translate-attr="title aria-label"><i class="bi bi-code-slash"></i></button>` : ""}
      ${type === "databases" ? `<button class="btn btn-sm btn-outline-info" type="button" data-database-configuration="${row.id}" translate="forms.databaseConnection" translate-attr="title aria-label"><i class="bi bi-plug"></i></button>` : ""}
      ${type === "databases" ? `<button class="btn btn-sm btn-outline-success" type="button" data-database-phpmyadmin="${row.id}" translate="forms.openPhpMyAdmin" translate-attr="title aria-label"><i class="bi bi-box-arrow-up-right"></i></button>` : ""}
      ${type === "mail" ? `<button class="btn btn-sm btn-outline-info" type="button" data-mail-configuration="${row.id}" translate="forms.mailConnection" translate-attr="title aria-label"><i class="bi bi-plug"></i></button>` : ""}
      <button class="btn btn-sm ${row.active ? "btn-outline-warning" : "btn-outline-success"}" type="button" data-preview-action="toggle" data-id="${row.id}" translate="${toggleKey}" translate-attr="title aria-label"><i class="bi ${toggleIcon}"></i></button>
      <button class="btn btn-sm btn-outline-danger" type="button" data-preview-action="delete" data-id="${row.id}" translate="common.delete" translate-attr="title aria-label"><i class="bi bi-trash3"></i></button>
    </div>`;
  }

  function dnsManagedActions(row) {
    const id = templates.esc(row.id || "");
    return `<div class="actions">
      <button class="btn btn-sm btn-outline-primary" type="button" data-dns-zone-edit="${id}" translate="common.edit" translate-attr="title aria-label"><i class="bi bi-pencil"></i></button>
      <button class="btn btn-sm btn-outline-info" type="button" data-dns-zone-fetch="${id}" translate="dns.fetchFromProvider" translate-attr="title aria-label"><i class="bi bi-cloud-download"></i></button>
      <button class="btn btn-sm btn-outline-danger" type="button" data-dns-zone-clear="${id}" translate="dns.deleteAllRecords" translate-attr="title aria-label"><i class="bi bi-trash3"></i></button>
      <button class="btn btn-sm btn-outline-success" type="button" data-dns-zone-push="${id}" translate="dns.sendToProvider" translate-attr="title aria-label"><i class="bi bi-cloud-upload"></i></button>
      <button class="btn btn-sm btn-outline-secondary" type="button" data-dns-zone-current="${id}" translate="dns.currentRecords" translate-attr="title aria-label"><i class="bi bi-eye"></i></button>
    </div>`;
  }

  function quotaCell(used, quota, extra) {
    const amount = percent(used, quota);
    return `<div class="quota-bar"><div><span>${formatBytes(used)}${extra ? ` · ${templates.esc(extra)}` : ""}</span><span>${amount}%</span></div><div class="progress"><div class="progress-bar" style="width:${Math.min(100, amount)}%"></div></div></div>`;
  }

  function formatLogDate(value) {
    const date = new Date(value || "");
    if (Number.isNaN(date.getTime())) return value || "—";
    try {
      return new Intl.DateTimeFormat(state.language, { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
    } catch (error) {
      return date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
    }
  }

  function createdAtColumn() {
    return {
      data: "createdAt",
      name: "createdAtTimestamp",
      render: function (value, type) {
        return type === "display"
          ? `<time datetime="${templates.esc(value || "")}">${templates.esc(formatLogDate(value))}</time>`
          : value;
      }
    };
  }

  function commentColumn() {
    return {
      data: "comment",
      name: "comment",
      className: "comment-column text-center",
      render: function (value, type) {
        const comment = String(value || "").trim();
        if (type !== "display") return comment;
        return comment
          ? `<span class="text-primary" title="${templates.esc(comment)}" aria-label="${templates.esc(text("common.comment"))}"><i class="bi bi-chat-left-text-fill"></i></span>`
          : "";
      }
    };
  }

  function logStatus(status) {
    const value = ["success", "error", "nofinished"].includes(status) ? status : "nofinished";
    const className = value === "success" ? "success" : (value === "error" ? "danger" : "warning");
    return `<span class="status-pill ${className}">${templates.esc(value)}</span>`;
  }

  function columnsFor(route) {
    let columns;
    if (["logs", "toolLogs"].includes(route)) {
      columns = [
        { data: null, orderable: false, searchable: false, render: function (_, type, row) { return type === "display" ? `<button class="btn btn-sm btn-light btn-icon" type="button" data-log-details="${templates.esc(row.requestId)}" data-log-source="${templates.esc(route)}" title="Подробности" aria-label="Подробности"><i class="bi bi-eye"></i></button>` : ""; } },
        { data: "timestampMs", name: "timestamp", render: function (value, type, row) { return type === "display" ? `<time datetime="${templates.esc(row.timestamp)}">${templates.esc(formatLogDate(row.timestamp))}</time>` : value; } },
        { data: "user", render: function (_, type, row) { return type === "display" ? `<div class="mail-cell"><strong>${templates.esc(row.email || row.prefix || "—")}</strong><small>${templates.esc(row.prefix || "")}</small></div>` : row.user; } },
        { data: "status", render: function (value, type) { return type === "display" ? logStatus(value) : value; } },
        { data: "ip", render: function (value, type) { return type === "display" ? `<code>${templates.esc(value || "—")}</code>` : value; } },
        { data: "operation", render: function (value, type) { return type === "display" ? `<code>${templates.esc(value)}</code>` : value; } },
        { data: "durationMs", render: function (value, type) { return type === "display" ? (value == null ? "—" : `${templates.esc(value)} ms`) : (value == null ? -1 : value); } },
        { data: "errorMessage", render: function (value, type) { return type === "display" ? `<span class="log-error" title="${templates.esc(value || "")}">${templates.esc(value || "—")}</span>` : value; } }
      ];
    } else if (route === "dnsManagement") {
      columns = [
        { data: null, orderable: false, searchable: false, render: function (_, type, row) { return type === "display" ? dnsManagedActions(row) : ""; } },
        { data: "domain", render: function (value, type) { return type === "display" ? `<strong>${templates.esc(value)}</strong>` : value; } },
        { data: "provider", render: function (value, type) { return type === "display" ? `<span class="badge text-bg-light">${templates.esc(String(value || "").toUpperCase())}</span>` : value; } },
        { data: "connectionName" },
        { data: "records", render: function (value, type, row) {
          if (type !== "display") return Number(value || 0);
          const synchronized = !!row.synchronized;
          const key = synchronized ? "dns.synchronized" : "dns.notSynchronized";
          const icon = synchronized ? "bi-cloud-check-fill text-success" : "bi-cloud-slash text-warning";
          const label = templates.esc(text(key));
          let copy = "";
          if (row.lastCopyStatus) {
            const copyOk = row.lastCopyStatus === "success";
            const copyText = copyOk
              ? text("dns.copySuccessFrom").replace("{domain}", row.lastCopySourceDomain || "—")
              : text("dns.copyErrorFrom").replace("{domain}", row.lastCopySourceDomain || "—").replace("{error}", row.lastCopyError || "—");
            const copyLabel = templates.esc(copyText);
            copy = `<i class="bi bi-copy ${copyOk ? "text-success" : "text-danger"}" title="${copyLabel}" aria-label="${copyLabel}"></i>`;
          }
          const bulkError = row.lastBulkChangeStatus === "error" && row.lastBulkChangeError
            ? `<i class="bi bi-exclamation-triangle-fill text-danger" title="${templates.esc(row.lastBulkChangeError)}" aria-label="${templates.esc(row.lastBulkChangeError)}"></i>`
            : "";
          return `<span class="d-inline-flex align-items-center gap-2"><span>${Number(value || 0)}</span><i class="bi ${icon}" title="${label}" aria-label="${label}"></i>${copy}${bulkError}</span>`;
        } },
        { data: "status", render: function (value, type) { return type === "display" ? `<span class="status-pill ${value === "active" ? "success" : "neutral"}">${templates.esc(value || "—")}</span>` : value; } },
        { data: "updatedAtTimestamp", name: "updatedAtTimestamp", render: function (_, type, row) { return type === "display" ? formatLogDate(row.updatedAt) : Number(row.updatedAtTimestamp || 0); } }
      ];
    } else if (route === "users") {
      columns = [
        { data: null, orderable: false, searchable: false, render: function (_, type, row) { return type === "display" ? actions("users", row) : ""; } },
        { data: "email", render: function (_, type, row) { return type === "display" ? `<div class="mail-cell"><strong>${templates.esc(row.email)}</strong><small>${templates.esc(row.name)}</small></div>` : row.email; } },
        commentColumn(),
        { data: "prefix", render: function (value, type) { return type === "display" ? `<code>${templates.esc(value)}_</code>` : value; } },
        { data: "rootPath", render: function (value, type) { return type === "display" ? `<span class="path-text" title="${templates.esc(value)}">${templates.esc(value)}</span>` : value; } },
        { data: "domains" },
        { data: "siteBytes", render: function (_, type, row) { return type === "display" ? quotaCell(row.siteBytes, row.siteQuotaBytes) : row.siteBytes; } },
        { data: "databases", render: function (_, type, row) { return type === "display" ? `<strong>${row.databases}</strong><div class="subtle">${formatBytes(row.databaseBytes)}</div>` : row.databases; } },
        { data: "mailAccounts", render: function (_, type, row) { return type === "display" ? `<strong>${row.mailDomains} / ${row.mailAccounts}</strong><div class="subtle">${formatBytes(row.mailBytes)}</div>` : row.mailAccounts; } },
        { data: "vhosts" },
        { data: "active", render: function (value, type) { return type === "display" ? statusPill(value) : (value ? 1 : 0); } }
      ];
      columns.splice(4, 0, { data: "tariffName", render: function (value, type, row) { return type === "display" ? `<div class="mail-cell"><strong>${templates.esc(value || row.tariff || "—")}</strong>${row.tariffRequest ? `<small class="text-primary">→ ${templates.esc(row.tariffRequest.name || row.tariffRequest.key || "")}</small>` : ""}</div>` : (value || row.tariff || ""); } });
      columns.push(createdAtColumn());
    } else if (route === "domains") {
      columns = [
        { data: null, orderable: false, searchable: false, render: function (_, type, row) { return type === "display" ? actions("domains", row) : ""; } },
        { data: "domain", render: function (_, type, row) { return type === "display" ? `<div class="domain-cell"><strong>${templates.esc(row.domain)}</strong></div>` : row.domain; } },
        commentColumn(),
        { data: "bound", render: function (value, type) { return type === "display" ? boolPill(value, "common.connected", "common.notConnected") : (value ? 1 : 0); } },
        { data: null, name: "sslSort", render: function (_, type, row) { const value = row.sslValid === undefined ? row.ssl : row.sslValid; return type === "display" ? `<i class="bi ${value ? "bi-shield-check text-success" : "bi-shield-x text-danger"} fs-5"></i>` : (value ? 1 : 0); } },
        { data: "redirectHttp", render: function (_, type, row) { return type === "display" ? `<div class="health-checks"><span class="${row.redirectHttp ? "ok" : "bad"}">HTTP</span><span class="${row.redirectWww ? "ok" : "bad"}">WWW</span></div>` : `${row.redirectHttp ? 1 : 0}${row.redirectWww ? 1 : 0}`; } },
        { data: "folderBytes", render: function (value, type, row) { return type === "display" ? (row.folderPrimary === false ? `<strong>0 B</strong><div class="subtle"><i class="bi bi-folder-symlink me-1"></i>${templates.esc(row.primaryDomain)}</div>` : formatBytes(value)) : value; } },
        { data: "database", render: function (_, type, row) { return type === "display" ? (row.database ? `<strong>${templates.esc(row.database)}</strong><div class="subtle">${formatBytes(row.databaseBytes)}</div>` : "—") : (row.database || ""); } },
        { data: "toolAccessCount", render: function (_, type, row) { const tools = row.toolAvailability || {}; return type === "display" ? `<div class="health-checks"><span class="${tools.phpmyadmin ? "ok" : "bad"}" title="phpMyAdmin">DB</span><span class="${tools.filemanager ? "ok" : "bad"}" title="File Manager">FM</span><span class="${tools.fileeditor ? "ok" : "bad"}" title="PHP Editor">ED</span></div><div class="subtle">${Number(row.toolAccessCount || 0)}</div>` : Number(row.toolAccessCount || 0); } },
        { data: "mailAccounts", render: function (_, type, row) { return type === "display" ? (row.mailAccounts ? `<strong>${row.mailAccounts}</strong><div class="subtle">${formatBytes(row.mailBytes)}</div>` : "—") : row.mailAccounts; } },
        { data: "dkim", render: function (_, type, row) { return type === "display" ? `<div class="health-checks"><span class="${row.dkim ? "ok" : "bad"}">DKIM</span><span class="${row.spf ? "ok" : "bad"}">SPF</span><span class="${row.dmarc ? "ok" : "bad"}">DMARC</span></div>` : `${row.dkim ? 1 : 0}${row.spf ? 1 : 0}${row.dmarc ? 1 : 0}`; } },
        { data: "active", render: function (value, type) { return type === "display" ? statusPill(value) : (value ? 1 : 0); } }
      ];
      columns.push(createdAtColumn());
    } else if (route === "databases") {
      columns = [
        { data: null, orderable: false, searchable: false, render: function (_, type, row) { return type === "display" ? actions("databases", row) : ""; } },
        { data: "name", render: function (value, type) { return type === "display" ? `<strong>${templates.esc(value)}</strong>` : value; } },
        commentColumn(),
        { data: "bytes", render: function (value, type) { return type === "display" ? formatBytes(value) : value; } },
        { data: "tables" },
        { data: "domain", render: function (value, type) { return type === "display" ? (value ? `<i class="bi bi-link-45deg text-primary me-1"></i>${templates.esc(value)}` : "—") : (value || ""); } },
        { data: "active", render: function (value, type) { return type === "display" ? statusPill(value) : (value ? 1 : 0); } }
      ];
      columns.push(createdAtColumn());
    } else {
      columns = [
        { data: null, orderable: false, searchable: false, render: function (_, type, row) { return type === "display" ? actions("mail", row) : ""; } },
        { data: "domain" },
        { data: "address", render: function (value, type) { return type === "display" ? `<div class="mail-cell"><strong>${templates.esc(value)}</strong><small>IMAP / SMTP</small></div>` : value; } },
        commentColumn(),
        { data: "catchAll", render: function (value, type) { return type === "display" ? (value ? `<span class="mail-catchall-indicator active" title="${templates.esc(text("columns.catchAllEnabled"))}" aria-label="${templates.esc(text("columns.catchAllEnabled"))}"><i class="bi bi-envelope-at"></i></span>` : `<span class="mail-catchall-indicator inactive" title="${templates.esc(text("columns.catchAllDisabled"))}" aria-label="${templates.esc(text("columns.catchAllDisabled"))}">—</span>`) : (value ? 1 : 0); } },
        { data: "forwardSearch", render: function (value, type, row) { const recipients = Array.isArray(row.forwardTo) ? row.forwardTo : []; return type === "display" ? (recipients.length ? `<div class="mail-forward-list">${recipients.map(function (address) { return `<span><i class="bi bi-arrow-right-short"></i>${templates.esc(address)}</span>`; }).join("")}</div>` : "—") : value; } },
        { data: "bytes", render: function (_, type, row) { return type === "display" ? quotaCell(row.bytes, row.quotaBytes) : row.bytes; } },
        { data: "active", render: function (value, type) { return type === "display" ? statusPill(value) : (value ? 1 : 0); } }
      ];
      columns.push(createdAtColumn());
    }
    if (config.role === "root" && route !== "users" && !["logs", "toolLogs"].includes(route)) {
      columns.splice(1, 0, { data: "user", render: function (value, type) { return type === "display" ? userChip(value) : value; } });
    }
    return columns;
  }

  function tableLanguage() {
    return {
      search: text("tables.globalSearch") + ":",
      searchPlaceholder: text("tables.globalSearch"),
      lengthMenu: "_MENU_ " + text("tables.entries"),
      info: text("tables.showing"),
      infoEmpty: text("tables.showingEmpty"),
      infoFiltered: text("tables.filtered"),
      emptyTable: text("tables.empty"),
      zeroRecords: text("tables.zero"),
      processing: `<div class="spinner-border spinner-border-sm text-primary me-2"></div>${text("tables.processing")}`,
      paginate: { previous: text("tables.previous"), next: text("tables.next") }
    };
  }

  const tablePageLengths = [5, 10, 25, 50, 100, 200, 300];

  function tablePreferencesKey(route) {
    const account = config.role === "root" ? "root" : `user-${Number(config.userId) || String(config.prefix || "unknown")}`;
    return `imagopanel.table.${account}.${route}`;
  }

  function loadTablePreferences(route, columns, defaultOrder) {
    const columnCount = columns.length;
    const defaults = { length: 10, search: "", columns: Array(columnCount).fill(""), order: defaultOrder };
    try {
      const saved = JSON.parse(localStorage.getItem(tablePreferencesKey(route)) || "null");
      if (!saved || typeof saved !== "object") return defaults;
      if (!Array.isArray(saved.columns) || saved.columns.length !== columnCount) return defaults;
      const length = Number(saved.length);
      const savedOrder = Array.isArray(saved.order) ? saved.order.reduce(function (result, item) {
        const columnIndex = Array.isArray(item) ? Number(item[0]) : -1;
        const direction = Array.isArray(item) ? String(item[1] || "").toLowerCase() : "";
        if (Number.isInteger(columnIndex) && columnIndex >= 0 && columnIndex < columnCount
          && columns[columnIndex].orderable !== false && ["asc", "desc"].includes(direction)) {
          result.push([columnIndex, direction]);
        }
        return result;
      }, []) : [];
      return {
        length: tablePageLengths.includes(length) ? length : defaults.length,
        search: typeof saved.search === "string" ? saved.search : "",
        columns: Array.from({ length: columnCount }, function (_, index) {
          return Array.isArray(saved.columns) && typeof saved.columns[index] === "string" ? saved.columns[index] : "";
        }),
        order: savedOrder.length ? savedOrder : defaults.order
      };
    } catch (error) {
      return defaults;
    }
  }

  function saveTablePreferences(route, api, columnCount) {
    try {
      localStorage.setItem(tablePreferencesKey(route), JSON.stringify({
        length: api.page.len(),
        search: api.search(),
        columns: Array.from({ length: columnCount }, function (_, index) { return api.column(index).search(); }),
        order: api.order().map(function (item) { return [Number(item[0]), String(item[1])]; })
      }));
    } catch (error) {
      // An unavailable localStorage must not prevent the table from working.
    }
  }

  function initTable(route) {
    const columns = columnsFor(route);
    const $table = $(`#${route}-table`);
    const defaultOrder = [[1, ["logs", "toolLogs"].includes(route) ? "desc" : "asc"]];
    const preferences = loadTablePreferences(route, columns, defaultOrder);
    state.table = $table.DataTable({
      serverSide: true,
      processing: true,
      ajax: function (request, callback) {
        request.action = "list";
        request.type = route;
        $.ajax({
          url: "api/index.php",
          method: "POST",
          dataType: "json",
          data: request
        }).done(callback).fail(function (xhr) {
          const response = xhr.responseJSON || {};
          showError(response.error || "API request failed");
          callback({ draw: request.draw, recordsTotal: 0, recordsFiltered: 0, data: [] });
        });
      },
      columns: columns,
      order: preferences.order,
      titleRow: 0,
      pageLength: preferences.length,
      lengthMenu: tablePageLengths,
      search: { search: preferences.search },
      searchCols: preferences.columns.map(function (value) { return { search: value }; }),
      autoWidth: true,
      scrollX: true,
      language: tableLanguage(),
      createdRow: function (row) { $(row).attr("data-row-highlight", "true"); },
      initComplete: function () {
        const api = this.api();
        const $container = $(api.table().container());
        $container.find("thead tr.filter-row").each(function () {
          $(this).children("th").each(function (index) {
            $(this).find("input").val(api.column(index).search());
          });
        });
        $container.off(".imagoColumnFilters")
          .on("click.imagoColumnFilters mousedown.imagoColumnFilters", "thead tr.filter-row input", function (event) {
            event.stopPropagation();
          })
          .on("input.imagoColumnFilters change.imagoColumnFilters", "thead tr.filter-row input", function () {
            const $input = $(this);
            const index = $input.closest("th").index();
            const value = String(this.value || "");
            $container.find("thead tr.filter-row").each(function () {
              $(this).children("th").eq(index).find("input").not($input).val(value);
            });
            if (api.column(index).search() !== value) api.column(index).search(value).draw();
          });
        api.on("search.dt length.dt order.dt", function () { saveTablePreferences(route, api, columns.length); });
        saveTablePreferences(route, api, columns.length);
        translatePage($table.closest(".table-panel"));
      },
      drawCallback: function () { translatePage($table); }
    });
  }

  function routeFromHash() {
    const candidate = window.location.hash.replace(/^#/, "").split("?")[0] || "overview";
    const allowed = ["overview", "domains", "databases", "mail"];
    if (config.dnsManagementEnabled) allowed.push("dnsManagement");
    if (config.role === "root") allowed.push("users", "logs", "toolLogs", "diagnostics", "migration");
    return allowed.includes(candidate) ? candidate : "overview";
  }

  function migrationSectionFromHash() {
    const query = String(window.location.hash || "").split("?")[1] || "";
    const section = new URLSearchParams(query).get("section") || "dates";
    return ["dates", "apache", "permissions"].includes(section) ? section : "dates";
  }

  function setSidebarGroupOpen(name, open, persist) {
    const groupName = String(name || "");
    if (!groupName) return;
    if (persist) {
      try { window.localStorage.setItem(`imago_sidebar_group_${groupName}`, open ? "1" : "0"); } catch (error) { /* localStorage may be unavailable */ }
    }
    $(`[data-sidebar-group="${groupName}"]`).each(function () {
      const $group = $(this).toggleClass("is-open", !!open);
      $group.find(`[data-sidebar-group-toggle="${groupName}"]`).first().attr("aria-expanded", open ? "true" : "false");
      $group.find(`[data-sidebar-group-content="${groupName}"]`).first().toggleClass("d-none", !open);
    });
  }

  function renderRoute(route) {
    state.route = route;
    if (state.table) { state.table.destroy(); state.table = null; }
    const $main = $("#main-content");
    if (route === "overview") $main.html(templates.overview(summary(), config.role === "root", config.systemWarnings || []));
    else if (route === "migration") $main.html(templates.migrationPage());
    else if (route === "diagnostics") $main.html(templates.serverDiagnosticsPage());
    else $main.html(templates.tablePage(route, config.role === "root"));
    const migrationSection = route === "migration" ? migrationSectionFromHash() : "";
    $(".sidebar-nav .nav-link").removeClass("active");
    if (route === "migration") {
      $(`.sidebar-nav .nav-link[data-route="migration"][data-migration-section="${migrationSection}"]`).addClass("active");
    } else {
      $(`.sidebar-nav .nav-link[data-route="${route}"]`).addClass("active");
    }
    if (route === "logs") $("#topbar-title").removeAttr("translate").text("Журнал действий клиентов");
    else if (route === "toolLogs") $("#topbar-title").removeAttr("translate").text("Доступы к инструментам доменов");
    else if (route === "diagnostics") $("#topbar-title").attr("translate", "diagnostics.title").text(text("diagnostics.title"));
    else if (route === "migration") $("#topbar-title").removeAttr("translate").text("Миграции");
    else $("#topbar-title").attr("translate", route === "dnsManagement" ? "dns.domainTitle" : `page.${route}Title`);
    translatePage(document);
    if (!["overview", "migration", "diagnostics"].includes(route)) initTable(route);
    if (route === "migration") {
      window.setTimeout(function () {
        const card = document.querySelector(`[data-migration-card="${migrationSection}"]`);
        if (card) card.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 0);
    } else if (route === "diagnostics") {
      loadServerDiagnostics();
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  function serverDiagnosticsMarkup(payload) {
    const data = payload && typeof payload === "object" ? payload : {};
    const summary = data.summary && typeof data.summary === "object" ? data.summary : {};
    const checks = Array.isArray(data.checks) ? data.checks : [];
    const groups = {};
    checks.forEach(function (check) {
      const category = String(check.category || "Other");
      if (!groups[category]) groups[category] = [];
      groups[category].push(check);
    });
    const statusMeta = {
      ok: { icon: "bi-check-circle-fill", badge: "text-bg-success", label: text("diagnostics.status.ok"), border: "border-success-subtle" },
      warning: { icon: "bi-exclamation-triangle-fill", badge: "text-bg-warning", label: text("diagnostics.status.warning"), border: "border-warning-subtle" },
      error: { icon: "bi-x-circle-fill", badge: "text-bg-danger", label: text("diagnostics.status.error"), border: "border-danger-subtle" }
    };
    function categoryLabel(category) {
      const categoryKeys = {
        "Configuration": "configuration", "PHP": "php", "Executables": "executables", "Services": "services",
        "Databases": "databases", "Apache / PHP-FPM": "apachePhp", "Paths and permissions": "paths",
        "OpenDKIM": "openDkim", "DNS providers": "dnsProviders", "Other": "other"
      };
      return text("diagnostics.categories." + (categoryKeys[category] || "other"));
    }
    function checkLabel(check) {
      const id = String(check.id || "");
      if (/^[a-z0-9_]+_directory$/.test(id)) return id.toUpperCase();
      if (id.indexOf("extension_") === 0) return "PHP: " + id.slice(10).replace(/_/g, "-");
      if (id === "required_constants" || id === "private_values") return "config.php";
      if (id === "config_permissions") return "config.php";
      if (id === "root_script_permissions") return "root.php";
      if (id === "runtime_version") return "PHP CLI 7.4";
      if (id === "service_names") return "SERVER_DIAGNOSTICS_SERVICE_NAMES";
      if (id === "systemctl_services") return "systemctl";
      if (id === "mysql_admin") return "MySQL / MariaDB";
      if (id === "postfix_database") return "PostfixAdmin";
      if (id === "php_versions") return "APACHE_PHP_VERSIONS";
      if (id === "php_default") return "APACHE_DEFAULT_PHP_VERSION";
      if (id === "apache_syntax") return "httpd -t";
      if (id === "ssl_options") return "APACHE_SSL_OPTIONS_FILE";
      if (id === "opendkim_mode") return "OPENDKIM_MANAGEMENT_MODE";
      if (id.indexOf("opendkim_") === 0) return id.toUpperCase();
      if (id.indexOf("service_") === 0 && check.details && check.details.service) return String(check.details.service);
      return String(check.label || id || "—").replace(/ \(default\)$/i, "");
    }
    function detailValue(value) {
      const normalized = String(value || "").trim().toLowerCase();
      const valueKeys = {
        "yes": "yes", "no": "no", "configured": "configured", "not configured": "notConfigured",
        "(not configured)": "notConfigured", "(missing)": "missing", "missing": "missing",
        "(fallback only)": "fallbackOnly", "(not detected)": "notDetected",
        "(server connection)": "serverConnection", "unknown": "unknown"
      };
      return valueKeys[normalized] ? text("diagnostics.detailValues." + valueKeys[normalized]) : String(value || "");
    }
    const cards = Object.keys(groups).map(function (category) {
      const rows = groups[category].map(function (check) {
        const status = statusMeta[check.status] ? check.status : "warning";
        const meta = statusMeta[status];
        const details = check.details && typeof check.details === "object" ? Object.keys(check.details).map(function (key) {
          const value = String(check.details[key] || "");
          return value ? `<div class="small text-secondary mt-1"><span>${escapeHtml(text("diagnostics.details." + key))}</span>: <span class="font-monospace text-break">${escapeHtml(detailValue(value))}</span></div>` : "";
        }).join("") : "";
        const resultText = text("diagnostics.result." + status);
        const actionCode = String(check.actionCode || "review");
        const action = status === "ok" ? "" : `<div class="alert ${status === "error" ? "alert-danger" : "alert-warning"} py-2 px-3 mt-2 mb-0"><strong>${escapeHtml(text("diagnostics.requiredAction"))}:</strong> ${escapeHtml(text("diagnostics.actions." + actionCode))}</div>`;
        return `<div class="border ${meta.border} rounded-3 p-3"><div class="d-flex align-items-start gap-3"><i class="bi ${meta.icon} fs-5 ${status === "ok" ? "text-success" : (status === "error" ? "text-danger" : "text-warning")}"></i><div class="flex-grow-1 min-w-0"><div class="d-flex flex-wrap justify-content-between gap-2"><strong>${escapeHtml(checkLabel(check))}</strong><span class="badge ${meta.badge}">${meta.label}</span></div><div class="small mt-1">${escapeHtml(resultText)}</div>${details}${action}</div></div></div>`;
      }).join("");
      return `<section class="panel-card"><div class="panel-header"><h3>${escapeHtml(categoryLabel(category))}</h3><span class="text-secondary small">${groups[category].length}</span></div><div class="panel-body"><div class="d-grid gap-2">${rows}</div></div></section>`;
    }).join("");
    const checkedAt = data.checkedAt ? new Date(data.checkedAt).toLocaleString(state.language) : "—";
    return `<section class="panel-card mb-3"><div class="panel-body"><div class="row g-3 align-items-center"><div class="col-md"><div class="small text-secondary">${escapeHtml(text("diagnostics.environment"))}</div><strong>${escapeHtml(data.environment || "—")}</strong><div class="small text-secondary mt-1">${escapeHtml(text("diagnostics.checked"))}: ${escapeHtml(checkedAt)}</div></div><div class="col-auto"><div class="d-flex flex-wrap gap-2"><span class="badge text-bg-success fs-6">${escapeHtml(text("diagnostics.status.ok"))}: ${Number(summary.ok || 0)}</span><span class="badge text-bg-warning fs-6">${escapeHtml(text("diagnostics.status.warning"))}: ${Number(summary.warning || 0)}</span><span class="badge text-bg-danger fs-6">${escapeHtml(text("diagnostics.status.error"))}: ${Number(summary.error || 0)}</span></div></div></div></div></section>${cards || `<div class="alert alert-warning">${escapeHtml(text("diagnostics.noResults"))}</div>`}`;
  }

  function loadServerDiagnostics() {
    const $result = $("[data-server-diagnostics-result]");
    const $button = $("[data-server-diagnostics-refresh]");
    if (!$result.length) return;
    $button.prop("disabled", true).html(`<span class="spinner-border spinner-border-sm me-2"></span>${escapeHtml(text("common.checking"))}`);
    $result.html(`<div class="panel-card"><div class="panel-body py-5 text-center"><span class="spinner-border text-primary" role="status"></span><div class="mt-3 text-secondary">${escapeHtml(text("diagnostics.running"))}</div></div></div>`);
    apiRequest({ action: "serverDiagnostics" }, "GET").done(function (response) {
      if (!response || !response.ok) {
        $result.html(`<div class="alert alert-danger">${escapeHtml(response && response.error || text("toast.error"))}</div>`);
        return;
      }
      $result.html(serverDiagnosticsMarkup(response.data || {}));
    }).fail(function (xhr) {
      $result.html(`<div class="alert alert-danger">${escapeHtml((xhr.responseJSON || {}).error || text("toast.error"))}</div>`);
    }).always(function () {
      $button.prop("disabled", false).html(`<i class="bi bi-arrow-repeat me-2"></i>${escapeHtml(text("diagnostics.refresh"))}`);
    });
  }

  function showNotification(message, isError) {
    const $container = $("#app-toast-container");
    if (!$container.length) return;
    const $toast = $(`<div class="toast" role="${isError ? "alert" : "status"}" aria-atomic="true">
      <div class="toast-body d-flex align-items-center gap-2">
        <i class="bi ${isError ? "bi-exclamation-circle text-danger" : "bi-info-circle text-primary"}"></i>
        <span class="toast-message flex-grow-1"></span>
        <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>`);
    $toast.find(".toast-message").text(message);
    $container.append($toast);
    const toast = bootstrap.Toast.getOrCreateInstance($toast[0], { autohide: false });
    $toast[0].addEventListener("hidden.bs.toast", function () {
      toast.dispose();
      $toast.remove();
    }, { once: true });
    toast.show();
  }

  function showToast(key) {
    showNotification(text(key), false);
  }

  function showError(message) {
    showNotification(message || text("toast.error"), true);
  }

  function apacheRefreshReportMarkup(report) {
    const data = report && typeof report === "object" ? report : {};
    const issues = Array.isArray(data.issues) ? data.issues : [];
    if (data.ok) {
      return `<div class="alert alert-success"><div class="d-flex gap-3 align-items-start"><i class="bi bi-check-circle-fill fs-4"></i><div><strong>Конфигурация Apache обновлена</strong><div class="mt-1">Проверка <code>httpd -t</code> выполнена успешно${data.reloaded ? ", Apache перезагружен" : ""}.</div></div></div></div>
        <div class="row g-3"><div class="col-sm-6"><div class="border rounded-3 p-3"><span class="text-secondary">Пользователей</span><strong class="d-block fs-4">${Number(data.users || 0)}</strong></div></div><div class="col-sm-6"><div class="border rounded-3 p-3"><span class="text-secondary">Активных доменов</span><strong class="d-block fs-4">${Number(data.domains || 0)}</strong></div></div></div>`;
    }
    const rollbackText = data.rollbackOk === false ? " Автоматический откат также завершился ошибкой — проверьте файлы Apache вручную." : " Старые файлы восстановлены.";
    const phaseText = data.phase === "current"
      ? "Текущая конфигурация Apache содержит ошибки. Новые файлы не применялись."
      : (data.phase === "generation" ? "Не удалось сгенерировать конфигурацию домена. Файлы Apache не изменялись." : (data.phase === "reload" ? `Проверка прошла, но Apache не удалось перезагрузить.${rollbackText}` : `Новые конфигурации не прошли проверку.${rollbackText}`));
    const rows = issues.map(function (issue) {
      const domain = String(issue.domain || "");
      const prefix = String(issue.prefix || "");
      const title = domain || (prefix ? `Пользователь ${prefix}` : "Общая ошибка Apache");
      const location = issue.file ? `${String(issue.file)}${Number(issue.line || 0) > 0 ? `:${Number(issue.line)}` : ""}` : "";
      const disable = domain && Number(issue.domainId || 0) > 0
        ? `<button class="btn btn-sm btn-outline-danger flex-shrink-0" type="button" data-apache-disable-domain="${Number(issue.domainId)}" data-domain="${escapeHtml(domain)}"><i class="bi bi-power me-1"></i>Отключить</button>`
        : "";
      return `<div class="border border-danger-subtle rounded-3 p-3 mb-3"><div class="d-flex justify-content-between align-items-start gap-3"><div><strong>${escapeHtml(title)}</strong>${prefix && domain ? `<div class="small text-secondary">Пользователь: ${escapeHtml(prefix)}</div>` : ""}</div>${disable}</div>${location ? `<div class="small font-monospace text-secondary mt-2">${escapeHtml(location)}</div>` : ""}<pre class="small bg-light border rounded p-2 mt-2 mb-0 text-wrap">${escapeHtml(issue.reason || data.output || "Apache configuration test failed")}</pre></div>`;
    }).join("");
    return `<div class="alert alert-danger"><strong><code>httpd -t</code> завершился с ошибкой</strong><div class="mt-1">${escapeHtml(phaseText)}</div></div>${rows || `<pre class="bg-light border rounded p-3">${escapeHtml(data.output || "Apache configuration test failed")}</pre>`}`;
  }

  function renderApacheRefreshReport(report) {
    $("[data-apache-refresh-report]").html(apacheRefreshReportMarkup(report));
  }

  function openApacheRefreshModal() {
    if ($("#apache-refresh-modal").length) return;
    $("#modal-root").html(templates.apacheRefreshModal());
    const element = document.getElementById("apache-refresh-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("hidden.bs.modal", function () {
      $("#modal-root").empty();
      state.modal = null;
    }, { once: true });
  }

  function runApacheVhostRefresh($button) {
    openApacheRefreshModal();
    const original = $button && $button.length ? $button.html() : "";
    if ($button && $button.length) $button.prop("disabled", true).html('<span class="spinner-border spinner-border-sm me-2"></span>Проверка...');
    $("[data-apache-refresh-report]").html('<div class="text-center py-5"><span class="spinner-border text-primary"></span><div class="mt-3">Проверка и обновление конфигурации Apache...</div></div>');
    $("[data-apache-refresh-rerun]").prop("disabled", true);
    apiRequest({ action: "apacheVhostsRefreshAll" }).done(function (response) {
      if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
      renderApacheRefreshReport(response.data || {});
      if (response.data && response.data.ok) showNotification("Конфигурация Apache обновлена.", false);
    }).fail(function (xhr) {
      const message = (xhr.responseJSON || {}).error || text("toast.error");
      $("[data-apache-refresh-report]").html(`<div class="alert alert-danger mb-0">${escapeHtml(message)}</div>`);
      showError(message);
    }).always(function () {
      $("[data-apache-refresh-rerun]").prop("disabled", false);
      if ($button && $button.length) $button.prop("disabled", false).html(original);
    });
  }

  function dnsBulkProgressUpdate(processed, total, currentDomain, errors, finished) {
    const $progress = $("[data-dns-records-progress]");
    if (!$progress.length) return;
    const remaining = Math.max(0, total - processed);
    const percent = total > 0 ? Math.round(processed / total * 100) : (finished ? 100 : 0);
    $progress.removeClass("d-none");
    $progress.find("[data-dns-progress-processed]").text(processed);
    $progress.find("[data-dns-progress-processed-copy]").text(processed);
    $progress.find("[data-dns-progress-total]").text(total);
    $progress.find("[data-dns-progress-remaining]").text(remaining);
    $progress.find("[data-dns-progress-errors]").text(errors.length);
    $progress.find("[data-dns-progress-current]").text(currentDomain || "—");
    $progress.find("[data-dns-progress-bar]").css("width", `${percent}%`).closest(".progress").attr("aria-valuenow", percent);
    const $errorList = $progress.find("[data-dns-progress-error-list]");
    if (errors.length) {
      $errorList.removeClass("d-none").text(errors.map(function (item) { return `${item.domain}: ${item.error}`; }).join("\n"));
    } else {
      $errorList.addClass("d-none").empty();
    }
    if (!finished) return;
    const $icon = $progress.find("[data-dns-progress-icon]");
    $icon.attr("class", `bi ${errors.length ? "bi-exclamation-triangle-fill text-warning" : "bi-check-circle-fill text-success"}`);
    $progress.find("[data-dns-progress-bar]").removeClass("progress-bar-striped progress-bar-animated").toggleClass("bg-warning", errors.length > 0);
  }

  function refreshAllDnsRecords($button) {
    if (state.dnsRecordsRefreshRunning) return;
    state.dnsRecordsRefreshRunning = true;
    const $buttons = $("[data-refresh-dns-zones], [data-refresh-all-dns-records]").prop("disabled", true);
    $button.prepend('<span class="spinner-border spinner-border-sm me-2" data-dns-bulk-button-spinner></span>');
    dnsBulkProgressUpdate(0, 0, "—", [], false);

    const finish = function (processed, total, errors, notificationKey) {
      state.dnsRecordsRefreshRunning = false;
      $buttons.prop("disabled", false);
      $button.find("[data-dns-bulk-button-spinner]").remove();
      dnsBulkProgressUpdate(processed, total, "—", errors, true);
      if (state.route === "dnsManagement" && state.table && state.table.ajax) state.table.ajax.reload(null, false);
      showNotification(text(notificationKey || (errors.length ? "dns.allRecordsFetchedWithErrors" : "dns.allRecordsFetched")), errors.length > 0);
    };

    apiRequest({ action: "dnsManagedZonesQueue" }, "GET").done(function (response) {
      if (!response || !response.ok) {
        const error = response && response.error || text("toast.error");
        finish(0, 0, [{ domain: text("dns.domainTitle"), error: error }]);
        return;
      }
      const zones = response.data && Array.isArray(response.data.zones) ? response.data.zones : [];
      if (!zones.length) {
        finish(0, 0, [], "dns.noManagedZones");
        return;
      }
      let processed = 0;
      const errors = [];
      const next = function () {
        if (processed >= zones.length) {
          finish(processed, zones.length, errors);
          return;
        }
        const zone = zones[processed] || {};
        const domain = String(zone.domain || "—");
        dnsBulkProgressUpdate(processed, zones.length, domain, errors, false);
        apiRequest({ action: "dnsManagedZoneFetch", id: String(zone.id || "") }).done(function (zoneResponse) {
          if (!zoneResponse || !zoneResponse.ok) {
            errors.push({ domain: domain, error: zoneResponse && zoneResponse.error || text("toast.error") });
          }
        }).fail(function (xhr) {
          errors.push({ domain: domain, error: (xhr.responseJSON || {}).error || text("toast.error") });
        }).always(function () {
          processed += 1;
          dnsBulkProgressUpdate(processed, zones.length, processed < zones.length ? String((zones[processed] || {}).domain || "—") : "—", errors, false);
          next();
        });
      };
      next();
    }).fail(function (xhr) {
      finish(0, 0, [{ domain: text("dns.domainTitle"), error: (xhr.responseJSON || {}).error || text("toast.error") }]);
    });
  }

  function domainLogDownloadUrl(domainId, file) {
    return `api/index.php?${$.param({ action: "domainLogDownload", id: domainId, file: file })}`;
  }

  function loadDomainLog() {
    if (!state.domainLog) return;
    const current = state.domainLog;
    const $modal = $("#domain-logs-modal");
    $modal.find("[data-domain-log-loading]").removeClass("d-none");
    $modal.find("[data-domain-log-viewer], [data-domain-log-empty]").addClass("d-none");
    $modal.find("[data-domain-log-newer], [data-domain-log-older]").prop("disabled", true);
    $modal.find("[data-domain-log-download]").addClass("disabled").attr("aria-disabled", "true").removeAttr("href");
    $modal.find("[data-domain-log-file]").each(function () {
      const active = String($(this).data("domain-log-file")) === current.file;
      $(this).toggleClass("active btn-primary", active).toggleClass("btn-outline-primary", !active);
    });

    apiRequest({ action: "domainLog", id: current.domainId, file: current.file, page: current.page }, "GET").done(function (response) {
      if (!response || !response.ok || !response.data) { showError(response && response.error || text("toast.error")); return; }
      const data = response.data;
      current.page = Number(data.page) || 1;
      const hasLines = Number(data.lines) > 0;
      $modal.find("[data-domain-log-viewer]").text(data.content || "").toggleClass("d-none", !hasLines);
      $modal.find("[data-domain-log-empty] span").text(text("domainLogs.empty"));
      $modal.find("[data-domain-log-empty]").toggleClass("d-none", hasLines);
      $modal.find("[data-domain-log-page]").text(`${text("domainLogs.page")} ${current.page} · ${Number(data.lines) || 0}/${Number(data.linesPerPage) || Number(config.domainLogLinesPerPage) || 100}`);
      $modal.find("[data-domain-log-newer]").prop("disabled", !data.hasNewer);
      $modal.find("[data-domain-log-older]").prop("disabled", !data.hasOlder);
      if (data.exists) {
        $modal.find("[data-domain-log-download]")
          .removeClass("disabled")
          .attr("aria-disabled", "false")
          .attr("href", domainLogDownloadUrl(current.domainId, current.file))
          .attr("download", `${data.domain}-${current.file}`);
      }
    }).fail(function (xhr) {
      const message = (xhr.responseJSON || {}).error || text("toast.error");
      $modal.find("[data-domain-log-empty] span").text(message);
      $modal.find("[data-domain-log-empty]").removeClass("d-none");
    }).always(function () {
      $modal.find("[data-domain-log-loading]").addClass("d-none");
    });
  }

  function openDomainLogs(domainId) {
    const domain = recordFor("domains", domainId);
    if (!domain) { showError(text("toast.error")); return; }
    const files = Array.isArray(config.domainLogFiles) && config.domainLogFiles.length
      ? config.domainLogFiles
      : ["combine.log", "error.log", "php_error.log"];
    state.domainLog = { domainId: Number(domainId), file: String(files[0]), page: 1 };
    $("#modal-root").html(templates.domainLogsModal(domain.domain, files));
    translatePage("#modal-root");
    const element = document.getElementById("domain-logs-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    loadDomainLog();
    element.addEventListener("hidden.bs.modal", function () {
      $("#modal-root").empty();
      state.modal = null;
      state.domainLog = null;
    }, { once: true });
  }

  function reloadCurrentRoute(successKey, messages) {
    refreshData().done(function () {
      renderRoute(state.route);
      if (successKey) showToast(successKey);
      (Array.isArray(messages) ? messages : []).forEach(function (message) {
        if (message) showNotification(String(message), false);
      });
    }).fail(function (xhr) {
      showError((xhr.responseJSON || {}).error || text("toast.error"));
    });
  }

  function showDnsManagedZoneModal(data, readOnly) {
    $("#modal-root").html(templates.dnsManagedZoneModal(data || {}, !!readOnly));
    translatePage("#modal-root");
    const element = document.getElementById("dns-managed-zone-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("hidden.bs.modal", function () {
      $("#modal-root").empty();
      state.modal = null;
    }, { once: true });
  }

  function dnsBulkSelectedTargets() {
    return $("#dns-bulk-change-modal [data-dns-bulk-target]:checked").map(function () {
      return { id: String($(this).val() || ""), domain: String($(this).data("domain") || "") };
    }).get().filter(function (target) { return target.id !== "" && target.domain !== ""; });
  }

  function updateDnsBulkSelection() {
    const targets = dnsBulkSelectedTargets();
    $("#dns-bulk-change-modal [data-dns-bulk-selected]").text(targets.length);
    const suffix = targets.length === 1 ? `.${targets[0].domain}` : ".domain";
    $("#dns-bulk-change-modal [data-dns-bulk-name-suffix]").text(suffix);
  }

  function filterDnsBulkZones(clearSelection) {
    const $modal = $("#dns-bulk-change-modal");
    const userId = String($modal.find("[data-dns-bulk-user]").val() || "");
    const provider = String($modal.find("[data-dns-bulk-provider]").val() || "");
    const serverOnly = $modal.find("[data-dns-bulk-server-only]").is(":checked");
    const query = String($modal.find("[data-dns-bulk-search]").val() || "").trim().toLowerCase();
    $modal.find("[data-dns-bulk-zone]").each(function () {
      const $row = $(this);
      const matches = (userId === "" || String($row.data("user-id") || "") === userId)
        && (provider === "" || String($row.data("provider") || "") === provider)
        && (!serverOnly || $row.attr("data-on-server") === "1")
        && (query === "" || String($row.data("search") || "").indexOf(query) !== -1);
      $row.toggleClass("d-none", !matches);
      if (clearSelection && !matches) $row.find("[data-dns-bulk-target]").prop("checked", false);
    });
    updateDnsBulkSelection();
  }

  function showDnsBulkChangeModal(data) {
    $("#modal-root").html(templates.dnsBulkChangeModal(data || {}, config.role === "root", config.dnsDefaultTtl || 3600));
    translatePage("#modal-root");
    const element = document.getElementById("dns-bulk-change-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("hidden.bs.modal", function () {
      $("#modal-root").empty();
      state.modal = null;
    }, { once: true });
  }

  function updateDnsBulkProgress(processed, total, currentDomain, successful, failures, finished) {
    const $progress = $("#dns-bulk-change-modal [data-dns-bulk-change-progress]").removeClass("d-none");
    const percentDone = total > 0 ? Math.round((processed / total) * 100) : 0;
    $progress.find("[data-dns-bulk-processed]").text(processed);
    $progress.find("[data-dns-bulk-total]").text(total);
    $progress.find("[data-dns-bulk-current]").text(currentDomain || "—");
    $progress.find("[data-dns-bulk-success]").text(successful);
    $progress.find("[data-dns-bulk-failed]").text(failures.length);
    $progress.find("[data-dns-bulk-bar]").css("width", `${percentDone}%`).toggleClass("progress-bar-animated", !finished);
    $progress.find("[data-dns-bulk-change-spinner]").toggleClass("d-none", !!finished);
  }

  function appendDnsBulkResult(domain, ok, message) {
    const $results = $("#dns-bulk-change-modal [data-dns-bulk-results]").removeClass("d-none");
    const icon = ok ? "bi-check-circle-fill text-success" : "bi-exclamation-triangle-fill text-danger";
    $results.append(`<div class="d-flex align-items-start gap-2"><i class="bi ${icon}"></i><div><strong>${escapeHtml(domain)}</strong>${message ? `<div class="small">${escapeHtml(message)}</div>` : ""}</div></div>`);
  }

  function runDnsBulkChange($form) {
    const targets = dnsBulkSelectedTargets();
    if (!targets.length) { showError(text("dns.chooseDomains")); return; }
    const values = String($form.find('[name="values"]').val() || "").split(/\r?\n/).map(function (value) { return value.trim(); }).filter(Boolean);
    if (!values.length) { showError(text("dns.recordValueRequired")); return; }
    if (!window.confirm(text("dns.bulkConfirm").replace("{count}", String(targets.length)))) return;

    const record = {
      type: String($form.find('[name="type"]').val() || "A"),
      name: String($form.find('[name="name"]').val() || "").trim(),
      ttl: Number($form.find('[name="ttl"]').val() || config.dnsDefaultTtl || 3600),
      values: values
    };
    const $controls = $form.find("input, select, textarea, button").not('[data-bs-dismiss="modal"]').prop("disabled", true);
    const $results = $form.find("[data-dns-bulk-results]").empty().addClass("d-none");
    let processed = 0;
    let successful = 0;
    const failures = [];
    updateDnsBulkProgress(0, targets.length, targets[0].domain, 0, failures, false);

    const finish = function () {
      updateDnsBulkProgress(processed, targets.length, "—", successful, failures, true);
      $controls.prop("disabled", false);
      if (state.table && state.table.ajax) state.table.ajax.reload(null, false);
      showNotification(text(failures.length ? "dns.bulkCompleteWithErrors" : "dns.bulkComplete"), failures.length > 0);
    };
    const next = function () {
      if (processed >= targets.length) { finish(); return; }
      const target = targets[processed];
      updateDnsBulkProgress(processed, targets.length, target.domain, successful, failures, false);
      apiRequest($.extend({ action: "dnsManagedBulkRecordApply", id: target.id }, record)).done(function (response) {
        if (!response || !response.ok) {
          const message = response && response.error || text("toast.error");
          failures.push({ domain: target.domain, error: message });
          appendDnsBulkResult(target.domain, false, message);
          return;
        }
        successful += 1;
        appendDnsBulkResult(target.domain, true, text("dns.recordSent"));
      }).fail(function (xhr) {
        const message = (xhr.responseJSON || {}).error || text("toast.error");
        failures.push({ domain: target.domain, error: message });
        appendDnsBulkResult(target.domain, false, message);
      }).always(function () {
        processed += 1;
        updateDnsBulkProgress(processed, targets.length, processed < targets.length ? targets[processed].domain : "—", successful, failures, false);
        next();
      });
    };
    next();
  }

  function dnsManagedTableRow($button) {
    if (!state.table) return null;
    return state.table.row($button.closest("tr")).data() || null;
  }

  function managedDnsRecordPayloads($scope) {
    return $scope.find("[data-managed-dns-record]").map(function () {
      const $row = $(this);
      return {
        name: String($row.find('[data-dns-field="name"]').val() || "@").trim(),
        type: String($row.find('[data-dns-field="type"]').val() || "A"),
        ttl: Number($row.find('[data-dns-field="ttl"]').val() || config.dnsDefaultTtl || 3600),
        values: String($row.find('[data-dns-field="values"]').val() || "").split(/\r?\n/).map(function (value) { return value.trim(); }).filter(Boolean)
      };
    }).get();
  }

  function managedDnsData($records) {
    try {
      return {
        types: JSON.parse(decodeURIComponent(String($records.attr("data-dns-types") || "%5B%5D"))),
        template: JSON.parse(decodeURIComponent(String($records.attr("data-dns-template") || "%5B%5D")))
      };
    } catch (error) {
      return { types: ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"], template: [] };
    }
  }

  function refreshManagedDnsEmpty($records) {
    const hasRows = $records.find("[data-managed-dns-record]").length > 0;
    $records.find("[data-managed-dns-empty]").toggleClass("d-none", hasRows);
    if (!hasRows && !$records.find("[data-managed-dns-empty]").length) {
      $records.append('<div class="text-secondary small py-3" data-managed-dns-empty translate="dns.noRecords"></div>');
      translatePage($records);
    }
  }

  function renderManagedDnsCopyResults($host, payload) {
    const results = payload && Array.isArray(payload.results) ? payload.results : [];
    const html = results.map(function (result) {
      const ok = !!result.ok;
      const message = ok
        ? text("dns.copyZoneSuccess").replace("{records}", String(Number(result.records || 0)))
        : (result.error || text("dns.copyZoneFailed"));
      return `<div class="dns-copy-result ${ok ? "is-success" : "is-error"}"><i class="bi bi-${ok ? "check-circle-fill" : "x-circle-fill"}"></i><div><strong>${templates.esc(result.domain || result.id || "—")}</strong><small>${templates.esc(message)}</small></div></div>`;
    }).join("");
    $host.html(html || `<div class="text-secondary small">${templates.esc(text("dns.copyZoneFailed"))}</div>`).removeClass("d-none");
  }

  function formRecord($form) {
    const record = {};
    $form.serializeArray().forEach(function (field) {
      const isArray = field.name.slice(-2) === "[]";
      const name = isArray ? field.name.slice(0, -2) : field.name;
      if (isArray) {
        if (!Array.isArray(record[name])) record[name] = [];
        record[name].push(field.value);
      } else {
        record[name] = field.value;
      }
    });
    $form.find('input[type="checkbox"][name]').each(function () { record[this.name] = this.checked; });
    return record;
  }

  function domainToolIso(value) {
    const date = new Date(String(value || ""));
    return Number.isNaN(date.getTime()) ? "" : date.toISOString();
  }

  function domainToolAccessRecord($access, editor) {
    const permission = function (name) {
      const $field = $access.find(`[data-tool-permission="${name}"]`);
      return editor ? $field.prop("checked") : String($field.val() || "0") === "1";
    };
    return {
      id: String($access.attr("data-access-id") || ""),
      name: String($access.find('[data-tool-field="name"]').val() || "").trim(),
      login: String($access.find('[data-tool-field="login"]').val() || "").trim(),
      password: String($access.find('[data-tool-field="password"]').val() || ""),
      ips: String($access.find('[data-tool-field="ips"]').val() || "").trim(),
      permissions: {
        phpmyadmin: permission("phpmyadmin"),
        filemanager: permission("filemanager"),
        fileeditor: permission("fileeditor")
      },
      active: String($access.find('[data-tool-field="active"]').val() || "1") === "1",
      startsAt: domainToolIso($access.find('[data-tool-field="startsAt"]').val()),
      expiresAt: domainToolIso($access.find('[data-tool-field="expiresAt"]').val())
    };
  }

  function validDomainToolAccess(record) {
    return !!record.name
      && /^[A-Za-z0-9_.@-]{2,64}$/.test(record.login)
      && validImportPassword(record.password)
      && !!record.ips
      && !!record.startsAt
      && !!record.expiresAt
      && Object.keys(record.permissions).some(function (key) { return record.permissions[key]; });
  }

  function refreshDomainToolAccessTable() {
    const $rows = $("[data-tool-access-list] [data-tool-access]");
    $rows.each(function (index) { $(this).find("[data-tool-row-number]").text(index + 1); });
    $("[data-tool-access-empty]").toggleClass("d-none", $rows.length > 0);
  }

  function collectDomainToolAccesses() {
    const accesses = [];
    let valid = true;
    $("[data-tool-access-list] [data-tool-access]").each(function () {
      const record = domainToolAccessRecord($(this), false);
      if (!validDomainToolAccess(record)) valid = false;
      accesses.push(record);
    });
    return { valid: valid, accesses: accesses };
  }

  function setDomainToolExpiry($access, baseDate) {
    const date = baseDate instanceof Date ? baseDate : new Date();
    const expires = new Date(date.getTime() + Number(config.domainToolAccessHours || 24) * 3600000);
    const local = new Date(expires.getTime() - expires.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    $access.find('[data-tool-field="expiresAt"]').val(local);
  }

  function recordFor(type, id) {
    return (state.data[type] || []).find(function (row) { return Number(row.id) === Number(id); }) || null;
  }

  function relevantDomains(userId) {
    return state.data.domains.filter(function (domain) { return config.role === "root" ? (!userId || domain.userId === Number(userId)) : domain.userId === Number(config.userId); });
  }

  function selectedDomainOwnerId() {
    const value = $("#entity-form [data-domain-owner]").val();
    return Number(value || config.userId || 0);
  }

  function selectedDomainOwnerPrefix() {
    const userId = selectedDomainOwnerId();
    const user = (state.data.users || []).find(function (item) { return Number(item.id) === userId; });
    return user ? user.prefix : (config.prefix || "{USER_PREFIX}");
  }

  function projectPathsForOwner() {
    const userId = selectedDomainOwnerId();
    const seen = {};
    return (state.data.domains || []).filter(function (domain) {
      return config.role !== "root" || Number(domain.userId) === userId;
    }).map(function (domain) {
      return domain.path || "";
    }).filter(function (path) {
      if (!path || seen[path]) return false;
      seen[path] = true;
      return true;
    });
  }

  function updateProjectPathPreview() {
    const existing = $('#entity-form [name="projectPathMode"]:checked').val() === "existing";
    const relativePath = existing
      ? String($("#entity-form [data-existing-project]").val() || "")
      : `${String($("#entity-form [data-project-folder]").val() || $("#entity-form [name=domain]").val() || "{PROJECT_FOLDER}").trim()}/${config.publicHtmlDirectory || "public_html"}`;
    const absolute = `${String(config.userWebRootDirectory || "/var/www").replace(/\/$/, "")}/${selectedDomainOwnerPrefix()}/${relativePath}`;
    $("#entity-form [data-project-absolute]").text(absolute);
  }

  function validateExistingProjectPath() {
    const input = $("#entity-form [data-existing-project]").get(0);
    if (!input) return true;
    const existing = $('#entity-form [name="projectPathMode"]:checked').val() === "existing";
    const value = String(input.value || "");
    const valid = !existing || value === "" || projectPathsForOwner().includes(value);
    input.setCustomValidity(valid ? "" : text("forms.existingProjectInvalid"));
    return valid;
  }

  function updateProjectFolderMode() {
    const existing = $('#entity-form [name="projectPathMode"]:checked').val() === "existing";
    $("#entity-form .project-existing-group").toggleClass("d-none", !existing);
    $("#entity-form .project-new-group").toggleClass("d-none", existing);
    $("#entity-form [data-existing-project]").prop("disabled", !existing).prop("required", existing);
    $("#entity-form [data-project-folder]").prop("disabled", existing).prop("required", !existing);
    validateExistingProjectPath();
    updateProjectPathPreview();
  }

  function updateProjectFolderOptions(preserveSelection) {
    const $input = $("#entity-form [data-existing-project]");
    const $options = $("#entity-form [data-existing-project-options]");
    if (!$input.length || !$options.length) return;
    const previous = preserveSelection ? String($input.val() || $input.data("current-path") || "") : "";
    const paths = projectPathsForOwner();
    $options.empty();
    paths.forEach(function (path) { $("<option>").val(path).text(path).appendTo($options); });
    $input.val(previous && paths.includes(previous) ? previous : (paths[0] || ""));
    const $existingMode = $('#entity-form [name="projectPathMode"][value="existing"]');
    $existingMode.prop("disabled", paths.length === 0);
    if (!paths.length && $existingMode.prop("checked")) {
      $('#entity-form [name="projectPathMode"][value="new"]').prop("checked", true);
    }
    updateProjectFolderMode();
  }

  function updateUserRootPath() {
    const $rootPath = $("#entity-form [data-user-root-path]");
    if (!$rootPath.length) return;
    const prefix = String($("#entity-form [name=prefix]").val() || "{USER_PREFIX}");
    $rootPath.val(`${String($rootPath.data("web-root") || "/var/www").replace(/\/$/, "")}/${prefix}`);
  }

  function translatedTemplate(key, replacements) {
    let value = text(key);
    Object.keys(replacements || {}).forEach(function (name) {
      value = value.split(`{${name}}`).join(String(replacements[name]));
    });
    return value;
  }

  function userPasswordRequirements() {
    const policy = config.userPasswordPolicy || {};
    const requirements = [translatedTemplate("profile.passwordPolicyMinLength", { count: Math.max(1, Number(policy.minLength || 8)) })];
    if (policy.requireUppercase) requirements.push(text("profile.passwordPolicyUppercase"));
    if (policy.requireLowercase) requirements.push(text("profile.passwordPolicyLowercase"));
    if (policy.requireNumber) requirements.push(text("profile.passwordPolicyNumber"));
    if (policy.requireSpecial) requirements.push(translatedTemplate("profile.passwordPolicySpecial", { characters: String(policy.specialCharacters || "") }));
    return requirements.join(", ");
  }

  function userPasswordMatchesPolicy(password) {
    const policy = config.userPasswordPolicy || {};
    if (String(password).length < Math.max(1, Number(policy.minLength || 8))) return false;
    if (policy.requireUppercase && !/[A-Z]/.test(password)) return false;
    if (policy.requireLowercase && !/[a-z]/.test(password)) return false;
    if (policy.requireNumber && !/[0-9]/.test(password)) return false;
    if (policy.requireSpecial) {
      const characters = String(policy.specialCharacters || "");
      if (!characters || !String(password).split("").some(function (character) { return characters.includes(character); })) return false;
    }
    return true;
  }

  function updateUserPasswordFeedback() {
    const $input = $('#entity-form [data-user-password]');
    const $feedback = $('#entity-form [data-user-password-feedback]');
    if (!$input.length || !$feedback.length) return;
    const password = String($input.val() || "");
    const required = String($feedback.data("password-required") || "0") === "1";
    $feedback.removeClass("text-warning text-success");
    if (password === "") {
      $feedback.text(required
        ? translatedTemplate("profile.passwordPolicyRecommendation", { requirements: userPasswordRequirements() })
        : text("profile.passwordHint"));
      return;
    }
    if (userPasswordMatchesPolicy(password)) {
      $feedback.addClass("text-success").text(text("profile.passwordPolicyOk"));
    } else {
      $feedback.addClass("text-warning").text(translatedTemplate("profile.passwordPolicyWarning", { requirements: userPasswordRequirements() }));
    }
  }

  function updateProfileIpAccess() {
    const $section = $('#entity-form [data-profile-ip-access]');
    if (!$section.length) return;
    const enabled = $section.find('[name="ipAccessEnabled"]').prop("checked");
    $section.find('[name="allowedIps"]').prop("required", enabled).attr("aria-required", enabled ? "true" : "false");
  }

  function selectedDatabaseOwnerPrefix() {
    const ownerId = Number($("#entity-form [data-database-owner]").val() || config.userId || 0);
    const owner = (state.data.users || []).find(function (user) { return Number(user.id) === ownerId; });
    return String(owner && owner.prefix || config.prefix || "prefix");
  }

  function databaseConfigurationText(record) {
    const item = record || {};
    const database = String(item.name || "");
    const username = String(item.username || database);
    const host = String(item.host || config.mysqlConnectionHost || "localhost");
    const port = Number(item.port || config.mysqlConnectionPort || 3306);
    const password = config.showDatabasePasswords ? String(item.password || "") : "********";
    return [
      `DB_HOST=${host}`,
      `DB_PORT=${port}`,
      `DB_NAME=${database}`,
      `DB_USER=${username}`,
      `DB_PASSWORD=${password}`
    ].join("\n");
  }

  function updateDatabaseCredentials() {
    const $form = $('#entity-form[data-entity="databases"]');
    if (!$form.length) return;
    const prefix = selectedDatabaseOwnerPrefix();
    $form.find("[data-database-prefix]").text(`${prefix}_`);
    const database = `${prefix}_${String($form.find('[name="name"]').val() || "")}`;
    const $credentials = $form.find("[data-database-credentials]");
    if (!$credentials.length) return;
    const username = String($credentials.data("database-username") || database);
    const host = String($credentials.data("database-host") || config.mysqlConnectionHost || "localhost");
    const port = Number($credentials.data("database-port") || config.mysqlConnectionPort || 3306);
    const password = config.showDatabasePasswords ? String($form.find('[name="password"]').val() || "") : "********";
    $credentials.val(databaseConfigurationText({ name: database, username: username, host: host, port: port, password: password }));
  }

  function openDatabaseConfiguration(databaseId) {
    const record = recordFor("databases", databaseId);
    if (!record) { showError(text("toast.error")); return; }
    $("#modal-root").html(templates.databaseConfigurationModal(record, databaseConfigurationText(record)));
    translatePage("#modal-root");
    const element = document.getElementById("database-configuration-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("hidden.bs.modal", function () { $("#modal-root").empty(); state.modal = null; }, { once: true });
  }

  function mailConfigurationText(record) {
    const item = record || {};
    const domain = String(item.domain || "").trim().toLowerCase();
    const email = String(item.address || (item.mailbox && domain ? `${item.mailbox}@${domain}` : "")).trim().toLowerCase();
    const aliases = Array.isArray(item.aliases) ? item.aliases : [];
    const forwardTo = Array.isArray(item.forwardTo) ? item.forwardTo : [];
    const password = config.showMailPasswords ? String(item.password || "") : "********";
    const settings = config.mailConnection || {};
    const domainWebmail = String(settings.domainWebmailTemplate || "https://{domain}/mail/").split("{domain}").join(domain || "example.com");
    return [
      `EMAIL=${email}`,
      `PASSWORD=${password}`,
      `ALIASES=${aliases.join(", ")}`,
      `FORWARD_COPIES_TO=${forwardTo.join(", ")}`,
      `CATCH_ALL=${item.catchAll && domain ? `@${domain} -> ${email}` : "disabled"}`,
      "",
      `IMAP_HOST=${settings.imapHost || "mail.lostweb.eu"}`,
      `IMAP_PORT=${Number(settings.imapPort || 993)}`,
      "IMAP_SECURITY=SSL/TLS",
      "",
      `POP3_HOST=${settings.pop3Host || "mail.lostweb.eu"}`,
      `POP3_PORT=${Number(settings.pop3Port || 995)}`,
      "POP3_SECURITY=SSL/TLS",
      "",
      `SMTP_HOST=${settings.smtpHost || "mail.lostweb.eu"}`,
      `SMTP_PORT=${Number(settings.smtpPort || 465)}`,
      "SMTP_SECURITY=SSL/TLS",
      "SMTP_AUTH=required",
      "",
      `WEBMAIL=${settings.webmailUrl || "https://mail.lostweb.eu"}`,
      `WEBMAIL_ALTERNATIVE=${domainWebmail}`
    ].join("\n");
  }

  function updateMailCredentials() {
    const $form = $('#entity-form[data-entity="mail"]');
    if (!$form.length) return;
    const domain = String($form.find('[name="domain"]').val() || "").trim().toLowerCase();
    const mailbox = String($form.find('[name="mailbox"]').val() || "").trim().toLowerCase();
    const email = mailbox && domain ? `${mailbox}@${domain}` : "";
    $form.find("[data-mail-domain-suffix]").text(`@${domain || "domain"}`);
    const aliases = [];
    $form.find("[data-mail-alias-input]").each(function () {
      const alias = String($(this).val() || "").trim().toLowerCase();
      if (alias && domain) aliases.push(`${alias}@${domain}`);
    });
    const forwardTo = String($form.find('[name="forwardTo"]').val() || "").trim().split(/[\s,;]+/).filter(Boolean);
    const catchAll = $form.find('[name="catchAll"]').prop("checked");
    const password = config.showMailPasswords ? String($form.find('[name="password"]').val() || "") : "********";
    $form.find("[data-mail-credentials]").val(mailConfigurationText({
      domain: domain,
      address: email,
      password: password,
      aliases: aliases,
      forwardTo: forwardTo,
      catchAll: catchAll
    }));
  }

  function openMailConfiguration(mailId) {
    const record = recordFor("mail", mailId);
    if (!record) { showError(text("toast.error")); return; }
    $("#modal-root").html(templates.mailConfigurationModal(record, mailConfigurationText(record), config.mailConnection || {}));
    translatePage("#modal-root");
    const element = document.getElementById("mail-configuration-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("hidden.bs.modal", function () { $("#modal-root").empty(); state.modal = null; }, { once: true });
  }

  function stopMailMigrationTimers() {
    if (state.mailMigrationTimer) window.clearTimeout(state.mailMigrationTimer);
    if (state.mailMigrationStageTimer) window.clearInterval(state.mailMigrationStageTimer);
    state.mailMigrationTimer = null;
    state.mailMigrationStageTimer = null;
  }

  function migrationDate(value) {
    if (!value) return "—";
    const normalized = String(value).indexOf("T") === -1 ? String(value).replace(" ", "T") + "Z" : String(value);
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(state.language);
  }

  function migrationDuration(job) {
    const start = job && job.started_at ? new Date(String(job.started_at).replace(" ", "T") + "Z") : null;
    const end = job && job.finished_at ? new Date(String(job.finished_at).replace(" ", "T") + "Z") : new Date();
    if (!start || Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "—";
    let seconds = Math.max(0, Math.floor((end.getTime() - start.getTime()) / 1000));
    const hours = Math.floor(seconds / 3600); seconds %= 3600;
    const minutes = Math.floor(seconds / 60); seconds %= 60;
    return [hours ? `${hours}h` : "", `${minutes}m`, `${seconds}s`].filter(Boolean).join(" ");
  }

  function mailMigrationPayload($section) {
    const value = function (name) { return String($section.find(`[data-migration-field="${name}"]`).val() || "").trim(); };
    return {
      mailboxId: Number($section.data("mailbox-id") || 0),
      sourceHost: value("sourceHost"),
      sourcePort: Number(value("sourcePort") || 0),
      sourceSecurity: value("sourceSecurity"),
      sourceLogin: value("sourceLogin"),
      sourcePassword: String($section.find('[data-migration-field="sourcePassword"]').val() || "")
    };
  }

  function renderMailMigrationStages($section, active) {
    const keys = ["connecting", "authenticating", "readingFolders", "countingMessages"];
    const $stages = $section.find("[data-mail-migration-stages]").removeClass("d-none");
    let index = 0;
    const draw = function () {
      $stages.html(keys.map(function (key, itemIndex) {
        const icon = itemIndex === index && active ? '<span class="spinner-border spinner-border-sm"></span>' : `<i class="bi ${active && itemIndex > index ? "bi-circle" : "bi-check-circle text-success"}"></i>`;
        return `<div>${icon}<span>${escapeHtml(text(`mailMigration.${key}`))}</span></div>`;
      }).join(""));
    };
    draw();
    if (active) {
      state.mailMigrationStageTimer = window.setInterval(function () { index = Math.min(keys.length - 1, index + 1); draw(); }, 1200);
    }
  }

  function renderMailMigrationCurrent($section, job) {
    const $current = $section.find("[data-mail-migration-current]");
    const $form = $section.find("[data-mail-migration-form]");
    if (!job) {
      $current.empty();
      $form.removeClass("d-none");
      $section.closest("form").find('.modal-footer [type="submit"]').prop("disabled", false);
      return;
    }
    const status = String(job.status || "failed");
    const active = ["pending", "checking", "ready", "running"].includes(status);
    const completed = status === "completed" || status === "completed_with_errors";
    const statusLabel = text(`mailMigration.status.${status}`);
    const calculated = Number(job.percent || 0);
    const percentValue = completed ? 100 : Math.max(0, Math.min(100, calculated));
    const remaining = active && percentValue > 0 && job.started_at
      ? Math.max(0, Math.round(((Date.now() - new Date(String(job.started_at).replace(" ", "T") + "Z").getTime()) / 1000) * (100 - percentValue) / percentValue))
      : 0;
    const remainingText = remaining > 0 ? `~${Math.floor(remaining / 60)} min` : "—";
    const style = status === "failed" ? "danger" : (status === "completed_with_errors" ? "warning" : (completed ? "success" : "primary"));
    $section.closest("form").find('.modal-footer [type="submit"]').prop("disabled", active);
    $current.html(`<div class="mail-migration-progress-card border border-${style}">
      <div class="d-flex justify-content-between align-items-center gap-2 mb-3"><strong>${escapeHtml(statusLabel)}</strong>${active ? '<span class="spinner-border spinner-border-sm text-primary"></span>' : `<i class="bi ${completed ? "bi-check-circle-fill text-success" : "bi-exclamation-triangle-fill text-danger"}"></i>`}</div>
      <div class="row g-2 small">
        <div class="col-sm-6"><span>${escapeHtml(text("mailMigration.server"))}</span><strong>${escapeHtml(job.source_host || "—")}</strong></div>
        <div class="col-sm-6"><span>${escapeHtml(text("mailMigration.currentFolder"))}</span><strong>${escapeHtml(job.current_folder || "—")}</strong></div>
        <div class="col-sm-6"><span>${escapeHtml(text("mailMigration.folders"))}</span><strong>${Number(job.folders_done || 0)} / ${Number(job.folders_total || 0)}</strong></div>
        <div class="col-sm-6"><span>${escapeHtml(text("mailMigration.messages"))}</span><strong>${Number(job.messages_done || 0).toLocaleString()} / ${Number(job.messages_total || 0).toLocaleString()}</strong></div>
        <div class="col-sm-6"><span>${escapeHtml(text("mailMigration.transferred"))}</span><strong>${escapeHtml(formatBytes(job.bytes_done || 0))} / ${escapeHtml(formatBytes(job.bytes_total || 0))}</strong></div>
        <div class="col-sm-6"><span>${escapeHtml(text("mailMigration.errors"))}</span><strong>${Number(job.errors_count || 0)}</strong></div>
      </div>
      <div class="progress mt-3" role="progressbar" aria-valuenow="${percentValue}" aria-valuemin="0" aria-valuemax="100"><div class="progress-bar${active ? " progress-bar-striped progress-bar-animated" : ""}" style="width:${percentValue}%">${percentValue}%</div></div>
      <div class="d-flex flex-wrap gap-3 small text-secondary mt-2"><span>${escapeHtml(text("mailMigration.elapsed"))}: ${escapeHtml(migrationDuration(job))}</span>${active ? `<span>${escapeHtml(text("mailMigration.remaining"))}: ${escapeHtml(remainingText)}</span>` : ""}</div>
      ${job.error_message ? `<div class="alert alert-danger py-2 mt-3 mb-0">${escapeHtml(job.error_message)}</div>` : ""}
      ${!active ? `<div class="d-flex gap-2 mt-3"><button class="btn btn-sm btn-outline-primary" type="button" data-mail-migration-view-report="${escapeHtml(job.id)}"><i class="bi bi-file-earmark-text me-1"></i>${escapeHtml(text("mailMigration.viewReport"))}</button><button class="btn btn-sm btn-primary" type="button" data-mail-migration-again><i class="bi bi-arrow-repeat me-1"></i>${escapeHtml(text("mailMigration.importAgain"))}</button></div>` : ""}
    </div>`);
    $form.toggleClass("d-none", active || completed || status === "failed");
  }

  function renderMailMigrationHistory($section, history) {
    const rows = Array.isArray(history) ? history : [];
    const $wrap = $section.find("[data-mail-migration-history-wrap]");
    if (!rows.length) { $wrap.addClass("d-none"); return; }
    $section.find("[data-mail-migration-history]").html(rows.map(function (job) {
      return `<div class="mail-migration-history-row"><div><strong>${escapeHtml(migrationDate(job.created_at))}</strong><small>${escapeHtml(job.source_host || "")}</small></div><span class="badge text-bg-light">${escapeHtml(text(`mailMigration.status.${job.status}`))}</span><span>${Number(job.messages_done || 0).toLocaleString()} · ${escapeHtml(formatBytes(job.bytes_done || 0))}</span></div>`;
    }).join(""));
    $wrap.removeClass("d-none");
  }

  function scheduleMailMigrationStatus($section, job) {
    if (!job || !["pending", "checking", "ready", "running"].includes(String(job.status || ""))) return;
    state.mailMigrationTimer = window.setTimeout(function () {
      if (!$section.closest("body").length) return;
      apiRequest({ action: "mailMigrationStatus", mailboxId: Number($section.data("mailbox-id")), migrationId: job.id }, "GET").done(function (response) {
        if (!response || !response.ok) return;
        const next = response.data && response.data.migration;
        renderMailMigrationCurrent($section, next);
        scheduleMailMigrationStatus($section, next);
        if (next && !["pending", "checking", "ready", "running"].includes(String(next.status || ""))) loadMailMigration($section);
      }).fail(function () { scheduleMailMigrationStatus($section, job); });
    }, Math.max(1000, Number(config.mailMigrationPollIntervalMs || 3000)));
  }

  function loadMailMigration($section) {
    stopMailMigrationTimers();
    $section.find("[data-mail-migration-loading]").removeClass("d-none");
    apiRequest({ action: "mailMigrationHistory", mailboxId: Number($section.data("mailbox-id")) }, "GET").done(function (response) {
      const history = response && response.ok && response.data ? response.data.history || [] : [];
      renderMailMigrationHistory($section, history);
      renderMailMigrationCurrent($section, history[0] || null);
      scheduleMailMigrationStatus($section, history[0] || null);
    }).fail(function (xhr) {
      $section.find("[data-mail-migration-current]").html(`<div class="alert alert-warning">${escapeHtml((xhr.responseJSON || {}).error || text("toast.error"))}</div>`);
    }).always(function () {
      $section.find("[data-mail-migration-loading]").addClass("d-none");
      $section.find("[data-mail-migration-content]").removeClass("d-none");
    });
  }

  function dnsValue(template, domain) {
    return String(template || "").split("{domain}").join(domain || "example.com");
  }

  function updateDnsRecords() {
    const domain = String($('#entity-form [name="domain"]').val() || "").trim().toLowerCase() || "example.com";
    $("[data-dns-record]").each(function () {
      const index = Number($(this).data("dns-record"));
      const record = (config.dnsRecords || [])[index] || {};
      const value = String(record.label || "").toUpperCase() === "DKIM" && state.dkimValues[domain]
        ? state.dkimValues[domain]
        : record.value;
      $(this).find("[data-dns-name]").text(dnsValue(record.name, domain));
      $(this).find("[data-dns-value]").text(dnsValue(value, domain));
    });
    const $allRecords = $("[data-all-required-dns]");
    if ($allRecords.length && String($allRecords.data("loaded-domain") || "") !== domain) {
      $allRecords.removeData("loaded-domain").attr("data-loaded-domain", "");
      $allRecords.find("[data-all-required-dns-records]").empty();
    }
  }

  function syncPrimaryDnsRecords(records, domain) {
    const safeRecords = Array.isArray(records) ? records : [];
    const dkim = safeRecords.find(function (record) {
      return String(record.type || "").toUpperCase() === "TXT" && String(record.name || "").toLowerCase().indexOf("._domainkey") > 0;
    });
    if (validDnsDomain(domain) && dkim && Array.isArray(dkim.values) && dkim.values.length) {
      state.dkimValues[domain] = String(dkim.values[0]);
    }
    updateDnsRecords();
  }

  function openModal(type, record) {
    let html;
    if (type === "users") html = templates.userModal(record, config.userWebRootDirectory, config.tariffs || [], config.defaultTariff, !!config.showUserPasswordsToAdmin);
    if (type === "profile") html = templates.profileModal(record, config.tariffs || [], config.dnsProviders || [], config.dnsDefaultProvider || "", !!config.showDnsProviderCredentials);
    if (type === "domains") html = templates.domainModal(record, state.data.users, state.data.domains, config.role === "root", config.dnsRecords || [], config.publicHtmlDirectory, config.phpVersions || [], config.dnsDefaultTtl || 3600);
    if (type === "databases") {
      const databaseRecord = record ? $.extend({}, record) : null;
      if (databaseRecord && !databaseRecord.password) {
        if (config.showDatabasePasswords) {
          databaseRecord.password = generateImportPassword();
          databaseRecord.credentialsPending = true;
        }
      }
      html = templates.databaseModal(databaseRecord, state.data.users, relevantDomains(databaseRecord && databaseRecord.userId), config.role === "root", config.prefix, config.mysqlConnectionHost, config.mysqlConnectionPort, config.showDatabasePasswords);
    }
    if (type === "mail") {
      const mailRecord = record ? $.extend({}, record) : null;
      if (mailRecord && !mailRecord.password && config.showMailPasswords) {
        mailRecord.password = generateImportPassword();
        mailRecord.credentialsPending = true;
      }
      html = templates.mailModal(mailRecord, state.data.users, relevantDomains(mailRecord && mailRecord.userId), config.role === "root", config.showMailPasswords, config.mailConnection || {}, config.mailboxQuotaOptionsMb || [], config.mailboxDefaultQuotaMb || 20, config.mailMigrationEnabled, config.mailMigrationAllowedPorts || []);
    }
    $("#modal-root").html(html);
    translatePage("#modal-root");
    if (type === "domains") {
      updateDnsRecords();
      updateProjectFolderOptions(true);
      window.setTimeout(function () { loadDnsProviderState(!!(record && record.id)); }, 120);
    }
    if (type === "users") { updateUserRootPath(); updateTariffSummary(); updateUserPasswordFeedback(); updateProfileIpAccess(); }
    if (type === "profile") { updateProfileMailOptions(); updateDnsProfileFields(); refreshDnsConnectionTable(); updateUserPasswordFeedback(); updateProfileIpAccess(); }
    if (type === "databases") updateDatabaseCredentials();
    if (type === "mail") {
      updateMailCredentials();
      updateMailInfoCatchAllAvailability();
    }
    const element = document.getElementById("entity-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    if (type === "mail" && record && config.mailMigrationEnabled) loadMailMigration($(element).find("[data-mail-migration]"));
    element.addEventListener("hidden.bs.modal", function () { stopMailMigrationTimers(); $("#modal-root").empty(); state.modal = null; }, { once: true });
  }

  function updateProfileMailOptions() {
    const $form = $('#entity-form[data-entity="profile"]');
    if (!$form.length) return;
    const hasForwardEmail = String($form.find('[name="defaultForwardEmail"]').val() || "").trim() !== "";
    const $whole = $form.find('[name="mailForwardWholeDomain"]');
    if (!hasForwardEmail && $whole.prop("checked")) $whole.prop("checked", false);
    const whole = $whole.prop("checked");
    $whole.prop("disabled", !hasForwardEmail && !whole);
    const $forwardNew = $form.find('[name="mailForwardNewDomains"]');
    if (!hasForwardEmail) $forwardNew.prop("checked", false);
    $forwardNew.prop("disabled", whole || !hasForwardEmail);
    $form.find('[name="mailCatchAllToInfo"]').prop("disabled", whole);
    if (whole) {
      $forwardNew.add($form.find('[name="mailCatchAllToInfo"]')).prop("checked", false);
    }
  }

  function dnsConnectionRecord($editor) {
    const value = function (field) { return String($editor.find(`[data-dns-connection-field="${field}"]`).val() || ""); };
    return $.extend({}, $editor.data("dns-original") || {}, {
      id: String($editor.data("dns-connection-id") || ""), name: value("name").trim(), provider: value("provider"),
      apiUrl: value("apiUrl").trim(), authType: value("authType"), apiToken: value("apiToken"),
      username: value("username"), password: value("password"), active: String($editor.attr("data-dns-active") || "1") !== "0",
      manageAllDomains: $editor.find('[data-dns-connection-field="manageAllDomains"]').prop("checked"),
      createdAt: String($editor.attr("data-dns-created-at") || ""), updatedAt: new Date().toISOString()
    });
  }

  function collectDnsConnections() {
    return $('#entity-form[data-entity="profile"] [data-dns-connection-row]').map(function () {
      try { return readDnsConnectionTableRow($(this)); } catch (error) { return null; }
    }).get().filter(Boolean);
  }

  function readDnsConnectionTableRow($row) {
    return JSON.parse(decodeURIComponent(String($row.attr("data-dns-connection-json") || "%7B%7D")));
  }

  function refreshDnsConnectionTable() {
    const $form = $('#entity-form[data-entity="profile"]');
    const $rows = $form.find("[data-dns-connection-row]");
    $rows.each(function (index) { $(this).find("[data-dns-connection-number]").text(index + 1); });
    $form.find("[data-dns-connections-empty]").toggleClass("d-none", $rows.length > 0);
    $form.find("[data-dns-connections]").closest(".table-responsive").toggleClass("d-none", $rows.length === 0);
  }

  function openDnsConnectionEditor(connection) {
    const item = connection || {};
    const $root = $('#entity-form[data-entity="profile"] [data-dns-connection-editor-root]');
    $root.html(templates.dnsConnectionRow(item, config.dnsProviders || [], !!config.showDnsProviderCredentials));
    $root.find("[data-dns-connection-editor]").data("dns-original", item);
    translatePage($root);
    updateDnsProfileFields();
  }

  function updateDnsProfileFields(event) {
    const $form = $('#entity-form[data-entity="profile"]');
    if (!$form.length) return;
    $form.find("option[data-dns-planned]").each(function () {
      $(this).text(`${String($(this).data("provider-name") || "")} — ${text("dns.planned")}`);
    });
    $form.find("[data-dns-connection-editor]").each(function () {
      const $row = $(this);
      const $provider = $row.find('[data-dns-connection-field="provider"]');
      const provider = String($provider.val() || "");
      const $selected = $provider.find("option:selected");
      const defaultApiUrl = String($selected.attr("data-api-url") || "");
      const $apiUrl = $row.find('[data-dns-connection-field="apiUrl"]');
      if (event && $(event.target).is($provider)) $apiUrl.val(defaultApiUrl);
      if (!$apiUrl.val()) $apiUrl.val(defaultApiUrl);
      const joker = provider === "joker";
      const regru = provider === "regru";
      const namecheap = provider === "namecheap";
      const internetbs = provider === "internetbs";
      const loginPasswordProvider = regru || namecheap;
      const authType = internetbs
        ? "api_key_password"
        : (loginPasswordProvider
        ? "login_password"
        : (joker ? String($row.find('[data-dns-connection-field="authType"]').val() || "api_key") : "api_key"));
      if (internetbs) $row.find('[data-dns-connection-field="authType"]').val("api_key_password");
      else if (loginPasswordProvider) $row.find('[data-dns-connection-field="authType"]').val("login_password");
      else if (!joker) $row.find('[data-dns-connection-field="authType"]').val("api_key");
      $row.find("[data-dns-auth-wrap]").toggleClass("d-none", !joker);
      $row.find("[data-dns-api-key-wrap]").toggleClass("d-none", !["api_key", "api_key_password"].includes(authType));
      $row.find("[data-dns-username-wrap]").toggleClass("d-none", authType !== "login_password");
      $row.find("[data-dns-password-wrap]").toggleClass("d-none", !["login_password", "api_key_password"].includes(authType));
      const passwordLabelKey = namecheap ? "dns.apiToken" : "dns.password";
      $row.find("[data-dns-login-wrap]").eq(1).find(".form-label").first()
        .attr("translate", passwordLabelKey).text(text(passwordLabelKey));
      const guidance = joker
        ? text("dns.jokerApiKeyHint")
        : (regru ? text("dns.regruApiPasswordHint") : (namecheap ? text("dns.namecheapApiHint") : ""));
      $row.find("[data-dns-provider-guidance]").toggleClass("d-none", !guidance).text(guidance);
      $row.find("[data-dns-connection-title]").text($row.find('[data-dns-connection-field="name"]').val() || "DNS");
    });
  }

  function domainDnsContext() {
    const $form = $('#entity-form[data-entity="domains"]');
    return {
      domain: String($form.find('[name="domain"]').val() || "").trim().toLowerCase(),
      domainId: Number($form.find('[name="id"]').val() || 0),
      userId: Number($form.find('[name="userId"]').val() || config.userId || 0),
      dnsConnectionId: String($form.find('[name="dnsConnectionId"]').val() || "")
    };
  }

  function validDnsDomain(domain) {
    return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain || "");
  }

  function dnsResultAlert(kind, message) {
    const icon = kind === "success" ? "check-circle" : (kind === "warning" ? "exclamation-triangle" : "x-circle");
    return `<div class="alert alert-${kind} py-2 mb-0 small"><i class="bi bi-${icon} me-2"></i>${escapeHtml(message)}</div>`;
  }

  function renderDnsApiRecords(data) {
    const $section = $("[data-dns-management]");
    const records = Array.isArray(data && data.records) ? data.records : [];
    const types = Array.isArray(data && data.types) ? data.types : ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"];
    $section.data("dns-types", types);
    $section.find("[data-dns-api-records]").html(records.length ? records.map(function (record) {
      return templates.dnsRecordRow(record, types, false);
    }).join("") : `<div class="text-secondary small py-3" translate="dns.noRecords"></div>`);
    $section.find("[data-add-dns-record]").prop("disabled", false);
    translatePage($section);
  }

  function renderRecommendedDnsRecords(records, error) {
    const $section = $("[data-dns-management]");
    const $preview = $section.find("[data-dns-recommended-preview]");
    const safeRecords = Array.isArray(records) ? records : [];
    if (!safeRecords.length) {
      $section.find("[data-dns-recommended-records]").html(error ? dnsResultAlert("warning", error) : "");
      return;
    }
    const html = safeRecords.map(function (record) {
      const values = Array.isArray(record.values) ? record.values : [];
      return `<div class="dns-recommended-record"><div class="dns-recommended-cell"><small>${escapeHtml(text("forms.recordName"))}</small><code>${escapeHtml(record.name || "@")}</code></div><div class="dns-recommended-cell"><small>${escapeHtml(text("dns.recordType"))}</small><span class="badge text-bg-light">${escapeHtml(record.type || "")}</span></div><div class="dns-recommended-cell"><small>TTL</small><code>${escapeHtml(record.ttl || "")}</code></div><div class="dns-recommended-cell dns-recommended-values"><small>${escapeHtml(text("dns.recordValues"))}</small>${values.map(function (value) { return `<code>${escapeHtml(value)}</code>`; }).join("")}</div></div>`;
    }).join("");
    $section.find("[data-dns-recommended-records]").html(html);
    translatePage($preview);
  }

  function fullDnsRecordName(name, domain) {
    const normalized = String(name || "@").replace(/\.+$/, "");
    if (normalized === "@" || normalized === "") return domain;
    if (normalized.toLowerCase() === domain || normalized.toLowerCase().endsWith(`.${domain}`)) return normalized;
    return `${normalized}.${domain}`;
  }

  function renderAllRequiredDnsRecords(records, domain, error) {
    const $panel = $("[data-all-required-dns]");
    const $records = $panel.find("[data-all-required-dns-records]");
    const safeRecords = Array.isArray(records) ? records : [];
    if (!safeRecords.length) {
      $records.html(error ? dnsResultAlert("warning", error) : "");
      return;
    }
    const html = safeRecords.map(function (record) {
      const name = fullDnsRecordName(record.name, domain);
      const type = String(record.type || "").toUpperCase();
      const ttl = String(record.ttl || "");
      const values = Array.isArray(record.values) ? record.values : [];
      const value = values.join("\n");
      const fullRecord = values.map(function (item) { return `${name} ${ttl} IN ${type} ${item}`; }).join("\n");
      return `<div class="dns-all-required-record"><span class="badge text-bg-light">${escapeHtml(type)}</span><div class="dns-all-required-field"><button class="btn btn-outline-secondary dns-copy-button-xs" type="button" data-copy-required-dns="${escapeHtml(name)}" translate="forms.recordName" translate-attr="title aria-label"><i class="bi bi-copy"></i></button><code class="dns-all-required-name">${escapeHtml(name)}</code></div><div class="dns-all-required-field dns-all-required-values"><button class="btn btn-outline-secondary dns-copy-button-xs" type="button" data-copy-required-dns="${escapeHtml(value)}" translate="forms.recordValue" translate-attr="title aria-label"><i class="bi bi-copy"></i></button><div>${values.map(function (item) { return `<code>${escapeHtml(item)}</code>`; }).join("")}</div></div><small>TTL ${escapeHtml(ttl)}</small><button class="btn btn-sm btn-outline-secondary dns-copy-button" type="button" data-copy-required-dns="${escapeHtml(fullRecord)}" translate="common.copy" translate-attr="title aria-label"><i class="bi bi-copy"></i></button></div>`;
    }).join("");
    $panel.attr("data-loaded-domain", domain).data("loaded-domain", domain);
    $records.html(html);
    translatePage($panel);
  }

  function loadAllRequiredDnsRecords() {
    const context = domainDnsContext();
    const $panel = $("[data-all-required-dns]");
    if (!validDnsDomain(context.domain)) {
      renderAllRequiredDnsRecords([], context.domain, text("forms.enterDomainForDnsRecords"));
      return;
    }
    if (String($panel.data("loaded-domain") || "") === context.domain && $panel.find("[data-all-required-dns-records]").children().length) return;
    $panel.find("[data-all-required-dns-records]").html(`<div class="dns-api-loading"><span class="spinner-border spinner-border-sm"></span><span>${escapeHtml(text("dns.recommendedLoading"))}</span></div>`);
    apiRequest($.extend({ action: "dnsRecommendedRecords" }, context)).done(function (response) {
      if (!response.ok) { renderAllRequiredDnsRecords([], context.domain, response.error || text("dns.recommendedUnavailable")); return; }
      syncPrimaryDnsRecords(response.data && response.data.records, context.domain);
      renderAllRequiredDnsRecords(response.data && response.data.records, context.domain);
    }).fail(function (xhr) {
      renderAllRequiredDnsRecords([], context.domain, (xhr.responseJSON || {}).error || text("dns.recommendedUnavailable"));
    });
  }

  function loadRecommendedDnsRecords(context) {
    const $section = $("[data-dns-management]");
    $section.find("[data-dns-recommended-preview]").addClass("d-none");
    $section.find("[data-toggle-recommended-dns]").attr("aria-expanded", "false").find("i").attr("class", "bi bi-chevron-down me-1");
    if (!$section.length || !validDnsDomain(context.domain)) {
      renderRecommendedDnsRecords([]);
      return;
    }
    $section.find("[data-dns-recommended-records]").html(`<div class="dns-api-loading"><span class="spinner-border spinner-border-sm"></span><span>${escapeHtml(text("dns.recommendedLoading"))}</span></div>`);
    apiRequest($.extend({ action: "dnsRecommendedRecords" }, context)).done(function (response) {
      if (!response.ok) { renderRecommendedDnsRecords([], response.error || text("dns.recommendedUnavailable")); return; }
      syncPrimaryDnsRecords(response.data && response.data.records, context.domain);
      renderRecommendedDnsRecords(response.data && response.data.records);
    }).fail(function (xhr) {
      renderRecommendedDnsRecords([], (xhr.responseJSON || {}).error || text("dns.recommendedUnavailable"));
    });
  }

  function loadDnsApiRecords() {
    const context = domainDnsContext();
    if (!context.domainId || !validDnsDomain(context.domain)) return;
    const $section = $("[data-dns-management]");
    $section.find("[data-dns-api-loading]").removeClass("d-none");
    apiRequest($.extend({ action: "dnsRecords" }, context)).done(function (response) {
      if (!response.ok) { showError(response.error); return; }
      renderDnsApiRecords(response.data || {});
    }).fail(function (xhr) {
      $section.find("[data-dns-api-records]").html(dnsResultAlert("warning", (xhr.responseJSON || {}).error || text("toast.error")));
    }).always(function () {
      $section.find("[data-dns-api-loading]").addClass("d-none");
    });
  }

  function loadDnsProviderState(loadRecords) {
    const context = domainDnsContext();
    const $section = $("[data-dns-management]");
    if (!$section.length) return;
    $section.addClass("d-none");
    loadRecommendedDnsRecords(context);
    if (!validDnsDomain(context.domain)) {
      $section.addClass("d-none");
      $section.find("[data-dns-provider-result]").addClass("d-none").empty();
      $section.find("[data-apply-recommended-dns]").addClass("d-none").prop("disabled", true);
      $section.find("[data-dns-connection-picker]").addClass("d-none");
      return;
    }
    const $button = $section.find("[data-detect-dns-provider]");
    const $result = $section.find("[data-dns-provider-result]");
    const $apply = $section.find("[data-apply-recommended-dns]");
    $button.prop("disabled", true).find("i").attr("class", "spinner-border spinner-border-sm me-1");
    apiRequest($.extend({ action: "dnsProviderDetect" }, context)).done(function (response) {
      if (!response.ok) { showError(response.error); return; }
      const data = response.data || {};
      const ns = Array.isArray(data.nameservers) ? data.nameservers.join(", ") : "";
      const connections = Array.isArray(data.connections) ? data.connections : [];
      $section.toggleClass("d-none", !connections.length);
      const $picker = $section.find("[data-dns-connection-picker]");
      const $select = $picker.find("[data-domain-dns-connection]");
      const saved = String($select.data("saved-value") || context.dnsConnectionId || "");
      $select.html(connections.map(function (connection) { return `<option value="${escapeHtml(connection.id)}"${connection.id === saved ? " selected" : ""}>${escapeHtml(connection.name)}</option>`; }).join(""));
      if (!$select.val() && connections.length) $select.val(connections[0].id);
      $picker.toggleClass("d-none", !connections.length);
      $apply.addClass("d-none").prop("disabled", true);
      const message = data.provider
        ? (connections.length ? `${String(data.provider).toUpperCase()}: ${ns || context.domain}` : text("dns.providerDetectedNeedsKey").replace("{provider}", data.provider))
        : text("dns.nameserversMismatch");
      $result.html(dnsResultAlert(connections.length ? "success" : "warning", message)).removeClass("d-none");
    }).fail(function (xhr) {
      $section.addClass("d-none");
      $result.addClass("d-none").empty();
      $apply.addClass("d-none").prop("disabled", true);
    }).always(function () {
      $button.prop("disabled", false).find("i").attr("class", "bi bi-search me-1");
    });
  }

  function verifyDnsProviderAccess(loadRecords) {
    const context = domainDnsContext();
    const $section = $("[data-dns-management]");
    const $button = $section.find("[data-verify-dns-access]");
    const $result = $section.find("[data-dns-provider-result]");
    const $apply = $section.find("[data-apply-recommended-dns]");
    if (!context.dnsConnectionId) { showError(text("dns.chooseConnection")); return; }
    $button.prop("disabled", true).find("i").attr("class", "spinner-border spinner-border-sm me-1");
    apiRequest($.extend({ action: "dnsProviderDetect", verifyConnection: true }, context)).done(function (response) {
      if (!response.ok) { showError(response.error); return; }
      const data = response.data || {};
      const ok = !!data.zoneFound && !!data.nameserversMatch;
      $result.html(dnsResultAlert(ok ? "success" : "warning", ok ? text("dns.accessConfirmed") : text("dns.nameserversMismatch"))).removeClass("d-none");
      $apply.toggleClass("d-none", !ok).prop("disabled", !ok);
      $section.find("[data-add-dns-record]").prop("disabled", !ok);
      if (ok && loadRecords && context.domainId) loadDnsApiRecords();
    }).fail(function (xhr) {
      $result.html(dnsResultAlert("danger", (xhr.responseJSON || {}).error || text("dns.providerUnavailable"))).removeClass("d-none");
      $apply.addClass("d-none").prop("disabled", true);
    }).always(function () {
      $button.prop("disabled", false).find("i").attr("class", "bi bi-shield-check me-1");
    });
  }

  function dnsRecordPayload($row) {
    return {
      name: String($row.find('[data-dns-field="name"]').val() || "@").trim().toLowerCase(),
      type: String($row.find('[data-dns-field="type"]').val() || "A").trim().toUpperCase(),
      ttl: Number($row.find('[data-dns-field="ttl"]').val() || config.dnsDefaultTtl || 3600),
      values: String($row.find('[data-dns-field="values"]').val() || "").split(/\r?\n/).map(function (value) { return value.trim(); }).filter(Boolean)
    };
  }

  function updateTariffSummary() {
    const key = String($('#entity-form[data-entity="users"] [data-tariff-select]').val() || "");
    const tariff = (config.tariffs || []).find(function (item) { return item.key === key; });
    if (!tariff) return;
    const count = function (value) { return Number(value || 0) > 0 ? String(value) : "∞"; };
    const size = function (value) { return Number(value || 0) > 0 ? formatBytes(value) : "∞"; };
    $('#entity-form[data-entity="users"] [data-tariff-summary]').html(`${escapeHtml(text("profile.tariffDomains"))}: ${count(tariff.domain)} · ${escapeHtml(text("profile.tariffDatabases"))}: ${count(tariff.db)} · ${escapeHtml(text("profile.tariffMailPerDomain"))}: ${count(tariff.mailbydomain)} · ${escapeHtml(text("profile.tariffWebsiteSize"))}: ${size(tariff.wwwsize)} · ${escapeHtml(text("profile.tariffMailboxSize"))}: ${size(tariff.mailsize)} · ${escapeHtml(text("profile.tariffDatabaseSize"))}: ${size(tariff.dbsize)}`);
  }

  function updateMailInfoCatchAllAvailability() {
    const $form = $('#entity-form[data-entity="mail"]');
    const $wrap = $form.find("[data-mail-info-catchall-wrap]");
    if (!$wrap.length) return;
    const domain = String($form.find('[name="domain"]').val() || "").toLowerCase();
    const ownerId = config.role === "root" ? Number($form.find('[name="userId"]').val() || 0) : Number(config.userId || 0);
    const domainRow = (state.data.domains || []).find(function (row) {
      return String(row.domain || "").toLowerCase() === domain && Number(row.userId || 0) === ownerId;
    });
    const hasMailbox = (state.data.mail || []).some(function (row) {
      return String(row.domain || "").toLowerCase() === domain && Number(row.userId || 0) === ownerId;
    });
    $wrap.toggleClass("d-none", !domainRow || hasMailbox || domainRow.mailMode === "domain_forward");
  }

  function verificationMarkup(kind, result) {
    if (kind === "mail") {
      const records = result && result.records || {};
      const labels = { mail_a: "MAIL A", mx: "MX", dkim: "DKIM", spf: "SPF", dmarc: "DMARC" };
      const recordTypes = { mail_a: "A", mx: "MX", dkim: "TXT", spf: "TXT", dmarc: "TXT" };
      return ["mail_a", "mx", "dkim", "spf", "dmarc"].map(function (type) {
        const record = records[type] || {};
        const valid = record.valid === true;
        const label = labels[type] || type.toUpperCase();
        const status = valid ? text("common.connected") : text("common.notConnected");
        const actual = Array.isArray(record.actual) ? record.actual.join("\n") : "";
        return `<div class="verification-row"${actual ? ` title="${escapeHtml(actual)}"` : ""}><i class="bi ${valid ? "bi-check-circle" : "bi-exclamation-triangle text-warning"}"></i><span><strong>${label}</strong> — ${escapeHtml(status)}</span><small>${valid ? "OK" : recordTypes[type]}</small></div>`;
      }).join("");
    }
    if (kind === "domain") {
      const checks = [
        { key: "forms.domainCorrect", valid: result && result.domainValid === true, actual: [] },
        { key: "forms.rootPoints", valid: result && result.rootPoints === true, actual: result && result.rootAddresses || [] },
        { key: "forms.wwwPoints", valid: result && result.wwwPoints === true, actual: result && result.wwwAddresses || [] },
        { key: "forms.sslReady", valid: result && result.sslReady === true, actual: [] }
      ];
      const expected = Array.isArray(result && result.hostingIps) ? result.hostingIps.join(", ") : "";
      return checks.map(function (check, index) {
        const actual = Array.isArray(check.actual) ? check.actual.join(", ") : "";
        const detail = check.valid ? "OK" : (actual || (index === 0 ? "—" : expected || "—"));
        const title = !check.valid && actual && expected ? `${actual} ≠ ${expected}` : "";
        return `<div class="verification-row"${title ? ` title="${escapeHtml(title)}"` : ""}><i class="bi ${check.valid ? "bi-check-circle" : "bi-x-circle text-danger"}"></i><span translate="${check.key}"></span><small>${escapeHtml(detail)}</small></div>`;
      }).join("");
    }
    const keys = kind === "domain"
      ? ["forms.domainCorrect", "forms.rootPoints", "forms.wwwPoints", "forms.sslReady"]
      : ["forms.recordDkim", "forms.recordSpf", "forms.recordDmarc"];
    return keys.map(function (key, index) {
      const warning = kind === "mail" && index === 2;
      return `<div class="verification-row"><i class="bi ${warning ? "bi-exclamation-triangle text-warning" : "bi-check-circle"}"></i><span translate="${key}"></span><small>${warning ? "TXT" : "OK"}</small></div>`;
    }).join("");
  }

  function randomIndex(maximum) {
    if (window.crypto && window.crypto.getRandomValues) {
      const values = new Uint32Array(1);
      window.crypto.getRandomValues(values);
      return values[0] % maximum;
    }
    return Math.floor(Math.random() * maximum);
  }

  function generateImportPassword() {
    const groups = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "+-_)(?%#!,."];
    const all = groups.join("");
    const characters = groups.map(function (group) { return group.charAt(randomIndex(group.length)); });
    while (characters.length < 8) characters.push(all.charAt(randomIndex(all.length)));
    for (let index = characters.length - 1; index > 0; index -= 1) {
      const target = randomIndex(index + 1);
      const temporary = characters[index];
      characters[index] = characters[target];
      characters[target] = temporary;
    }
    return characters.join("");
  }

  function validImportPassword(password) {
    const value = String(password || "");
    return value.length >= 8 && value.length <= 128
      && /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value)
      && /[+\-_)(?%#!,.]/.test(value);
  }

  function importOwnerId() {
    return Number($("[data-import-owner]").val() || config.userId || 0);
  }

  function normalizeImportedPath(path) {
    let normalized = String(path || "").trim().replace(/^\{(.+)\}$/, "$1").replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
    const owner = (state.data.users || []).find(function (user) { return Number(user.id) === importOwnerId(); });
    const prefix = owner ? owner.prefix : config.prefix;
    const absolutePrefix = `${String(config.userWebRootDirectory || "/var/www").replace(/^\/+|\/+$/g, "")}/${prefix}/`;
    if (normalized.toLowerCase().indexOf(absolutePrefix.toLowerCase()) === 0) normalized = normalized.substring(absolutePrefix.length);
    const publicDirectory = String(config.publicHtmlDirectory || "public_html").replace(/^\/+|\/+$/g, "");
    if (normalized && normalized !== publicDirectory && normalized.slice(-(publicDirectory.length + 1)) !== `/${publicDirectory}`) normalized += `/${publicDirectory}`;
    return normalized;
  }

  function parseDomainImport(source) {
    return String(source || "").split(/\r?\n/).map(function (line) { return line.trim(); }).filter(Boolean).map(function (line) {
      const parts = line.split(/\s+/);
      const flags = parts.slice(2).map(function (flag) { return flag.toLowerCase(); });
      return {
        domain: String(parts[0] || "").replace(/^https?:\/\//i, "").replace(/\/$/, "").toLowerCase(),
        path: normalizeImportedPath(parts[1] || ""),
        ssl: flags.includes("ssl"),
        www: flags.includes("www")
      };
    });
  }

  function parseMailImport(source) {
    return String(source || "").split(/\r?\n/).filter(function (line) { return line.trim() !== ""; }).map(function (line) {
      if (line.indexOf("\t") !== -1) {
        const parts = line.split("\t");
        return {
          email: String(parts[0] || "").trim().toLowerCase(),
          password: String(parts[1] || "").trim() || generateImportPassword(),
          aliases: importList(parts[2]),
          forwardTo: importList(parts[3]),
          catchAll: /^(?:1|yes|true|on|\+|да)$/i.test(String(parts[4] || "").trim())
        };
      }
      const match = line.trim().match(/^(\S+)(?:\s+(.+))?$/);
      return { email: String(match && match[1] || "").toLowerCase(), password: String(match && match[2] || "").trim() || generateImportPassword(), aliases: [], forwardTo: [], catchAll: false };
    });
  }

  function importList(value) {
    const unique = {};
    return String(value || "").split(/[\s,;]+/).map(function (item) { return item.trim().toLowerCase(); }).filter(function (item) {
      if (!item || unique[item]) return false;
      unique[item] = true;
      return true;
    });
  }

  function validImportEmail(value) {
    return /^[a-z0-9][a-z0-9._+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(String(value || ""));
  }

  function collectImportRecords() {
    const type = $("[data-import-type]").data("import-type");
    const records = [];
    $("[data-import-row]").each(function () {
      const $row = $(this);
      if (type === "domains") {
        records.push({
          domain: String($row.find('[data-import-field="domain"]').val() || "").trim().toLowerCase(),
          path: normalizeImportedPath($row.find('[data-import-field="path"]').val()),
          ssl: $row.find('[data-import-field="ssl"]').prop("checked"),
          www: $row.find('[data-import-field="www"]').prop("checked")
        });
      } else {
        let password = String($row.find('[data-import-field="password"]').val() || "");
        if (!password) {
          password = generateImportPassword();
          $row.find('[data-import-field="password"]').val(password);
        }
        records.push({
          email: String($row.find('[data-import-field="email"]').val() || "").trim().toLowerCase(),
          password: password,
          aliases: importList($row.find('[data-import-field="aliases"]').val()),
          forwardTo: importList($row.find('[data-import-field="forwardTo"]').val()),
          catchAll: $row.find('[data-import-field="catchAll"]').prop("checked")
        });
      }
    });
    state.importRecords = records;
    return records;
  }

  function validateImportPreview() {
    const type = $("[data-import-type]").data("import-type");
    const records = collectImportRecords();
    const ownerId = importOwnerId();
    const existing = {};
    const existingCatchAll = {};
    const seen = {};
    const seenCatchAll = {};
    (state.data[type] || []).forEach(function (item) {
      existing[type === "domains" ? String(item.domain).toLowerCase() : String(item.address).toLowerCase()] = true;
      if (type === "mail") {
        (Array.isArray(item.aliases) ? item.aliases : []).forEach(function (alias) { existing[String(alias).toLowerCase()] = true; });
        if (item.catchAll) existingCatchAll[String(item.domain || String(item.address || "").split("@").pop()).toLowerCase()] = true;
      }
    });
    let valid = records.length > 0 && records.length <= Number(config.importMaxRows || 500);
    records.forEach(function (record, index) {
      let key;
      let rowValid;
      if (type === "domains") {
        key = record.domain;
        rowValid = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(record.domain)
          && /^(?!.*(?:^|\/)\.\.(?:\/|$))[^\0\r\n]+\/public_html$/i.test(record.path);
      } else {
        key = record.email;
        rowValid = validImportEmail(record.email) && record.password.length > 0;
        const domain = record.email.split("@").pop();
        rowValid = rowValid && (state.data.domains || []).some(function (item) { return Number(item.userId) === ownerId && String(item.domain).toLowerCase() === domain; });
        const normalizedAliases = record.aliases.map(function (alias) { return alias.indexOf("@") === -1 ? `${alias}@${domain}` : alias; }).filter(function (alias) { return alias !== record.email; });
        rowValid = rowValid && normalizedAliases.every(function (alias) {
          return validImportEmail(alias)
            && alias.split("@").pop() === domain
            && !existing[alias]
            && !seen[alias];
        });
        rowValid = rowValid && record.forwardTo.every(function (recipient) {
          return validImportEmail(recipient);
        });
        if (record.catchAll) rowValid = rowValid && !existingCatchAll[domain] && !seenCatchAll[domain];
        normalizedAliases.forEach(function (alias) { seen[alias] = true; });
        if (record.catchAll) seenCatchAll[domain] = true;
      }
      const duplicate = !!seen[key] || !!existing[key];
      seen[key] = true;
      rowValid = rowValid && !duplicate;
      valid = valid && rowValid;
      const $status = $(`[data-import-row="${index}"] .import-row-status`);
      $status.attr("class", `import-row-status status-pill ${rowValid ? "success" : "danger"}`).attr("translate", rowValid ? "forms.importReady" : (duplicate ? "forms.importDuplicate" : "forms.importInvalid"));
    });
    $("[data-accept-import]").prop("disabled", !valid);
    $("[data-import-count]").text(`${records.length} / ${Number(config.importMaxRows || 500)}`);
    if (type === "mail") {
      $("[data-import-credentials]").val(records.map(function (record) { return `${record.email}\t${record.password}`; }).join("\n"));
    }
    translatePage("#import-modal");
    return valid;
  }

  function showImportPreview() {
    const type = $("[data-import-type]").data("import-type");
    const source = $("[data-import-source]").val();
    const records = type === "domains" ? parseDomainImport(source) : parseMailImport(source);
    if (!records.length) { showError(text("forms.importEmpty")); return; }
    if (records.length > Number(config.importMaxRows || 500)) { showError(text("forms.importTooMany")); return; }
    state.importRecords = records;
    $("[data-import-preview]").html(type === "domains" ? templates.domainImportRows(records) : templates.mailImportRows(records));
    $("[data-import-preview-section], [data-accept-import]").removeClass("d-none");
    if (type === "mail") $("[data-import-credentials-section]").removeClass("d-none");
    translatePage("#import-modal");
    validateImportPreview();
  }

  function openImportModal(type) {
    state.importRecords = [];
    $("#modal-root").html(templates.importModal(type, state.data.users || [], config.role === "root"));
    translatePage("#modal-root");
    const element = document.getElementById("import-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("hidden.bs.modal", function () { $("#modal-root").empty(); state.modal = null; state.importRecords = []; }, { once: true });
  }

  function openLanguageModal() {
    $("#modal-root").html(templates.languageModal(state.languages, state.language));
    translatePage("#modal-root");
    const element = document.getElementById("language-modal");
    state.modal = new bootstrap.Modal(element);
    state.modal.show();
    element.addEventListener("shown.bs.modal", function () { $("[data-language-search]").trigger("focus"); }, { once: true });
    element.addEventListener("hidden.bs.modal", function () { $("#modal-root").empty(); state.modal = null; }, { once: true });
  }

  function csvCell(value) {
    return `"${String(value == null ? "" : value).replace(/"/g, '""')}"`;
  }

  function exportDomainsCsv() {
    const rows = scopedData("domains");
    const csv = [["domain", "path", "ssl", "www"]].concat(rows.map(function (row) {
      return [row.domain, row.path, row.ssl ? "ssl" : "", row.redirectWww ? "www" : ""];
    })).map(function (row) { return row.map(csvCell).join(","); }).join("\r\n");
    const blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `domains-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    showToast("toast.exported");
  }

  function bindEvents() {
    $(document).on("click", "[data-language]", function () { setLanguage($(this).data("language")); });
    $(document).on("click", "[data-language-picker]", openLanguageModal);
    $(document).on("input", "[data-language-search]", function () {
      const query = String($(this).val() || "").trim().toLocaleLowerCase();
      let visible = 0;
      $("[data-language-list] .language-option").each(function () {
        const $option = $(this);
        const matches = !query || String($option.data("language-name") || "").includes(query) || String($option.data("language-code") || "").includes(query);
        $option.toggleClass("d-none", !matches);
        if (matches) visible++;
      });
      $("[data-language-empty]").toggleClass("d-none", visible > 0);
    });
    $(document).on("click", "[data-password-toggle]", function () {
      const $input = $($(this).data("password-toggle"));
      const hidden = $input.attr("type") === "password";
      $input.attr("type", hidden ? "text" : "password");
      $(this).find("i").toggleClass("bi-eye", !hidden).toggleClass("bi-eye-slash", hidden);
    });
    $(document).on("click", "[data-generate-database-password]", function () {
      $('#entity-form[data-entity="databases"] [name="password"]').val(generateImportPassword()).trigger("input");
    });
    $(document).on("input", '#entity-form[data-entity="databases"] [name="name"], #entity-form[data-entity="databases"] [name="password"]', updateDatabaseCredentials);
    $(document).on("change", '#entity-form[data-entity="databases"] [data-database-owner]', updateDatabaseCredentials);
    $(document).on("click", "[data-generate-mail-password]", function () {
      $('#entity-form[data-entity="mail"] [name="password"]').val(generateImportPassword()).trigger("input");
    });
    $(document).on("click", "[data-open-profile]", function () {
      openModal("profile", (state.data.users || [])[0] || {});
    });
    $(document).on("input change", '#entity-form[data-entity="profile"] [name="defaultForwardEmail"], #entity-form[data-entity="profile"] [name="mailForwardWholeDomain"]', updateProfileMailOptions);
    $(document).on("change input", '#entity-form[data-entity="profile"] [data-dns-connection-field]', updateDnsProfileFields);
    $(document).on("click", "[data-add-dns-connection]", function () {
      openDnsConnectionEditor({ active: true });
    });
    $(document).on("click", "[data-cancel-dns-connection]", function () { $(this).closest("[data-dns-connection-editor-root]").empty(); });
    $(document).on("click", "[data-edit-dns-connection]", function () {
      try { openDnsConnectionEditor(readDnsConnectionTableRow($(this).closest("[data-dns-connection-row]"))); } catch (error) { showError(text("toast.error")); }
    });
    $(document).on("click", "[data-save-dns-connection]", function () {
      const $editor = $(this).closest("[data-dns-connection-editor]");
      const invalid = $editor.find(":input[required]").filter(function () { return !this.checkValidity(); }).first();
      if (invalid.length) { invalid[0].reportValidity(); return; }
      const connection = dnsConnectionRecord($editor);
      const $tbody = $('#entity-form[data-entity="profile"] [data-dns-connections]');
      let $existing = $tbody.find("[data-dns-connection-row]").filter(function () {
        try { return readDnsConnectionTableRow($(this)).id === connection.id; } catch (error) { return false; }
      }).first();
      const html = templates.dnsConnectionTableRow(connection, $existing.length ? $existing.index() : $tbody.children().length);
      if ($existing.length) $existing.replaceWith(html); else $tbody.append(html);
      $editor.closest("[data-dns-connection-editor-root]").empty();
      refreshDnsConnectionTable();
      translatePage($tbody);
    });
    $(document).on("click", "[data-toggle-dns-connection]", function () {
      const $row = $(this).closest("[data-dns-connection-row]");
      try {
        const connection = readDnsConnectionTableRow($row);
        connection.active = connection.active === false;
        connection.updatedAt = new Date().toISOString();
        $row.replaceWith(templates.dnsConnectionTableRow(connection, $row.index()));
        translatePage('#entity-form[data-entity="profile"] [data-dns-connections]');
      } catch (error) { showError(text("toast.error")); }
    });
    $(document).on("click", "[data-delete-dns-connection]", function () {
      if (!window.confirm(text("dns.confirmDeleteConnection"))) return;
      $(this).closest("[data-dns-connection-row]").remove();
      $('#entity-form[data-entity="profile"] [data-dns-connection-editor-root]').empty();
      refreshDnsConnectionTable();
    });
    $(document).on("click", "[data-toggle-dns-secret]", function () {
      const $input = $(this).siblings("input");
      const show = $input.attr("type") === "password";
      $input.attr("type", show ? "text" : "password");
      $(this).find("i").attr("class", `bi bi-eye${show ? "-slash" : ""}`);
    });
    $(document).on("click", "[data-test-dns-provider]", function () {
      const $button = $(this);
      const $form = $('#entity-form[data-entity="profile"]');
      const $row = $button.closest("[data-dns-connection-editor]");
      const $result = $row.find("[data-dns-profile-result]");
      const record = dnsConnectionRecord($row);
      $button.prop("disabled", true).find("i").attr("class", "spinner-border spinner-border-sm me-1");
      apiRequest({ action: "dnsProviderTest", connection: record }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        $result.html(dnsResultAlert("success", text("dns.connectionOk"))).removeClass("d-none");
      }).fail(function (xhr) {
        $result.html(dnsResultAlert("danger", (xhr.responseJSON || {}).error || text("toast.error"))).removeClass("d-none");
      }).always(function () {
        $button.prop("disabled", false).find("i").attr("class", "bi bi-plug me-1");
      });
    });
    $(document).on("change", '#entity-form[data-entity="users"] [data-tariff-select]', updateTariffSummary);
    $(document).on("click", "[data-request-tariff]", function () {
      const tariff = String($(this).closest(".form-section").find("[data-tariff-request]").val() || "");
      const $button = $(this).prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "tariffRequest", tariff: tariff }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        if (state.modal) state.modal.hide();
        window.setTimeout(function () { refreshData().done(function () { openModal("profile", (state.data.users || [])[0] || {}); }); }, 250);
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("change", '#entity-form[data-entity="mail"] [name="domain"], #entity-form[data-entity="mail"] [name="userId"]', updateMailInfoCatchAllAvailability);
    $(document).on("click", "[data-mail-info-catchall]", function () {
      const $form = $('#entity-form[data-entity="mail"]');
      $form.find('[name="mailbox"]').val("info").trigger("input");
      $form.find('[name="catchAll"]').prop("checked", true).trigger("change");
    });
    $(document).on("click", "[data-add-mail-alias]", function () {
      const domain = String($('#entity-form[data-entity="mail"] [name="domain"]').val() || "domain");
      const $row = $(templates.mailAliasRow("", domain));
      $(this).siblings("[data-mail-alias-list]").append($row);
      translatePage($row);
      $row.find("[data-mail-alias-input]").trigger("focus");
      updateMailCredentials();
    });
    $(document).on("click", "[data-remove-mail-alias]", function () {
      $(this).closest("[data-mail-alias-row]").remove();
      updateMailCredentials();
    });
    $(document).on("input change", '#entity-form[data-entity="mail"] [name="domain"], #entity-form[data-entity="mail"] [name="mailbox"], #entity-form[data-entity="mail"] [name="password"], #entity-form[data-entity="mail"] [data-mail-alias-input], #entity-form[data-entity="mail"] [name="forwardTo"], #entity-form[data-entity="mail"] [name="catchAll"]', updateMailCredentials);
    $(document).on("input change", "[data-mail-migration] [data-migration-field]", function () {
      const $section = $(this).closest("[data-mail-migration]");
      $section.removeData("tested").find("[data-mail-migration-start]").addClass("d-none");
      $section.find("[data-mail-migration-test-result], [data-mail-migration-stages]").addClass("d-none").empty();
    });
    $(document).on("click", "[data-mail-migration-test]", function () {
      const $button = $(this);
      const $section = $button.closest("[data-mail-migration]");
      const payload = mailMigrationPayload($section);
      if (!payload.sourceHost || !payload.sourcePort || !payload.sourceLogin || !payload.sourcePassword) {
        showError(text("mailMigration.fillRequired"));
        return;
      }
      stopMailMigrationTimers();
      renderMailMigrationStages($section, true);
      $section.find("[data-mail-migration-test-result]").addClass("d-none").empty();
      $button.prop("disabled", true).find("i").attr("class", "spinner-border spinner-border-sm me-1");
      apiRequest($.extend({ action: "mailMigrationTest" }, payload), "POST", { timeout: 190000 }).done(function (response) {
        const result = response && response.data || {};
        if (!response || !response.ok || result.available === false) {
          $section.find("[data-mail-migration-stages]").addClass("d-none").empty();
          showError(result.error || response && response.error || text("toast.error"));
          return;
        }
        $section.data("tested", true);
        renderMailMigrationStages($section, false);
        $section.find("[data-mail-migration-test-result]").removeClass("d-none").html(`<div class="alert alert-success mb-0"><strong>${escapeHtml(text("mailMigration.connectionSuccessful"))}</strong><div class="mt-2">${escapeHtml(text("mailMigration.folders"))}: ${Number(result.folders || 0).toLocaleString()} · ${escapeHtml(text("mailMigration.messages"))}: ${Number(result.messages || 0).toLocaleString()} · ${escapeHtml(text("mailMigration.size"))}: ${escapeHtml(formatBytes(result.bytes || 0))}</div></div>`);
        $section.find("[data-mail-migration-start]").removeClass("d-none");
      }).fail(function (xhr) {
        $section.find("[data-mail-migration-stages]").addClass("d-none").empty();
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        if (state.mailMigrationStageTimer) window.clearInterval(state.mailMigrationStageTimer);
        state.mailMigrationStageTimer = null;
        $button.prop("disabled", false).find("i").attr("class", "bi bi-plug me-1");
      });
    });
    $(document).on("click", "[data-mail-migration-start]", function () {
      const $button = $(this);
      const $section = $button.closest("[data-mail-migration]");
      if (!$section.data("tested")) { showError(text("mailMigration.testFirst")); return; }
      const payload = mailMigrationPayload($section);
      $button.prop("disabled", true).find("i").attr("class", "spinner-border spinner-border-sm me-1");
      apiRequest($.extend({ action: "mailMigrationStart" }, payload)).done(function (response) {
        if (!response || !response.ok || !response.data) { showError(response && response.error || text("toast.error")); return; }
        $section.find('[data-migration-field="sourcePassword"]').val("");
        $section.removeData("tested");
        renderMailMigrationCurrent($section, response.data);
        scheduleMailMigrationStatus($section, response.data);
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).find("i").attr("class", "bi bi-play-fill me-1");
      });
    });
    $(document).on("click", "[data-mail-migration-again]", function () {
      const $section = $(this).closest("[data-mail-migration]");
      const latestHost = $section.find("[data-mail-migration-current] .mail-migration-progress-card .col-sm-6 strong").first().text();
      $section.find("[data-mail-migration-current]").empty();
      $section.find("[data-mail-migration-form]").removeClass("d-none");
      if (latestHost && latestHost !== "—") $section.find('[data-migration-field="sourceHost"]').val(latestHost);
      $section.find('[data-migration-field="sourcePassword"]').val("").trigger("focus");
    });
    $(document).on("click", "[data-mail-migration-view-report]", function () {
      const $button = $(this);
      const $section = $button.closest("[data-mail-migration]");
      const $report = $section.find("[data-mail-migration-report]").removeClass("d-none").html('<div class="text-center py-3"><span class="spinner-border"></span></div>');
      apiRequest({ action: "mailMigrationReport", mailboxId: Number($section.data("mailbox-id")), migrationId: String($button.data("mail-migration-view-report")) }, "GET").done(function (response) {
        const report = response && response.data && response.data.report;
        if (!report) { $report.html(`<div class="alert alert-warning">${escapeHtml(text("toast.error"))}</div>`); return; }
        $report.html(`<div class="card card-body bg-light"><div class="d-flex justify-content-between"><strong>${escapeHtml(text("mailMigration.report"))}</strong><button type="button" class="btn-close" data-mail-migration-close-report></button></div><dl class="row small mt-3 mb-0"><dt class="col-sm-4">${escapeHtml(text("mailMigration.statusLabel"))}</dt><dd class="col-sm-8">${escapeHtml(text(`mailMigration.status.${report.status}`))}</dd><dt class="col-sm-4">${escapeHtml(text("mailMigration.server"))}</dt><dd class="col-sm-8">${escapeHtml(report.server || "—")}</dd><dt class="col-sm-4">${escapeHtml(text("mailMigration.messages"))}</dt><dd class="col-sm-8">${Number(report.messages || 0).toLocaleString()} / ${Number(report.messagesTotal || 0).toLocaleString()}</dd><dt class="col-sm-4">${escapeHtml(text("mailMigration.transferred"))}</dt><dd class="col-sm-8">${escapeHtml(formatBytes(report.bytes || 0))}</dd><dt class="col-sm-4">${escapeHtml(text("mailMigration.errors"))}</dt><dd class="col-sm-8">${Number(report.errors || 0)}${report.error ? ` · ${escapeHtml(report.error)}` : ""}</dd><dt class="col-sm-4">${escapeHtml(text("mailMigration.started"))}</dt><dd class="col-sm-8">${escapeHtml(migrationDate(report.startedAt))}</dd><dt class="col-sm-4">${escapeHtml(text("mailMigration.finished"))}</dt><dd class="col-sm-8">${escapeHtml(migrationDate(report.finishedAt))}</dd></dl></div>`);
      }).fail(function (xhr) { $report.html(`<div class="alert alert-danger">${escapeHtml((xhr.responseJSON || {}).error || text("toast.error"))}</div>`); });
    });
    $(document).on("click", "[data-mail-migration-close-report]", function () { $(this).closest("[data-mail-migration-report]").addClass("d-none").empty(); });
    $(document).on("click", "[data-migrate-created-at]", function () {
      if (!window.confirm("Выставить отсутствующие даты во всех пользовательских JSON?")) return;
      const $button = $(this);
      const $result = $("[data-migrate-created-at-result]").addClass("d-none").removeClass("alert-success alert-danger").empty();
      $button.prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "migrateCreatedAt" }).done(function (response) {
        if (!response || !response.ok) {
          $result.addClass("alert-danger").removeClass("d-none").text(response && response.error || text("toast.error"));
          return;
        }
        const data = response.data || {};
        $result.addClass("alert-success").removeClass("d-none").html(
          `<strong>Готово.</strong> Файлов проверено: ${Number(data.files || 0)}, обновлено: ${Number(data.filesUpdated || 0)}.<br>` +
          `Пользователи: ${Number(data.profilesUpdated || 0)}, домены: ${Number(data.domainsUpdated || 0)}, базы: ${Number(data.databasesUpdated || 0)}, почта: ${Number(data.mailUpdated || 0)}.`
        );
        refreshData();
      }).fail(function (xhr) {
        $result.addClass("alert-danger").removeClass("d-none").text((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("click", "[data-all-domain-permissions]", function () {
      if (!window.confirm("Выставить правильные права всем доменным папкам всех пользователей?")) return;
      const $button = $(this);
      const original = $button.html();
      const $result = $("[data-all-domain-permissions-result]").addClass("d-none").removeClass("alert-success alert-warning alert-danger").empty();
      $button.prop("disabled", true).html('<span class="spinner-border spinner-border-sm me-2"></span>Выполняется...');
      apiRequest({ action: "domainPermissionsAll" }).done(function (response) {
        if (!response || !response.ok) {
          $result.addClass("alert-danger").removeClass("d-none").text(response && response.error || text("toast.error"));
          return;
        }
        const data = response.data || {};
        const issues = Array.isArray(data.issues) ? data.issues : [];
        const issuesTotal = Number(data.issuesTotal || issues.length);
        const issueRows = issues.map(function (issue) {
          const target = issue.domain || issue.prefix || issue.path || "Неизвестный путь";
          const path = issue.path ? `<div class="small font-monospace text-secondary">${escapeHtml(issue.path)}</div>` : "";
          return `<li class="mb-2"><strong>${escapeHtml(target)}</strong>${path}<div>${escapeHtml(issue.error || "Ошибка установки прав")}</div></li>`;
        }).join("");
        const hiddenIssues = Math.max(0, issuesTotal - issues.length);
        $result.addClass(issuesTotal ? "alert-warning" : "alert-success").removeClass("d-none").html(
          `<strong>${issuesTotal ? "Выполнено с предупреждениями." : "Готово."}</strong> ` +
          `Пользователей: ${Number(data.users || 0)}, доменов: ${Number(data.domains || 0)}, ` +
          `уникальных папок: ${Number(data.paths || 0)}, права выставлены: ${Number(data.updated || 0)}, ` +
          `общих папок пропущено повторно: ${Number(data.duplicatePaths || 0)}.` +
          (issueRows ? `<ul class="mt-3 mb-0">${issueRows}${hiddenIssues ? `<li>И ещё ошибок: ${hiddenIssues}.</li>` : ""}</ul>` : "")
        );
        showNotification(issuesTotal ? "Права выставлены не для всех папок — проверьте отчёт." : "Права всех доменных папок выставлены.", issuesTotal > 0);
      }).fail(function (xhr) {
        const message = (xhr.responseJSON || {}).error || text("toast.error");
        $result.addClass("alert-danger").removeClass("d-none").text(message);
        showError(message);
      }).always(function () {
        $button.prop("disabled", false).html(original);
      });
    });
    $(document).on("click", "[data-refresh-dns-zones]", function () {
      const $button = $(this).prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "dnsManagedZonesRefresh" }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        const errors = response.data && Array.isArray(response.data.errors) ? response.data.errors : [];
        reloadCurrentRoute("dns.zonesRefreshed", errors);
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("click", "[data-refresh-all-dns-records]", function () {
      refreshAllDnsRecords($(this));
    });
    $(document).on("click", "[data-open-dns-bulk-change]", function () {
      const $button = $(this).prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "dnsManagedBulkOptions" }, "GET").done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        showDnsBulkChangeModal(response.data || {});
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("input", "[data-dns-bulk-search]", function () { filterDnsBulkZones(false); });
    $(document).on("change", "[data-dns-bulk-user], [data-dns-bulk-provider], [data-dns-bulk-server-only]", function () { filterDnsBulkZones(true); });
    $(document).on("change", "[data-dns-bulk-target]", updateDnsBulkSelection);
    $(document).on("click", "[data-dns-bulk-select-all]", function () {
      $("#dns-bulk-change-modal [data-dns-bulk-zone]:not(.d-none) [data-dns-bulk-target]").prop("checked", true);
      updateDnsBulkSelection();
    });
    $(document).on("click", "[data-dns-bulk-clear]", function () {
      $("#dns-bulk-change-modal [data-dns-bulk-target]").prop("checked", false);
      updateDnsBulkSelection();
    });
    $(document).on("submit", "#dns-bulk-change-form", function (event) {
      event.preventDefault();
      runDnsBulkChange($(this));
    });
    $(document).on("click", "[data-dns-zone-edit]", function () {
      apiRequest({ action: "dnsManagedZoneDetails", id: String($(this).data("dns-zone-edit") || "") }, "GET").done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        showDnsManagedZoneModal(response.data, false);
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); });
    });
    $(document).on("click", "[data-dns-zone-current]", function () {
      const $button = $(this);
      const row = dnsManagedTableRow($button) || {};
      apiRequest({ action: "dnsManagedZoneCurrent", id: String($button.data("dns-zone-current") || "") }, "GET").done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        const current = response.data || {};
        showDnsManagedZoneModal({ zone: { id: row.id, domain: row.domain || current.zone, provider: row.provider || current.provider, connectionName: row.connectionName, records: current.records || [] }, types: current.types || [] }, true);
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); });
    });
    $(document).on("click", "[data-dns-zone-fetch]", function () {
      const id = String($(this).data("dns-zone-fetch") || "");
      apiRequest({ action: "dnsManagedZoneFetch", id: id }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        reloadCurrentRoute("dns.recordsFetched");
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); });
    });
    $(document).on("click", "[data-dns-zone-clear]", function () {
      if (!window.confirm(text("dns.confirmDeleteAllRecords"))) return;
      apiRequest({ action: "dnsManagedZoneClear", id: String($(this).data("dns-zone-clear") || "") }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        reloadCurrentRoute("dns.recordsCleared");
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); });
    });
    $(document).on("click", "[data-dns-zone-push]", function () {
      if (!window.confirm(text("dns.confirmSendToProvider"))) return;
      apiRequest({ action: "dnsManagedZonePush", id: String($(this).data("dns-zone-push") || "") }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        reloadCurrentRoute("dns.recordsSent");
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); });
    });
    $(document).on("click", "[data-add-managed-dns-record]", function () {
      const $records = $(this).closest(".modal-content").find("[data-managed-dns-records]");
      const data = managedDnsData($records);
      $records.find("[data-managed-dns-empty]").remove();
      $records.append(templates.dnsManagedRecordRow({ name: "@", type: "A", ttl: config.dnsDefaultTtl || 3600, values: [] }, data.types, false));
      translatePage($records);
    });
    $(document).on("click", "[data-remove-managed-dns-record]", function () {
      const $records = $(this).closest("[data-managed-dns-records]");
      $(this).closest("[data-managed-dns-record]").remove();
      refreshManagedDnsEmpty($records);
    });
    $(document).on("click", "[data-add-managed-dns-template]", function () {
      const $records = $(this).closest(".modal-content").find("[data-managed-dns-records]");
      const data = managedDnsData($records);
      const merged = {};
      managedDnsRecordPayloads($records).forEach(function (record) { merged[`${record.name}|${record.type}`] = record; });
      data.template.forEach(function (record) {
        const key = `${record.name}|${record.type}`;
        if (key === "@|TXT" && merged[key]) {
          const preserved = (merged[key].values || []).filter(function (value) { return !/^v=spf1\b/i.test(String(value)); });
          merged[key] = $.extend({}, record, { values: Array.from(new Set(preserved.concat(record.values || []))) });
        } else {
          merged[key] = record;
        }
      });
      const rows = Object.keys(merged).sort().map(function (key) { return templates.dnsManagedRecordRow(merged[key], data.types, false); }).join("");
      $records.html(rows || '<div class="text-secondary small py-3" data-managed-dns-empty translate="dns.noRecords"></div>');
      translatePage($records);
    });
    $(document).on("click", "[data-toggle-managed-dns-copy]", function () {
      const $panel = $(this).closest(".modal-content").find("[data-dns-copy-panel]");
      $panel.toggleClass("d-none");
      if (!$panel.hasClass("d-none")) $panel.find("[data-dns-copy-search]").trigger("focus");
    });
    $(document).on("input", "[data-dns-copy-search]", function () {
      const query = String($(this).val() || "").trim().toLowerCase();
      $(this).closest("[data-dns-copy-panel]").find("[data-dns-copy-zone]").each(function () {
        $(this).toggleClass("d-none", query !== "" && String($(this).data("search") || "").indexOf(query) === -1);
      });
    });
    $(document).on("click", "[data-dns-copy-submit]", function () {
      const $button = $(this);
      const $form = $button.closest("#dns-managed-zone-form");
      const $panel = $button.closest("[data-dns-copy-panel]");
      const $results = $panel.find("[data-dns-copy-results]");
      const targetIds = $panel.find("[data-dns-copy-target]:checked").map(function () { return String($(this).val() || ""); }).get().filter(Boolean);
      if (!targetIds.length) { showError(text("dns.selectCopyTargets")); return; }
      if (!window.confirm(text("dns.confirmCopyZones").replace("{count}", String(targetIds.length)))) return;
      $button.prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-1"></span>');
      $results.html(`<div class="dns-api-loading"><span class="spinner-border spinner-border-sm"></span><span>${templates.esc(text("dns.copyingZones"))}</span></div>`).removeClass("d-none");
      apiRequest({
        action: "dnsManagedZoneCopy",
        id: String($form.find('[name="id"]').val() || ""),
        targetIds: targetIds,
        records: managedDnsRecordPayloads($form)
      }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        renderManagedDnsCopyResults($results, response.data || {});
        if (state.table) state.table.ajax.reload(null, false);
      }).fail(function (xhr) {
        const message = (xhr.responseJSON || {}).error || text("toast.error");
        $results.html(`<div class="alert alert-danger mb-0">${templates.esc(message)}</div>`).removeClass("d-none");
      }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("submit", "#dns-managed-zone-form", function (event) {
      event.preventDefault();
      const $form = $(this);
      if ($form.attr("data-read-only") === "1") return;
      const $submit = $form.find('[type="submit"]').prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "dnsManagedZoneSave", id: String($form.find('[name="id"]').val() || ""), records: managedDnsRecordPayloads($form) }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        if (state.modal) state.modal.hide();
        window.setTimeout(function () { reloadCurrentRoute("toast.saved"); }, 250);
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); }).always(function () {
        $submit.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("click", "[data-sidebar-group-toggle]", function () {
      const group = String($(this).data("sidebar-group-toggle") || "");
      const open = $(this).attr("aria-expanded") !== "true";
      setSidebarGroupOpen(group, open, true);
    });
    $(document).on("click", "[data-route]", function (event) {
      if (!config.isAuthenticated) return;
      event.preventDefault();
      const route = String($(this).data("route") || "overview");
      const migrationSection = String($(this).data("migration-section") || "");
      const targetHash = route === "migration" && migrationSection
        ? `#migration?section=${encodeURIComponent(migrationSection)}`
        : `#${route}`;
      if (window.location.hash === targetHash) renderRoute(route);
      else window.location.hash = targetHash;
      const offcanvas = document.getElementById("mobile-navigation");
      const instance = offcanvas ? bootstrap.Offcanvas.getInstance(offcanvas) : null;
      if (instance) instance.hide();
    });
    $(window).on("hashchange", function () { if (config.isAuthenticated) renderRoute(routeFromHash()); });
    $(document).on("click", "[data-add]", function () { openModal($(this).data("add"), null); });
    $(document).on("click", "[data-tool-add]", function () {
      const domain = String($('#entity-form[data-entity="domains"] [name="domain"]').val() || "domain.example");
      const $editor = $(templates.domainToolAccessEditor(null, -1, domain));
      $("[data-tool-editor-host]").html($editor);
      $editor.find('[data-tool-field="password"]').val(generateImportPassword()).trigger("input");
      if (config.clientIp) $editor.find('[data-tool-field="ips"]').val(config.clientIp).trigger("input");
      $editor.find('[data-tool-field="name"]').trigger("focus");
    });
    $(document).on("click", "[data-tool-password]", function () {
      $(this).closest("[data-tool-editor-form]").find('[data-tool-field="password"]').val(generateImportPassword()).trigger("input");
    });
    $(document).on("click", "[data-tool-current-ip]", function () {
      const $input = $(this).closest("[data-tool-editor-form]").find('[data-tool-field="ips"]');
      const values = String($input.val() || "").split(/[\s,;]+/).filter(Boolean);
      if (config.clientIp && !values.includes(config.clientIp)) values.push(config.clientIp);
      $input.val(values.join("\n")).trigger("input");
    });
    $(document).on("change", '[data-tool-field="startsAt"]', function () {
      const value = new Date(String($(this).val() || ""));
      if (!Number.isNaN(value.getTime())) setDomainToolExpiry($(this).closest("[data-tool-editor-form]"), value);
    });
    $(document).on("change", "[data-tool-start-mode]", function () {
      const $access = $(this).closest("[data-tool-editor-form]");
      const scheduled = $access.find('[data-tool-start-mode][value="scheduled"]:checked').length > 0;
      const $start = $access.find('[data-tool-field="startsAt"]');
      $start.prop("readonly", !scheduled);
      if (!scheduled) {
        const now = new Date();
        const local = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        $start.val(local);
        setDomainToolExpiry($access, now);
      } else {
        $start.trigger("focus");
      }
    });
    $(document).on("input", '[data-tool-field="name"]', function () {
      const $editor = $(this).closest("[data-tool-editor-form]");
      if ($editor.length) $editor.find("[data-access-summary]").text(String($(this).val() || "Новый доступ"));
    });
    $(document).on("input", '[data-tool-field="login"], [data-tool-field="password"], [data-tool-field="ips"]', function () {
      const $access = $(this).closest("[data-tool-editor-form]");
      if (!$access.length) return;
      $access.find("[data-access-login-preview]").text(String($access.find('[data-tool-field="login"]').val() || ""));
      $access.find("[data-access-password-preview]").text(String($access.find('[data-tool-field="password"]').val() || ""));
      $access.find("[data-access-ip-preview]").text(String($access.find('[data-tool-field="ips"]').val() || "").split(/[\s,;]+/).filter(Boolean).join(", "));
    });
    $(document).on("click", "[data-tool-extend]", function () {
      const $row = $(this).closest("[data-tool-access]");
      const index = $("[data-tool-access-list] [data-tool-access]").index($row);
      const record = domainToolAccessRecord($row, false);
      const current = new Date(record.expiresAt || "");
      const base = !Number.isNaN(current.getTime()) && current.getTime() > Date.now() ? current : new Date();
      record.expiresAt = new Date(base.getTime() + Number(config.domainToolAccessHours || 24) * 3600000).toISOString();
      $row.replaceWith(templates.domainToolAccessRow(record, index));
      refreshDomainToolAccessTable();
    });
    $(document).on("click", "[data-tool-toggle]", function () {
      const $row = $(this).closest("[data-tool-access]");
      const index = $("[data-tool-access-list] [data-tool-access]").index($row);
      const record = domainToolAccessRecord($row, false);
      record.active = !record.active;
      $row.replaceWith(templates.domainToolAccessRow(record, index));
      refreshDomainToolAccessTable();
    });
    $(document).on("change", "[data-tool-active-switch]", function () {
      const $access = $(this).closest("[data-tool-editor-form]");
      const enabled = $(this).prop("checked");
      $access.find('[data-tool-field="active"]').val(enabled ? "1" : "0");
    });
    $(document).on("click", "[data-tool-edit]", function () {
      const $row = $(this).closest("[data-tool-access]");
      const index = $("[data-tool-access-list] [data-tool-access]").index($row);
      const domain = String($('#entity-form[data-entity="domains"] [name="domain"]').val() || "domain.example");
      const $editor = $(templates.domainToolAccessEditor(domainToolAccessRecord($row, false), index, domain));
      $("[data-tool-editor-host]").html($editor);
      $editor.find('[data-tool-field="name"]').trigger("focus");
    });
    $(document).on("click", "[data-tool-remove]", function () {
      if (!window.confirm(text("common.confirmDelete"))) return;
      $(this).closest("[data-tool-access]").remove();
      $("[data-tool-editor-host]").empty();
      refreshDomainToolAccessTable();
    });
    $(document).on("click", "[data-tool-editor-cancel]", function () {
      $(this).closest("[data-tool-editor-host]").empty();
    });
    $(document).on("click", "[data-tool-editor-save]", function () {
      const $editor = $(this).closest("[data-tool-editor-form]");
      const record = domainToolAccessRecord($editor, true);
      if (!validDomainToolAccess(record)) {
        $editor.addClass("was-validated");
        showError("Проверьте название, логин, пароль, IP, срок и разрешённые инструменты временного доступа.");
        return;
      }
      const index = Number($editor.attr("data-edit-index"));
      const $rows = $("[data-tool-access-list] [data-tool-access]");
      if (index >= 0 && $rows.eq(index).length) {
        $rows.eq(index).replaceWith(templates.domainToolAccessRow(record, index));
      } else {
        $("[data-tool-access-empty]").before(templates.domainToolAccessRow(record, $rows.length));
      }
      $("[data-tool-editor-host]").empty();
      refreshDomainToolAccessTable();
    });
    $(document).on("click", "[data-domain-logs]", function () { openDomainLogs($(this).data("domain-logs")); });
    $(document).on("click", "[data-domain-permissions]", function () {
      if (!window.confirm("Выставить правильные права всем файлам и папкам этого сайта?")) return;
      const $button = $(this);
      const original = $button.html();
      const iconOnly = $button.is("[data-icon-only]");
      $button.prop("disabled", true).html(iconOnly
        ? '<span class="spinner-border spinner-border-sm"></span>'
        : '<span class="spinner-border spinner-border-sm me-2"></span>Выполняется...');
      apiRequest({ action: "domainPermissions", id: Number($button.data("domain-permissions") || 0) }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        showNotification("Права файлов и папок выставлены.", false);
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).html(original);
      });
    });
    $(document).on("click", "[data-domain-log-file]", function () {
      if (!state.domainLog) return;
      state.domainLog.file = String($(this).data("domain-log-file"));
      state.domainLog.page = 1;
      loadDomainLog();
    });
    $(document).on("click", "[data-domain-log-newer]", function () {
      if (!state.domainLog || state.domainLog.page <= 1) return;
      state.domainLog.page--;
      loadDomainLog();
    });
    $(document).on("click", "[data-domain-log-older]", function () {
      if (!state.domainLog) return;
      state.domainLog.page++;
      loadDomainLog();
    });
    $(document).on("click", "[data-log-details]", function () {
      const $button = $(this);
      const requestId = String($button.data("log-details") || "");
      const detailsAction = String($button.data("log-source") || "logs") === "toolLogs" ? "toolLogDetails" : "rootLogDetails";
      $button.prop("disabled", true).html('<span class="spinner-border spinner-border-sm"></span>');
      apiRequest({ action: detailsAction, requestId: requestId }).done(function (response) {
        if (!response || !response.ok || !response.data) { showError(response && response.error || text("toast.error")); return; }
        $("#modal-root").html(templates.logDetailsModal(response.data));
        translatePage("#modal-root");
        const element = document.getElementById("log-details-modal");
        state.modal = new bootstrap.Modal(element);
        state.modal.show();
        element.addEventListener("hidden.bs.modal", function () { $("#modal-root").empty(); state.modal = null; }, { once: true });
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).html('<i class="bi bi-eye"></i>');
      });
    });
    $(document).on("click", "[data-import]", function () { openImportModal($(this).data("import")); });
    $(document).on("click", "[data-export-domains]", exportDomainsCsv);
    $(document).on("click", "[data-server-diagnostics-refresh]", loadServerDiagnostics);
    $(document).on("click", "[data-apache-vhosts-refresh]", function () { runApacheVhostRefresh($(this)); });
    $(document).on("click", "[data-apache-refresh-rerun]", function () { runApacheVhostRefresh($(this)); });
    $(document).on("click", "[data-apache-disable-domain]", function () {
      const $button = $(this);
      const id = Number($button.data("apache-disable-domain") || 0);
      const domain = String($button.data("domain") || "");
      if (!id || !window.confirm(`Отключить домен ${domain}?`)) return;
      const original = $button.html();
      $button.prop("disabled", true).html('<span class="spinner-border spinner-border-sm me-1"></span>Отключение...');
      $("[data-apache-refresh-rerun]").prop("disabled", true);
      apiRequest({ action: "apacheDisableDomain", id: id }).done(function (response) {
        if (!response || !response.ok) { showError(response && response.error || text("toast.error")); return; }
        renderApacheRefreshReport(response.data || {});
        if (state.table) state.table.ajax.reload(null, false);
        refreshData();
        if (response.data && response.data.ok) showNotification(`Домен ${domain} отключён. Конфигурация Apache обновлена.`, false);
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
        $button.prop("disabled", false).html(original);
      }).always(function () {
        $("[data-apache-refresh-rerun]").prop("disabled", false);
      });
    });
    $(document).on("click", "[data-parse-import]", showImportPreview);
    $(document).on("input change", "[data-import-row] input, [data-import-row] textarea, [data-import-owner]", validateImportPreview);
    $(document).on("click", "[data-regenerate-import-password]", function () {
      $(this).closest("[data-import-row]").find('[data-import-field="password"]').val(generateImportPassword());
      validateImportPreview();
    });
    $(document).on("click", "[data-copy-import-credentials]", function () {
      const input = document.querySelector("[data-import-credentials]");
      if (!input) return;
      input.select();
      document.execCommand("copy");
      showToast("toast.copied");
    });
    $(document).on("click", "[data-accept-import]", function () {
      if (!validateImportPreview()) { showError(text("forms.importFixErrors")); return; }
      const type = $("[data-import-type]").data("import-type");
      const ownerId = importOwnerId();
      const records = state.importRecords.map(function (record) {
        if (type === "domains") return { userId: ownerId, domain: record.domain, path: record.path, useSsl: record.ssl, redirectHttp: record.ssl, redirectWww: record.www };
        const parts = record.email.split("@");
        return { userId: ownerId, mailbox: parts.shift(), domain: parts.join("@"), password: record.password, quota: Number(config.importMailQuotaMb || 20), aliases: record.aliases, forwardTo: record.forwardTo, catchAll: record.catchAll };
      });
      const $button = $(this);
      $button.prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "import", type: type, records: records }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        if (state.modal) state.modal.hide();
        window.setTimeout(function () { reloadCurrentRoute("toast.imported"); }, 250);
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("click", "[data-edit]", function () {
      const type = $(this).data("edit");
      openModal(type, recordFor(type, $(this).data("id")));
    });
    $(document).on("click", "[data-database-configuration]", function () {
      openDatabaseConfiguration($(this).data("database-configuration"));
    });
    $(document).on("click", "[data-database-phpmyadmin]", function () {
      const $button = $(this);
      const popup = window.open("about:blank", "_blank");
      if (popup) popup.opener = null;
      $button.prop("disabled", true);
      apiRequest({ action: "databasePhpMyAdminLaunch", id: Number($button.data("database-phpmyadmin") || 0) }).done(function (response) {
        const url = response && response.ok && response.data ? String(response.data.url || "") : "";
        if (!url) {
          if (popup) popup.close();
          showError(response && response.error || text("toast.error"));
          return;
        }
        if (popup) popup.location.replace(url);
        else window.open(url, "_blank", "noopener,noreferrer");
      }).fail(function (xhr) {
        if (popup) popup.close();
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false);
      });
    });
    $(document).on("click", "[data-domain-panel-tool]", function () {
      const $button = $(this);
      const popup = window.open("about:blank", "_blank");
      if (popup) popup.opener = null;
      $button.prop("disabled", true);
      apiRequest({
        action: "domainPanelToolLaunch",
        tool: String($button.data("domain-panel-tool") || ""),
        id: Number($button.data("id") || 0)
      }).done(function (response) {
        const url = response && response.ok && response.data ? String(response.data.url || "") : "";
        if (!url) {
          if (popup) popup.close();
          showError(response && response.error || text("toast.error"));
          return;
        }
        if (popup) popup.location.replace(url);
        else window.open(url, "_blank", "noopener,noreferrer");
      }).fail(function (xhr) {
        if (popup) popup.close();
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false);
      });
    });
    $(document).on("click", "[data-mail-configuration]", function () {
      openMailConfiguration($(this).data("mail-configuration"));
    });
    $(document).on("click", "[data-preview-action]", function () {
      const action = $(this).data("preview-action");
      const id = Number($(this).data("id") || 0);
      if (action === "refresh") {
        reloadCurrentRoute("toast.refreshed");
        return;
      }
      if (action === "delete" && !window.confirm(text(state.route === "domains" ? "common.confirmDeleteDomain" : "common.confirmDelete"))) return;
      const apiAction = action === "password" ? "resetPassword" : action;
      apiRequest({ action: apiAction, type: state.route, id: id }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        if (action === "password") {
          reloadCurrentRoute("toast.saved");
        } else {
          reloadCurrentRoute(action === "delete" ? "toast.deleted" : "toast.toggled");
        }
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); });
    });
    $(document).on("click", "[data-verify]", function () {
      const $button = $(this);
      const kind = $button.data("verify");
      const $result = $(`[data-verification-results="${kind}"]`);
      const $form = $("#entity-form");
      const domain = $form.find('[name="domain"]').val();
      $button.prop("disabled", true).html(`<span class="spinner-border spinner-border-sm me-1"></span><span translate="common.checking"></span>`);
      translatePage($button);
      apiRequest({ action: "verify", kind: kind, domain: domain }, "POST", {
        timeout: Number(config.dnsVerifyRequestTimeoutMs) || 20000
      }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        $result.html(verificationMarkup(kind, response.data)).removeClass("d-none");
        translatePage($("#entity-modal"));
        if (config.role === "root") showToast("toast.verificationDone");
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $button.prop("disabled", false).html(`<i class="bi bi-arrow-repeat me-1"></i><span translate="common.check"></span>`);
        translatePage($button);
      });
    });
    $(document).on("input change", '#entity-form[data-entity="domains"] [name="domain"]', updateDnsRecords);
    $(document).on("blur", '#entity-form[data-entity="domains"] [name="domain"]', function () { loadDnsProviderState(false); });
    $(document).on("click", "[data-detect-dns-provider]", function () { loadDnsProviderState(false); });
    $(document).on("click", "[data-verify-dns-access]", function () { verifyDnsProviderAccess(true); });
    $(document).on("click", "[data-toggle-recommended-dns]", function () {
      const $button = $(this);
      const $preview = $button.siblings("[data-dns-recommended-preview]");
      const opening = $preview.hasClass("d-none");
      $preview.toggleClass("d-none", !opening);
      $button.attr("aria-expanded", opening ? "true" : "false").find("i").attr("class", `bi bi-chevron-${opening ? "up" : "down"} me-1`);
    });
    $(document).on("click", "[data-toggle-all-required-dns]", function () {
      const $button = $(this);
      const $panel = $button.closest(".dns-requirements").find("[data-all-required-dns]");
      const opening = $panel.hasClass("d-none");
      $panel.toggleClass("d-none", !opening);
      $button.attr("aria-expanded", opening ? "true" : "false");
      $button.find("strong").attr("translate", opening ? "forms.hideAllDnsRecords" : "forms.showAllDnsRecords");
      translatePage($button);
      if (opening) loadAllRequiredDnsRecords();
    });
    $(document).on("change", "[data-domain-dns-connection]", function () {
      const $section = $(this).closest("[data-dns-management]");
      $section.find("[data-apply-recommended-dns]").addClass("d-none").prop("disabled", true);
      $section.find("[data-add-dns-record]").prop("disabled", true);
    });
    $(document).on("click", "[data-apply-recommended-dns]", function () {
      if (!window.confirm(text("dns.confirmRecommended"))) return;
      const $button = $(this);
      const context = domainDnsContext();
      $button.prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-1"></span>');
      apiRequest($.extend({ action: "dnsApplyRecommended" }, context)).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        showToast("dns.recommendedSaved");
        if (context.domainId) loadDnsApiRecords();
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); }).always(function () {
        $button.prop("disabled", false).find(".spinner-border").remove();
      });
    });
    $(document).on("click", "[data-add-dns-record]", function () {
      const $section = $(this).closest("[data-dns-management]");
      const types = $section.data("dns-types") || ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV"];
      $section.find("[data-dns-api-records] .text-secondary").remove();
      $section.find("[data-dns-api-records]").prepend(templates.dnsRecordRow({ name: "@", type: "A", ttl: Number($section.data("dns-default-ttl") || 3600), values: [""] }, types, true));
      translatePage($section);
    });
    $(document).on("click", "[data-cancel-dns-record]", function () { $(this).closest("[data-dns-api-record]").remove(); });
    $(document).on("click", "[data-save-dns-record]", function () {
      const $button = $(this);
      const $row = $button.closest("[data-dns-api-record]");
      const context = domainDnsContext();
      $button.prop("disabled", true).html('<span class="spinner-border spinner-border-sm"></span>');
      apiRequest($.extend({ action: "dnsRecordSave", record: dnsRecordPayload($row) }, context)).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        showToast("toast.saved");
        loadDnsApiRecords();
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); }).always(function () {
        $button.prop("disabled", false).html('<i class="bi bi-check-lg"></i>');
      });
    });
    $(document).on("click", "[data-delete-dns-record]", function () {
      if (!window.confirm(text("dns.confirmDelete"))) return;
      const $button = $(this);
      const $row = $button.closest("[data-dns-api-record]");
      const context = domainDnsContext();
      $button.prop("disabled", true).html('<span class="spinner-border spinner-border-sm"></span>');
      apiRequest($.extend({ action: "dnsRecordDelete", name: String($row.data("dns-original-name") || ""), type: String($row.data("dns-original-type") || "") }, context)).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        showToast("toast.deleted");
        loadDnsApiRecords();
      }).fail(function (xhr) { showError((xhr.responseJSON || {}).error || text("toast.error")); }).always(function () {
        $button.prop("disabled", false).html('<i class="bi bi-trash"></i>');
      });
    });
    $(document).on("change", '#entity-form[data-entity="domains"] [name="projectPathMode"]', updateProjectFolderMode);
    $(document).on("change", '#entity-form[data-entity="domains"] [data-domain-owner]', function () { updateProjectFolderOptions(false); loadDnsProviderState(false); });
    $(document).on("input change", '#entity-form[data-entity="domains"] [data-existing-project], #entity-form[data-entity="domains"] [data-project-folder]', function () {
      if ($(this).is("[data-project-folder]")) $(this).val(String($(this).val() || "").toLowerCase());
      if ($(this).is("[data-existing-project]")) validateExistingProjectPath();
      updateProjectPathPreview();
    });
    $(document).on("input", '#entity-form[data-entity="domains"] [name="domain"]', function () {
      const $folder = $("#entity-form [data-project-folder]");
      const previousAuto = String($folder.data("auto-value") || "");
      if (!$folder.val() || $folder.val() === previousAuto) {
        const next = String($(this).val() || "").trim().toLowerCase();
        $folder.val(next).data("auto-value", next);
      }
      updateProjectPathPreview();
    });
    $(document).on("input", '#entity-form[data-entity="users"] [name="prefix"]', function () {
      $(this).val(String($(this).val() || "").toLowerCase());
      updateUserRootPath();
    });
    $(document).on("input", '#entity-form [data-user-password]', updateUserPasswordFeedback);
    $(document).on("change", '#entity-form [name="ipAccessEnabled"]', updateProfileIpAccess);
    $(document).on("click", "[data-profile-current-ip]", function () {
      const $input = $(this).closest("[data-profile-ip-access]").find('[name="allowedIps"]');
      const values = String($input.val() || "").split(/[\s,;]+/).filter(Boolean);
      if (config.clientIp && !values.includes(config.clientIp)) values.push(config.clientIp);
      $input.val(values.join("\n")).trigger("input");
    });
    $(document).on("click", "[data-copy-dns]", function () {
      const $record = $(this).closest("[data-dns-record]");
      const target = String($(this).data("copy-dns") || "value");
      const content = $record.find(target === "name" ? "[data-dns-name]" : "[data-dns-value]").text();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(content).then(function () { showToast("toast.copied"); });
      } else {
        const $temporary = $("<textarea>").val(content).appendTo("body").select();
        document.execCommand("copy");
        $temporary.remove();
        showToast("toast.copied");
      }
    });
    $(document).on("click", "[data-copy-required-dns]", function () {
      const content = String($(this).attr("data-copy-required-dns") || "");
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(content).then(function () { showToast("toast.copied"); });
      } else {
        const $temporary = $("<textarea>").val(content).appendTo("body").select();
        document.execCommand("copy");
        $temporary.remove();
        showToast("toast.copied");
      }
    });
    $(document).on("submit", "#entity-form", function (event) {
      event.preventDefault();
      if ($(this).find("[data-tool-editor-form]").length) {
        showError("Сначала добавьте или отмените открытую запись временного доступа.");
        return;
      }
      if (!this.checkValidity()) { this.classList.add("was-validated"); return; }
      const $form = $(this);
      const type = $form.data("entity");
      if (type === "profile" && $form.find("[data-dns-connection-editor]").length) {
        showError(text("dns.finishConnectionEdit"));
        return;
      }
      const record = formRecord($form);
      if (type === "profile") record.dnsConnections = collectDnsConnections();
      if (type === "profile" && String(record.password || "") !== String(record.passwordConfirmation || "")) {
        showError(text("profile.passwordMismatch"));
        return;
      }
      if (type === "domains" && Number(record.id || 0) > 0) {
        const toolAccesses = collectDomainToolAccesses();
        if (!toolAccesses.valid) {
          showError("Проверьте название, логин, пароль, IP и разрешённые инструменты временного доступа.");
          return;
        }
        record.toolAccesses = toolAccesses.accesses;
      }
      if (type === "users") {
        const prefix = String(record.prefix || "").trim().toLowerCase();
        const userId = Number(record.id || 0);
        const prefixUsed = (state.data.users || []).some(function (user) {
          return Number(user.id || 0) !== userId && String(user.prefix || "").trim().toLowerCase() === prefix;
        });
        if (prefixUsed) {
          showError("Такой префикс используется");
          return;
        }
      }
      const $submit = $form.find('[type="submit"]');
      $submit.prop("disabled", true).prepend('<span class="spinner-border spinner-border-sm me-2"></span>');
      apiRequest({ action: "save", type: type, record: record }).done(function (response) {
        if (!response.ok) { showError(response.error); return; }
        const warnings = response.data && Array.isArray(response.data.warnings) ? response.data.warnings : [];
        if (state.modal) state.modal.hide();
        if (type === "profile") {
          window.setTimeout(function () { window.location.reload(); }, 250);
          return;
        }
        window.setTimeout(function () { reloadCurrentRoute("toast.saved", warnings); }, 250);
      }).fail(function (xhr) {
        showError((xhr.responseJSON || {}).error || text("toast.error"));
      }).always(function () {
        $submit.prop("disabled", false).find(".spinner-border").remove();
      });
    });
  }

  function start() {
    bindEvents();
    $(document).on("visibilitychange", function () {
      if (document.hidden) {
        pageHiddenAt = Date.now();
        return;
      }
      if (!config.isAuthenticated || !pageHiddenAt || Date.now() - pageHiddenAt < 300000) {
        pageHiddenAt = 0;
        return;
      }
      pageHiddenAt = 0;
      refreshCsrfToken().fail(function (xhr) {
        if (xhr && Number(xhr.status) === 401) reloadExpiredSession();
      });
    });
    $.getJSON(`assets/data/languages.json?v=${encodeURIComponent(config.assetVersion || "1")}`).done(function (languages) {
      state.languages = Array.isArray(languages) ? languages : [];
      if (!state.languages.some(function (item) { return item.code === state.language; })) state.language = config.defaultLanguage || "ru";
      $.when(loadTranslation("en"), loadTranslation(state.language)).done(function () {
        if (config.isAuthenticated) {
          refreshData().done(function () {
            $("#app").html(templates.shell(config));
            renderRoute(routeFromHash());
            updateLanguageButton();
            window.setTimeout(function () { $("#app-loader").addClass("is-hidden"); }, 250);
          }).fail(function (xhr) {
            $("#app-loader small").text((xhr.responseJSON || {}).error || "Failed to load API data");
          });
        } else {
          $("#app").html(templates.login(config));
          translatePage(document);
          updateLanguageButton();
          window.setTimeout(function () { $("#app-loader").addClass("is-hidden"); }, 250);
        }
      }).fail(function () {
        $("#app-loader small").text("Failed to load local translation data");
      });
    }).fail(function () {
      $("#app-loader small").text("Failed to load local language list");
    });
  }

  $(start);
})(window, jQuery);
