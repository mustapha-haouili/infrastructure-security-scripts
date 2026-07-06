(function () {
  "use strict";

  const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info", "Hold"];
  const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((item, index) => [item, index]));
  const SCOPES = ["AD", "Host", "Server", "Workstation", "Network"];

  const state = {
    files: [],
    findings: [],
    correlations: [],
    historyComparison: null,
    coverage: null,
    selectedId: "",
    filters: {
      query: "",
      scope: "All",
      machine: "All",
      severity: "All",
      source: "All",
      objectType: "All",
      status: "All",
    },
  };

  const elements = {
    folderInput: document.getElementById("folderInput"),
    fileInput: document.getElementById("fileInput"),
    openFolderButton: document.getElementById("openFolderButton"),
    openFilesButton: document.getElementById("openFilesButton"),
    loadSampleButton: document.getElementById("loadSampleButton"),
    workspaceStatus: document.getElementById("workspaceStatus"),
    searchInput: document.getElementById("searchInput"),
    scopeFilter: document.getElementById("scopeFilter"),
    machineFilter: document.getElementById("machineFilter"),
    severityFilter: document.getElementById("severityFilter"),
    sourceFilter: document.getElementById("sourceFilter"),
    objectFilter: document.getElementById("objectFilter"),
    statusFilter: document.getElementById("statusFilter"),
    sourceList: document.getElementById("sourceList"),
    metricTotal: document.getElementById("metricTotal"),
    metricFiles: document.getElementById("metricFiles"),
    metricCritical: document.getElementById("metricCritical"),
    metricHigh: document.getElementById("metricHigh"),
    metricLinked: document.getElementById("metricLinked"),
    visibleCount: document.getElementById("visibleCount"),
    relationCount: document.getElementById("relationCount"),
    historyStatus: document.getElementById("historyStatus"),
    historySummary: document.getElementById("historySummary"),
    coverageStatus: document.getElementById("coverageStatus"),
    coverageSummary: document.getElementById("coverageSummary"),
    severityBars: document.getElementById("severityBars"),
    relationList: document.getElementById("relationList"),
    findingsTable: document.getElementById("findingsTable"),
    detailPanel: document.getElementById("detailPanel"),
    clearFiltersButton: document.getElementById("clearFiltersButton"),
    detailTemplate: document.getElementById("detailTemplate"),
  };

  function initialize() {
    elements.openFolderButton.addEventListener("click", () => elements.folderInput.click());
    elements.openFilesButton.addEventListener("click", () => elements.fileInput.click());
    elements.loadSampleButton.addEventListener("click", loadSampleData);
    elements.folderInput.addEventListener("change", (event) => readSelectedFiles(event.target.files));
    elements.fileInput.addEventListener("change", (event) => readSelectedFiles(event.target.files));
    elements.searchInput.addEventListener("input", (event) => {
      state.filters.query = event.target.value.trim();
      render();
    });
    elements.scopeFilter.addEventListener("change", (event) => {
      state.filters.scope = event.target.value;
      render();
    });
    elements.machineFilter.addEventListener("change", (event) => {
      state.filters.machine = event.target.value;
      render();
    });
    elements.severityFilter.addEventListener("change", (event) => {
      state.filters.severity = event.target.value;
      render();
    });
    elements.sourceFilter.addEventListener("change", (event) => {
      state.filters.source = event.target.value;
      render();
    });
    elements.objectFilter.addEventListener("change", (event) => {
      state.filters.objectType = event.target.value;
      render();
    });
    elements.statusFilter.addEventListener("change", (event) => {
      state.filters.status = event.target.value;
      render();
    });
    elements.clearFiltersButton.addEventListener("click", clearFilters);
    render();
  }

  async function readSelectedFiles(fileList) {
    const jsonFiles = Array.from(fileList || []).filter((file) => file.name.toLowerCase().endsWith(".json"));
    const parsedFiles = [];
    const findings = [];
    const officialCorrelations = [];
    let officialHistory = null;
    let officialCoverage = null;

    for (const [fileIndex, file] of jsonFiles.entries()) {
      const path = file.webkitRelativePath || file.name;
      try {
        const data = JSON.parse(await file.text());
        const record = buildFileRecord(file, path, data);
        record.findingCount = 0;
        parsedFiles.push(record);
        const extracted = extractFindings(data, record, fileIndex + 1);
        officialCorrelations.push(...extractOfficialCorrelations(data, record, fileIndex + 1));
        if (!officialHistory && data && typeof data.history_comparison === "object" && !Array.isArray(data.history_comparison)) {
          officialHistory = data.history_comparison;
        }
        if (!officialCoverage) {
          officialCoverage = extractCoverage(data, record);
        }
        record.findingCount = extracted.length;
        findings.push(...extracted);
      } catch (error) {
        parsedFiles.push({
          name: file.name,
          path,
          kind: "Invalid JSON",
          reportType: "parse-error",
          generatedAt: "",
          domain: "",
          summary: {},
          findingCount: 0,
          error: error.message,
        });
      }
    }

    state.files = parsedFiles;
    state.findings = enrichFindings(findings);
    state.correlations = normalizeOfficialCorrelations(officialCorrelations, state.findings);
    state.historyComparison = normalizeHistoryComparison(officialHistory);
    state.coverage = officialCoverage || null;
    state.selectedId = state.findings[0]?.dashboard_id || "";
    resetFilters();
    render();
  }

  function buildFileRecord(file, path, data) {
    const metadata = objectValue(data.ReportMetadata) || objectValue(data.metadata) || {};
    const normalized = Array.isArray(data.findings) && typeof data.report_id === "string";
    const reportType = stringValue(data.report_type || metadata.ReportType || data.ReportType || inferReportType(data, file.name));
    const summary = objectValue(data.summary) || objectValue(data.Summary) || {};
    return {
      name: file.name,
      path,
      kind: normalized ? "Normalized report" : "Source JSON",
      reportType,
      generatedAt: stringValue(data.generated_at_utc || data.GeneratedAtUtc || metadata.GeneratedAtUtc),
      domain: stringValue(data.environment_summary?.domain || data.Domain || data.DomainName || metadata.Domain || metadata.DomainName),
      machineName: stringValue(data.environment_summary?.computer_name || data.ComputerName || metadata.ComputerName),
      scope: inferScope(data, path, reportType),
      summary,
      findingCount: 0,
    };
  }

  function inferReportType(data, name) {
    const lower = name.toLowerCase();
    if (Array.isArray(data.InactiveUsers) || lower.includes("inactive")) return "ad-inactive-users";
    if (Array.isArray(data.PasswordNeverExpiresAccounts) || lower.includes("password-never-expires")) return "ad-password-never-expires";
    if (Array.isArray(data.ServiceAccounts) || lower.includes("service-account")) return "ad-service-accounts";
    if (Array.isArray(data.SPNAccounts) || lower.includes("spn")) return "ad-spn-exposure";
    if (Array.isArray(data.StaleComputers) || lower.includes("stale-computer")) return "ad-stale-computers";
    if (Array.isArray(data.Changes) || lower.includes("privileged-group")) return "ad-privileged-groups";
    if (Array.isArray(data.Findings) && lower.includes("gpo")) return "gpo-health";
    if (Array.isArray(data.Findings)) return "source-findings";
    return "json";
  }

  function extractFindings(data, fileRecord, fileIndex) {
    if (Array.isArray(data.findings)) {
      return data.findings.map((finding, index) => normalizeFinding(finding, fileRecord, fileIndex, index + 1, true));
    }

    const configs = [
      { key: "Findings", label: "Source finding", category: "Source Report", objectType: "Source finding" },
      { key: "InactiveUsers", label: "Inactive account", category: "Active Directory Security", objectType: "Active Directory user" },
      { key: "PasswordNeverExpiresAccounts", label: "PasswordNeverExpires account", category: "Active Directory Security", objectType: "Active Directory user" },
      { key: "ServiceAccounts", label: "Service account", category: "Active Directory Security", objectType: "Active Directory service account" },
      { key: "SPNAccounts", label: "SPN-bearing account", category: "Active Directory Security", objectType: "Active Directory SPN account" },
      { key: "StaleComputers", label: "Stale computer", category: "Active Directory Security", objectType: "Active Directory computer" },
      { key: "Changes", label: "Privileged group change", category: "Active Directory Security", objectType: "Active Directory privileged group membership" },
    ];

    const findings = [];
    for (const config of configs) {
      const rows = data[config.key];
      if (!Array.isArray(rows)) continue;
      rows.forEach((row, index) => {
        findings.push(sourceRowToFinding(row, config, fileRecord, fileIndex, index + 1));
      });
    }
    return findings;
  }

  function extractOfficialCorrelations(data, fileRecord, fileIndex) {
    if (!Array.isArray(data.correlations)) return [];
    return data.correlations.map((correlation, index) => ({
      ...correlation,
      dashboard_correlation_id: `${fileIndex}:${index + 1}:${correlation.correlation_id || "correlation"}`,
      source_file: fileRecord.path,
    }));
  }

  function normalizeFinding(finding, fileRecord, fileIndex, index, normalized) {
    const evidence = objectValue(finding.evidence) || {};
    const severity = normalizeSeverity(finding.severity || evidence.severity || evidence.review_priority);
    const id = stringValue(finding.finding_id || `${normalized ? "NORM" : "SRC"}-${fileIndex}-${index}`);
    const normalizedFinding = {
      dashboard_id: `${fileIndex}:${index}:${id}`,
      finding_id: id,
      title: stringValue(finding.title || "Finding requires review"),
      category: stringValue(finding.category || "Security Review"),
      severity,
      affected_object: stringValue(finding.affected_object || evidence.sam_account_name || evidence.subject || evidence.gpo_name || `finding-${index}`),
      object_type: stringValue(finding.object_type || "Security object"),
      source_script: stringValue(finding.source_script || fileRecord.reportType || fileRecord.name),
      evidence,
      risk_factors: arrayValue(finding.risk_factors),
      business_impact: stringValue(finding.business_impact),
      technical_impact: stringValue(finding.technical_impact),
      recommendation: stringValue(finding.recommendation || evidence.recommendation || evidence.admin_action || "Review evidence and validate ownership before change."),
      remediation_priority: stringValue(finding.remediation_priority || priorityFor(severity)),
      requires_owner_review: Boolean(finding.requires_owner_review ?? true),
      requires_change_approval: Boolean(finding.requires_change_approval ?? ["Critical", "High", "Medium", "Hold"].includes(severity)),
      safe_to_auto_remediate: Boolean(finding.safe_to_auto_remediate ?? false),
      not_safe_for_auto_remediation_reason: stringValue(finding.not_safe_for_auto_remediation_reason || "Human review and approved change control are required."),
      status: stringValue(finding.status || "Open"),
      timestamp_utc: stringValue(finding.timestamp_utc || fileRecord.generatedAt),
      source_file: fileRecord.path,
      source_kind: normalized ? "normalized" : "source",
      scope: normalizeScope(finding.scope || evidence.scope || inferScopeFromFinding(finding, fileRecord)),
      machine_name: stringValue(finding.machine_name || evidence.machine_name || evidence.computer_name || fileRecord.machineName),
    };
    normalizedFinding.related_keys = relatedKeys(normalizedFinding);
    return normalizedFinding;
  }

  function sourceRowToFinding(row, config, fileRecord, fileIndex, index) {
    const evidence = compactEvidence(row);
    const severity = normalizeSeverity(row.Severity || row.ReviewPriority || row.ExposurePriority || row.ActionPriority);
    const affected = firstPresent(row, [
      "SamAccountName",
      "Subject",
      "Name",
      "DNSHostName",
      "GpoName",
      "DisplayName",
      "MemberSamAccountName",
      "MemberName",
      "GroupName",
      "TargetPath",
    ]) || `${config.label.toLowerCase().replace(/\s+/g, "-")}-${index}`;
    return normalizeFinding(
      {
        finding_id: `SRC-${fileIndex}-${index}`,
        title: stringValue(row.Title || row.FindingType || row.ChangeType || `${config.label} requires review`),
        category: config.category,
        severity,
        affected_object: affected,
        object_type: config.objectType,
        source_script: fileRecord.reportType,
        evidence,
        risk_factors: riskFactorsFromRow(row),
        recommendation: stringValue(row.Recommendation || row.AdminAction || row.RecommendedAction || "Review source evidence and validate owner approval."),
        remediation_priority: priorityFor(severity),
        status: "Open",
        timestamp_utc: fileRecord.generatedAt,
      },
      fileRecord,
      fileIndex,
      index,
      false
    );
  }

  function compactEvidence(row) {
    const evidence = {};
    Object.entries(row || {}).forEach(([key, value]) => {
      if (value === null || value === undefined || value === "") return;
      if (Array.isArray(value) && value.length === 0) return;
      if (typeof value === "object" && !Array.isArray(value)) return;
      evidence[toSnakeCase(key)] = value;
    });
    return evidence;
  }

  function enrichFindings(findings) {
    return findings
      .map((finding) => ({ ...finding, related_keys: relatedKeys(finding) }))
      .sort((a, b) => {
        const severityDelta = (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99);
        if (severityDelta !== 0) return severityDelta;
        return a.finding_id.localeCompare(b.finding_id);
      });
  }

  function render() {
    const visible = filteredFindings();
    const groups = relationGroups();
    renderWorkspace();
    renderFilters();
    renderSources();
    renderMetrics(visible, groups);
    renderSeverityBars(visible);
    renderRelations(groups);
    renderCoverage();
    renderHistory();
    renderTable(visible);
    renderDetail();
  }

  function renderWorkspace() {
    const jsonCount = state.files.length;
    const findingCount = state.findings.length;
    elements.workspaceStatus.textContent = jsonCount
      ? `${jsonCount} JSON file${jsonCount === 1 ? "" : "s"} loaded, ${findingCount} finding${findingCount === 1 ? "" : "s"} indexed`
      : "No report files loaded";
  }

  function renderFilters() {
    setOptions(elements.scopeFilter, ["All", ...unique([...state.findings.map((item) => item.scope), ...missingScopeOptions()])], state.filters.scope);
    setOptions(elements.machineFilter, ["All", ...unique([...state.findings.map((item) => item.machine_name), ...coverageMachineOptions()])], state.filters.machine);
    setOptions(elements.severityFilter, ["All", ...SEVERITIES], state.filters.severity);
    setOptions(elements.sourceFilter, ["All", ...unique(state.findings.map((item) => item.source_script))], state.filters.source);
    setOptions(elements.objectFilter, ["All", ...unique(state.findings.map((item) => item.object_type))], state.filters.objectType);
    setOptions(elements.statusFilter, ["All", ...unique(state.findings.map((item) => item.status))], state.filters.status);
    if (elements.searchInput.value !== state.filters.query) {
      elements.searchInput.value = state.filters.query;
    }
  }

  function renderSources() {
    elements.sourceList.replaceChildren();
    if (!state.files.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No JSON files loaded.";
      elements.sourceList.appendChild(empty);
      return;
    }
    state.files.forEach((file) => {
      const item = document.createElement("div");
      item.className = "source-item";
      const machine = file.machineName ? ` - ${file.machineName}` : "";
      item.append(
        textElement("strong", file.name),
        textElement(
          "span",
          `${file.scope || "Unknown"} - ${file.reportType}${machine} - ${file.findingCount} finding${file.findingCount === 1 ? "" : "s"}`
        )
      );
      if (file.error) {
        const error = document.createElement("span");
        error.textContent = file.error;
        item.appendChild(error);
      }
      elements.sourceList.appendChild(item);
    });
  }

  function renderMetrics(visible, groups) {
    const counts = severityCounts(visible);
    elements.metricTotal.textContent = String(visible.length);
    elements.metricFiles.textContent = `${state.files.length} JSON file${state.files.length === 1 ? "" : "s"}`;
    elements.metricCritical.textContent = String(counts.Critical || 0);
    elements.metricHigh.textContent = String(counts.High || 0);
    elements.metricLinked.textContent = String(groups.length);
    elements.visibleCount.textContent = `${visible.length} visible`;
    elements.relationCount.textContent = `${groups.length} group${groups.length === 1 ? "" : "s"}`;
  }

  function renderSeverityBars(visible) {
    elements.severityBars.replaceChildren();
    const counts = severityCounts(visible);
    const max = Math.max(1, ...Object.values(counts));
    SEVERITIES.forEach((severity) => {
      const row = document.createElement("div");
      row.className = "bar-row";
      const count = counts[severity] || 0;
      row.innerHTML = `
        <span>${severity}</span>
        <div class="bar-track"><div class="bar-fill severity-fill-${severity}" style="width: ${(count / max) * 100}%"></div></div>
        <strong>${count}</strong>
      `;
      const fill = row.querySelector(".bar-fill");
      fill.style.background = severityColor(severity);
      elements.severityBars.appendChild(row);
    });
  }

  function renderRelations(groups) {
    elements.relationList.replaceChildren();
    if (!groups.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No linked objects yet.";
      elements.relationList.appendChild(empty);
      return;
    }
    groups.slice(0, 14).forEach((group) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "relation-chip";
      button.textContent = `${group.label} (${group.count})`;
      button.title = group.rationale || "Related findings";
      button.addEventListener("click", () => {
        state.filters.query = group.label;
        render();
      });
      elements.relationList.appendChild(button);
    });
  }

  function renderHistory() {
    elements.historySummary.replaceChildren();
    const history = state.historyComparison;
    if (!history) {
      elements.historyStatus.textContent = "No baseline";
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "Load a normalized report generated with --previous-normalized-report to see trend data.";
      elements.historySummary.appendChild(empty);
      return;
    }

    elements.historyStatus.textContent = history.previous_generated_at_utc
      ? `Compared with ${history.previous_generated_at_utc}`
      : "Baseline loaded";

    elements.historySummary.appendChild(historyStat("New", history.new_count, "new"));
    elements.historySummary.appendChild(historyStat("Persistent", history.persistent_count, "persistent"));
    elements.historySummary.appendChild(historyStat("Resolved", history.resolved_count, "resolved"));
    elements.historySummary.appendChild(historyStat("Previous", fileName(history.previous_source_file) || history.previous_report_id, "previous"));

    if (history.resolved_findings.length) {
      const resolved = document.createElement("div");
      resolved.className = "history-resolved";
      const heading = document.createElement("strong");
      heading.textContent = "Resolved since previous run";
      resolved.appendChild(heading);
      history.resolved_findings.slice(0, 5).forEach((finding) => {
        const item = document.createElement("span");
        item.textContent = `${finding.finding_id} - ${finding.title}`;
        resolved.appendChild(item);
      });
      elements.historySummary.appendChild(resolved);
    }
  }

  function historyStat(label, value, className) {
    const item = document.createElement("div");
    item.className = `history-stat ${className}`;
    const labelNode = document.createElement("span");
    labelNode.textContent = label;
    const valueNode = document.createElement("strong");
    valueNode.textContent = String(value ?? "Not provided");
    item.append(labelNode, valueNode);
    return item;
  }

  function renderCoverage() {
    elements.coverageSummary.replaceChildren();
    const coverage = state.coverage;
    if (!coverage) {
      elements.coverageStatus.textContent = "No bundle";
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No client-bundle coverage metadata loaded.";
      elements.coverageSummary.appendChild(empty);
      return;
    }

    elements.coverageStatus.textContent = coverage.status;
    const overview = document.createElement("div");
    overview.className = "coverage-overview";
    overview.appendChild(coverageStatusCard(coverage));
    coverage.scopeRows.forEach((row) => overview.appendChild(coverageScopeCard(row)));
    elements.coverageSummary.appendChild(overview);

    if (coverage.machineRows?.length) {
      elements.coverageSummary.appendChild(fleetMachineCards(coverage.machineRows));
    }

    const issues = coverageIssues(coverage);
    const issueWrap = document.createElement("div");
    issueWrap.className = "coverage-issues";
    if (!issues.length) {
      const item = document.createElement("span");
      item.className = "coverage-note ok";
      item.textContent = "No missing or failed files for selected scopes.";
      issueWrap.appendChild(item);
    } else {
      issues.slice(0, 8).forEach((issue) => {
        const item = document.createElement("span");
        item.className = `coverage-note ${issue.kind}`;
        item.textContent = issue.text;
        issueWrap.appendChild(item);
      });
    }
    elements.coverageSummary.appendChild(issueWrap);
  }

  function coverageStatusCard(coverage) {
    const card = document.createElement("article");
    card.className = `coverage-card status-${coverage.statusClass}`;
    card.append(
      textElement("span", "Quality"),
      textElement("strong", coverage.status),
      textElement("small", coverage.collectionId || coverage.computerName || "Client bundle")
    );
    return card;
  }

  function coverageScopeCard(row) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = `coverage-card scope-card ${row.statusClass}`;
    const detail = row.machineCount
      ? `${row.status} - ${row.collectedCount}/${row.machineCount} collected - ${row.fileCount} files`
      : `${row.status} - ${row.fileCount} file${row.fileCount === 1 ? "" : "s"}`;
    card.append(
      textElement("span", row.scope),
      textElement("strong", row.findingCount),
      textElement("small", detail)
    );
    card.addEventListener("click", () => {
      state.filters.scope = row.scope;
      render();
    });
    return card;
  }

  function fleetMachineCards(machineRows) {
    const wrap = document.createElement("div");
    wrap.className = "fleet-machines";
    machineRows.slice(0, 8).forEach((machine) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `machine-card ${machine.statusClass}`;
      button.append(
        textElement("span", machine.coverageStatus),
        textElement("strong", machine.machineName),
        textElement("small", `${machine.findingCount} findings - ${machine.critical} Critical - ${machine.high} High`)
      );
      button.addEventListener("click", () => {
        state.filters.machine = machine.machineName;
        render();
      });
      wrap.appendChild(button);
    });
    return wrap;
  }

  function coverageIssues(coverage) {
    const issues = [];
    if (coverage.mode === "fleet") {
      coverage.failedBundles.forEach((item) => issues.push({ kind: "failed", text: `Bundle failed: ${fileName(item.input) || item.input}` }));
      coverage.skippedBundles.forEach((item) => issues.push({ kind: "partial", text: `Skipped duplicate: ${fileName(item.input) || item.input}` }));
      coverage.coverageMatrix
        .filter((row) => row.status === "Failed" || row.status === "Needs rerun")
        .forEach((row) => {
          const detail = row.requiredMissing.length ? `missing ${row.requiredMissing.join(", ")}` : row.status;
          issues.push({ kind: row.status === "Failed" ? "failed" : "rerun", text: `${row.machineName} ${row.scope}: ${detail}` });
        });
      if (!issues.length) {
        coverage.machineRows
          .filter((row) => row.coverageStatus !== "Complete")
          .forEach((row) => issues.push({ kind: "partial", text: `${row.machineName}: ${row.coverageStatus}` }));
      }
      return issues;
    }
    coverage.scopeRows.forEach((row) => {
      if (!row.selected) {
        issues.push({ kind: "partial", text: `${row.scope}: not collected` });
      }
      row.requiredMissing.forEach((item) => issues.push({ kind: "rerun", text: `${row.scope}: missing ${item}` }));
    });
    coverage.failedFiles.forEach((item) => issues.push({ kind: "failed", text: `Failed: ${item.key}` }));
    return issues;
  }

  function renderTable(visible) {
    elements.findingsTable.replaceChildren();
    if (!visible.length) {
      const row = document.createElement("tr");
      const cell = textElement("td", "No findings match the current scope.", "empty-state");
      cell.colSpan = 5;
      row.appendChild(cell);
      elements.findingsTable.appendChild(row);
      return;
    }
    visible.forEach((finding) => {
      const row = document.createElement("tr");
      row.className = finding.dashboard_id === state.selectedId ? "active" : "";
      const historyStatus = historyStatusForFinding(finding);
      const severityCell = document.createElement("td");
      const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "Info";
      severityCell.appendChild(textElement("span", severity, `severity-pill severity-${severity}`));

      const findingCell = document.createElement("td");
      findingCell.append(
        textElement("span", finding.title, "finding-title"),
        textElement("span", finding.finding_id, "finding-id")
      );
      if (historyStatus) {
        findingCell.appendChild(textElement("span", historyStatus, `history-badge ${historyClass(historyStatus)}`));
      }

      const objectCell = document.createElement("td");
      objectCell.append(
        document.createTextNode(finding.affected_object),
        textElement("span", finding.object_type, "cell-muted")
      );

      const sourceCell = document.createElement("td");
      sourceCell.append(
        textElement("span", finding.scope || "Unknown", "scope-tag"),
        document.createTextNode(finding.source_script),
        textElement("span", finding.machine_name || fileName(finding.source_file), "cell-muted"),
        textElement("span", fileName(finding.source_file), "cell-muted")
      );

      row.append(
        severityCell,
        findingCell,
        objectCell,
        sourceCell,
        textElement("td", finding.status)
      );
      row.addEventListener("click", () => {
        state.selectedId = finding.dashboard_id;
        render();
      });
      elements.findingsTable.appendChild(row);
    });
  }

  function renderDetail() {
    const finding = state.findings.find((item) => item.dashboard_id === state.selectedId);
    if (!finding) {
      elements.detailPanel.innerHTML = `
        <div class="empty-detail">
          <svg viewBox="0 0 80 80" aria-hidden="true">
            <path d="M40 8 64 16v20c0 16-10 29-24 36C26 65 16 52 16 36V16l24-8Z"></path>
            <path d="M30 39h20"></path>
            <path d="M30 49h13"></path>
            <path d="M29 29h22"></path>
          </svg>
          <h2>No finding selected</h2>
          <p>Load reports and select a row.</p>
        </div>
      `;
      return;
    }

    const fragment = elements.detailTemplate.content.cloneNode(true);
    const pill = fragment.querySelector(".severity-pill");
    const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "Info";
    pill.textContent = severity;
    pill.classList.add(`severity-${severity}`);
    fragment.querySelector(".detail-header h2").textContent = finding.title;
    fragment.querySelector(".detail-header p").textContent = finding.affected_object;
    const meta = fragment.querySelector(".detail-meta");
    addMeta(meta, "Finding ID", finding.finding_id);
    addMeta(meta, "Scope", finding.scope || "Unknown");
    addMeta(meta, "Machine", finding.machine_name || "Not provided");
    addMeta(meta, "Object type", finding.object_type);
    addMeta(meta, "Source", finding.source_script);
    addMeta(meta, "File", finding.source_file);
    addMeta(meta, "Priority", finding.remediation_priority);
    addMeta(meta, "Approval", finding.requires_change_approval ? "Required" : "Review");
    addMeta(meta, "History", historyStatusForFinding(finding) || "No baseline match");
    fragment.querySelector(".recommendation").textContent = finding.recommendation || "Not provided.";
    fragment.querySelector(".safety").textContent = finding.not_safe_for_auto_remediation_reason || "Human review required.";
    renderEvidence(fragment.querySelector(".evidence-grid"), finding.evidence);
    renderRelated(fragment.querySelector(".related-findings"), finding);
    elements.detailPanel.replaceChildren(fragment);
  }

  function renderEvidence(container, evidence) {
    container.replaceChildren();
    const entries = Object.entries(evidence || {}).filter(([, value]) => value !== null && value !== undefined && value !== "");
    if (!entries.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No evidence fields available.";
      container.appendChild(empty);
      return;
    }
    entries.slice(0, 32).forEach(([key, value]) => {
      const item = document.createElement("div");
      item.className = "evidence-item";
      item.append(
        textElement("span", evidenceLabel(key), "evidence-key"),
        textElement("span", renderValue(value), "evidence-value")
      );
      container.appendChild(item);
    });
  }

  function renderRelated(container, finding) {
    container.replaceChildren();
    const related = relatedFindings(finding).slice(0, 8);
    if (!related.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No related findings found.";
      container.appendChild(empty);
      return;
    }
    related.forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "related-link";
      button.append(
        textElement("strong", item.title),
        textElement("span", `${item.affected_object} - ${item.source_script}`)
      );
      button.addEventListener("click", () => {
        state.selectedId = item.dashboard_id;
        render();
      });
      container.appendChild(button);
    });
  }

  function filteredFindings() {
    const query = state.filters.query.toLowerCase();
    return state.findings.filter((finding) => {
      if (state.filters.severity !== "All" && finding.severity !== state.filters.severity) return false;
      if (state.filters.scope !== "All" && finding.scope !== state.filters.scope) return false;
      if (state.filters.machine !== "All" && finding.machine_name !== state.filters.machine) return false;
      if (state.filters.source !== "All" && finding.source_script !== state.filters.source) return false;
      if (state.filters.objectType !== "All" && finding.object_type !== state.filters.objectType) return false;
      if (state.filters.status !== "All" && finding.status !== state.filters.status) return false;
      if (!query) return true;
      return searchableText(finding).includes(query);
    });
  }

  function clearFilters() {
    resetFilters();
    render();
  }

  function resetFilters() {
    state.filters = {
      query: "",
      scope: "All",
      machine: "All",
      severity: "All",
      source: "All",
      objectType: "All",
      status: "All",
    };
  }

  function relatedFindings(finding) {
    if (state.correlations.length) {
      const relatedIds = new Set();
      state.correlations
        .filter((correlation) => correlation.finding_ids.includes(finding.finding_id) || correlation.dashboard_ids.includes(finding.dashboard_id))
        .forEach((correlation) => {
          correlation.finding_ids.forEach((id) => relatedIds.add(id));
          correlation.dashboard_ids.forEach((id) => relatedIds.add(id));
        });
      return state.findings
        .filter((item) => item.dashboard_id !== finding.dashboard_id && (relatedIds.has(item.finding_id) || relatedIds.has(item.dashboard_id)))
        .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99));
    }

    const keys = new Set(finding.related_keys);
    return state.findings
      .filter((item) => item.dashboard_id !== finding.dashboard_id && item.related_keys.some((key) => keys.has(key)))
      .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99));
  }

  function relationGroups() {
    if (state.correlations.length) {
      return state.correlations.map((correlation) => ({
        label: correlation.key,
        count: correlation.finding_count,
        rationale: correlation.rationale,
      }));
    }

    const map = new Map();
    state.findings.forEach((finding) => {
      finding.related_keys.forEach((key) => {
        if (!map.has(key)) map.set(key, new Set());
        map.get(key).add(finding.dashboard_id);
      });
    });
    return Array.from(map.entries())
      .map(([key, ids]) => ({ label: key, count: ids.size }))
      .filter((item) => item.count > 1)
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  }

  function normalizeOfficialCorrelations(correlations, findings) {
    const byFindingId = new Map();
    findings.forEach((finding) => {
      if (!byFindingId.has(finding.finding_id)) byFindingId.set(finding.finding_id, []);
      byFindingId.get(finding.finding_id).push(finding.dashboard_id);
    });

    return correlations
      .map((correlation) => {
        const findingIds = arrayValue(correlation.finding_ids);
        const dashboardIds = findingIds.flatMap((id) => byFindingId.get(id) || []);
        return {
          id: stringValue(correlation.correlation_id || correlation.dashboard_correlation_id),
          key: stringValue(correlation.key || correlation.normalized_key || "related findings"),
          normalized_key: stringValue(correlation.normalized_key || correlation.key || ""),
          title: stringValue(correlation.title || "Related findings"),
          severity: normalizeSeverity(correlation.severity),
          finding_ids: findingIds,
          dashboard_ids: dashboardIds,
          finding_count: Number(correlation.finding_count || findingIds.length || dashboardIds.length),
          rationale: stringValue(correlation.rationale || ""),
          recommended_review: stringValue(correlation.recommended_review || ""),
        };
      })
      .filter((correlation) => correlation.finding_count > 1 && (correlation.finding_ids.length > 1 || correlation.dashboard_ids.length > 1))
      .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99) || b.finding_count - a.finding_count || a.key.localeCompare(b.key));
  }

  function extractCoverage(data, fileRecord) {
    if (!data) return null;
    if (data.report_type === "multi-bundle") return extractFleetCoverage(data, fileRecord);
    if (data.report_type !== "client-bundle") return null;
    const metadata = objectValue(data.report_type_metadata) || objectValue(data.metadata) || {};
    const summary = objectValue(data.summary) || {};
    const environment = objectValue(data.environment_summary) || {};
    const loadedFiles = objectEntries(metadata.loaded_files);
    const detectedFiles = objectEntries(metadata.detected_files);
    const failedFiles = objectEntries(metadata.failed_files);
    const missingFiles = arrayValue(metadata.missing_files);
    const scopeFindingCounts = objectValue(summary.scope_finding_counts) || objectValue(metadata.scope_finding_counts) || {};
    const scopeFileCounts = objectValue(summary.scope_file_counts) || {};
    const requestedScopes = normalizeScopes(environment.scope_resolved);
    const supportedScopes = normalizeScopes(metadata.supported_scopes).length ? normalizeScopes(metadata.supported_scopes) : SCOPES;
    const scopeRows = supportedScopes.map((scope) =>
      coverageScopeRow(scope, requestedScopes, scopeFindingCounts, scopeFileCounts, missingFiles, failedFiles, loadedFiles, detectedFiles)
    );
    const status = coverageStatus(scopeRows, failedFiles);
    return {
      fileName: fileRecord.name,
      reportId: stringValue(data.report_id),
      collectionId: stringValue(environment.collection_id),
      computerName: stringValue(environment.computer_name),
      requestedScopes,
      supportedScopes,
      loadedFiles,
      detectedFiles,
      missingFiles,
      failedFiles,
      scopeRows,
      status: status.label,
      statusClass: status.className,
    };
  }

  function extractFleetCoverage(data, fileRecord) {
    const metadata = objectValue(data.report_type_metadata) || objectValue(data.metadata) || {};
    const summary = objectValue(data.summary) || {};
    const environment = objectValue(data.environment_summary) || {};
    const machineRows = normalizeMachineRows(metadata.machine_inventory);
    const coverageMatrix = normalizeCoverageMatrix(metadata.coverage_matrix);
    const failedBundles = Array.isArray(metadata.failed_bundles)
      ? metadata.failed_bundles.map((item) => ({
          input: stringValue(item?.input),
          error: stringValue(item?.error),
        }))
      : [];
    const skippedBundles = Array.isArray(metadata.skipped_bundles)
      ? metadata.skipped_bundles.map((item) => ({
          input: stringValue(item?.input),
          reason: stringValue(item?.reason),
        }))
      : [];
    const scopeFindingCounts = objectValue(summary.scope_finding_counts) || {};
    const scopeRows = SCOPES.map((scope) => fleetScopeRow(scope, coverageMatrix, scopeFindingCounts, machineRows.length));
    const status = fleetStatus(machineRows, failedBundles, stringValue(environment.coverage_status));
    return {
      mode: "fleet",
      fileName: fileRecord.name,
      reportId: stringValue(data.report_id),
      collectionId: `${machineRows.length} machine${machineRows.length === 1 ? "" : "s"}`,
      computerName: "Fleet",
      requestedScopes: SCOPES,
      supportedScopes: SCOPES,
      loadedFiles: [],
      detectedFiles: [],
      missingFiles: [],
      failedFiles: [],
      failedBundles,
      skippedBundles,
      machineRows,
      coverageMatrix,
      scopeRows,
      status: status.label,
      statusClass: status.className,
    };
  }

  function normalizeMachineRows(value) {
    if (!Array.isArray(value)) return [];
    return value
      .filter((item) => item && typeof item === "object")
      .map((item) => {
        const counts = objectValue(item.severity_counts) || {};
        return {
          machineId: stringValue(item.machine_id),
          machineName: stringValue(item.machine_name || item.machine_id || "Unknown"),
          collectionId: stringValue(item.collection_id),
          input: stringValue(item.input),
          findingCount: Number(item.finding_count || 0),
          critical: Number(counts.Critical || 0),
          high: Number(counts.High || 0),
          coverageStatus: stringValue(item.coverage_status || "Partial"),
          statusClass: classForCoverageStatus(item.coverage_status),
        };
      })
      .sort((a, b) => b.critical - a.critical || b.high - a.high || b.findingCount - a.findingCount || a.machineName.localeCompare(b.machineName));
  }

  function normalizeCoverageMatrix(value) {
    if (!Array.isArray(value)) return [];
    return value
      .filter((item) => item && typeof item === "object")
      .map((item) => ({
        machineId: stringValue(item.machine_id),
        machineName: stringValue(item.machine_name || item.machine_id || "Unknown"),
        scope: normalizeScope(item.scope),
        selected: Boolean(item.selected),
        findingCount: Number(item.finding_count || 0),
        fileCount: Number(item.file_count || 0),
        requiredMissing: arrayValue(item.required_missing),
        status: stringValue(item.status || "Partial"),
        statusClass: classForCoverageStatus(item.status),
      }))
      .filter((item) => SCOPES.includes(item.scope));
  }

  function fleetScopeRow(scope, coverageMatrix, scopeFindingCounts, machineCount) {
    const rows = coverageMatrix.filter((row) => row.scope === scope);
    const selectedRows = rows.filter((row) => row.selected);
    const failedRows = rows.filter((row) => row.status === "Failed");
    const rerunRows = rows.filter((row) => row.status === "Needs rerun");
    const collectedRows = rows.filter((row) => row.status === "Collected");
    const partialRows = rows.filter((row) => row.status === "Partial" || row.status === "Not collected");
    const requiredMissing = unique(rows.flatMap((row) => row.requiredMissing));
    let status = "Collected";
    let statusClass = "complete";
    if (failedRows.length) {
      status = "Failed";
      statusClass = "failed";
    } else if (rerunRows.length) {
      status = "Needs rerun";
      statusClass = "rerun";
    } else if (partialRows.length || selectedRows.length < machineCount) {
      status = "Partial";
      statusClass = "partial";
    }
    return {
      scope,
      selected: selectedRows.length > 0,
      findingCount: Number(scopeFindingCounts[scope] ?? rows.reduce((total, row) => total + row.findingCount, 0)),
      fileCount: rows.reduce((total, row) => total + row.fileCount, 0),
      requiredMissing,
      status,
      statusClass,
      machineCount,
      collectedCount: collectedRows.length,
      selectedCount: selectedRows.length,
      failedCount: failedRows.length,
      rerunCount: rerunRows.length,
    };
  }

  function coverageScopeRow(scope, requestedScopes, scopeFindingCounts, scopeFileCounts, missingFiles, failedFiles, loadedFiles, detectedFiles) {
    const selected = requestedScopes.length ? requestedScopes.includes(scope) : scopeFileCount(scope, scopeFileCounts, loadedFiles, detectedFiles) > 0;
    const requiredMissing = selected ? requiredFilesForScope(scope).filter((file) => missingFiles.includes(file)) : [];
    const failed = failedFiles.some((item) => scopeForClientFileKey(item.key) === scope);
    const fileCount = Number(scopeFileCounts[scope] ?? scopeFileCount(scope, scopeFileCounts, loadedFiles, detectedFiles));
    const findingCount = Number(scopeFindingCounts[scope] ?? 0);
    let status = "Collected";
    let statusClass = "complete";
    if (!selected) {
      status = "Not collected";
      statusClass = "partial";
    } else if (failed) {
      status = "Failed";
      statusClass = "failed";
    } else if (requiredMissing.length) {
      status = "Needs rerun";
      statusClass = "rerun";
    } else if (fileCount === 0) {
      status = "Partial";
      statusClass = "partial";
    }
    return { scope, selected, findingCount, fileCount, requiredMissing, status, statusClass };
  }

  function coverageStatus(scopeRows, failedFiles) {
    if (failedFiles.length) return { label: "Failed", className: "failed" };
    if (scopeRows.some((row) => row.status === "Needs rerun")) return { label: "Needs rerun", className: "rerun" };
    if (scopeRows.some((row) => !row.selected || row.status === "Partial")) return { label: "Partial", className: "partial" };
    return { label: "Complete", className: "complete" };
  }

  function fleetStatus(machineRows, failedBundles, reportedStatus) {
    if (failedBundles.length) return { label: "Failed", className: "failed" };
    if (reportedStatus) return { label: reportedStatus, className: classForCoverageStatus(reportedStatus) };
    if (machineRows.some((row) => row.coverageStatus === "Failed")) return { label: "Failed", className: "failed" };
    if (machineRows.some((row) => row.coverageStatus === "Needs rerun")) return { label: "Needs rerun", className: "rerun" };
    if (machineRows.some((row) => row.coverageStatus === "Partial")) return { label: "Partial", className: "partial" };
    return { label: machineRows.length ? "Complete" : "No bundles", className: machineRows.length ? "complete" : "partial" };
  }

  function classForCoverageStatus(status) {
    const text = stringValue(status).toLowerCase();
    if (text.includes("failed")) return "failed";
    if (text.includes("rerun")) return "rerun";
    if (text.includes("complete") || text.includes("collected")) return "complete";
    return "partial";
  }

  function requiredFilesForScope(scope) {
    return {
      AD: ["ad-shared/"],
      Host: ["host/windows-security-audit.json"],
      Server: ["server/windows-server-security.json", "server/windows-local-admins.json", "server/windows-rdp-exposure.json"],
      Workstation: [
        "workstation/windows-workstation-security.json",
        "workstation/windows-local-admins.json",
        "workstation/windows-rdp-exposure.json",
      ],
      Network: ["network/windows-network-exposure.json"],
    }[scope] || [];
  }

  function scopeFileCount(scope, scopeFileCounts, loadedFiles, detectedFiles) {
    if (scopeFileCounts && scopeFileCounts[scope] !== undefined) return Number(scopeFileCounts[scope] || 0);
    const keys = [...loadedFiles.map((item) => item.key), ...detectedFiles.map((item) => item.key)];
    return keys.filter((key) => scopeForClientFileKey(key) === scope).length;
  }

  function objectEntries(value) {
    const object = objectValue(value) || {};
    return Object.entries(object).map(([key, val]) => ({ key, value: stringValue(val) }));
  }

  function normalizeScopes(value) {
    return arrayValue(value)
      .map(normalizeScope)
      .filter((scope) => SCOPES.includes(scope));
  }

  function missingScopeOptions() {
    return state.coverage ? state.coverage.scopeRows.map((row) => row.scope) : [];
  }

  function coverageMachineOptions() {
    if (!state.coverage || !Array.isArray(state.coverage.machineRows)) return [];
    return state.coverage.machineRows.map((row) => row.machineName);
  }

  function normalizeHistoryComparison(history) {
    if (!history || typeof history !== "object" || Array.isArray(history)) return null;
    return {
      comparison_id: stringValue(history.comparison_id),
      current_report_id: stringValue(history.current_report_id),
      previous_report_id: stringValue(history.previous_report_id),
      previous_source_file: stringValue(history.previous_source_file),
      current_generated_at_utc: stringValue(history.current_generated_at_utc),
      previous_generated_at_utc: stringValue(history.previous_generated_at_utc),
      matched_on: stringValue(history.matched_on || "finding_id"),
      new_finding_ids: arrayValue(history.new_finding_ids),
      persistent_finding_ids: arrayValue(history.persistent_finding_ids),
      resolved_finding_ids: arrayValue(history.resolved_finding_ids),
      new_count: Number(history.new_count || 0),
      persistent_count: Number(history.persistent_count || 0),
      resolved_count: Number(history.resolved_count || 0),
      resolved_findings: Array.isArray(history.resolved_findings)
        ? history.resolved_findings.map((item) => ({
            finding_id: stringValue(item?.finding_id),
            title: stringValue(item?.title || "Previous finding"),
            severity: normalizeSeverity(item?.severity),
            affected_object: stringValue(item?.affected_object),
            source_script: stringValue(item?.source_script),
          }))
        : [],
      notes: arrayValue(history.notes),
    };
  }

  function historyStatusForFinding(finding) {
    const history = state.historyComparison;
    if (!history) return "";
    if (history.new_finding_ids.includes(finding.finding_id)) return "New";
    if (history.persistent_finding_ids.includes(finding.finding_id)) return "Persistent";
    return "";
  }

  function inferScope(data, path, reportType) {
    const lowerPath = stringValue(path).toLowerCase().replace(/\\/g, "/");
    const lowerType = stringValue(reportType).toLowerCase();
    if (lowerPath.includes("/ad-shared/") || lowerType.startsWith("ad-") || lowerType.includes("gpo")) return "AD";
    if (lowerPath.includes("/network/") || lowerType.includes("network")) return "Network";
    if (lowerPath.includes("/workstation/")) return "Workstation";
    if (lowerPath.includes("/server/")) return "Server";
    if (lowerPath.includes("/host/") || lowerType.includes("windows")) return "Host";
    if (data && data.report_type === "client-bundle") return "Client";
    return "";
  }

  function inferScopeFromFinding(finding, fileRecord) {
    const evidence = objectValue(finding.evidence) || {};
    const combined = [
      finding.finding_id,
      finding.category,
      finding.object_type,
      finding.source_script,
      fileRecord.scope,
      fileRecord.path,
      evidence.source_file,
    ].join(" ").toLowerCase();
    if (combined.includes("workstation")) return "Workstation";
    if (combined.includes("network")) return "Network";
    if (combined.includes("server") || combined.includes("rdp-profile-cache")) return "Server";
    if (combined.includes("host") || combined.includes("windows")) return "Host";
    if (combined.includes("active directory") || combined.includes("gpo") || combined.includes("ad-")) return "AD";
    return fileRecord.scope || "";
  }

  function scopeForClientFileKey(key) {
    if (key === "ad_shared" || key.startsWith("ad_")) return "AD";
    if (key.startsWith("network_")) return "Network";
    if (key.startsWith("workstation_")) return "Workstation";
    if (key.startsWith("server_")) return "Server";
    if (key.startsWith("host_")) return "Host";
    return "";
  }

  function normalizeScope(value) {
    const text = stringValue(value).trim().toLowerCase();
    if (text === "ad" || text.includes("active directory") || text.includes("gpo")) return "AD";
    if (text === "host" || text.includes("windows host")) return "Host";
    if (text === "server" || text.includes("terminal server")) return "Server";
    if (text === "workstation" || text.includes("endpoint")) return "Workstation";
    if (text === "network" || text.includes("network exposure")) return "Network";
    if (text === "client") return "Client";
    return stringValue(value).trim();
  }

  function relatedKeys(finding) {
    const keys = new Set();
    const add = (value) => {
      if (value === null || value === undefined) return;
      if (Array.isArray(value)) {
        value.forEach(add);
        return;
      }
      if (typeof value === "object") {
        Object.entries(value).forEach(([key, child]) => {
          if (isRelationshipField(key)) add(child);
        });
        return;
      }
      const text = String(value).trim();
      if (!text || text.length < 3) return;
      splitRelationshipText(text).forEach((part) => {
        const normalized = normalizeRelation(part);
        if (normalized) keys.add(normalized);
      });
    };

    add(finding.affected_object);
    add(finding.evidence);
    return Array.from(keys).filter((key) => !isGenericKey(key)).slice(0, 28);
  }

  function isRelationshipField(key) {
    const normalized = toSnakeCase(key);
    if (["bundle_input", "collection_id", "computer_name", "machine_id", "machine_name", "source_file", "source_report_type"].includes(normalized)) {
      return false;
    }
    return [
      "sam_account_name",
      "subject",
      "name",
      "dns_host_name",
      "member_sam_account_name",
      "member_name",
      "group_name",
      "gpo_name",
      "target_path",
      "service_principal_names",
      "privileged_groups",
      "distinguished_name",
      "object_sid",
      "sid",
    ].some((token) => normalized.includes(token));
  }

  function splitRelationshipText(text) {
    return text
      .split(/[;,]/)
      .map((part) => part.trim())
      .filter(Boolean);
  }

  function normalizeRelation(value) {
    const clean = value
      .replace(/^CN=/i, "")
      .replace(/\\+/g, "\\")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
    if (clean.length < 3 || clean.length > 160) return "";
    return clean;
  }

  function isGenericKey(key) {
    return ["true", "false", "high", "medium", "low", "critical", "info", "hold", "user", "group"].includes(key);
  }

  function riskFactorsFromRow(row) {
    return [
      ...arrayValue(row.RiskFlags || row.RiskFlagsText),
      ...arrayValue(row.ReviewReasons || row.ReviewReasonsText),
      stringValue(row.FindingType || row.ChangeType || "").trim(),
    ].filter(Boolean);
  }

  function severityCounts(findings) {
    return Object.fromEntries(SEVERITIES.map((severity) => [severity, findings.filter((item) => item.severity === severity).length]));
  }

  function setOptions(select, values, selected) {
    const current = new Set(Array.from(select.options).map((option) => option.value));
    const next = new Set(values);
    const unchanged = current.size === next.size && values.every((value) => current.has(value));
    if (!unchanged) {
      select.replaceChildren(...values.map((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        return option;
      }));
    }
    select.value = next.has(selected) ? selected : "All";
  }

  function addMeta(meta, key, value) {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value || "Not provided";
    meta.append(dt, dd);
  }

  function textElement(tagName, value, className = "") {
    const element = document.createElement(tagName);
    if (className) {
      element.className = className;
    }
    element.textContent = String(value ?? "");
    return element;
  }

  function historyClass(value) {
    return value === "New" ? "new" : value === "Persistent" ? "persistent" : "";
  }

  function searchableText(finding) {
    return [
      finding.finding_id,
      finding.title,
      finding.affected_object,
      finding.object_type,
      finding.source_script,
      finding.source_file,
      finding.scope,
      finding.machine_name,
      finding.status,
      historyStatusForFinding(finding),
      renderValue(finding.evidence),
      finding.risk_factors.join(" "),
    ].join(" ").toLowerCase();
  }

  function normalizeSeverity(value) {
    const text = String(value || "").trim();
    if (SEVERITIES.includes(text)) return text;
    const lower = text.toLowerCase();
    if (lower === "p1" || lower.startsWith("p1") || lower.includes("critical")) return "Critical";
    if (lower === "p2" || lower.startsWith("p2") || lower.includes("high")) return "High";
    if (lower === "p3" || lower.startsWith("p3") || lower.includes("medium") || lower.includes("moderate")) return "Medium";
    if (lower === "p4" || lower.startsWith("p4") || lower.includes("low")) return "Low";
    if (lower.includes("hold")) return "Hold";
    return "Info";
  }

  function priorityFor(severity) {
    return {
      Critical: "Immediate Review",
      High: "High Priority",
      Medium: "Planned Remediation",
      Low: "Monitor",
      Info: "Monitor",
      Hold: "Hold",
    }[severity] || "Monitor";
  }

  function severityColor(severity) {
    return {
      Critical: "#b42318",
      High: "#b54708",
      Medium: "#946200",
      Low: "#246b43",
      Info: "#245b86",
      Hold: "#5b4b7a",
    }[severity] || "#25636f";
  }

  function firstPresent(row, keys) {
    for (const key of keys) {
      if (row && row[key] !== null && row[key] !== undefined && row[key] !== "") return String(row[key]);
    }
    return "";
  }

  function objectValue(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  }

  function arrayValue(value) {
    if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean);
    if (typeof value === "string") {
      if (!value.trim()) return [];
      return value.split(/[;,]/).map((part) => part.trim()).filter(Boolean);
    }
    return value === null || value === undefined ? [] : [String(value)];
  }

  function stringValue(value) {
    return value === null || value === undefined ? "" : String(value);
  }

  function renderValue(value) {
    if (Array.isArray(value)) return value.map(renderValue).join(", ");
    if (value && typeof value === "object") return JSON.stringify(value);
    return stringValue(value);
  }

  function evidenceLabel(key) {
    const text = stringValue(key).replace(/_/g, " ").trim();
    if (!text) return "";
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  function unique(values) {
    return Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b));
  }

  function fileName(path) {
    return String(path || "").split(/[\\/]/).pop() || "";
  }

  function toSnakeCase(value) {
    return String(value)
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/[\s-]+/g, "_")
      .toLowerCase();
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function loadSampleData() {
    const report = {
      report_id: "secureinfra-ai-sample-client-bundle",
      report_type: "client-bundle",
      tool_name: "SecureInfra AI Client Bundle Analyzer",
      source_files: ["sample/normalized-report.json"],
      generated_at_utc: "2026-06-15T09:00:00Z",
      environment_summary: {
        company: "Example GmbH",
        domain: "example.local",
        computer_name: "EXAMPLE-SRV01",
        collection_id: "secureinfra-client-EXAMPLE-SRV01-20260615-090000",
        scope_resolved: ["AD", "Host", "Server"],
      },
      summary: {
        normalized_finding_count: 7,
        scope_finding_counts: { AD: 5, Host: 1, Server: 1, Workstation: 0 },
        scope_file_counts: { Client: 3, AD: 1, Host: 4, Server: 2, Workstation: 0 },
      },
      report_type_metadata: {
        report_type: "client-bundle",
        supported_scopes: ["AD", "Host", "Server", "Workstation"],
        loaded_files: {
          ad_shared: "sample/ad-shared",
          client_info: "sample/client-info.json",
          collection_summary: "sample/collection-summary.json",
          manifest: "sample/manifest.json",
          host_windows_security_audit: "sample/host/windows-security-audit.json",
          host_windows_events_summary: "sample/host/windows-events/summary.json",
          server_windows_rdp_exposure: "sample/server/windows-rdp-exposure.json",
        },
        missing_files: ["server/windows-local-admins.json", "workstation/windows-local-admins.json", "workstation/windows-rdp-exposure.json"],
        failed_files: {},
      },
      metadata: { normalizer: "sample" },
      notes: ["Fictional sample data."],
      findings: [
        sampleFinding("AD-PGROUP-0001", "Privileged group membership addition requires review", "Critical", "alex.admin", "Active Directory privileged group membership", "Watch-ADPrivilegedGroupChanges.ps1", { group_name: "Domain Admins", member_sam_account_name: "alex.admin", member_name: "Alex Admin", risk_flags: ["CriticalGroup"] }),
        sampleFinding("AD-PID-0001", "Privileged identity protection gap requires review", "High", "alex.admin", "Active Directory privileged identity", "Get-PrivilegedIdentityProtectionAudit.ps1", { subject: "alex.admin", group_name: "Domain Admins", smartcard_logon_required: false, protected_users_member: false }),
        sampleFinding("AD-SPN-0001", "SPN-bearing account requires exposure review", "High", "svc-legacy-api", "Active Directory SPN account", "Get-ADSPNExposureAudit.ps1", { sam_account_name: "svc-legacy-api", service_principal_names: ["HTTP/api.example.local"], password_never_expires: true }),
        sampleFinding("AD-SVC-0001", "Service account requires owner and dependency review", "High", "svc-legacy-api", "Active Directory service account", "Get-ADServiceAccountAudit.ps1", { sam_account_name: "svc-legacy-api", has_spn: true, owner_evidence_missing: true }),
        sampleFinding("GPO-HEALTH-0001", "AD and SYSVOL GPO versions differ", "High", "EX Workstation Baseline", "Group Policy Object", "Get-ADGPOHealthReport.ps1", { gpo_name: "EX Workstation Baseline", target_path: "OU=Workstations,DC=example,DC=local", change_risk: "High" }),
        sampleFinding("HOST-WIN-WIN-FW-001", "Windows Firewall profile is disabled", "High", "EXAMPLE-SRV01", "Windows host security control", "Invoke-WindowsSecurityAudit.ps1", { scope: "Host", computer_name: "EXAMPLE-SRV01", area: "Firewall", evidence: "Domain profile Enabled=False" }),
        sampleFinding("SERVER-RDP-RDPENABLED", "Remote Desktop is enabled", "Medium", "EXAMPLE-SRV01", "Windows RDP exposure", "Get-WindowsRDPExposureAudit.ps1", { scope: "Server", computer_name: "EXAMPLE-SRV01", rdp_enabled: true, rdp_port: 3389 }),
      ],
      correlations: [
        sampleCorrelation("CORR-0001", "alex.admin", "Critical", ["AD-PGROUP-0001", "AD-PID-0001"], ["Watch-ADPrivilegedGroupChanges.ps1", "Get-PrivilegedIdentityProtectionAudit.ps1"]),
        sampleCorrelation("CORR-0002", "domain admins", "Critical", ["AD-PGROUP-0001", "AD-PID-0001"], ["Watch-ADPrivilegedGroupChanges.ps1", "Get-PrivilegedIdentityProtectionAudit.ps1"]),
        sampleCorrelation("CORR-0003", "svc-legacy-api", "High", ["AD-SPN-0001", "AD-SVC-0001"], ["Get-ADSPNExposureAudit.ps1", "Get-ADServiceAccountAudit.ps1"]),
      ],
      history_comparison: {
        comparison_id: "secureinfra-history-secureinfra-ai-sample-dashboard",
        current_report_id: "secureinfra-ai-sample-dashboard",
        previous_report_id: "secureinfra-ai-sample-dashboard-previous",
        previous_source_file: "sample/previous-normalized-report.json",
        current_generated_at_utc: "2026-06-15T09:00:00Z",
        previous_generated_at_utc: "2026-06-08T09:00:00Z",
        matched_on: "finding_id",
        new_finding_ids: ["GPO-HEALTH-0001"],
        persistent_finding_ids: ["AD-PGROUP-0001", "AD-PID-0001", "AD-SPN-0001", "AD-SVC-0001"],
        resolved_finding_ids: ["AD-PNE-0001"],
        new_count: 1,
        persistent_count: 4,
        resolved_count: 1,
        resolved_findings: [
          {
            finding_id: "AD-PNE-0001",
            title: "Password-never-expires account required review",
            severity: "High",
            affected_object: "svc-fixed-password",
            source_script: "Get-ADPasswordNeverExpiresAudit.ps1",
          },
        ],
        notes: ["Fictional baseline comparison for dashboard preview."],
      },
    };
    const fileRecord = buildFileRecord({ name: "sample-normalized-report.json" }, "sample-normalized-report.json", report);
    const findings = extractFindings(report, fileRecord, 1);
    fileRecord.findingCount = findings.length;
    state.files = [fileRecord];
    state.findings = enrichFindings(findings);
    state.correlations = normalizeOfficialCorrelations(report.correlations || [], state.findings);
    state.historyComparison = normalizeHistoryComparison(report.history_comparison);
    state.coverage = extractCoverage(report, fileRecord);
    state.selectedId = state.findings[0]?.dashboard_id || "";
    clearFilters();
  }

  function sampleCorrelation(id, key, severity, findingIds, sourceScripts) {
    return {
      correlation_id: id,
      correlation_type: "cross-source-object",
      key,
      normalized_key: key,
      title: `Related findings for ${key}`,
      severity,
      finding_ids: findingIds,
      finding_count: findingIds.length,
      source_scripts: sourceScripts,
      affected_objects: [key],
      rationale: `Multiple source scripts reference ${key}, indicating the findings should be reviewed together.`,
      recommended_review: "Review these findings together before remediation so ownership, dependencies, and change approval are validated once.",
    };
  }

  function sampleFinding(id, title, severity, objectName, objectType, sourceScript, evidence) {
    return {
      finding_id: id,
      title,
      category: objectType.includes("Group Policy") ? "Group Policy Health" : "Active Directory Security",
      severity,
      affected_object: objectName,
      object_type: objectType,
      source_script: sourceScript,
      evidence,
      risk_factors: arrayValue(evidence.risk_flags),
      business_impact: "Fictional sample finding for dashboard preview.",
      technical_impact: "Fictional evidence shows how linked findings are grouped.",
      recommendation: "Validate owner, source evidence, and change approval before remediation.",
      remediation_priority: priorityFor(severity),
      requires_owner_review: true,
      requires_change_approval: true,
      safe_to_auto_remediate: false,
      not_safe_for_auto_remediation_reason: "Human owner review and approved change control are required.",
      status: "Open",
      timestamp_utc: "2026-06-15T09:00:00Z",
    };
  }

  initialize();
})();
