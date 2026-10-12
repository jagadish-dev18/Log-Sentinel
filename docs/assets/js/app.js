/*
 * Log Sentinel
 * A small browser-side authentication log analyzer.
 * The functions are intentionally kept simple so the project is easy to explain.
 */

const SAMPLE_LOGS = `2026-10-12 08:10:12 SUCCESS_LOGIN user=operator ip=192.0.2.18
2026-10-12 08:14:33 FAILED_LOGIN user=admin ip=192.0.2.44
2026-10-12 08:15:09 FAILED_LOGIN user=admin ip=192.0.2.44
2026-10-12 08:16:21 FAILED_LOGIN user=root ip=192.0.2.44
2026-10-12 08:17:48 FAILED_LOGIN user=service ip=192.0.2.44
2026-10-12 08:19:02 FAILED_LOGIN user=admin ip=192.0.2.44
2026-10-12 08:22:50 FAILED_LOGIN user=admin ip=192.0.2.44
2026-10-12 08:24:10 SUCCESS_LOGIN user=operator ip=192.0.2.18
2026-10-12 09:01:02 FAILED_LOGIN user=guest ip=198.51.100.27
2026-10-12 09:04:22 SUCCESS_LOGIN user=maintainer ip=198.51.100.27
2026-10-12 09:20:41 FAILED_LOGIN user=deploy ip=203.0.113.73
2026-10-12 09:22:07 FAILED_LOGIN user=deploy ip=203.0.113.73
2026-10-12 09:25:18 SUCCESS_LOGIN user=deploy ip=203.0.113.73
Oct 12 10:13:45 lab-host sshd[2241]: Failed password for invalid user test from 192.0.2.44 port 53812 ssh2
Oct 12 10:15:06 lab-host sshd[2248]: Accepted password for analyst from 192.0.2.18 port 53821 ssh2
2026-10-12 10:18:44 INFO user=system ip=192.0.2.18 message=scheduled rotation started
this line intentionally does not match a supported authentication log format`;

const state = {
  rawText: SAMPLE_LOGS,
  fileName: "demo-auth.log",
  isDemo: true,
  events: [],
  unparsed: [],
  allRows: [],
  threshold: 5,
  currentView: "overview",
  dismissedNotice: false
};

const $ = (id) => document.getElementById(id);
const numberFormat = new Intl.NumberFormat("en-US");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function normalizeEventName(value) {
  const eventName = String(value ?? "").toLowerCase().replace(/[\s-]+/g, "_");
  if (/fail|denied|invalid_password|authentication_failure/.test(eventName)) return "failed";
  if (/success|accepted|authenticated|login_ok/.test(eventName)) return "success";
  return "other";
}

function normalizeIp(value) {
  if (!value) return "Unknown";
  return String(value).replace(/[;,]$/, "");
}

function parseTimestamp(value, fallbackYear) {
  if (!value) return null;
  const cleaned = String(value).trim();
  let parsed = new Date(cleaned);
  if (!Number.isNaN(parsed.getTime())) return parsed;

  // Classic syslog lines omit the year. Use the current year for display only.
  const syslogMatch = cleaned.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/);
  if (syslogMatch) {
    parsed = new Date(`${syslogMatch[1]} ${syslogMatch[2]}, ${fallbackYear || new Date().getFullYear()} ${syslogMatch[3]}`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }
  return null;
}

function makeEvent({ line, lineNumber, timestamp, type, username, ip, detail, format }) {
  return {
    id: `${lineNumber}-${Math.random().toString(36).slice(2, 7)}`,
    lineNumber,
    rawLine: line,
    timestamp: parseTimestamp(timestamp, new Date().getFullYear()),
    timestampText: timestamp || "Timestamp unavailable",
    type,
    username: username || "—",
    ip: normalizeIp(ip),
    detail: detail || "Recognized authentication event",
    format: format || "key-value"
  };
}

function parseJsonLine(line, lineNumber) {
  if (!line.trim().startsWith("{")) return null;
  try {
    const record = JSON.parse(line);
    const rawType = record.event ?? record.event_type ?? record.action ?? record.status ?? "";
    const type = normalizeEventName(rawType);
    const timestamp = record.timestamp ?? record.time ?? record.datetime ?? record.ts ?? "";
    const username = record.username ?? record.user ?? record.account ?? "—";
    const ip = record.ip ?? record.source_ip ?? record.src_ip ?? record.remote_addr ?? record.remote_ip ?? "Unknown";
    const explicitLoginEvent = /login|auth|password|accepted|failed|denied/i.test(String(rawType));
    if (!explicitLoginEvent) return null;
    return makeEvent({ line, lineNumber, timestamp, type, username, ip, detail: String(rawType || "Authentication event"), format: "JSON" });
  } catch {
    // Not valid JSON; other parsers may still recognize this line.
    return null;
  }
}

function parseKeyValueLine(line, lineNumber) {
  const match = line.match(/^(.{10,30}?)\s+(FAILED_LOGIN|LOGIN_FAILED|AUTH_FAILURE|SUCCESS_LOGIN|LOGIN_SUCCESS|AUTH_SUCCESS|INFO|WARNING|ERROR|OTHER)\b(.*)$/i);
  if (!match) return null;
  const timestamp = match[1].trim();
  const rawEvent = match[2].toUpperCase();
  const rest = match[3] || "";
  const field = (names) => {
    const expression = new RegExp(`\\b(?:${names})=([^\\s,]+)`, "i");
    return (rest.match(expression) || [])[1] || "";
  };
  const rawType = rawEvent === "INFO" || rawEvent === "WARNING" || rawEvent === "ERROR" || rawEvent === "OTHER" ? rawEvent : rawEvent;
  const type = normalizeEventName(rawType);
  const username = field("user|username|account");
  const ip = field("ip|source_ip|src_ip|remote_ip");
  const detail = rest.trim() || rawEvent.replace(/_/g, " ").toLowerCase();
  if (!/\d{4}-\d{2}-\d{2}/.test(timestamp) && !/\d{2}:\d{2}:\d{2}/.test(timestamp)) return null;
  return makeEvent({ line, lineNumber, timestamp, type, username, ip, detail, format: "key-value" });
}

function parseSshLine(line, lineNumber) {
  const timestampMatch = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+/);
  const failure = line.match(/Failed password for (?:(?:invalid|illegal) user )?(\S+) from ([0-9a-fA-F:.]+)(?: port (\d+))?/i);
  const success = line.match(/Accepted (?:password|publickey|keyboard-interactive(?:\/pam)?) for (\S+) from ([0-9a-fA-F:.]+)(?: port (\d+))?/i);
  const otherAuth = line.match(/authentication failure.*rhost=([0-9a-fA-F:.]+)/i);
  if (!timestampMatch || (!failure && !success && !otherAuth)) return null;
  if (failure) {
    return makeEvent({ line, lineNumber, timestamp: timestampMatch[1], type: "failed", username: failure[1], ip: failure[2], detail: `SSH failed password${failure[3] ? ` on port ${failure[3]}` : ""}`, format: "OpenSSH" });
  }
  if (success) {
    return makeEvent({ line, lineNumber, timestamp: timestampMatch[1], type: "success", username: success[1], ip: success[2], detail: `SSH accepted authentication${success[3] ? ` on port ${success[3]}` : ""}`, format: "OpenSSH" });
  }
  return makeEvent({ line, lineNumber, timestamp: timestampMatch[1], type: "other", username: "—", ip: otherAuth[1], detail: "PAM authentication failure", format: "OpenSSH" });
}

function parseGenericLine(line, lineNumber) {
  const failed = /failed password|login failed|authentication failure|invalid password|access denied/i.test(line);
  const success = /accepted password|login successful|authentication success|user authenticated/i.test(line);
  if (!failed && !success) return null;
  const ipMatch = line.match(/(?:from|ip[=: ]|src[=: ]|rhost=)([0-9a-fA-F:.]{3,})/i);
  const userMatch = line.match(/(?:for|user[=: ]|username[=: ])\s*(?:invalid user\s+)?([A-Za-z0-9_.@-]+)/i);
  const timestamp = (line.match(/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/) || [])[0] || "";
  return makeEvent({ line, lineNumber, timestamp, type: failed ? "failed" : "success", username: userMatch?.[1] || "—", ip: ipMatch?.[1] || "Unknown", detail: failed ? "Login failure pattern" : "Successful authentication pattern", format: "generic" });
}

function parseLine(line, lineNumber) {
  return parseJsonLine(line, lineNumber)
    || parseSshLine(line, lineNumber)
    || parseKeyValueLine(line, lineNumber)
    || parseGenericLine(line, lineNumber);
}

function analyzeText(text) {
  const lines = String(text ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const events = [];
  const unparsed = [];
  lines.forEach((line, index) => {
    const event = parseLine(line, index + 1);
    if (event) events.push(event);
    else unparsed.push({ id: `u-${index + 1}`, lineNumber: index + 1, rawLine: line, timestamp: null, timestampText: "—", type: "unparsed", username: "—", ip: "Unknown", detail: "Line format not recognized", format: "unparsed" });
  });
  return { events, unparsed, lineCount: lines.length };
}

function getIpStats(events) {
  const map = new Map();
  events.forEach((event) => {
    const ip = event.ip || "Unknown";
    if (ip === "Unknown") return;
    if (!map.has(ip)) map.set(ip, { ip, failed: 0, success: 0, other: 0, lastSeen: null, users: new Set() });
    const stats = map.get(ip);
    if (event.type === "failed") stats.failed += 1;
    else if (event.type === "success") stats.success += 1;
    else stats.other += 1;
    if (event.timestamp && (!stats.lastSeen || event.timestamp > stats.lastSeen)) stats.lastSeen = event.timestamp;
    if (event.username && event.username !== "—") stats.users.add(event.username);
  });
  return [...map.values()].map((item) => ({
    ...item,
    users: [...item.users],
    flagged: item.failed >= state.threshold
  })).sort((a, b) => b.failed - a.failed || b.success - a.success || a.ip.localeCompare(b.ip));
}

function formatDate(value, includeDate = false) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("en-GB", includeDate
      ? { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }
      : { hour: "2-digit", minute: "2-digit", hour12: false }).format(value);
  } catch { return "—"; }
}

function setDataset(text, fileName, isDemo) {
  state.rawText = text;
  state.fileName = fileName || "pasted-auth.log";
  state.isDemo = Boolean(isDemo);
  const result = analyzeText(text);
  state.events = result.events;
  state.unparsed = result.unparsed;
  state.lineCount = result.lineCount;
  renderAll();
}

function renderAll() {
  const events = state.events;
  const unparsed = state.unparsed;
  const lineCount = state.lineCount || 0;
  const failed = events.filter((event) => event.type === "failed").length;
  const success = events.filter((event) => event.type === "success").length;
  const ips = getIpStats(events);
  const flagged = ips.filter((item) => item.flagged).length;
  const percentage = lineCount ? Math.round((events.length / lineCount) * 100) : 0;

  $("metricTotal").textContent = numberFormat.format(events.length);
  $("metricFailed").textContent = numberFormat.format(failed);
  $("metricFlagged").textContent = numberFormat.format(flagged);
  $("metricParsed").textContent = lineCount ? `${percentage}%` : "—";
  $("metricTotalFoot").textContent = `${lineCount} non-empty input lines`;
  $("metricFailedFoot").textContent = `${success} successful · ${events.length - failed - success} other`;
  $("metricFlaggedFoot").textContent = `Threshold: ${state.threshold} failed attempts`;
  $("metricParsedFoot").textContent = `${unparsed.length} unrecognized lines`;
  $("navEventCount").textContent = numberFormat.format(events.length + unparsed.length);
  $("datasetBadge").innerHTML = `<span class="demo-dot"></span> ${state.isDemo ? "DEMO DATA" : "LOCAL DATA"}`;
  $("datasetBadge").classList.toggle("local-data-badge", !state.isDemo);
  $("qualityRecognized").textContent = numberFormat.format(events.length);
  $("qualityUnparsed").textContent = numberFormat.format(unparsed.length);
  $("qualityBarFill").style.width = `${percentage}%`;
  $("qualityCopy").textContent = lineCount
    ? `${percentage}% of non-empty lines were recognized. ${unparsed.length ? "Review unparsed lines in Event Explorer to improve the parser for your log format." : "All non-empty input lines matched a supported pattern."}`
    : "Upload or paste authentication logs. Unrecognized lines will be shown for review.";
  $("ipThresholdValue").textContent = `${state.threshold} failures`;
  $("ipUniqueCount").textContent = numberFormat.format(ips.length);
  $("ipFlaggedCount").textContent = numberFormat.format(flagged);
  $("ipSuccessCount").textContent = numberFormat.format(success);
  $("timelineFootnote").textContent = state.isDemo ? "Synthetic demonstration records · Not live monitoring." : `${state.fileName} · Processed locally in this browser.`;
  renderActivityChart(events);
  renderTopIpChart(ips);
  renderRecentEvents(events);
  renderEventExplorer();
  renderIpTable(ips);
  renderAnalysisResult();
}

function renderActivityChart(events) {
  const container = $("activityChart");
  if (!events.length) {
    container.innerHTML = '<div class="chart-empty"><span>▥</span><strong>No activity to plot</strong><small>Analyze logs to generate the timeline.</small></div>';
    return;
  }
  const withDates = events.filter((event) => event.timestamp);
  let buckets = [];
  if (withDates.length) {
    const dayKeys = [...new Set(withDates.map((event) => event.timestamp.toISOString().slice(0, 10)))].sort().slice(-7);
    buckets = dayKeys.map((key) => {
      const records = withDates.filter((event) => event.timestamp.toISOString().slice(0, 10) === key);
      const label = new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short" }).format(new Date(`${key}T12:00:00`));
      return { key, label, failed: records.filter((event) => event.type === "failed").length, success: records.filter((event) => event.type === "success").length };
    });
  } else {
    const failed = events.filter((event) => event.type === "failed").length;
    const success = events.filter((event) => event.type === "success").length;
    buckets = [{ key: "all", label: "All events", failed, success }];
  }
  while (buckets.length < 2) {
    const prior = buckets[0];
    buckets = [{ key: "empty", label: "Earlier", failed: 0, success: 0 }, prior];
  }
  const width = 660, height = 220, left = 32, right = 15, top = 15, bottom = 31;
  const chartWidth = width - left - right, chartHeight = height - top - bottom;
  const maxValue = Math.max(1, ...buckets.map((bucket) => Math.max(bucket.failed, bucket.success)));
  const x = (index) => left + (buckets.length === 1 ? chartWidth / 2 : index * chartWidth / (buckets.length - 1));
  const y = (value) => top + chartHeight - (value / maxValue) * chartHeight;
  const createPath = (key) => buckets.map((bucket, index) => `${index ? "L" : "M"} ${x(index).toFixed(1)} ${y(bucket[key]).toFixed(1)}`).join(" ");
  let grid = "";
  for (let i = 0; i <= 3; i += 1) {
    const gy = top + i * chartHeight / 3;
    const val = Math.round(maxValue * (1 - i / 3));
    grid += `<line x1="${left}" y1="${gy}" x2="${width - right}" y2="${gy}" stroke="#edf1f5" stroke-dasharray="3 5"/><text x="${left - 9}" y="${gy + 3}" fill="#a2adb8" text-anchor="end" font-size="9">${val}</text>`;
  }
  let labels = "", dots = "";
  buckets.forEach((bucket, index) => {
    labels += `<text x="${x(index)}" y="${height - 8}" fill="#98a5b1" text-anchor="middle" font-size="9">${escapeHtml(bucket.label)}</text>`;
    dots += `<circle cx="${x(index)}" cy="${y(bucket.failed)}" r="3.8" fill="#ed755b" stroke="#fff" stroke-width="2"/><circle cx="${x(index)}" cy="${y(bucket.success)}" r="3.8" fill="#18a6a0" stroke="#fff" stroke-width="2"/>`;
  });
  const failArea = `${createPath("failed")} L ${x(buckets.length - 1)} ${top + chartHeight} L ${x(0)} ${top + chartHeight} Z`;
  container.innerHTML = `<svg class="activity-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Failed and successful authentication events over time"><defs><linearGradient id="failedFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#ed755b" stop-opacity=".17"/><stop offset="100%" stop-color="#ed755b" stop-opacity="0"/></linearGradient></defs>${grid}<path d="${failArea}" fill="url(#failedFill)"/><path d="${createPath("failed")}" fill="none" stroke="#ed755b" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><path d="${createPath("success")}" fill="none" stroke="#18a6a0" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>${dots}${labels}</svg>`;
}

function renderTopIpChart(ips) {
  const container = $("topIpChart");
  const top = ips.filter((item) => item.failed > 0).slice(0, 5);
  if (!top.length) {
    container.innerHTML = '<div class="chart-empty compact"><span>⌁</span><strong>No failed logins found</strong><small>Parsed sources with failures appear here.</small></div>';
    $("topIpInsight").innerHTML = '<span class="insight-icon">✦</span><span>No failed login events were detected in the parsed records.</span>';
    return;
  }
  const max = Math.max(...top.map((item) => item.failed), 1);
  container.innerHTML = top.map((item) => `<div class="top-ip-row"><span class="top-ip-address">${escapeHtml(item.ip)}</span><span class="bar-track"><span class="bar-fill ${item.flagged ? "bar-fill-flagged" : ""}" style="width:${Math.max(5, item.failed / max * 100)}%"></span></span><span class="bar-number">${item.failed}</span></div>`).join("");
  const topItem = top[0];
  $("topIpInsight").innerHTML = `<span class="insight-icon">✦</span><span><strong>${escapeHtml(topItem.ip)}</strong> has ${topItem.failed} failed login${topItem.failed === 1 ? "" : "s"}${topItem.flagged ? " and meets your review threshold." : " and is below your review threshold."}</span>`;
}

function renderRecentEvents(events) {
  const body = $("recentEventsBody");
  const recent = [...events].sort((a, b) => (b.timestamp?.getTime() || 0) - (a.timestamp?.getTime() || 0) || b.lineNumber - a.lineNumber).slice(0, 5);
  $("recentEmpty").classList.toggle("hidden", recent.length > 0);
  body.innerHTML = recent.map((event) => `<tr><td><span class="event-type ${event.type}"><i class="event-type-dot"></i>${event.type === "failed" ? "Failed login" : event.type === "success" ? "Successful login" : "Other event"}</span></td><td><span class="event-user">${escapeHtml(event.username)}</span><span class="event-source">${escapeHtml(event.ip)}</span></td><td>${escapeHtml(formatDate(event.timestamp, true))}</td><td><span class="result-pill ${event.type}">${event.type === "failed" ? "FAILED" : event.type === "success" ? "SUCCESS" : "OTHER"}</span></td></tr>`).join("");
}

function getAllRows() {
  return [
    ...state.events.map((event) => ({ ...event, rowKind: "recognized" })),
    ...state.unparsed.map((event) => ({ ...event, rowKind: "unparsed" }))
  ].sort((a, b) => (b.timestamp?.getTime() || 0) - (a.timestamp?.getTime() || 0) || b.lineNumber - a.lineNumber);
}

function renderEventExplorer() {
  const query = $("eventSearch").value.trim().toLowerCase();
  const filter = $("eventTypeFilter").value;
  const allRows = getAllRows();
  const filtered = allRows.filter((event) => {
    const typeMatches = filter === "all" || (filter === "unparsed" ? event.rowKind === "unparsed" : event.type === filter);
    const haystack = `${event.rawLine} ${event.username} ${event.ip} ${event.type} ${event.detail}`.toLowerCase();
    return typeMatches && haystack.includes(query);
  });
  const body = $("eventsTableBody");
  body.innerHTML = filtered.slice(0, 250).map((event) => {
    const isUnparsed = event.rowKind === "unparsed";
    const typeLabel = isUnparsed ? "Unparsed line" : event.type === "failed" ? "Failed login" : event.type === "success" ? "Successful login" : "Other event";
    const statusClass = isUnparsed ? "flagged" : event.type;
    return `<tr><td><span class="event-type ${isUnparsed ? "other" : event.type}"><i class="event-type-dot"></i>${typeLabel}</span></td><td>${escapeHtml(event.timestamp ? formatDate(event.timestamp, true) : event.timestampText)}</td><td><span class="event-user">${escapeHtml(event.username)}</span></td><td><span class="ip-mono">${escapeHtml(event.ip)}</span></td><td><span class="result-pill ${statusClass}" title="${escapeHtml(event.rawLine)}">${escapeHtml(isUnparsed ? `Line ${event.lineNumber}: ${event.detail}` : event.detail)}</span></td></tr>`;
  }).join("");
  $("eventsEmpty").classList.toggle("hidden", filtered.length > 0);
  $("eventResultCount").textContent = `${numberFormat.format(filtered.length)} record${filtered.length === 1 ? "" : "s"}`;
  $("eventFooterText").textContent = filtered.length > 250 ? `Showing 250 of ${filtered.length} matching records` : `Showing ${filtered.length} record${filtered.length === 1 ? "" : "s"} from ${state.fileName || "current input"}`;
}

function renderIpTable(ips = getIpStats(state.events)) {
  const query = $("ipSearch").value.trim().toLowerCase();
  const filter = $("ipStateFilter").value;
  const filtered = ips.filter((item) => {
    const statusMatches = filter === "all" || (filter === "flagged" ? item.flagged : !item.flagged);
    return statusMatches && item.ip.toLowerCase().includes(query);
  });
  const max = Math.max(1, ...ips.map((item) => item.failed));
  $("ipTableBody").innerHTML = filtered.map((item) => `<tr><td><span class="ip-mono">${escapeHtml(item.ip)}</span><span class="event-source">${item.users.length} distinct user${item.users.length === 1 ? "" : "s"}</span></td><td><strong class="count-failed">${item.failed}</strong></td><td>${item.success}</td><td>${escapeHtml(formatDate(item.lastSeen, true))}</td><td><span class="result-pill ${item.flagged ? "flagged" : "success"}">${item.flagged ? "REVIEW" : "BELOW THRESHOLD"}</span></td><td><div class="mini-bar"><span>${item.failed}</span><span class="mini-bar-track"><span style="width:${item.failed / max * 100}%"></span></span></div></td></tr>`).join("");
  $("ipsEmpty").classList.toggle("hidden", filtered.length > 0);
  $("ipResultCount").textContent = `${filtered.length} source${filtered.length === 1 ? "" : "s"}`;
}

function renderAnalysisResult() {
  const panel = $("analyzerResultPanel");
  if (!state.lineCount) {
    panel.innerHTML = '<div class="result-placeholder"><span class="placeholder-icon">⌁</span><strong>Your analysis appears here</strong><p>Load sample data or paste a log file, then select Analyze logs.</p></div>';
    return;
  }
  const failed = state.events.filter((event) => event.type === "failed").length;
  const success = state.events.filter((event) => event.type === "success").length;
  const ips = getIpStats(state.events);
  const flagged = ips.filter((item) => item.flagged).length;
  panel.innerHTML = `<div class="analysis-result-heading"><div><div class="section-kicker">ANALYSIS COMPLETE</div><h2>Results for ${escapeHtml(state.fileName || "pasted logs")}</h2><p>Computed locally from ${state.lineCount} non-empty input lines.</p></div><span class="result-pill ${state.unparsed.length ? "flagged" : "success"}">${state.unparsed.length ? `${state.unparsed.length} UNPARSED` : "PARSING COMPLETE"}</span></div><div class="analysis-summary"><div class="analysis-summary-card"><span>Recognized events</span><strong>${numberFormat.format(state.events.length)}</strong></div><div class="analysis-summary-card alert"><span>Failed logins</span><strong>${numberFormat.format(failed)}</strong></div><div class="analysis-summary-card good"><span>Successful logins</span><strong>${numberFormat.format(success)}</strong></div><div class="analysis-summary-card alert"><span>IPs for review</span><strong>${numberFormat.format(flagged)}</strong></div></div><div class="parse-warning"><strong>Interpretation:</strong> flagged IPs met the configured count threshold. This is an investigation signal, not proof of brute-force activity or malicious intent. ${state.unparsed.length ? `${state.unparsed.length} line(s) could not be parsed; review them in Event Explorer.` : "All non-empty input lines were recognized."}</div><div class="analysis-result-actions"><button class="button button-secondary" data-open-view="events">Review event details</button><button class="button button-secondary" data-open-view="ips">Investigate IPs</button><button class="button button-primary" id="resultExportButton">Export IP CSV ↓</button></div>`;
  $("resultExportButton").addEventListener("click", exportIpCsv);
}

function showView(name) {
  const validNames = ["overview", "analyzer", "events", "ips", "help"];
  const view = validNames.includes(name) ? name : "overview";
  state.currentView = view;
  document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active-view", panel.dataset.viewPanel === view));
  document.querySelectorAll(".nav-item[data-view]").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  const labelMap = { overview: "Overview", analyzer: "Analyze logs", events: "Event explorer", ips: "IP investigation", help: "Project notes" };
  $("currentPageName").textContent = labelMap[view];
  closeMobileNav();
  window.scrollTo({ top: 0, behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

function openMobileNav() {
  $("sidebar").classList.add("open");
  $("mobileMenu").setAttribute("aria-expanded", "true");
}
function closeMobileNav() {
  $("sidebar").classList.remove("open");
  $("mobileMenu").setAttribute("aria-expanded", "false");
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  $("toastRegion").appendChild(toast);
  window.setTimeout(() => toast.remove(), 3800);
}

function analyzeCurrentInput() {
  const text = $("logTextInput").value;
  if (!text.trim()) {
    $("analyzeError").textContent = "Paste log lines, choose a file, or load sample data before analyzing.";
    $("analyzeError").classList.remove("hidden");
    $("logTextInput").focus();
    return;
  }
  $("analyzeError").classList.add("hidden");
  const lineCount = text.split(/\r?\n/).filter((line) => line.trim()).length;
  if (lineCount > 20000) {
    $("analyzeError").textContent = "This learning version supports up to 20,000 non-empty lines per analysis. Please split a larger file.";
    $("analyzeError").classList.remove("hidden");
    return;
  }
  state.fileName = state.fileName || "pasted-auth.log";
  setDataset(text, state.fileName, state.isDemo && text === SAMPLE_LOGS);
  showView("analyzer");
  showToast(`Analysis complete: ${state.events.length} recognized, ${state.unparsed.length} unparsed.`, "success");
  $("analyzerResultPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function loadSampleData() {
  $("logTextInput").value = SAMPLE_LOGS;
  $("lineCount").textContent = `${SAMPLE_LOGS.split(/\r?\n/).length} lines`;
  $("logFileInput").value = "";
  $("analyzeError").classList.add("hidden");
  setDataset(SAMPLE_LOGS, "demo-auth.log", true);
  showView("analyzer");
  showToast("Sample authentication logs loaded. Select Analyze logs to run the parser.", "success");
}

function clearData() {
  state.rawText = "";
  state.fileName = "";
  state.isDemo = false;
  state.events = [];
  state.unparsed = [];
  state.lineCount = 0;
  $("logTextInput").value = "";
  $("logFileInput").value = "";
  $("lineCount").textContent = "0 lines";
  $("analyzeError").classList.add("hidden");
  $("eventSearch").value = "";
  $("eventTypeFilter").value = "all";
  $("ipSearch").value = "";
  $("ipStateFilter").value = "all";
  renderAll();
  showToast("Current analysis cleared. Raw logs were not stored.", "success");
}

function csvCell(value) {
  let text = String(value ?? "");
  // Prevent spreadsheet formula execution when exported text starts with a formula marker.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function downloadCsv(filename, headers, rows) {
  const content = [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob(["\uFEFF", content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast(`${filename} exported.`, "success");
}

function exportIpCsv() {
  const ips = getIpStats(state.events);
  if (!ips.length) return showToast("There are no parsed IP addresses to export.", "error");
  const rows = ips.map((item) => [item.ip, item.failed, item.success, item.other, item.lastSeen?.toISOString() || "", item.flagged ? "Review" : "Below threshold", state.threshold, item.users.join("; ")]);
  downloadCsv("log-sentinel-ip-summary.csv", ["Source IP", "Failed logins", "Successful logins", "Other events", "Last seen", "Review status", "Threshold", "Observed users"], rows);
}

function exportEventsCsv() {
  const rows = getAllRows().map((event) => [event.lineNumber, event.timestamp?.toISOString() || "", event.type, event.username, event.ip, event.detail, event.format, event.rawLine]);
  if (!rows.length) return showToast("There are no events to export.", "error");
  downloadCsv("log-sentinel-events.csv", ["Line number", "Timestamp", "Type", "Username", "Source IP", "Detail", "Format", "Raw line"], rows);
}

function setThreshold(value) {
  const parsed = Number.parseInt(value, 10);
  state.threshold = Math.min(20, Math.max(2, Number.isFinite(parsed) ? parsed : 5));
  $("thresholdInput").value = state.threshold;
  renderAll();
}

async function readLogFile(file) {
  if (!file) return;
  const allowed = /\.(log|txt|csv)$/i.test(file.name) || ["text/plain", "text/csv", "application/csv"].includes(file.type);
  if (!allowed) {
    showToast("Choose a .log, .txt or .csv text file.", "error");
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    showToast("This version accepts text files up to 5 MB.", "error");
    return;
  }
  try {
    const text = await file.text();
    $("logTextInput").value = text;
    $("lineCount").textContent = `${text.split(/\r?\n/).filter((line) => line.trim()).length} lines`;
    state.fileName = file.name;
    state.isDemo = false;
    $("analyzeError").classList.add("hidden");
    showToast(`${file.name} loaded locally. Select Analyze logs to inspect it.`, "success");
  } catch {
    showToast("The selected file could not be read.", "error");
  }
}

function bindEvents() {
  document.querySelectorAll(".nav-item[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
  document.addEventListener("click", (event) => {
    const viewButton = event.target.closest("[data-open-view]");
    if (viewButton) showView(viewButton.dataset.openView);
  });
  $("goAnalyzeButton").addEventListener("click", () => showView("analyzer"));
  $("loadSampleButton").addEventListener("click", loadSampleData);
  $("analyzeButton").addEventListener("click", analyzeCurrentInput);
  $("clearInputButton").addEventListener("click", clearData);
  $("dismissNotice").addEventListener("click", () => { $("noticeBanner").remove(); state.dismissedNotice = true; });
  $("eventSearch").addEventListener("input", renderEventExplorer);
  $("eventTypeFilter").addEventListener("change", renderEventExplorer);
  $("ipSearch").addEventListener("input", () => renderIpTable());
  $("ipStateFilter").addEventListener("change", () => renderIpTable());
  $("thresholdInput").addEventListener("change", (event) => setThreshold(event.target.value));
  $("thresholdDown").addEventListener("click", () => setThreshold(state.threshold - 1));
  $("thresholdUp").addEventListener("click", () => setThreshold(state.threshold + 1));
  $("exportEventsButton").addEventListener("click", exportEventsCsv);
  $("exportIpsButton").addEventListener("click", exportIpCsv);
  $("showAllEventsButton").addEventListener("click", () => { $("eventSearch").value = ""; $("eventTypeFilter").value = "all"; renderEventExplorer(); });
  $("logTextInput").addEventListener("input", () => {
    const lines = $("logTextInput").value.split(/\r?\n/).filter((line) => line.trim()).length;
    $("lineCount").textContent = `${lines} line${lines === 1 ? "" : "s"}`;
    state.isDemo = false;
    if (!state.fileName || state.fileName === "demo-auth.log") state.fileName = "pasted-auth.log";
  });
  $("logFileInput").addEventListener("change", (event) => readLogFile(event.target.files[0]));
  $("dropZone").addEventListener("click", () => $("logFileInput").click());
  $("dropZone").addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); $("logFileInput").click(); } });
  ["dragenter", "dragover"].forEach((type) => $("dropZone").addEventListener(type, (event) => { event.preventDefault(); $("dropZone").classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((type) => $("dropZone").addEventListener(type, (event) => { event.preventDefault(); $("dropZone").classList.remove("dragging"); }));
  $("dropZone").addEventListener("drop", (event) => readLogFile(event.dataTransfer.files[0]));
  $("mobileMenu").addEventListener("click", () => $("sidebar").classList.contains("open") ? closeMobileNav() : openMobileNav());
  document.addEventListener("click", (event) => {
    if (window.innerWidth <= 930 && $("sidebar").classList.contains("open") && !$("sidebar").contains(event.target) && !$("mobileMenu").contains(event.target)) closeMobileNav();
  });
  $("helpButton").addEventListener("click", () => $("helpDialog").showModal());
  $("profileButton").addEventListener("click", () => showToast("Local demo workspace — no account or log upload is used.", "info"));
  $("closeHelp").addEventListener("click", () => $("helpDialog").close());
  $("closeHelpBottom").addEventListener("click", () => $("helpDialog").close());
}

function initialize() {
  bindEvents();
  $("logTextInput").value = SAMPLE_LOGS;
  $("lineCount").textContent = `${SAMPLE_LOGS.split(/\r?\n/).length} lines`;
  setDataset(SAMPLE_LOGS, "demo-auth.log", true);
}

document.addEventListener("DOMContentLoaded", initialize);
