"use strict";

const state = {
  scope: null,
  wifi: null,
  net: null,
  busy: false,
};

const $ = (id) => document.getElementById(id);

function setBusy(b) {
  state.busy = b;
  document.querySelectorAll("button[data-action]").forEach((el) => { el.disabled = b; });
  $("status").textContent = b ? "working…" : "ready";
  $("status").className = "badge" + (b ? " busy" : " ok");
}

function showError(msg) {
  const el = $("error");
  if (!msg) { el.classList.add("hidden"); el.textContent = ""; return; }
  el.textContent = msg;
  el.classList.remove("hidden");
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function api(method, path, body, asText = false) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["content-type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try { msg = JSON.parse(text).detail || text; } catch {}
    throw new Error(`${res.status}: ${msg}`);
  }
  return asText ? text : JSON.parse(text);
}

// --- render ------------------------------------------------------------------

function renderScope() {
  const s = state.scope;
  if (!s) { $("scope-card").innerHTML = '<span class="muted">No scope loaded.</span>'; return; }
  const targets = (s.targets || []).map((t) => {
    const parts = [];
    if (t.ssid) parts.push(`ssid=${t.ssid}`);
    if (t.bssid) parts.push(`bssid=${t.bssid}`);
    if (t.host) parts.push(`host=${t.host}`);
    if (t.cidr) parts.push(`cidr=${t.cidr}`);
    return `<div class="muted">· ${esc(parts.join("  "))}</div>`;
  }).join("") || '<div class="muted">No targets.</div>';

  $("scope-card").innerHTML = `
    <div class="grid">
      <div><div class="label">Owner</div><div class="value">${esc(s.owner)}</div></div>
      <div><div class="label">Authorized by</div><div class="value">${esc(s.authorized_by)}</div></div>
      <div><div class="label">Valid until</div><div class="value">${esc(s.valid_until)}</div></div>
      <div><div class="label">Targets</div><div class="value">${(s.targets || []).length}</div></div>
    </div>
    <div style="margin-top:12px">${targets}</div>
  `;
}

function renderWifi() {
  const data = state.wifi;
  const el = $("wifi-results");
  if (!data) { el.innerHTML = '<p class="muted">No WiFi scan yet.</p>'; return; }

  const rows = (data.access_points || []).map((ap) => {
    let enc;
    if (ap.privacy === false) enc = '<span class="pill bad">OPEN</span>';
    else if (ap.rsn) enc = '<span class="pill ok">WPA2/3</span>';
    else if (ap.wpa) enc = '<span class="pill warn">WPA/Legacy</span>';
    else enc = '<span class="pill warn">Unknown</span>';

    const sig = ap.signal_dbm != null ? `${ap.signal_dbm} dBm`
              : ap.signal_pct != null ? `${ap.signal_pct}%`
              : "-";

    const findings = (ap.findings || []).map((f) =>
      `<div><span class="pill warn">${esc(f)}</span></div>`
    ).join("") || '<span class="muted">-</span>';

    return `<tr>
      <td>${esc(ap.ssid || "<hidden>")}</td>
      <td>${esc(ap.bssid || "-")}</td>
      <td>${esc(ap.channel ?? "-")}</td>
      <td>${esc(sig)}</td>
      <td>${enc}</td>
      <td>${findings}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="6" class="muted">No access points.</td></tr>';

  el.innerHTML = `
    <p class="muted">Backend: ${esc(data.backend || "-")}
      &middot; ${esc(data.scanned_at || "-")}
      &middot; ${(data.access_points || []).length} AP(s)</p>
    <table>
      <thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>Signal</th><th>Enc</th><th>Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderNet() {
  const data = state.net;
  const el = $("net-results");
  if (!data) { el.innerHTML = '<p class="muted">No network scan yet.</p>'; return; }

  let rows = "";
  (data.hosts || []).forEach((h) => {
    (h.open_ports || []).forEach((p, i) => {
      const banner = p.banner
        ? (p.banner.length > 60 ? esc(p.banner.slice(0, 60)) + "…" : esc(p.banner))
        : '<span class="muted">-</span>';
      rows += `<tr>
        <td>${i === 0 ? esc(h.ip) : ""}</td>
        <td>${esc(p.port)}</td>
        <td>${esc(p.service || "-")}</td>
        <td>${banner}</td>
      </tr>`;
    });
  });
  if (!rows) rows = '<tr><td colspan="4" class="muted">No live hosts.</td></tr>';

  const skipped = data.skipped_out_of_scope
    ? ` &middot; ${data.skipped_out_of_scope} host(s) skipped (out of scope)`
    : "";

  el.innerHTML = `
    <p class="muted">CIDR: ${esc(data.cidr)}
      &middot; ports: ${esc(data.ports_spec)}
      &middot; ${esc(data.scanned_at || "-")}${skipped}</p>
    <table>
      <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- actions -----------------------------------------------------------------

async function loadScope() {
  try {
    state.scope = await api("GET", "/api/scope");
    renderScope();
  } catch (e) {
    showError(`Scope: ${e.message}`);
  }
}

async function loadVersion() {
  try {
    const h = await api("GET", "/api/health");
    $("version").textContent = "v" + h.version;
  } catch {}
}

async function runWifi() {
  showError("");
  setBusy(true);
  try {
    state.wifi = await api("POST", "/api/wifi/scan", {
      iface: $("iface").value.trim() || null,
      include_out_of_scope: $("wifi-all").value === "true",
    });
    renderWifi();
  } catch (e) {
    showError(`WiFi scan: ${e.message}`);
  } finally {
    setBusy(false);
  }
}

async function runNet() {
  showError("");
  setBusy(true);
  try {
    state.net = await api("POST", "/api/net/scan", {
      cidr: $("cidr").value.trim(),
      ports: $("ports").value,
      timeout: parseFloat($("timeout").value) || 1.0,
    });
    renderNet();
  } catch (e) {
    showError(`Net scan: ${e.message}`);
  } finally {
    setBusy(false);
  }
}

async function buildReport(fmt) {
  showError("");
  if (!state.wifi && !state.net) { showError("Run a scan first."); return; }
  setBusy(true);
  try {
    const body = {
      wifi: state.wifi, net: state.net, format: fmt,
    };
    const text = await api("POST", "/api/report", body, true);
    if (fmt === "json") {
      const blob = new Blob([text], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "scopeguard-report.json";
      a.click(); URL.revokeObjectURL(url);
    } else {
      const w = window.open("", "_blank");
      if (w) { w.document.open(); w.document.write(text); w.document.close(); }
      else { showError("Popup blocked. Allow popups for this page."); }
    }
  } catch (e) {
    showError(`Report: ${e.message}`);
  } finally {
    setBusy(false);
  }
}

// --- wire up -----------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  $("btn-wifi").addEventListener("click", runWifi);
  $("btn-net").addEventListener("click", runNet);
  $("btn-report-html").addEventListener("click", () => buildReport("html"));
  $("btn-report-json").addEventListener("click", () => buildReport("json"));

  loadVersion();
  loadScope();
  renderWifi();
  renderNet();
});
