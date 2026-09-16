(() => {
  const tierLabel = value => ({
    native: "native",
    provisioned: "provisioned",
    container: "container",
    wsl: "wsl",
    remote: "remote",
    "builtin-fallback": "builtin-fallback",
    unavailable: "unavailable"
  })[String(value || "unavailable")] || String(value || "unavailable");

  const tierSummary = tiers => Object.entries(tiers || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([tier, count]) => `<span>${esc(tierLabel(tier))}: ${Number(count || 0)}</span>`)
    .join("");

  window.toolCard = function toolCardV4(t) {
    const runnable = Boolean(t.ready && t.compatible);
    const state = t.ready ? "ready" : "blocked";
    const compat = t.compatible ? "compatible" : "target mismatch";
    const tier = tierLabel(t.runtime_tier);
    const backend = t.backend ? ` via ${t.backend}` : "";
    const reason = t.blocked_reason || `Runnable at ${tier}${backend}`;
    const served = t.alias_to ? `<span>alias → ${esc(t.alias_to)}</span>` : "";
    const setup = !t.ready && t.has_provision_recipe
      ? `<small>Run <code>winddeep doctor --heal</code> to provision this integration.</small>`
      : "";
    const disabled = runnable ? "" : " disabled aria-disabled=\"true\"";
    return `<article class="tool-card" data-tool-name="${esc(t.name)}" data-category="${esc(t.category)}" data-state="${state}" data-compatible="${t.compatible}">
      <div class="tool-card-head"><div><strong>${esc(t.name)}</strong><small>${esc(t.category)} · ${esc(t.release_support)}</small></div><span class="status ${runnable ? "ok" : "warn"}">${esc(tier)}</span></div>
      <p>${esc(t.description)}</p>
      <div class="tool-meta"><span>${esc(compat)}</span><span>${esc(tier + backend)}</span>${served}<span>${esc((t.target_types || []).join(", "))}</span><span>${esc(reason)}</span></div>
      ${setup}
      <details><summary>Execution contract</summary><pre>${esc(JSON.stringify({runtime_strategy:t.runtime_strategy,backend:t.backend,tier:t.runtime_tier,chain:t.execution_chain,options:t.options_schema},null,2))}</pre></details>
      <div class="actions wrap"><button data-tool-run="${esc(t.name)}"${disabled}>Run</button><button data-tool-run-options="${esc(t.name)}"${disabled}>Run with options</button></div>
    </article>`;
  };

  window.loadTools = async function loadToolsV4() {
    const t = activeTarget();
    const query = t ? `?target_type=${encodeURIComponent(t.type)}` : "";
    const d = await api(`/api/v2/tools${query}`);
    tools = d.tools || [];
    $("toolsSummary").innerHTML = `<span>${d.total} registered</span><span>${d.ready} runnable now</span><span>${d.unavailable || 0} unavailable on this host</span>${tierSummary(d.tiers)}`;
    renderToolFilters();
    filterTools();
    $("readyToolCount").textContent = d.ready;
    return d;
  };

  window.refreshOverview = async function refreshOverviewV4() {
    const [h, s] = await Promise.all([api("/api/health"), api("/api/v2/status")]);
    $("version").textContent = h.version;
    $("toolCount").textContent = s.registered ?? s.catalog;
    $("readyToolCount").textContent = s.ready;
    $("testCount").textContent = h.test_count;
    $("findingCount").textContent = s.findings;
    $("runningCount").textContent = s.running_scans;
    renderControls(h.controls);
    const tiers = Object.entries(s.tiers || {}).sort(([a], [b]) => a.localeCompare(b)).map(([tier, count]) => `${esc(tierLabel(tier))}: <b>${Number(count || 0)}</b>`).join(" · ");
    $("readinessSnapshot").innerHTML = `<div><span>Registered integrations</span><b>${s.registered ?? s.catalog}</b></div><div><span>Runnable on this host</span><b>${s.ready}</b></div><div><span>Unavailable on this host</span><b>${s.unavailable || 0}</b></div><div><span>Runtime tiers</span><small>${tiers || "No tier data"}</small></div><div><span>Raw proof exports</span><b class="ok">${s.raw_proof_exports ? "ON" : "OFF"}</b></div><div><span>Process cancellation</span><b class="ok">${s.cancellable_processes ? "ON" : "OFF"}</b></div>`;
  };
})();
