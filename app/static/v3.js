/* Windeep v3 additive UI overlay: tester triage + all-findings report. */
(() => {
  const state = {filter: "actionable", rows: [], scanId: 0};
  const groupFor = disposition => disposition === "actionable" ? "actionable" : disposition === "needs-review" ? "needs-review" : "not-actionable";
  const verificationClass = value => value === "verified" ? "ok" : value === "partially_verified" ? "warn" : value === "needs-review" ? "warn" : "";

  function ensureTabs(){
    const list = document.getElementById("findingList");
    if(!list || document.getElementById("v3FindingTabs")) return;
    const tabs = document.createElement("div");
    tabs.id = "v3FindingTabs";
    tabs.className = "toolbar";
    tabs.innerHTML = [
      ["actionable", "Actionable"],
      ["needs-review", "Needs-review"],
      ["not-actionable", "Not-actionable"]
    ].map(([value,label]) => `<button data-v3-tab="${value}">${label}</button>`).join("");
    list.parentNode.insertBefore(tabs, list);
    tabs.addEventListener("click", event => {
      const button = event.target.closest("[data-v3-tab]");
      if(!button) return;
      state.filter = button.dataset.v3Tab;
      render();
    });
  }

  async function latestAuthorizedScan(){
    const rows = await api("/api/scans");
    const targetId = Number(activeTargetId || document.getElementById("reportTarget")?.value || 0);
    return rows.find(row => Number(row.target_id) === targetId) || rows[0] || null;
  }

  function editor(row){
    return `<details><summary>Classify / rank</summary><div class="inline-grid">
      <label>Disposition<select data-v3-disposition="${row.finding_id}">
        ${["actionable","needs-review","not-actionable","informational"].map(value => `<option value="${value}" ${value===row.disposition?"selected":""}>${value}</option>`).join("")}
      </select></label>
      <label>Priority 0–100<input data-v3-priority="${row.finding_id}" type="number" min="0" max="100" step="1" value="${Number(row.tester_priority||0)}"></label>
      <label>Duplicate risk<select data-v3-duplicate="${row.finding_id}">
        ${["low","medium","high"].map(value => `<option value="${value}" ${value===row.duplicate_risk?"selected":""}>${value}</option>`).join("")}
      </select></label>
    </div><label>Rationale<input data-v3-rationale="${row.finding_id}" value="${esc(row.rationale||"")}"></label>
    <button data-v3-save="${row.finding_id}">Save tester triage</button></details>`;
  }

  function render(){
    ensureTabs();
    const list = document.getElementById("findingList");
    if(!list || !state.scanId) return;
    const rows = state.rows.filter(row => groupFor(row.disposition) === state.filter);
    const title = state.filter === "actionable" ? "Actionable" : state.filter === "needs-review" ? "Needs-review" : "Not-actionable";
    list.innerHTML = rows.map(row => `<div class="item" data-v3-finding="${row.finding_id}"><div class="grow">
      <div class="row"><strong>[${esc(String(row.severity||"info").toUpperCase())}] ${esc(row.title||"Finding")}</strong><span class="status ${verificationClass(row.verification_state)}">verification: ${esc(row.verification_state||"not-recorded")}</span></div>
      <small>${esc(row.tool||"unknown")} · ${esc(row.endpoint||"")} · ${esc(row.asset_class)} · disposition ${esc(row.disposition)}</small>
      <p>${esc(row.rationale||"Tester has not classified this finding yet.")}</p>
      <details><summary>Why this rank</summary><p>Tester priority ${Number(row.tester_priority||0).toFixed(0)}, duplicate risk ${esc(row.duplicate_risk)}, severity ${esc(row.severity)}, final score ${Number(row.score||0).toFixed(2)}. Classification changes prominence only; the finding remains in the all-findings report.</p></details>
      ${editor(row)}
    </div><button data-finding-view="${row.finding_id}">Proof</button></div>`).join("") || `<span class="muted">No ${title.toLowerCase()} findings in this scan.</span>`;
    document.querySelectorAll("[data-v3-tab]").forEach(button => button.classList.toggle("primary", button.dataset.v3Tab===state.filter));
  }

  async function loadV3Findings(){
    ensureTabs();
    const scan = await latestAuthorizedScan();
    if(!scan){ state.scanId=0; state.rows=[]; return; }
    state.scanId = Number(scan.id);
    const data = await api(`/api/v3/scans/${state.scanId}/findings`);
    state.rows = data.findings || [];
    render();
  }

  const legacyLoadFindings = loadFindings;
  loadFindings = async function(){
    const result = await legacyLoadFindings();
    try { await loadV3Findings(); } catch(error) { console.warn("v3 triage view unavailable", error); }
    return result;
  };

  document.addEventListener("click", async event => {
    const save = event.target.closest("[data-v3-save]");
    if(!save) return;
    const findingId = Number(save.dataset.v3Save);
    try {
      const result = await api(`/api/v3/findings/${findingId}/triage`, {
        method: "POST",
        body: JSON.stringify({
          disposition: document.querySelector(`[data-v3-disposition="${findingId}"]`).value,
          tester_priority: Number(document.querySelector(`[data-v3-priority="${findingId}"]`).value),
          duplicate_risk: document.querySelector(`[data-v3-duplicate="${findingId}"]`).value,
          rationale: document.querySelector(`[data-v3-rationale="${findingId}"]`).value.trim()
        })
      });
      const index = state.rows.findIndex(row => row.finding_id === findingId);
      if(index >= 0) state.rows[index] = {...state.rows[index], ...result.classification};
      render();
      toast("Tester triage saved");
    } catch(error) { toast(error.message, true); }
  });

  const reportButton = document.getElementById("generateReport");
  if(reportButton){
    reportButton.onclick = async () => {
      try {
        const scan = await latestAuthorizedScan();
        if(!scan) throw new Error("No authorized scan is available for this target");
        const response = await fetch(`/api/v3/scans/${scan.id}/report?format=markdown`, {headers:{"Accept":"text/markdown"}});
        if(!response.ok){ let detail={}; try{detail=await response.json()}catch{}; throw new Error(detail.error||`${response.status} ${response.statusText}`); }
        document.getElementById("reportPreview").textContent = await response.text();
        toast("V3 all-findings report generated");
      } catch(error) { toast(error.message, true); }
    };
  }

  ensureTabs();
})();
