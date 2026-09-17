/* Windeep v3/v4 additive UI overlay: tester triage + resolver-aware runtime. */
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
    tabs.innerHTML = [["actionable","Actionable"],["needs-review","Needs-review"],["not-actionable","Not-actionable"]].map(([value,label]) => `<button data-v3-tab="${value}">${label}</button>`).join("");
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
      <label>Disposition<select data-v3-disposition="${row.finding_id}">${["actionable","needs-review","not-actionable","informational"].map(value => `<option value="${value}" ${value===row.disposition?"selected":""}>${value}</option>`).join("")}</select></label>
      <label>Priority 0–100<input data-v3-priority="${row.finding_id}" type="number" min="0" max="100" step="1" value="${Number(row.tester_priority||0)}"></label>
      <label>Duplicate risk<select data-v3-duplicate="${row.finding_id}">${["low","medium","high"].map(value => `<option value="${value}" ${value===row.duplicate_risk?"selected":""}>${value}</option>`).join("")}</select></label>
    </div><label>Rationale<input data-v3-rationale="${row.finding_id}" value="${esc(row.rationale||"")}"></label><button data-v3-save="${row.finding_id}">Save tester triage</button></details>`;
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
      ${editor(row)}</div><button data-finding-view="${row.finding_id}">Proof</button></div>`).join("") || `<span class="muted">No ${title.toLowerCase()} findings in this scan.</span>`;
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
      const result = await api(`/api/v3/findings/${findingId}/triage`, {method:"POST",body:JSON.stringify({
        disposition: document.querySelector(`[data-v3-disposition="${findingId}"]`).value,
        tester_priority: Number(document.querySelector(`[data-v3-priority="${findingId}"]`).value),
        duplicate_risk: document.querySelector(`[data-v3-duplicate="${findingId}"]`).value,
        rationale: document.querySelector(`[data-v3-rationale="${findingId}"]`).value.trim()
      })});
      const index = state.rows.findIndex(row => row.finding_id === findingId);
      if(index >= 0) state.rows[index] = {...state.rows[index], ...result.classification};
      render(); toast("Tester triage saved");
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
        toast("V3-compatible all-findings report generated");
      } catch(error) { toast(error.message, true); }
    };
  }

  /* v4 runtime truth: the UI consumes resolver state rather than catalog presence. */
  toolCard = function(t){
    const alias=t.alias_to?` · alias→${esc(t.alias_to)}`:"";
    const reason=t.blocked_reason||`Resolved through ${t.tier}`;
    const action=t.ready
      ? `<button data-tool-run="${esc(t.name)}">Run</button><button data-tool-run-options="${esc(t.name)}">Run with options</button>`
      : t.provisionable
        ? `<button class="primary" data-tool-run="${esc(t.name)}">Provision & run</button>`
        : `<button disabled>Unavailable</button>`;
    return `<article class="tool-card" data-tool-name="${esc(t.name)}" data-category="${esc(t.category)}" data-state="${t.ready?"ready":"blocked"}" data-compatible="${t.compatible}">
      <div class="tool-card-head"><div><strong>${esc(t.name)}</strong><small>${esc(t.category)} · ${esc(t.tier)}${alias}</small></div><span class="status ${t.ready?"ok":"warn"}">${esc(t.tier)}</span></div>
      <p>${esc(t.description)}</p><div class="tool-meta"><span>${t.compatible?"compatible":"target mismatch"}</span><span>${esc((t.target_types||[]).join(", "))}</span><span>${esc(reason)}</span></div>
      <details><summary>Backend chain / options</summary><pre>${esc(JSON.stringify({chain:t.backend_chain,options:t.options_schema},null,2))}</pre></details><div class="actions wrap">${action}</div></article>`;
  };

  loadTools = async function(){
    const t=activeTarget();
    const query=t?`?target_type=${encodeURIComponent(t.type)}`:"";
    const d=await api(`/api/v4/tools${query}`);
    tools=d.tools||[];
    $("toolsSummary").innerHTML=`<span>${d.total} catalog</span><span>${d.ready} ready here</span><span>${d.runnable} runnable tier</span><span>${d.unavailable} unavailable</span>`;
    renderToolFilters(); filterTools(); $("readyToolCount").textContent=d.ready; return d;
  };

  function eligibleForPayload(payload){
    const base=tools.filter(t=>t.ready&&t.compatible&&t.category!=="utilities");
    const mode=payload.mode||"smart";
    if(mode==="selected") return base.filter(t=>(payload.tools||[]).includes(t.name));
    if(mode==="module"||mode==="category") return base.filter(t=>(payload.modules||[]).includes(t.category));
    if(mode==="smart") return base.filter(t=>t.scan_default!==false);
    return base;
  }

  previewPlan = async function(){
    const id=Number($("scanTarget").value); if(!id) throw new Error("Select a target");
    const payload=scanRequestFromUi(), selected=eligibleForPayload(payload).map(t=>t.name);
    const blocked=tools.filter(t=>t.compatible&&!t.ready&&t.category!=="utilities");
    const box=$("scanPlan"); box.dataset.targetId=String(id); box.dataset.mode=payload.mode; box.dataset.selectedTools=JSON.stringify(selected); box.dataset.modules=JSON.stringify(payload.modules||[]);
    box.innerHTML=`<b>${selected.length} resolver-ready</b> · ${blocked.length} currently unavailable<br><small>${selected.slice(0,24).map(esc).join(", ")}${selected.length>24?" …":""}</small>${blocked.length?`<details><summary>Unavailable / healable</summary><pre>${esc(blocked.slice(0,80).map(x=>`${x.name}: ${x.blocked_reason}`).join("\n"))}</pre></details>`:""}`;
    return {selected,selected_count:selected.length,skipped:blocked};
  };

  startScan = async function(payload){
    const selected=eligibleForPayload(payload).map(t=>t.name);
    if(!selected.length) throw new Error("No resolver-ready integrations match this scan plan. Use Tools to provision one, or run winddeep doctor --heal.");
    const consent=await ensureConsent(payload.target_id);
    const requestPayload={...payload,mode:"selected",tools:selected,consent_id:consent,global_rps:Number($("scanRps").value||5)};
    const d=await api("/api/v2/scans",{method:"POST",body:JSON.stringify(requestPayload)});
    toast(`Scan #${d.scan_id} started with ${selected.length} resolver-ready integration(s)`); await loadScans(); return d;
  };

  runTool = async function(name,withOptions=false){
    const target=activeTarget(); if(!target) throw new Error("Select an active target first");
    let tool=tools.find(item=>item.name===name); if(!tool) throw new Error(`Unknown integration: ${name}`);
    if(!tool.ready){
      if(!tool.provisionable) throw new Error(tool.blocked_reason||`${name} is unavailable on this host`);
      if(!confirm(`${name} is not installed. Provision it now using its declared ${tool.provision?.ecosystem||"package"} recipe?`)) return;
      toast(`Provisioning ${name}…`);
      await api(`/api/v4/tools/${encodeURIComponent(name)}/provision`,{method:"POST",body:JSON.stringify({consent:true})});
      await loadTools(); tool=tools.find(item=>item.name===name);
      if(!tool?.ready) throw new Error(`${name} was provisioned but is not resolver-ready; run its probe/doctor for details.`);
    }
    let options={}; if(withOptions){const raw=prompt(`Optional JSON options for ${name}`,"{}"); if(raw===null)return; options=JSON.parse(raw||"{}");}
    await startScan({target_id:target.id,mode:"selected",tools:[name],modules:[],tool_options:{[name]:options}});
  };

  refreshOverview = async function(){
    const [h,v4,v2]=await Promise.all([api("/api/health"),api("/api/v4/status"),api("/api/v2/status")]);
    $("version").textContent=v4.version; $("toolCount").textContent=v4.catalog; $("readyToolCount").textContent=v4.runnable; $("testCount").textContent=h.test_count; $("findingCount").textContent=v2.findings; $("runningCount").textContent=v2.running_scans; renderControls(h.controls);
    $("readinessSnapshot").innerHTML=`<div><span>Catalog integrations</span><b>${v4.catalog}</b></div><div><span>Runnable on this host</span><b>${v4.runnable}</b></div><div><span>Unavailable</span><b>${v4.unavailable}</b></div>${Object.entries(v4.tiers||{}).map(([k,v])=>`<div><span>${esc(k)}</span><b>${v}</b></div>`).join("")}`;
  };

  ensureTabs();
})();
