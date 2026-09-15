"""Make v2 scan execution consume the exact selection that the user previewed.

A background tool-matrix refresh may rebuild the multi-select after Preview and
before Start.  The backend correctly rejected that stale empty selection.  This
migration stores the backend-normalized preview selection on the plan element
and reuses it for selected-tool execution when the same target/mode is started.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "app" / "static" / "app.js"

OLD_PREVIEW = '''async function previewPlan(){const id=Number($("scanTarget").value);if(!id)throw new Error("Select a target");const mode=$("scanMode").value,modules=selectedCategories().join(","),names=selectedValues($("scanToolSelect")).join(",");const d=await api(`/api/v2/scan-plan?target_id=${id}&mode=${encodeURIComponent(mode)}&modules=${encodeURIComponent(modules)}&tools=${encodeURIComponent(names)}`);$("scanPlan").innerHTML=`<b>${d.selected_count} selected</b> · ${d.ready_compatible_count} ready + compatible · ${d.skipped_count} skipped<br><small>${d.selected.slice(0,24).map(esc).join(", ")}${d.selected.length>24?" …":""}</small>${d.skipped.length?`<details><summary>Skipped / setup required</summary><pre>${esc(d.skipped.map(x=>`${x.tool}: ${x.reason}`).join("\\n"))}</pre></details>`:""}`;return d}'''

NEW_PREVIEW = '''async function previewPlan(){const id=Number($("scanTarget").value);if(!id)throw new Error("Select a target");const mode=$("scanMode").value,modules=selectedCategories(),names=selectedValues($("scanToolSelect"));const d=await api(`/api/v2/scan-plan?target_id=${id}&mode=${encodeURIComponent(mode)}&modules=${encodeURIComponent(modules.join(","))}&tools=${encodeURIComponent(names.join(","))}`);const box=$("scanPlan");box.dataset.targetId=String(id);box.dataset.mode=mode;box.dataset.selectedTools=JSON.stringify(d.selected||[]);box.dataset.modules=JSON.stringify(modules);box.innerHTML=`<b>${d.selected_count} selected</b> · ${d.ready_compatible_count} ready + compatible · ${d.skipped_count} skipped<br><small>${d.selected.slice(0,24).map(esc).join(", ")}${d.selected.length>24?" …":""}</small>${d.skipped.length?`<details><summary>Skipped / setup required</summary><pre>${esc(d.skipped.map(x=>`${x.tool}: ${x.reason}`).join("\\n"))}</pre></details>`:""}`;return d}
function scanRequestFromUi(){const targetId=Number($("scanTarget").value),mode=$("scanMode").value,box=$("scanPlan");let names=selectedValues($("scanToolSelect")),modules=selectedCategories();if(mode==="selected"&&box.dataset.targetId===String(targetId)&&box.dataset.mode===mode){try{const planned=JSON.parse(box.dataset.selectedTools||"[]");if(Array.isArray(planned)&&planned.length)names=planned;const plannedModules=JSON.parse(box.dataset.modules||"[]");if(Array.isArray(plannedModules))modules=plannedModules}catch{}}return{target_id:targetId,mode,modules,tools:names,tool_options:{}}}'''

OLD_START = '''$("startScan").onclick=async()=>{try{await startScan({target_id:Number($("scanTarget").value),mode:$("scanMode").value,modules:selectedCategories(),tools:selectedValues($("scanToolSelect")),tool_options:{}})}catch(e){toast(e.message,true);if(e.payload?.plan)$("scanPlan").textContent=JSON.stringify(e.payload.plan,null,2)}};'''
NEW_START = '''$("startScan").onclick=async()=>{try{await startScan(scanRequestFromUi())}catch(e){toast(e.message,true);if(e.payload?.plan)$("scanPlan").textContent=JSON.stringify(e.payload.plan,null,2)}};'''


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"v2 UI migration anchor missing: {label}")
    return text.replace(old, new, 1)


def main() -> int:
    text = APP_JS.read_text(encoding="utf-8")
    text = replace_once(text, OLD_PREVIEW, NEW_PREVIEW, "previewPlan")
    text = replace_once(text, OLD_START, NEW_START, "startScan")
    APP_JS.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
