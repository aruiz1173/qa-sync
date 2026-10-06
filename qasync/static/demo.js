"use strict";

// The presentation runs entirely from a static synthetic fixture. It never calls /api/.
const $ = selector => document.querySelector(selector);
const escapeHtml = value => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const clone = value => JSON.parse(JSON.stringify(value));
const demo = {data:null, runId:null, caseId:null, stage:"case", selected:new Set(), proposal:null, drafts:new Map(), outcomes:new Map(), retriedCases:new Set(), history:{past:[],future:[],current:null}, tourIndex:-1, audit:[]};
let editTimer=null;
let toastTimer=null;

function toast(message){const box=$("#demo-toast");box.textContent=message;box.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>box.hidden=true,4000)}
function currentRun(){return demo.data?.runs.find(run=>run.id===demo.runId)}
function currentCase(){return demo.data?.cases.find(item=>item.id===demo.caseId)}
function runCases(runId){return demo.data.cases.filter(item=>item.run_id===runId)}
function resetDetailScroll(){const detail=$("#demo-detail");detail.scrollTop=0;requestAnimationFrame(()=>detail.scrollTop=0)}
function statusLabel(status){return status.charAt(0).toUpperCase()+status.slice(1)}
function record(action){demo.audit.unshift({at:new Date().toISOString(),case_id:demo.caseId,action});demo.audit=demo.audit.slice(0,30)}

function renderRuns(){
  const box=$("#demo-runs");box.innerHTML=demo.data.runs.map(run=>{
    const cases=runCases(run.id),passed=cases.filter(item=>item.status==="passed").length;
    return `<button class="${run.id===demo.runId?'active':''}" type="button" data-run="${run.id}"><strong>${escapeHtml(run.name)}</strong><small>${escapeHtml(run.device)}</small><div class="progress-track"><span style="width:${passed/cases.length*100}%"></span></div><small>Example R${run.id} · ${passed} illustrative passed statuses · ${cases.length} fictitious cases</small></button>`;
  }).join("");
  box.querySelectorAll("[data-run]").forEach(button=>button.addEventListener("click",()=>selectRun(Number(button.dataset.run))));
}

function selectRun(runId){
  window.demoExecution?.leave();
  demo.runId=runId;demo.caseId=null;demo.stage="case";demo.proposal=null;
  updateRunHeading();
  $("#demo-search").value="";renderRuns();renderCases();renderDetail();resetDetailScroll();record(`Opened demo run R${runId}`);
}
function updateRunHeading(){
  const run=currentRun(),cases=runCases(run.id);
  $("#demo-run-id").textContent=`RUN R${run.id} · ${run.platform.toUpperCase()}`;
  $("#demo-run-title").textContent=run.name;
  $("#demo-run-summary").textContent=`${cases.length} fictitious cases · ${cases.filter(item=>item.status==='passed').length} illustrative passed · ${cases.filter(item=>item.status==='failed').length} illustrative failed`;
}

function renderCases(){
  const query=$("#demo-search").value.trim().toLowerCase();
  const cases=runCases(demo.runId).filter(item=>`${item.title} C${item.id} ${item.status}`.toLowerCase().includes(query));
  $("#demo-cases").innerHTML=cases.map(item=>`<button class="${item.id===demo.caseId?'active':''}" type="button" data-case="${item.id}"><div class="subline"><span class="status-dot status-${item.status}"></span><strong>${escapeHtml(item.title)}</strong></div><small>Example C${item.id} · illustrative ${statusLabel(item.status)} · ${item.steps.length} steps</small></button>`).join("")||'<p class="demo-bottom-note">No cases match that search.</p>';
  $("#demo-cases").querySelectorAll("[data-case]").forEach(button=>button.addEventListener("click",()=>selectCase(Number(button.dataset.case))));
}

function selectCase(caseId){
  window.demoExecution?.leave();
  demo.caseId=caseId;demo.stage="case";demo.proposal=null;renderCases();renderDetail();resetDetailScroll();record(`Opened synthetic case C${caseId}`);
}

function caseHead(item){return `<div class="detail-head"><div><span class="eyebrow">EXAMPLE CASE C${item.id} · ${currentRun().platform.toUpperCase()}</span><h2>${escapeHtml(item.title)}</h2><p>${escapeHtml(currentRun().device)} · <span class="status-badge ${item.status}">Illustrative ${statusLabel(item.status)}</span> · ${escapeHtml(item.category||"Functional")}</p></div><div class="detail-actions"><button class="button" id="demo-execute" data-action="execute" type="button">Try separate Execute simulation</button><button class="button primary" id="demo-generate" data-action="capture" type="button">Explore evidence example</button></div></div>`}
function renderCase(){
  const item=currentCase();if(!item){$("#demo-detail").innerHTML='<div class="demo-empty">Choose a case to inspect its preconditions, steps and expected results.</div>';return}
  const outcome=demo.outcomes.get(item.id);
  $("#demo-detail").innerHTML=`<div id="demo-case">${caseHead(item)}${outcome?`<div class="demo-note">Demo decision: ${escapeHtml(outcome.label)} · original synthetic TC ${outcome.keepOriginal?'unchanged':'preserved as baseline'}</div>`:''}<section class="case-section"><h3>Preconditions</h3><p>${escapeHtml(item.preconditions)}</p></section><section class="case-section"><h3>Existing steps and expected results</h3><ol class="step-list">${item.steps.map(step=>`<li><div>${step.optional?'<span class="small-badge">Optional</span>':''}<p>${escapeHtml(step.content)}</p><p class="expected">Expected: ${escapeHtml(step.expected)}</p></div></li>`).join("")}</ol></section><div class="demo-note">Synthetic baseline only. A real tester reviews device evidence, corrects the proposal and explicitly decides whether the TestRail case should change. This page cannot access a device or TestRail.</div></div>`;
}

function startCapture(){demo.stage="capture";demo.selected=new Set([0,1,2,4,5,7,9,11]);renderDetail();resetDetailScroll();record("Opened simulated evidence review")}
const screenNames=["Settings entry","More navigation","Modes destination","Modes list","Single mode row","Mode details","Assignment label","Assignment value","Return navigation","Modes list again","Status banner","Final visible state"];
function renderCapture(){
  const item=currentCase();if(!item)return renderCase();
  $("#demo-detail").innerHTML=`<div id="demo-capture"><div class="detail-head"><div><span class="eyebrow">PREWRITTEN EVIDENCE EXAMPLE · C${item.id}</span><h2>Review an evidence-selection example</h2><p>These are labels from a fixture, not device screenshots.</p></div><button class="button" data-action="back-case" type="button">Back to case</button></div><div class="capture-steps"><span>1 · Device setup (not performed)</span><span class="active">2 · Example selection</span><span>3 · AI analysis (not performed)</span><span>4 · Example proposal</span></div><div class="demo-note">The live app can capture a device journey and let a tester choose which screens to send. Here you only select illustrative labels; no images exist, no batches run and no provider is contacted.</div><div class="capture-grid">${screenNames.map((name,index)=>`<label class="capture-card"><input type="checkbox" value="${index}" ${demo.selected.has(index)?'checked':''}><strong>Example state ${index+1}</strong><small>${escapeHtml(name)}</small></label>`).join("")}</div><div class="capture-summary"><p id="demo-capture-count">${demo.selected.size} of 12 labels selected · no images</p><button class="button primary" data-action="generate" type="button">Load prewritten proposal example</button></div></div>`;
  $("#demo-capture").querySelectorAll('.capture-card input').forEach(input=>input.addEventListener("change",()=>{const index=Number(input.value);if(input.checked)demo.selected.add(index);else demo.selected.delete(index);$("#demo-capture-count").textContent=`${demo.selected.size} of 12 labels selected · no images`}));
}

function generatedProposal(){
  if(!demo.selected.size)return toast("Select at least one example label first.");
  const item=currentCase();
  if(["blocked","insufficient"].includes(item.scenario)||(item.scenario==="timeout"&&!demo.retriedCases.has(item.id))){
    demo.stage="gate";renderDetail();resetDetailScroll();record(`Opened prewritten review-gate scenario: ${item.scenario}`);toast(item.scenario==="timeout"?"Example timeout scenario; no provider call occurred.":"Example blocker: no proposal is shown.");return;
  }
  const candidate=item.candidate_steps||item.steps;
  demo.proposal={title:item.title,preconditions:item.preconditions,steps:candidate.map(step=>({...clone(step),verdict:"pending",reason:""}))};
  demo.history={past:[],future:[],current:clone(demo.proposal)};
  demo.stage="proposal";renderDetail();resetDetailScroll();record(`Loaded prewritten proposal fixture; ${demo.selected.size} labels selected separately`);toast("Prewritten example loaded. No screenshot or AI call was used.");
}
function renderGate(){
  const item=currentCase(),insufficient=item.scenario==="insufficient",timeout=item.scenario==="timeout";
  $("#demo-detail").innerHTML=`<div id="demo-gate"><span class="eyebrow">EXAMPLE REVIEW GATE · C${item.id}</span><h2>${timeout?'Hypothetical provider timeout':insufficient?'Example: insufficient evidence':'Example: environment blocked'}</h2><div class="demo-note">${escapeHtml(item.candidate_note||'A reviewer would resolve the blocker before updating a real case.')}</div><p class="demo-bottom-note">No analysis or execution occurred. ${demo.selected.size} selected example labels remain in this tab; the fictitious TC is unchanged.</p><div class="proposal-actions">${timeout?'<button class="button primary" data-action="retry" type="button">Show retry outcome example</button>':''}<button class="button" data-action="keep-original" type="button">Record no update</button><button class="button" data-action="back-case" type="button">Back to case</button></div></div>`;
}

function stepEditor(step,index){
  return `<article class="demo-step-edit" data-step="${index}"><div class="step-edit-head"><strong>Step ${index+1}</strong><div><button class="button" data-action="up" data-index="${index}" type="button" ${index===0?'disabled':''} aria-label="Move step up">↑</button><button class="button" data-action="down" data-index="${index}" type="button" ${index===demo.proposal.steps.length-1?'disabled':''} aria-label="Move step down">↓</button><button class="button" data-action="delete" data-index="${index}" type="button" ${demo.proposal.steps.length===1?'disabled':''}>Delete</button></div></div><label>Action<textarea data-field="content" maxlength="5000">${escapeHtml(step.content)}</textarea></label><label>Expected result<textarea data-field="expected" maxlength="5000">${escapeHtml(step.expected)}</textarea></label><label class="optional-check"><input data-field="optional" type="checkbox" ${step.optional?'checked':''}> Optional step</label><div class="feedback-row"><label>QA verdict<select data-field="verdict"><option value="pending" ${!step.verdict||step.verdict==='pending'?'selected':''}>Needs review</option><option value="accept" ${step.verdict==='accept'?'selected':''}>Accept</option><option value="edit" ${step.verdict==='edit'?'selected':''}>Edited</option><option value="reject" ${step.verdict==='reject'?'selected':''}>Reject</option></select></label><label>Reason / evidence note<input data-field="reason" maxlength="500" value="${escapeHtml(step.reason||'')}" placeholder="Required when edited or rejected"></label></div></article>`;
}
function renderProposal(){
  const item=currentCase(),p=demo.proposal;
  const comparison=p.steps.map((step,index)=>{const old=item.steps[index],changed=!old||old.content!==step.content||old.expected!==step.expected;return `<div class="comparison-row ${changed?'changed':''}"><strong>Step ${index+1} · ${changed?'Proposed change':'No change'}</strong><p><span>Existing:</span> ${escapeHtml(old?.expected||'No step')}</p><p><span>Example:</span> ${escapeHtml(step.expected)}</p></div>`}).join("");
  $("#demo-detail").innerHTML=`<div id="demo-proposal"><div class="detail-head"><div><span class="eyebrow">PREWRITTEN PROPOSAL EXAMPLE · C${item.id}</span><h2>Review an example suggestion</h2><p>Fixture content · not derived from selected labels · no images, batches or AI calls</p></div><button class="button" data-action="back-case" type="button">Back to case</button></div><div class="demo-note">${escapeHtml(item.candidate_note||"Compare this hypothetical suggestion with the existing TC.")} This example did not come from an AI provider or a device. No live TestRail write is possible here.</div><section class="comparison" id="demo-comparison"><h3>Existing example TC vs prewritten suggestion</h3>${comparison}</section><div class="editor-toolbar" id="demo-editor-toolbar"><p id="demo-undo-status">${demo.history.past.length} undo · ${demo.history.future.length} redo available</p><div><button class="button" data-action="undo" type="button" ${demo.history.past.length?'':'disabled'}>Undo</button><button class="button" data-action="redo" type="button" ${demo.history.future.length?'':'disabled'}>Redo</button><button class="button" data-action="preview" type="button">Preview</button></div></div><div class="editor-grid" id="demo-proposal-editor"><label>Title<input data-proposal="title" maxlength="250" value="${escapeHtml(p.title)}"></label><label>Preconditions<textarea data-proposal="preconditions" maxlength="10000">${escapeHtml(p.preconditions)}</textarea></label></div><div class="step-edit-head"><h3>Proposed steps · QA feedback</h3><button class="button" data-action="add" type="button">Add step</button></div><div id="demo-step-editors">${p.steps.map(stepEditor).join("")}</div><div class="proposal-actions"><button id="demo-save-draft" class="button primary" data-action="save" type="button">Save demo draft</button><button class="button" data-action="preview" type="button">Preview final TC</button><button class="button" data-action="decision" type="button">Review simulated decision</button><button class="button" data-action="export" type="button">Export this TC</button><button class="button" type="button" disabled title="No TestRail writes in the guided demo">Update TestRail · disabled</button></div><p class="demo-bottom-note">The draft lives only in this tab. Resetting or closing the demo clears it. Every change still requires a human decision.</p></div>`;
}

function renderDetail(){if(demo.stage==="capture")renderCapture();else if(demo.stage==="proposal")renderProposal();else if(demo.stage==="gate")renderGate();else if(demo.stage==="execute")window.demoExecution?.render();else renderCase()}
function readEditor(){
  if(demo.stage!=="proposal")return demo.proposal;
  return {title:$("[data-proposal=title]").value,preconditions:$("[data-proposal=preconditions]").value,steps:[...document.querySelectorAll("#demo-step-editors [data-step]")].map(node=>({content:node.querySelector("[data-field=content]").value,expected:node.querySelector("[data-field=expected]").value,optional:node.querySelector("[data-field=optional]").checked,verdict:node.querySelector("[data-field=verdict]").value,reason:node.querySelector("[data-field=reason]").value}))};
}
function snapshotChange(message,rerender=false){
  if(demo.stage!=="proposal")return;
  const next=readEditor();if(JSON.stringify(next)===JSON.stringify(demo.history.current))return;
  demo.history.past.push(clone(demo.history.current));if(demo.history.past.length>50)demo.history.past.shift();demo.history.current=clone(next);demo.history.future=[];demo.proposal=clone(next);
  if(rerender)renderProposal();else{const label=$("#demo-undo-status");if(label)label.textContent=`${demo.history.past.length} undo · 0 redo available`;const button=$("[data-action=undo]");if(button)button.disabled=false}
  if(message)toast(message);
}
function flushEditor(){if(!editTimer)return;clearTimeout(editTimer);editTimer=null;snapshotChange("")}
function mutateStep(action,index){
  flushEditor();const steps=demo.proposal.steps;
  if(action==="add")steps.push({content:"",expected:"",optional:false,verdict:"pending",reason:""});
  if(action==="delete"&&steps.length>1)steps.splice(index,1);
  if(action==="up"&&index>0)[steps[index-1],steps[index]]=[steps[index],steps[index-1]];
  if(action==="down"&&index<steps.length-1)[steps[index+1],steps[index]]=[steps[index],steps[index+1]];
  renderProposal();snapshotChange({add:"Step added.",delete:"Step deleted.",up:"Step moved up.",down:"Step moved down."}[action],false);
}
function undo(){flushEditor();if(!demo.history.past.length)return;demo.history.future.push(clone(demo.history.current));demo.history.current=demo.history.past.pop();demo.proposal=clone(demo.history.current);renderProposal();toast("Demo edit undone.")}
function redo(){flushEditor();if(!demo.history.future.length)return;demo.history.past.push(clone(demo.history.current));demo.history.current=demo.history.future.pop();demo.proposal=clone(demo.history.current);renderProposal();toast("Demo edit restored.")}
function saveDraft(){flushEditor();demo.proposal=readEditor();demo.drafts.set(demo.caseId,clone(demo.proposal));$("#demo-draft-count").textContent=demo.drafts.size;record("Saved demo draft in this browser tab");toast(`Demo draft for C${demo.caseId} saved in this tab.`)}
function downloadJson(filename,value){const link=document.createElement("a");const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:"application/json"}));link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1500)}
function exportCase(){flushEditor();const item=currentCase();downloadJson(`qa-sync-DEMO-C${item.id}.json`,{demo:true,case_id:item.id,run_id:item.run_id,status:item.status,original:item,proposal:demo.proposal});record("Exported synthetic case JSON");toast("Synthetic case exported; no real data included.")}
function openModal(title,html){$("#demo-modal-title").textContent=title;$("#demo-modal-content").innerHTML=html;$("#demo-modal").showModal()}
function previewProposal(){flushEditor();const p=readEditor();openModal("Preview final TC",`<div class="demo-panel-item"><strong>${escapeHtml(p.title)}</strong><p>${escapeHtml(p.preconditions)}</p></div>${p.steps.map((step,index)=>`<div class="demo-panel-item"><strong>${index+1}. ${step.optional?'<span class="small-badge">Optional</span>':''}${escapeHtml(step.content)}</strong><p>Expected: ${escapeHtml(step.expected)}</p><p>QA verdict: ${escapeHtml(step.verdict||'pending')}${step.reason?' · '+escapeHtml(step.reason):''}</p></div>`).join("")}<p class="demo-bottom-note">Preview only; TestRail is unchanged.</p>`)}
function reviewDecision(){
  flushEditor();const item=currentCase(),p=readEditor(),pending=p.steps.filter(step=>step.verdict==="pending").length,missing=p.steps.filter(step=>["edit","reject"].includes(step.verdict)&&!step.reason.trim()).length;
  const changed=JSON.stringify(p.steps.map(({content,expected,optional})=>({content,expected,optional})))!==JSON.stringify(item.steps.map(({content,expected,optional})=>({content,expected,optional:!!optional})));
  openModal("QA decision · simulated",`<div class="demo-panel-item"><strong>Before / after: C${item.id}</strong><p>Existing: ${item.steps.length} steps · proposed: ${p.steps.length} steps · ${changed?'content differs':'no content change'}.</p><p>Feedback: ${p.steps.filter(step=>step.verdict==='accept').length} accepted · ${p.steps.filter(step=>step.verdict==='edit').length} edited · ${p.steps.filter(step=>step.verdict==='reject').length} rejected · ${pending} pending.</p></div><div class="demo-panel-item"><strong>Human gate</strong><p>${missing?'Edited or rejected steps need a reason. ':''}${pending?'Some steps still need review. ':''}No action here changes TestRail. The original synthetic TC remains available for comparison.</p><div class="proposal-actions"><button class="button" id="demo-keep-original" type="button">Keep original · no update</button><button class="button primary" id="demo-approve-simulated" type="button" ${pending||missing||p.steps.some(step=>step.verdict==='reject')||!changed?'disabled':''}>Approve simulated update</button></div></div>`);
  $("#demo-keep-original").addEventListener("click",()=>{if(missing)return toast("Add a reason for each edited or rejected step.");recordDecision(true)});
  $("#demo-approve-simulated").addEventListener("click",()=>recordDecision(false));
}
function recordDecision(keepOriginal){
  const item=currentCase(),label=keepOriginal?"Keep original · no update":"Simulated update approved";
  demo.outcomes.set(item.id,{label,keepOriginal,at:new Date().toISOString(),feedback:clone(demo.proposal?.steps||[])});
  record(label);if($("#demo-modal").open)$("#demo-modal").close();demo.stage="case";renderDetail();resetDetailScroll();toast(`${label}. No TestRail write was made.`);
}

function showPanel(kind){
  if(kind==="capabilities"){
    const capabilities=[
      ["Connect and prepare","TestRail project/run selection, provider choice, device discovery, preflight checks and project profiles."],
      ["Capture a journey","Android ADB/scrcpy or iOS Simulator/Appium capture, manual screen selection, encrypted evidence and retention policies."],
      ["Reconstruct a case","Chronological batches, full-workflow synthesis, confidence checks, prompt versioning, cache and cost/latency reporting."],
      ["Human review","Edit, add, delete and reorder steps; mark steps optional; preview, undo/redo and record step-level feedback."],
      ["Preserve and publish","Autosaved proposals, local drafts, explicit TestRail confirmation, backup history, rollback and audit export."],
      ["Verify execution","Guided device control, deterministic result capture, optional-step handling and AI-assisted verification with manual verdicts."],
      ["Operate safely","Local-only browser service, protected credentials, selectable test-credential policy, device matrix and configurable retention."]
    ];
    openModal("What QA Sync does",capabilities.map(([title,detail])=>`<div class="demo-panel-item"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p></div>`).join("")+"<p class='demo-bottom-note'>This demo illustrates the workflow only. To perform these actions, return to the live workspace with real configuration and devices.</p>");
  }else if(kind==="drafts"){
    const drafts=[...demo.drafts.entries()];openModal("Demo drafts",drafts.length?drafts.map(([id,p])=>`<div class="demo-panel-item"><strong>C${id} · ${escapeHtml(p.title)}</strong><p>${p.steps.length} edited steps · this browser tab only</p><button class="button" type="button" data-open-draft="${id}">Open draft</button></div>`).join(""):'<div class="demo-panel-item"><strong>No demo drafts yet</strong><p>Generate a proposal and choose Save demo draft.</p></div>');
    $("#demo-modal-content").querySelectorAll("[data-open-draft]").forEach(button=>button.addEventListener("click",()=>{const id=Number(button.dataset.openDraft),item=demo.data.cases.find(value=>value.id===id);$("#demo-modal").close();selectRun(item.run_id);selectCase(id);demo.proposal=clone(demo.drafts.get(id));demo.history={past:[],future:[],current:clone(demo.proposal)};demo.stage="proposal";renderDetail()}));
  }else if(kind==="matrix"){
    openModal("Illustrative device matrix",demo.data.runs.map(run=>`<div class="demo-panel-item"><strong>${escapeHtml(run.device)}</strong><p>${run.platform.toUpperCase()} · ${runCases(run.id).length} demo cases · R${run.id}</p></div>`).join("")+"<p class='demo-bottom-note'>Real matrix entries are recorded from tested device/version combinations.</p>");
  }else if(kind==="quality"){
    const feedback=[...demo.outcomes.values()].flatMap(outcome=>outcome.feedback),count=verdict=>feedback.filter(step=>step.verdict===verdict).length;
    openModal("QA review quality · this demo",`<div class="demo-panel-item"><strong>20 synthetic cases · 4 runs</strong><p>These counts reflect only actions taken in this tab; they are not team performance metrics.</p></div><div class="demo-panel-item"><strong>${count('accept')} accepted · ${count('edit')} edited · ${count('reject')} rejected</strong><p>${demo.outcomes.size} simulated case decisions. A reviewer still decides whether a proposal is safe.</p></div><div class="demo-panel-item"><strong>0 tokens · $0.00 spent</strong><p>No provider was called. Live QA Sync displays actual usage and latency when reported.</p></div>`);
  }else if(kind==="audit"){
    openModal("Audit & export",`<div class="demo-panel-item"><strong>Presentation-only activity</strong><p>Demo actions and decisions are kept in memory in this tab. Live QA Sync stores an audit history and exports JSON or CSV.</p><button id="demo-export-audit" class="button" type="button">Export demo audit JSON</button></div>${demo.audit.slice(0,8).map(event=>`<div class="demo-panel-item"><strong>${escapeHtml(event.action)}</strong><p>${escapeHtml(event.at)}${event.case_id?` · C${event.case_id}`:''}</p></div>`).join("")}`);
    $("#demo-export-audit").addEventListener("click",()=>downloadJson("qa-sync-DEMO-audit.json",{demo:true,events:demo.audit,outcomes:[...demo.outcomes.entries()].map(([case_id,outcome])=>({case_id,...outcome}))}));
  }
}

const tourSteps=[
  {title:"An isolated presentation",text:"All 20 cases, four runs, devices, and statuses are fictitious. The tour does not read production data, execute test cases, capture screens, or call AI.",target:"#demo-safety"},
  {title:"Example runs",text:"These four runs are sample records. Their IDs and statuses illustrate navigation; they are not TestRail results.",target:"#demo-runs-panel",enter:()=>selectRun(9101)},
  {title:"Case handling",text:"The 20 fictitious cases cover different QA review scenarios. You can inspect any of them without changing a real case.",target:"#demo-cases-panel",enter:()=>selectCase(900001)},
  {title:"Read the case first",text:"The preconditions, steps, and expected results shown here come from the fixture. The status is illustrative too; nobody executed this case.",target:"#demo-case .detail-head"},
  {title:"Execute is a separate feature",text:"The live app has an Execute workflow, but this tour does not start it or mark any steps Pass or Fail. You can try the separate local simulation if you choose.",target:"#demo-execute"},
  {title:"Illustrative evidence selection",text:"The live app lets a tester review captures before sending them. Here there are only prewritten screen labels: no images exist and no batches ran.",target:"#demo-capture .detail-head",enter:startCapture},
  {title:"A prewritten suggestion",text:"This example comes from the fixture. AI did not generate it, and it was not inferred from the selected labels. Use it to practice human review.",target:"#demo-proposal .detail-head",enter:generatedProposal},
  {title:"Compare before and after",text:"This comparison contains an intentional discrepancy between the example case and the prewritten suggestion. It is not a finding from a test execution.",target:"#demo-comparison"},
  {title:"Step-level feedback",text:"You can accept, edit, or reject the example content. Those decisions affect only this demo tab.",target:".feedback-row"},
  {title:"Edit, undo, and preview",text:"Try the editor, optional-step flag, Undo/Redo, and Preview. These changes do not modify TestRail.",target:"#demo-editor-toolbar"},
  {title:"Draft and human decision",text:"Save an example draft or keep the original text. Nothing is published; the Update TestRail button is disabled.",target:"#demo-save-draft"},
  {title:"Metrics from this tab only",text:"Quality counts only example decisions made here; Audit exports only demo activity. These are not team metrics.",target:"#demo-open-quality"},
  {title:"More fictitious scenarios",text:"After the tour, inspect C900008, C900010, and C900018 to discuss insufficient evidence, blockers, and no-change cases. None is executed automatically.",target:"#demo-header"}
];
function showTourStep(){
  const spotlight=$("#demo-spotlight");spotlight.hidden=true;
  const step=tourSteps[demo.tourIndex];if(step.enter)step.enter();
  $("#demo-tour").hidden=false;$("#demo-tour-count").textContent=`${demo.tourIndex+1} / ${tourSteps.length}`;$("#demo-tour-title").textContent=step.title;$("#demo-tour-text").textContent=step.text;$("#demo-tour-back").disabled=demo.tourIndex===0;$("#demo-tour-next").textContent=demo.tourIndex===tourSteps.length-1?"Finish":"Next";
  const target=$(step.target);
  if(!target||!target.getClientRects().length)return;
  target.scrollIntoView({block:"center",inline:"nearest",behavior:"auto"});
  requestAnimationFrame(positionSpotlight);
}
function positionSpotlight(){
  const spot=$("#demo-spotlight");spot.hidden=true;
  if(demo.tourIndex<0)return;
  const target=$(tourSteps[demo.tourIndex].target);
  if(!target||!target.getClientRects().length)return;
  const bounds=target.getBoundingClientRect();
  const visible={left:Math.max(0,bounds.left),top:Math.max(0,bounds.top),right:Math.min(innerWidth,bounds.right),bottom:Math.min(innerHeight,bounds.bottom)};
  for(let parent=target.parentElement;parent&&parent!==document.body;parent=parent.parentElement){
    const style=getComputedStyle(parent);
    if(!/(auto|scroll|hidden|clip)/.test(`${style.overflowX} ${style.overflowY}`))continue;
    const clip=parent.getBoundingClientRect();
    visible.left=Math.max(visible.left,clip.left);visible.top=Math.max(visible.top,clip.top);
    visible.right=Math.min(visible.right,clip.right);visible.bottom=Math.min(visible.bottom,clip.bottom);
  }
  if(visible.right-visible.left<8||visible.bottom-visible.top<8)return;
  const panel=$("#demo-tour");
  panel.style.left=visible.left>innerWidth/2?"20px":"";
  panel.style.right=visible.left>innerWidth/2?"auto":"20px";
  spot.style.left=`${Math.max(4,visible.left-5)}px`;
  spot.style.top=`${Math.max(4,visible.top-5)}px`;
  spot.style.width=`${Math.min(innerWidth-8,visible.right-visible.left+10)}px`;
  spot.style.height=`${Math.min(innerHeight-8,visible.bottom-visible.top+10)}px`;
  spot.hidden=false;
}
function endTour(){demo.tourIndex=-1;$("#demo-tour").hidden=true;$("#demo-spotlight").hidden=true;toast("Tour finished. The 20 synthetic cases are yours to explore.")}
function moveTour(delta){const next=demo.tourIndex+delta;if(next>=tourSteps.length)return endTour();if(next<0)return;demo.tourIndex=next;showTourStep()}
function startTour(){if(!demo.data)return;window.demoExecution?.leave();demo.runId=9101;demo.caseId=900001;demo.stage="case";demo.proposal=null;updateRunHeading();renderRuns();renderCases();renderDetail();demo.tourIndex=0;showTourStep()}
function resetDemo(){endTour();window.demoExecution?.leave();demo.drafts.clear();demo.outcomes.clear();demo.retriedCases.clear();demo.audit=[];$("#demo-draft-count").textContent="0";demo.runId=9101;demo.caseId=900001;demo.stage="case";demo.proposal=null;updateRunHeading();renderRuns();renderCases();renderDetail();resetDetailScroll();toast("Demo reset. Local synthetic screenshots are retained until overwritten.")}

$("#demo-detail").addEventListener("click",event=>{
  const button=event.target.closest("[data-action]");if(!button)return;const action=button.dataset.action,index=Number(button.dataset.index||0);
  if(action==="capture")startCapture();else if(action==="execute")window.demoExecution?.open();else if(action==="back-case"){demo.stage="case";renderDetail();resetDetailScroll()}else if(action==="generate")generatedProposal();else if(action==="retry"){demo.retriedCases.add(demo.caseId);record("Retried mock analysis with preserved evidence");generatedProposal()}else if(action==="keep-original")recordDecision(true);else if(["add","delete","up","down"].includes(action))mutateStep(action,index);else if(action==="undo")undo();else if(action==="redo")redo();else if(action==="save")saveDraft();else if(action==="preview")previewProposal();else if(action==="decision")reviewDecision();else if(action==="export")exportCase();
});
$("#demo-detail").addEventListener("input",event=>{if(!event.target.matches("[data-proposal],[data-field=content],[data-field=expected],[data-field=reason]"))return;clearTimeout(editTimer);editTimer=setTimeout(()=>{editTimer=null;snapshotChange("")},450)});
$("#demo-detail").addEventListener("change",event=>{if(event.target.matches("[data-field=optional],[data-field=verdict]")){flushEditor();snapshotChange("QA step review updated.")}});
$("#demo-search").addEventListener("input",renderCases);
$("#demo-start-tour").addEventListener("click",startTour);
$("#demo-reset").addEventListener("click",resetDemo);
$("#demo-tour-back").addEventListener("click",()=>moveTour(-1));
$("#demo-tour-next").addEventListener("click",()=>moveTour(1));
$("#demo-tour-exit").addEventListener("click",endTour);
$("#demo-close-modal").addEventListener("click",()=>$("#demo-modal").close());
for(const kind of ["capabilities","drafts","matrix","quality","audit"])$("#demo-open-"+kind).addEventListener("click",()=>showPanel(kind));
window.addEventListener("resize",positionSpotlight);
document.addEventListener("scroll",positionSpotlight,true);
document.addEventListener("keydown",event=>{if(event.key==="Escape"&&demo.tourIndex>=0)endTour();if(demo.stage!=="proposal"||!(event.metaKey||event.ctrlKey)||event.altKey)return;if(event.key.toLowerCase()==="z"){event.preventDefault();event.shiftKey?redo():undo()}else if(event.key.toLowerCase()==="y"){event.preventDefault();redo()}});

fetch("/demo-qa-data.json").then(response=>{if(!response.ok)throw new Error("Demo fixture unavailable");return response.json()}).then(data=>{
  if(data.version!==1||data.runs?.length!==4||data.cases?.length!==20)throw new Error("The demo fixture is incomplete.");
  demo.data=data;$("#demo-project-name").textContent=data.project;demo.runId=data.runs[0].id;demo.caseId=data.cases[0].id;updateRunHeading();renderRuns();renderCases();renderDetail();resetDetailScroll();record("Opened guided demo");
}).catch(error=>{$("#demo-detail").textContent=`The demo could not load: ${error.message}`;toast(error.message)});
