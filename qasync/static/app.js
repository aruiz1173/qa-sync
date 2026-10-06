const $=selector=>document.querySelector(selector);
const state={draftId:'',draftUpdatedAt:0,projects:[],runs:[],plans:[],planRuns:{},expandedPlan:null,pastedRun:null,preservedSession:null,tests:[],activeRun:null,activeTest:null,currentCase:null,proposal:null,devices:{android:[],ios:[]},session:null,analysisSession:null,lastEvidencePreview:null,lastEvidenceSessionId:'',recoveredSessionCaseId:null,sessionPreserved:false,evidencePreview:null,analysisInProgress:false,analysisMinimized:false,timer:null,screenTimer:null,execution:null,executionTimer:null,executionReviewIndex:null,mirrors:{},serverInstanceId:'',preflightReady:false,queueReviewId:null,queueReviewCaseId:null,deferredSnapshot:'',deferredTimer:null,deferredRequestId:0,deferredLoading:false,deferredRefreshQueued:false,workspace:{project_id:'',runs:{},choices:{}},preferredDeviceId:''};
let analysisProgressTimer=null;
let editorHistory=null;
let autosaveTimer=null;
let pendingAutosavePayload=null,autosaveRevision=0,autosaveError=null,autosaveOutstanding=0,autosaveChain=Promise.resolve();
const editorTabId=globalThis.crypto?.randomUUID?.()||`${Date.now()}-${Math.random()}`;
let editorLeaseKey='',editorLeaseTimer=null;
const leaseStorageKey=caseId=>`qasync:editor:${caseId}`;
function readEditorLease(){try{return JSON.parse(localStorage.getItem(editorLeaseKey)||'null')}catch(_){return null}}
function ownsEditorLease(){const lease=readEditorLease();return !editorLeaseKey||!lease||lease.until<Date.now()||lease.owner===editorTabId}
function releaseEditorLease(){clearInterval(editorLeaseTimer);editorLeaseTimer=null;if(editorLeaseKey&&ownsEditorLease()){try{localStorage.removeItem(editorLeaseKey)}catch(_){}}editorLeaseKey=''}
function renewEditorLease(){if(!editorLeaseKey)return;const lease=readEditorLease();if(lease&&lease.owner!==editorTabId&&lease.until>Date.now()){updateEditorLeaseUI();return}try{localStorage.setItem(editorLeaseKey,JSON.stringify({owner:editorTabId,until:Date.now()+15000}))}catch(_){}updateEditorLeaseUI()}
function claimEditorLease(force=false){if(!state.proposal)return;const key=leaseStorageKey(state.proposal.case_id);if(editorLeaseKey&&editorLeaseKey!==key)releaseEditorLease();editorLeaseKey=key;const lease=readEditorLease();if(force||!lease||lease.until<Date.now()||lease.owner===editorTabId){try{localStorage.setItem(key,JSON.stringify({owner:editorTabId,until:Date.now()+15000}))}catch(_){editorLeaseKey='';updateEditorLeaseUI();return}}clearInterval(editorLeaseTimer);editorLeaseTimer=setInterval(renewEditorLease,5000);updateEditorLeaseUI()}
function updateEditorLeaseUI(){const box=$('#edit-lease');if(!box||!state.proposal)return;const lease=readEditorLease(),other=lease&&lease.owner!==editorTabId&&lease.until>Date.now();box.hidden=!other;$('#edit-lease-message').textContent=other?'Another tab is editing this case. Your local changes are preserved; take over only after coordinating with that tab.':'';$('#take-over-edit').hidden=!other;document.querySelectorAll('#proposal-content .proposal-editor input,#proposal-content .proposal-editor textarea,#proposal-content .proposal-editor select,#proposal-content .step-toolbar button,#add-step,#undo-edit,#redo-edit,#save-draft,#apply-update').forEach(el=>{if(other)el.disabled=true;else if(!el.matches('#apply-update')||state.proposal.write_mode!=='review_only')el.disabled=false});if(!other)updateEditorHistoryButtons();updateAutosaveActions()}
window.addEventListener('storage',event=>{if(event.key===editorLeaseKey)updateEditorLeaseUI()});
async function showAnalysisProgress(){$('#evidence-step').hidden=true;$('#recording-step').hidden=false;$('#recording-step h3').textContent='Analysing selected screens';$('#recording-step>p').textContent='QA Sync is sending only the screens you reviewed and is reconstructing the complete workflow.';const box=$('#analysis-progress');box.hidden=false;let frames=0,budget=40;try{const [status,server]=await Promise.all([api('/api/record/status',{session_id:state.session}),getJson('/api/status')]);frames=Number(status.frames||0);budget=Number(server.ai_max_images||budget)}catch(_){}const selected=state.evidencePreview?selectedEvidenceFrames().length:Math.min(frames,budget);const batches=selected>4?Math.ceil(selected/4):1;const calls=batches+(batches>1?1:0);const started=Date.now();const render=()=>{const elapsed=Math.floor((Date.now()-started)/1000);const batch=Math.min(batches,Math.max(1,Math.floor(elapsed/30)+1));const synthesis=batch===batches&&elapsed>=batches*30;const detail=`${selected} reviewed screens selected from ${frames} captures. Estimated ${calls} provider calls (${batches} chronological batch${batches===1?'':'es'}${calls>batches?' + final synthesis':''}). Full evidence remains local. Elapsed ${elapsed}s; each call can take up to 90s.`;$('#analysis-progress-title').textContent=synthesis?'Synthesising complete workflow…':`Analysing batch ${batch} of ${batches}…`;$('#analysis-progress-detail').textContent=detail;$('#analysis-task-title').textContent=synthesis?'Synthesising complete workflow…':`Analysing batch ${batch} of ${batches}…`;$('#analysis-task-detail').textContent=detail};render();clearInterval(analysisProgressTimer);analysisProgressTimer=setInterval(render,1000)}
function hideAnalysisProgress(){clearInterval(analysisProgressTimer);analysisProgressTimer=null;$('#analysis-progress').hidden=true}
const escapeHtml=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
let toastMessage='';let toastUndoAction=null;
function hideToast(){const el=$('#toast');el.className='toast';if(typeof el.hidePopover==='function'&&el.matches(':popover-open'))el.hidePopover()}
const showToast=(message,error=false)=>{const el=$('#toast');toastUndoAction=null;$('#undo-toast').hidden=true;$('#copy-toast').hidden=false;toastMessage=String(message||'');$('#toast-message').textContent=toastMessage;$('#copy-toast').textContent='Copy';el.className=`toast show${error?' error':''}`;if(error){$('#error-message').textContent=toastMessage;$('#copy-error-message').textContent='Copy error';const dialog=$('#error-dialog');if(!dialog.open)dialog.showModal()}if(typeof el.showPopover==='function'&&!el.matches(':popover-open'))el.showPopover();clearTimeout(showToast.timer);showToast.timer=setTimeout(hideToast,4200)};
function showUndoToast(message,label='Undo',action=undoEditor){const el=$('#toast');toastMessage=String(message||'');toastUndoAction=action;$('#toast-message').textContent=toastMessage;$('#undo-toast').textContent=label;$('#undo-toast').hidden=false;$('#copy-toast').hidden=true;el.className='toast show';if(typeof el.showPopover==='function'&&!el.matches(':popover-open'))el.showPopover();clearTimeout(showToast.timer);showToast.timer=setTimeout(()=>{toastUndoAction=null;hideToast()},8000)}
function invalidateUndoToast(){if(!toastUndoAction)return;toastUndoAction=null;clearTimeout(showToast.timer);hideToast()}
async function copyToast(){if(!toastMessage)return;const buttons=[$('#copy-toast'),$('#copy-error-message')];try{if(!navigator.clipboard?.writeText)throw new Error('Clipboard API unavailable');await navigator.clipboard.writeText(toastMessage);buttons.forEach(button=>button.textContent='Copied')}catch(error){const range=document.createRange();range.selectNodeContents($('#error-message'));const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);try{document.execCommand('copy');buttons.forEach(button=>button.textContent='Copied')}catch(copyError){buttons.forEach(button=>button.textContent='Select text')}}}
$('#copy-toast').addEventListener('click',copyToast);
$('#undo-toast').addEventListener('click',()=>{const action=toastUndoAction;if(!action)return;toastUndoAction=null;hideToast();action()});
$('#copy-error-message').addEventListener('click',copyToast);$('#close-error-message').addEventListener('click',()=>$('#error-dialog').close());$('#dismiss-error-message').addEventListener('click',()=>$('#error-dialog').close());
const api=async(path,body={})=>{const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await response.json().catch(()=>({error:'Invalid response from the server.'}));if(!response.ok){const error=new Error(data.error||`Error HTTP ${response.status}`);error.status=response.status;error.code=data.code||'';throw error}return data};
const getJson=async path=>{const response=await fetch(path);const data=await response.json().catch(()=>({error:'Invalid response from the server.'}));if(!response.ok)throw new Error(data.error||`Error HTTP ${response.status}`);return data};
let workspaceSave=Promise.resolve();
function saveWorkspace(payload){
  state.workspace.project_id=payload.project_id;
  if(payload.run_id)state.workspace.runs[payload.project_id]=payload.run_id;
  if(payload.choice){const value={...payload.choice,suite_id:payload.suite_id||''};state.workspace.choices[`run:${payload.project_id}:${payload.run_id}`]=value;if(payload.suite_id)state.workspace.choices[`suite:${payload.project_id}:${payload.suite_id}`]=value}
  workspaceSave=workspaceSave.catch(()=>{}).then(async()=>{state.workspace=await api('/api/workspace',payload)}).catch(error=>showToast(`Could not remember this suite/device: ${error.message}`,true));
  return workspaceSave;
}
function activeChoice(){
  const run=state.activeRun;if(!run)return null;
  const project=String(run.project_id||$('#project-select').value),suite=String(run.suite_id||'');
  const specific=state.workspace.choices?.[`run:${project}:${run.id}`];if(specific)return specific;
  const shared=state.workspace.choices?.[`suite:${project}:${suite}`];
  return shared&&(!runConfig(run)||!shared.target_config||shared.target_config===runConfig(run))?shared:null;
}
function rememberDeviceChoice(){
  const run=state.activeRun;if(!run||!$('#update-dialog').open||$('#device-step').hidden)return;
  return saveWorkspace({project_id:String(run.project_id||$('#project-select').value),run_id:String(run.id),suite_id:String(run.suite_id||''),choice:{platform:selectedPlatform(),device_id:$('#device-select').value,target_config:$('#target-config').value}});
}
async function forgetRememberedDevice(){const run=state.activeRun;if(!run)return;try{await workspaceSave;state.workspace=await api('/api/workspace/forget-device',{project_id:String(run.project_id||$('#project-select').value),run_id:String(run.id),suite_id:String(run.suite_id||'')});state.preferredDeviceId='';renderDevices();showToast('Saved device forgotten for this run and suite. Platform and target remain saved.')}catch(error){showToast(error.message,true)}}
const totalForRun=run=>['passed_count','blocked_count','untested_count','retest_count','failed_count','custom_status1_count','custom_status2_count'].reduce((sum,key)=>sum+Number(run[key]||0),0);
const passedPercent=run=>{const total=totalForRun(run);return total?Math.round(Number(run.passed_count||0)*100/total):0};

async function loadProjects(){
  try{
    const [data,workspace]=await Promise.all([api('/api/projects'),getJson('/api/workspace').catch(error=>{showToast(`Saved suite choices could not be loaded: ${error.message}`,true);return {project_id:'',runs:{},choices:{}}})]);state.projects=data.projects;state.workspace=workspace;
    const select=$('#project-select');select.innerHTML=state.projects.map(p=>`<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');select.disabled=!state.projects.length;
    const preferred=[workspace.project_id,data.preferred_project_id].map(String).find(id=>state.projects.some(p=>String(p.id)===id));if(preferred)select.value=preferred;
    if(state.projects.length)await loadRuns();else $('#runs-list').innerHTML='<div class="empty"><p>No active projects.</p></div>';
  }catch(error){$('#runs-list').innerHTML='<div class="empty"><h2>Set up TestRail</h2><p>Fill in the credentials and reconnect from Settings.</p></div>';showToast(error.message,true)}
}

async function loadRuns(){
  const projectId=$('#project-select').value;if(!projectId)return;
  $('#runs-list').innerHTML='<div class="skeleton tall"></div><div class="skeleton tall"></div>';
  try{const data=await api('/api/runs',{project_id:projectId});state.runs=data.runs;state.plans=data.plans||[];state.planRuns={};state.expandedPlan=null;renderRuns();const last=Number(state.workspace.runs?.[projectId]);if(last){let run=knownRuns().find(item=>item.id===last);if(!run){try{run=(await api('/api/run',{run_id:last})).run;if(String(run.project_id)===String(projectId))state.pastedRun=run;else run=null}catch(_){run=null}}if(run)await selectRun(last,false)}}
  catch(error){$('#runs-list').innerHTML='<div class="empty"><p>Runs could not be loaded.</p></div>';showToast(error.message,true)}
}

// Un run puede venir del listado del proyecto, de dentro de un plan, o pegado por URL.
const knownRuns=()=>[...state.runs,...Object.values(state.planRuns).flat(),...(state.pastedRun?[state.pastedRun]:[])];

// La configuración de TestRail dice a qué dispositivo apunta el run ("Android
// Phone", "Android Tablet"): sin mostrarla, dos runs del mismo plan se ven idénticos.
const runConfig=run=>String(run.config||'').trim();

function runItemHtml(run){
  const total=totalForRun(run);
  const config=runConfig(run);
  const badge=config?`<span class="run-config">${escapeHtml(config)}</span>`:'';
  const suite=run.entry_name&&run.entry_name!==run.name?`<span class="run-suite">${escapeHtml(run.entry_name)}</span>`:'';
  return `<button class="run-item${state.activeRun?.id===run.id?' active':''}" data-run="${run.id}" type="button"><strong>${escapeHtml(run.name)}</strong>${badge}${suite}<div class="mini-progress"><span style="width:${passedPercent(run)}%"></span></div><div class="run-meta"><span>R${run.id}</span><span>${run.passed_count||0} de ${total} passed</span></div></button>`;
}

// El mismo campo filtra y abre: un proyecto puede traer 148 planes, y una lista
// plana de ese tamaño no se navega. Si lo escrito parece una URL o un id, Enter lo abre.
const matchesQuery=(item,prefix,query)=>!query||`${item.name||''} ${item.config||''} ${prefix}${item.id}`.toLowerCase().includes(query);

function renderRuns(){
  const query=$('#run-locator').value.trim().toLowerCase();
  const pasted=state.pastedRun&&!state.runs.some(run=>run.id===state.pastedRun.id)?runItemHtml(state.pastedRun):'';
  const runs=state.runs.filter(run=>matchesQuery(run,'r',query)).map(runItemHtml).join('');
  const plans=state.plans.filter(plan=>matchesQuery(plan,'p',query)).map(plan=>{
    const open=state.expandedPlan===plan.id;
    const inside=(state.planRuns[plan.id]||[]).filter(run=>matchesQuery(run,'r',query));
    const nested=open?`<div class="plan-runs">${inside.map(runItemHtml).join('')||'<div class="run-meta">No matching runs.</div>'}</div>`:'';
    return `<button class="run-item plan-item" data-plan="${plan.id}" type="button"><strong>${open?'▾':'▸'} ${escapeHtml(plan.name)}<span class="plan-badge">PLAN</span></strong><div class="run-meta"><span>P${plan.id}</span><span>${plan.passed_count||0} de ${totalForRun(plan)} passed</span></div></button>${nested}`;
  }).join('');
  const body=pasted+runs+plans;
  const empty=query
    ?`<div class="empty"><h2>No matches</h2><p>Nothing matches “${escapeHtml($('#run-locator').value.trim())}”. If that is a run URL, press Enter to open it.</p></div>`
    :'<div class="empty"><h2>No active runs</h2><p>This project has no open runs or plans. You can open a run by URL or R-number, switch project, or review local work.</p><div class="dialog-inline-actions"><button id="empty-paste-run" class="secondary" type="button">Paste run ID or URL</button><button id="empty-change-project" class="secondary" type="button">Change project</button><button id="empty-my-work" class="secondary" type="button">My work</button></div></div>';
  $('#runs-list').innerHTML=body||empty;
  document.querySelectorAll('[data-run]').forEach(button=>button.addEventListener('click',()=>selectRun(Number(button.dataset.run))));
  document.querySelectorAll('[data-plan]').forEach(button=>button.addEventListener('click',()=>togglePlan(Number(button.dataset.plan))));
  $('#empty-paste-run')?.addEventListener('click',()=>$('#run-locator').focus());
  $('#empty-change-project')?.addEventListener('click',()=>$('#project-select').focus());
  $('#empty-my-work')?.addEventListener('click',openMyWork);
}

async function togglePlan(id){
  if(state.expandedPlan===id){state.expandedPlan=null;renderRuns();return}
  state.expandedPlan=id;
  if(!state.planRuns[id]){
    // Se expande un plan a la vez: recorrer todos costaría un request por plan.
    try{const data=await api('/api/plan-runs',{plan_id:id});state.planRuns[id]=data.runs}
    catch(error){state.expandedPlan=null;showToast(error.message,true);return}
  }
  renderRuns();
}

async function openLocatorRun(){
  const value=$('#run-locator').value.trim();if(!value)return;
  try{
    const data=await api('/api/run',{run_id:value});
    state.pastedRun=data.run;$('#run-locator').value='';renderRuns();await selectRun(data.run.id);
  }catch(error){showToast(error.message,true)}
}

async function selectRun(id,persist=true){
  if(!await ensureProposalSaved())return;
  state.activeRun=knownRuns().find(run=>run.id===id);if(!state.activeRun)return;
  if(persist)saveWorkspace({project_id:String(state.activeRun.project_id||$('#project-select').value),run_id:String(id)});
  state.activeTest=null;state.currentCase=null;renderRuns();
  $('#run-empty').hidden=true;$('#run-content').hidden=false;$('#run-label').textContent=[`RUN R${id}`,state.activeRun.plan_id?`PLAN P${state.activeRun.plan_id}`:'',runConfig(state.activeRun)].filter(Boolean).join(' · ');$('#run-name').textContent=state.activeRun.name;
  $('#run-progress').style.width=`${passedPercent(state.activeRun)}%`;$('#run-summary').textContent=`${state.activeRun.passed_count||0} passed · ${state.activeRun.failed_count||0} failed · ${state.activeRun.untested_count||0} untested`;
  $('#tests-list').innerHTML='<div class="skeleton"></div><div class="skeleton"></div>';showCaseEmpty();
  try{const data=await api('/api/tests',{run_id:id});state.tests=data.tests;renderTests()}
  catch(error){$('#tests-list').innerHTML='<div class="empty"><p>Cases could not be loaded.</p></div>';showToast(error.message,true)}
}

function renderTests(){
  const query=$('#case-search').value.trim().toLowerCase();const tests=state.tests.filter(test=>`${test.title} c${test.case_id}`.toLowerCase().includes(query));
  $('#tests-list').innerHTML=tests.map(test=>`<button class="test-item${state.activeTest?.id===test.id?' active':''}" data-test="${test.id}" type="button"><span class="status-dot status-${test.status_id}"></span><span class="test-copy"><strong>${escapeHtml(test.title)}</strong><span>${test.refs?escapeHtml(test.refs):'No references'}</span></span><span class="test-id">C${test.case_id}</span></button>`).join('')||'<div class="empty"><p>No matches.</p></div>';
  document.querySelectorAll('[data-test]').forEach(button=>button.addEventListener('click',()=>selectTest(Number(button.dataset.test))));
}


// TestRail guarda los casos con HTML, así que mostrarlo escapado llenaba la vista de
// etiquetas. Se renderiza, pero nunca crudo: el contenido de TestRail es dato no
// confiable, igual que para el prompt. Allowlist de etiquetas, sin ningún atributo
// salvo href http(s), y las etiquetas peligrosas se eliminan con su contenido.
const RICH_TAGS=new Set(['P','BR','UL','OL','LI','STRONG','B','EM','I','U','SPAN','CODE','PRE','A','H1','H2','H3','H4','H5','H6','TABLE','THEAD','TBODY','TR','TD','TH','BLOCKQUOTE','HR','DIV','SUB','SUP','SMALL','DEL','INS']);
const RICH_DROP=new Set(['SCRIPT','STYLE','IFRAME','OBJECT','EMBED','LINK','META','SVG','MATH','TEMPLATE','NOSCRIPT','FORM','INPUT','BUTTON','SELECT','TEXTAREA','BASE','IMG','VIDEO','AUDIO','SOURCE','CANVAS']);

function richHtml(value){
  const doc=new DOMParser().parseFromString(String(value??''),'text/html');
  const clean=node=>{
    for(const child of [...node.childNodes]){
      if(child.nodeType===Node.TEXT_NODE)continue;
      if(child.nodeType!==Node.ELEMENT_NODE){child.remove();continue}
      const tag=child.tagName.toUpperCase();
      if(RICH_DROP.has(tag)){child.remove();continue}
      if(!RICH_TAGS.has(tag)){
        // Se limpia dentro antes de desenvolver, o los hijos se saltarían el filtro.
        clean(child);
        child.replaceWith(...child.childNodes);
        continue;
      }
      for(const attr of [...child.attributes]){
        const name=attr.name.toLowerCase();
        const keep=tag==='A'&&name==='href'&&/^https?:\/\//i.test(attr.value.trim());
        if(!keep)child.removeAttribute(attr.name);
      }
      if(tag==='A'){child.setAttribute('target','_blank');child.setAttribute('rel','noopener noreferrer')}
      clean(child);
    }
  };
  clean(doc.body);
  return doc.body.innerHTML;
}

// Los pasos como los muestra TestRail: acción y resultado esperado emparejados.
function stepsPreview(steps){
  if(!steps.length)return '<p class="rich-empty">No steps.</p>';
  return `<ol class="rich-steps">${steps.map(step=>{
    const content=String(step.content||'');
    const optional=/^\[(optional|opcional)\]\s*/i.test(content);
    return `<li><div class="rich-step">${optional?'<span class="optional-badge">Optional</span>':''}<div class="rich-body">${richHtml(content.replace(/^\[(optional|opcional)\]\s*/i,''))}</div><div class="rich-expected"><span class="rich-label">Expected result</span><div class="rich-body">${richHtml(step.expected||'')||'<p class="rich-empty">No expected result</p>'}</div></div></div></li>`;
  }).join('')}</ol>`;
}


// El editor guarda HTML crudo porque eso es lo que va a TestRail; el preview lo
// muestra ya interpretado, para revisar lo que verá el equipo y no un muro de etiquetas.
function renderPreview(){
  const edits=proposalEdits();
  const box=$('#proposal-preview');
  if(!box)return;
  box.innerHTML=`<div class="rich-case"><p class="overline">PREVIEW</p><h3>${escapeHtml(edits.title)}</h3>`
    +`<section><h4>Preconditions</h4><div class="rich-body">${richHtml(edits.preconditions)||'<p class="rich-empty">No preconditions.</p>'}</div></section>`
    +`<section><h4>Steps</h4>${stepsPreview(edits.steps)}</section></div>`;
}

function togglePreview(){
  const preview=$('#proposal-preview');
  const editor=document.querySelector('.proposal-editor');
  const button=$('#toggle-preview');
  if(!preview||!editor||!button)return;
  flushEditorHistory();const showing=preview.hidden;
  if(showing)renderPreview();
  preview.hidden=!showing;
  editor.hidden=showing;
  button.textContent=showing?'Back to editing':'Preview as TestRail';
}

function showCaseEmpty(){releaseEditorLease();$('#case-empty').hidden=false;$('#case-loading').hidden=true;$('#case-content').hidden=true;$('#proposal-content').hidden=true}
async function selectTest(id){
  if(!await ensureProposalSaved())return;
  state.activeTest=state.tests.find(test=>test.id===id);renderTests();$('#case-empty').hidden=true;$('#case-content').hidden=true;$('#proposal-content').hidden=true;$('#case-loading').hidden=false;
  try{const data=await api('/api/case',{case_id:state.activeTest.case_id});state.currentCase=data.case;renderCase()}
  catch(error){showCaseEmpty();showToast(error.message,true)}
}

function renderCase(){
  releaseEditorLease();
  const item=state.currentCase;$('#case-loading').hidden=true;$('#proposal-content').hidden=true;$('#case-content').hidden=false;
  $('#case-id').textContent=`CASE C${item.id}`;$('#case-title').textContent=item.title;$('#case-refs').textContent=item.refs||'No references';$('#case-estimate').textContent=item.estimate||'No estimate';
  $('#case-preconditions').innerHTML=richHtml(item.preconditions)||'<p class="rich-empty">No preconditions documented.</p>';
  const steps=item.steps||[];$('#case-steps').innerHTML=steps.length?steps.map(step=>{const content=String(step.content||'');const optional=/^\[(optional|opcional)\]\s*/i.test(content);return `<li><div>${optional?'<span class="optional-badge">Optional</span>':''}<div class="rich-body">${richHtml(content.replace(/^\[(optional|opcional)\]\s*/i,''))}</div><div class="rich-expected"><span class="rich-label">Expected result</span><div class="rich-body">${richHtml(step.expected)||'<p class="rich-empty">No expected result</p>'}</div></div></div></li>`}).join(''):'<li><div><p class="step-action">This case has no separate steps.</p></div></li>';
}

async function openHistory(){
  if(!state.currentCase)return;
  $('#history-title').textContent=`History for C${state.currentCase.id}`;
  $('#history-list').innerHTML='<div class="skeleton"></div>';
  $('#history-dialog').showModal();
  try{
    const data=await api('/api/history',{case_id:state.currentCase.id});
    $('#history-list').innerHTML=data.history.length?data.history.map(item=>`<article class="history-item"><div><strong>${escapeHtml(item.proposed_title||`C${item.case_id}`)}</strong><p>${new Date(item.created_at*1000).toLocaleString()} · ${escapeHtml(item.state)}</p></div>${item.state==='pending'?`<button class="secondary" data-reconcile="${item.id}" type="button">Check outcome</button>`:item.state==='rolled_back'?'<span class="optional-badge">Restaurado</span>':`<button class="secondary" data-rollback="${item.id}" data-confirmation="${escapeHtml(item.confirmation)}" type="button">Restore</button>`}</article>`).join(''):'<div class="empty"><p>No backups for this case yet.</p></div>';
    document.querySelectorAll('[data-rollback]').forEach(button=>button.addEventListener('click',()=>rollbackBackup(button)));
    document.querySelectorAll('[data-reconcile]').forEach(button=>button.addEventListener('click',()=>reconcileBackup(button)));
  }catch(error){$('#history-list').innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}
}
async function rollbackBackup(button){
  const expected=button.dataset.confirmation;const confirmation=window.prompt(`Type ${expected} to restore the case.`,'');
  if(confirmation===null)return;
  button.disabled=true;
  try{await api('/api/rollback',{backup_id:button.dataset.rollback,confirmation});showToast('Caso restaurado correctamente.');$('#history-dialog').close();await selectTest(state.activeTest.id)}
  catch(error){showToast(error.message,true);button.disabled=false}
}

const selectedPlatform=()=>document.querySelector('input[name="platform"]:checked').value;
// Sin simctl (macOS) ni un Appium remoto no existe ningún camino a iOS, así que
// elegirlo sólo llevaba a una lista vacía. Se desactiva y se dice por qué.
function applyPlatformSupport(){
  const caps=state.devices.capabilities||{};
  const iosPossible=Boolean(caps.simctl||caps.appium);
  const input=document.querySelector('input[name="platform"][value="ios"]');
  if(!input)return iosPossible;
  input.disabled=!iosPossible;
  const label=input.closest('label');
  if(label){
    label.classList.toggle('unsupported',!iosPossible);
    label.title=iosPossible?'':'iOS needs macOS with Xcode, or a remote Appium on a Mac.';
  }
  if(!iosPossible&&input.checked){
    const android=document.querySelector('input[name="platform"][value="android"]');
    if(android)android.checked=true;
  }
  return iosPossible;
}

function renderDevices(){applyPlatformSupport();const platform=selectedPlatform();const list=state.devices[platform]||[];const unavailable=state.devices[`${platform}_unavailable`]||[];const mirrors=state.devices.mirrors||{};const current=$('#device-select').value;const ready=list.map(d=>`<option value="${escapeHtml(d.id)}">${escapeHtml(d.name)} · ${escapeHtml(d.kind)}${d.version?` · Android ${escapeHtml(d.version)}`:''}${mirrors[d.id]?' · mirror open':''}</option>`);const blocked=unavailable.map(d=>`<option value="" disabled>${escapeHtml(d.name)} · ${escapeHtml(d.kind)}</option>`);$('#device-select').innerHTML=ready.length||blocked.length?[...ready,...blocked].join(''):'<option value="">No device available</option>';const preferred=[state.preferredDeviceId,current].find(id=>id&&list.some(item=>item.id===id));if(preferred)$('#device-select').value=preferred;const notice=$('#remembered-device');const saved=activeChoice()?.device_id||'';if(saved&&!list.some(item=>item.id===saved)){const missing=document.createElement('option');missing.value='';missing.textContent='Remembered device unavailable — choose a device';$('#device-select').prepend(missing);$('#device-select').value=''}notice.hidden=!saved;notice.textContent=saved?(list.some(item=>item.id===saved)?'Restored the last device for this run or suite. Confirm it before recording.':'The remembered device is not connected. Select an available device before recording.'):'';const renderLaunchers=(selector,items,empty)=>{const select=$(selector);select.innerHTML=items.length?['<option value="">Select a device to start</option>',...items.map(item=>`<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)} · ${escapeHtml(item.kind)}${item.api_level?` · API ${escapeHtml(item.api_level)}`:''}${item.abi?` · ${escapeHtml(item.abi)}`:''}</option>`)].join(''):empty};renderLaunchers('#android-avd-select',state.devices.android_avds||[],'<option value="">No Android virtual devices found</option>');renderLaunchers('#ios-simulator-select',state.devices.ios_simulators||[],'<option value="">No available iOS Simulators found</option>');$('#start-android-avd').disabled=!(state.devices.android_avds||[]).length;$('#start-ios-simulator').disabled=!(state.devices.ios_simulators||[]).length}
const renderDevicesBase=renderDevices;
renderDevices=()=>{renderDevicesBase();$('#remembered-device-row').hidden=!activeChoice()?.device_id};
async function refreshDevices(){$('#refresh-devices').disabled=true;try{state.devices=await getJson('/api/devices');renderDevices();const relevant=(state.devices.errors||[]).filter(item=>item.toLowerCase().startsWith(selectedPlatform()));if(relevant.length)showToast(relevant.join(' '),true)}catch(error){showToast(error.message,true)}finally{$('#refresh-devices').disabled=false}}

const executionPlatform=()=>document.querySelector('input[name="execution-platform"]:checked').value;
function renderExecutionDevices(){const platform=executionPlatform();const list=platform==='ios'&&!state.devices.capabilities?.appium?[]:(state.devices[platform]||[]);const current=$('#execution-device').value;$('#execution-device').innerHTML=list.length?list.map(item=>`<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)} · ${escapeHtml(item.kind)}</option>`).join(''):platform==='ios'?'<option value="">Configure Appium/XCUITest for deterministic iOS execution</option>':'<option value="">No device available</option>';const preferred=[current,activeChoice()?.device_id].find(id=>id&&list.some(item=>item.id===id));if(preferred)$('#execution-device').value=preferred}
async function openExecution(){if(!state.currentCase||!state.activeTest||!state.activeRun)return;state.execution=null;state.executionReviewIndex=null;$('#execution-title').textContent=`Execute C${state.currentCase.id} · T${state.activeTest.id}`;$('#execution-setup').hidden=false;$('#execution-active').hidden=true;const choice=activeChoice();const platform=document.querySelector(`input[name="execution-platform"][value="${choice?.platform==='ios'?'ios':'android'}"]`);if(platform)platform.checked=true;$('#execution-dialog').showModal();try{state.devices=await getJson('/api/devices');renderExecutionDevices()}catch(error){showToast(error.message,true)}}
async function startExecution(){const button=$('#start-execution');const device=$('#execution-device').value;if(!device)return showToast('Select a device.',true);button.disabled=true;try{const data=await api('/api/execution/start',{run_id:state.activeRun.id,test_id:state.activeTest.id,case_id:state.currentCase.id,platform:executionPlatform(),device_id:device,offline:$('#execution-offline').checked});await saveWorkspace({project_id:String(state.activeRun.project_id||$('#project-select').value),run_id:String(state.activeRun.id),suite_id:String(state.activeRun.suite_id||''),choice:{platform:executionPlatform(),device_id:device,target_config:activeChoice()?.target_config||runConfig(state.activeRun)}});state.execution=data.execution;$('#execution-setup').hidden=true;$('#execution-active').hidden=false;renderExecution();await refreshExecutionScreen();state.executionTimer=setInterval(refreshExecutionScreen,2200)}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
function renderExecution(){const run=state.execution;if(!run)return;const finalCount=(run.results||[]).filter(item=>['passed','failed','blocked','skipped'].includes(item.outcome)).length;$('#execution-progress').textContent=`${finalCount} of ${run.steps.length} steps completed${run.offline?' · Capture-only (no AI)':''}`;const reviewIndex=state.executionReviewIndex;const index=reviewIndex===null?run.current_index:reviewIndex;const complete=run.complete&&reviewIndex===null;$('#execution-step-number').textContent=complete?'EXECUTION COMPLETE':`STEP ${index+1} OF ${run.steps.length}`;const step=run.steps[index];$('#execution-action').textContent=complete?'Review the final result':step.content;$('#execution-expected').textContent=complete?'Publish is optional and always requires explicit confirmation.':step.expected;$('#execution-skip').disabled=complete||!step?.optional;$('#verify-execution-step').disabled=complete||reviewIndex!==null||run.state!=='running'||Boolean(run.offline);$('#verify-execution-step').title=run.offline?'No AI calls in capture-only mode. Finish manually and analyze later from AI queue.':'';$('#execution-next').hidden=reviewIndex===null;const review=(run.results||[]).find(item=>item.step_index===index);const box=$('#execution-verification');box.hidden=!review;box.textContent=review?`${review.source==='ai'?'AI':'Manual'}: ${review.outcome.replace('_',' ')}${review.confidence===null||review.confidence===undefined?'':` · ${Math.round(Number(review.confidence)*100)}%`} · ${review.reason||'No reason recorded'}`:'';$('#execution-finish').hidden=!complete;$('#finish-execution').hidden=run.state!=='running';$('#publish-execution').closest('label').hidden=run.state!=='running';$('#execution-confirmation').closest('label').hidden=run.state!=='running';$('#export-execution').hidden=run.state==='running';$('#reconcile-execution').hidden=run.state!=='publish_unknown';if(complete)$('#execution-confirmation').placeholder=`PUBLICAR T${run.test_id}`}
async function refreshExecutionScreen(){if(!state.execution||state.execution.complete)return;try{const shot=await api('/api/record/screenshot',{session_id:state.execution.recorder_session_id});const screen=$('#execution-screen');screen.src=`data:${shot.type};base64,${shot.data}`;screen.dataset.logicalWidth=shot.logical_width;screen.dataset.logicalHeight=shot.logical_height}catch(error){showToast(error.message,true)}}
async function showExecutionLocators(){if(!state.execution)return;const box=$('#execution-locators');try{const data=await api('/api/record/locators',{session_id:state.execution.recorder_session_id});const list=data.locators||[];box.hidden=false;box.textContent=list.length?list.map(item=>`${item.strategy}: ${item.value}${item.label?` (${item.label})`:''}`).join('\n'):'No stable accessibility locators are exposed on this screen.'}catch(error){showToast(error.message,true)}}
let executionPointer=null;
function executionPoint(event){const screen=$('#execution-screen');const rect=screen.getBoundingClientRect();const width=Number(screen.dataset.logicalWidth);const height=Number(screen.dataset.logicalHeight);return{x:Math.max(0,Math.min(width,Math.round((event.clientX-rect.left)*width/rect.width))),y:Math.max(0,Math.min(height,Math.round((event.clientY-rect.top)*height/rect.height)))}}
async function finishExecutionGesture(event){if(!executionPointer||!state.execution)return;const end=executionPoint(event);const start=executionPointer;executionPointer=null;const type=Math.abs(end.x-start.x)+Math.abs(end.y-start.y)<12?'tap':'swipe';try{await api('/api/record/action',{session_id:state.execution.recorder_session_id,type,start,end});await refreshExecutionScreen()}catch(error){showToast(error.message,true)}}
async function sendExecutionText(){const value=$('#execution-text').value;if(!value||!state.execution)return;try{await api('/api/record/action',{session_id:state.execution.recorder_session_id,type:'text',text:value});$('#execution-text').value='';await refreshExecutionScreen()}catch(error){showToast(error.message,true)}}
async function verifyExecutionStep(){if(!state.execution)return;const button=$('#verify-execution-step');const verifiedIndex=state.execution.current_index;button.disabled=true;button.textContent='Waiting for stable screen…';try{const data=await api('/api/execution/verify',{execution_id:state.execution.id,step_index:verifiedIndex});state.execution=data.execution;state.executionReviewIndex=verifiedIndex;renderExecution();await refreshExecutionScreen();const v=data.verification;const message=data.warning||(!v.stable?`The screen did not stabilize after ${Number(v.settle_seconds||0).toFixed(1)}s; manual review required.`:v.outcome==='needs_review'?`AI is ${Math.round(v.confidence*100)}% confident; manual review required.`:`AI marked the step ${v.outcome}; review or override it.`);showToast(message,Boolean(data.warning||!v.stable))}catch(error){showToast(error.message,true)}finally{button.disabled=false;button.textContent='Verify with AI'}}
async function setExecutionOutcome(outcome){if(!state.execution)return;const index=state.executionReviewIndex===null?state.execution.current_index:state.executionReviewIndex;if(index>=state.execution.steps.length)return;try{const data=await api('/api/execution/verdict',{execution_id:state.execution.id,step_index:index,outcome,reason:$('#execution-reason').value});state.execution=data.execution;state.executionReviewIndex=null;$('#execution-reason').value='';renderExecution();await refreshExecutionScreen();if(data.warning)showToast(data.warning,true)}catch(error){showToast(error.message,true)}}
async function finishExecution(){if(!state.execution)return;const button=$('#finish-execution');button.disabled=true;try{const data=await api('/api/execution/finish',{execution_id:state.execution.id,publish:$('#publish-execution').checked,confirmation:$('#execution-confirmation').value,defer_analysis:$('#defer-execution').checked});clearInterval(state.executionTimer);state.execution=data.execution;renderExecution();showToast(data.publish_unknown?data.warning:`Execution ${data.overall}${data.published?' and TestRail result published':''}.${data.deferred?' Evidence queued locally; review screens in AI queue when ready.':''}`,Boolean(data.publish_unknown));if(state.activeRun)await selectRun(state.activeRun.id)}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
async function downloadExecutionReport(){if(!state.execution)return;try{const report=await api('/api/execution/report',{execution_id:state.execution.id});const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`qa-sync-execution-t${state.execution.test_id}-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);showToast('Execution report downloaded.')}catch(error){showToast(error.message,true)}}
async function reconcileExecutionPublication(){if(!state.execution)return;const button=$('#reconcile-execution');button.disabled=true;try{const data=await api('/api/execution/reconcile-publication',{execution_id:state.execution.id});state.execution=data.execution;renderExecution();showToast(data.found?'TestRail confirms the result was published.':'No matching result was found. It was not re-published automatically.',!data.found)}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
async function closeExecution(){if(state.execution?.state==='running'){if(!window.confirm('Cancel this execution and discard its device evidence?'))return;try{await api('/api/execution/cancel',{execution_id:state.execution.id})}catch(error){showToast(error.message,true);return}}clearInterval(state.executionTimer);state.execution=null;state.executionReviewIndex=null;$('#execution-dialog').close()}
async function discoverWireless(){
  const button=$('#discover-wireless');button.disabled=true;
  try{
    const data=await api('/api/device/android-discover');
    const services=(data.services||[]).filter(item=>item.kind==='pairing'||item.kind==='connect');
    $('#wireless-found').innerHTML=services.length?services.map(item=>
      `<button type="button" data-host="${escapeHtml(item.host)}" data-port="${escapeHtml(item.port)}">${escapeHtml(item.host)}:${escapeHtml(item.port)} · ${item.kind==='pairing'?'pair':'connect'}</button>`
    ).join(''):'<p class="dialog-intro">Nothing is advertising. Turn on Wireless Debugging on the device.</p>';
    document.querySelectorAll('#wireless-found [data-host]').forEach(item=>item.addEventListener('click',()=>{
      $('#wireless-host').value=item.dataset.host;$('#wireless-port').value=item.dataset.port;
    }));
  }catch(error){showToast(error.message,true)}finally{button.disabled=false}
}

async function usbToWireless(){
  const deviceId=$('#device-select').value;
  if(!deviceId)return showToast('Select the USB device in the list first.',true);
  const button=$('#usb-to-wireless');button.disabled=true;button.textContent='Switching to Wi‑Fi';
  try{
    const result=await api('/api/device/android-tcpip',{device_id:deviceId});
    const [host,port]=result.endpoint.split(':');
    $('#wireless-host').value=host;$('#wireless-port').value=port;
    showToast(`Now also over Wi‑Fi: ${result.endpoint}`);await refreshDevices();
  }catch(error){showToast(error.message,true)}
  finally{button.disabled=false;button.textContent='Switch the selected USB device to Wi‑Fi'}
}

async function disconnectWireless(){
  const host=$('#wireless-host').value.trim(),port=$('#wireless-port').value.trim();
  if(!host||!port)return showToast('Indica IP y puerto del dispositivo a desconnect.',true);
  const button=$('#disconnect-wireless');button.disabled=true;
  try{const result=await api('/api/device/android-disconnect',{endpoint:`${host}:${port}`});showToast(`Disconnected: ${result.endpoint}`);await refreshDevices()}
  catch(error){showToast(error.message,true)}finally{button.disabled=false}
}

async function connectWireless(){const button=$('#connect-wireless');button.disabled=true;try{const result=await api('/api/device/android-wireless',{host:$('#wireless-host').value,port:$('#wireless-port').value,pairing_code:$('#wireless-code').value});$('#wireless-code').value='';showToast(`Android connected: ${result.endpoint}`);await refreshDevices()}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
async function startLocalDevice(kind){
  const android=kind==='android';const select=$(android?'#android-avd-select':'#ios-simulator-select');const id=select.value;
  if(!id)return showToast('Select a device to start.',true);
  const button=$(android?'#start-android-avd':'#start-ios-simulator');button.disabled=true;button.textContent='Starting…';
  try{
    const result=await api(android?'/api/device/android-emulator':'/api/device/ios-simulator',android?{avd_name:id}:{simulator_id:id});
    showToast(`${android?result.name:'iOS Simulator'} is starting. The list will refresh automatically.`);
    let attempts=0;const refresh=async()=>{await refreshDevices();if(++attempts<12&&!(state.devices[android?'android':'ios']||[]).length)setTimeout(refresh,2500)};setTimeout(refresh,1500);
  }catch(error){showToast(error.message,true)}finally{button.disabled=false;button.textContent=android?'Start Android':'Start iOS'}
}
async function reconcileBackup(button){button.disabled=true;try{const result=await api('/api/history/reconcile',{backup_id:button.dataset.reconcile});const message={applied:'TestRail confirms the update was applied.',not_applied:'TestRail confirms the update was not applied. Reanalyse before retrying.',conflict:'TestRail differs from both versions; review it manually.'}[result.outcome];showToast(message,result.outcome==='conflict');await openHistory()}catch(error){showToast(error.message,true);button.disabled=false}}
// La lista de dispositivos vive en las configuraciones del proyecto en TestRail:
// así cada proyecto trae la suya y un dispositivo nuevo no requiere tocar la app.
async function loadTargetConfigs(){
  const select=$('#target-config');
  const projectId=state.activeRun?.project_id||$('#project-select').value;
  const preset=runConfig(state.activeRun);
  select.innerHTML='<option value="">Unspecified</option>';
  if(!projectId)return;
  try{
    const data=await api('/api/device-configs',{project_id:projectId});
    for(const group of data.groups||[]){
      if(!group.options?.length)continue;
      const optgroup=document.createElement('optgroup');optgroup.label=group.name||'Configuration';
      for(const option of group.options){
        const el=document.createElement('option');el.value=option.name;el.textContent=option.name;
        optgroup.appendChild(el);
      }
      select.appendChild(optgroup);
    }
    // El run ya dice a qué apunta: se preselecciona en vez de hacerlo elegir de nuevo.
    const preferred=activeChoice()?.target_config;
    if(preferred&&[...select.options].some(option=>option.value===preferred))select.value=preferred;
    else if(preset&&[...select.options].some(option=>option.value===preset))select.value=preset;
  }catch(error){showToast(`Configurations could not be read: ${error.message}`,true)}
}

async function refreshUpdatePreflight(){
  const button=$('#continue-update'),notice=$('#update-preflight');button.disabled=true;notice.hidden=true;
  try{
    const data=await getJson('/api/preflight');state.preflightReady=data.ready===true;
    const blocked=data.checks.filter(item=>item.status==='blocked');
    if(blocked.length){notice.textContent=`Before recording: ${blocked.map(item=>`${item.name}: ${item.detail}`).join(' ')}`;notice.hidden=false}
  }catch(error){state.preflightReady=false;notice.textContent=`Preflight could not run: ${error.message}`;notice.hidden=false}
  finally{button.disabled=!state.preflightReady}
}
function openUpdateDialog(){if(!state.currentCase)return;state.queueReviewId=null;state.queueReviewCaseId=null;$('#defer-update').hidden=true;$('#continue-update').hidden=false;$('#dialog-case').textContent=`C${state.currentCase.id} · ${state.currentCase.title}`;const runTarget=runConfig(state.activeRun),choice=activeChoice();$('#dialog-target').textContent=runTarget?`This run targets: ${runTarget}${choice?.target_config&&choice.target_config!==runTarget?` · Your remembered choice is ${choice.target_config}; confirm before recording.`:''}`:'';$('#dialog-target').hidden=!runConfig(state.activeRun);$('#device-step').hidden=false;$('#recording-step').hidden=true;$('#minimize-update').hidden=true;$('#cancel-update').hidden=false;$('#continue-update').textContent='Continue';$('#cancel-update').textContent='Close';const input=document.querySelector(`input[name="platform"][value="${choice?.platform==='ios'?'ios':'android'}"]`);if(input)input.checked=true;state.preferredDeviceId=choice?.device_id||'';$('#device-select').innerHTML='<option value="">Looking for devices</option>';$('#update-dialog').showModal();refreshDevices();loadTargetConfigs();refreshUpdatePreflight()}
async function closeUpdateDialog(){
  if(state.analysisInProgress){minimizeAnalysis();return}
  if(state.queueReviewId){
    state.session=null;state.sessionPreserved=false;state.preservedSession=null;
    state.queueReviewId=null;state.queueReviewCaseId=null;state.evidencePreview=null;
    $('#update-dialog').close();showToast('Queued evidence is still saved locally.');return;
  }
  if(state.session){
    const sessionId=state.session,caseId=state.queueReviewCaseId||state.preservedSession?.case_id||state.currentCase?.id;
    if(!state.sessionPreserved){
      try{await api('/api/record/stop',{session_id:sessionId})}catch(error){showToast(`Could not save this recording: ${error.message}`,true);return}
    }
    if(caseId){
      try{await api('/api/deferred/add',{session_id:sessionId,case_id:caseId,project_id:state.activeRun?.project_id||$('#project-select').value||null,context:$('#context').value,target_config:$('#target-config').value})}
      catch(error){showToast(`Recording saved, but it could not be added to My work: ${error.message}`,true);return}
    }
    clearInterval(state.timer);clearInterval(state.screenTimer);
    state.session=null;state.sessionPreserved=false;state.preservedSession=null;state.evidencePreview=null;state.recoveredSessionCaseId=null;
    $('#update-dialog').close();showToast(`C${caseId||''} saved locally. Open My work to continue; no AI was called.`);return;
  }
  $('#update-dialog').close();
}
function minimizeAnalysis(){if(!state.analysisInProgress)return;state.analysisMinimized=true;$('#update-dialog').close();$('#analysis-task').hidden=false;showToast('Proposal generation continues in the background.');}
function restoreAnalysis(){if(!state.analysisInProgress)return;state.analysisMinimized=false;$('#analysis-task').hidden=true;$('#update-dialog').showModal();}
function playCompletionSound(){try{const AudioContext=window.AudioContext||window.webkitAudioContext;if(!AudioContext)return;const audio=new AudioContext();const tone=audio.createOscillator();const gain=audio.createGain();tone.type='sine';tone.frequency.setValueAtTime(740,audio.currentTime);tone.frequency.setValueAtTime(940,audio.currentTime+.13);gain.gain.setValueAtTime(.0001,audio.currentTime);gain.gain.exponentialRampToValueAtTime(.08,audio.currentTime+.02);gain.gain.exponentialRampToValueAtTime(.0001,audio.currentTime+.3);tone.connect(gain).connect(audio.destination);tone.start();tone.stop(audio.currentTime+.31);tone.addEventListener('ended',()=>audio.close())}catch(_error){/* Sound is optional and can be blocked by browser preferences. */}}
function viewGeneratedProposal(){if(!state.proposal)return;renderProposal();document.querySelector('#proposal-content')?.scrollIntoView({block:'start',behavior:'smooth'});}

// El screenshot del control guiado va en su propio intervalo: pedirlo en cada poll
// de estado disparaba un `adb screencap` por segundo peleándose con el del hilo
// grabador, que ya captura cada 1.25s contra el mismo dispositivo.
async function refreshGuidedScreen(){
  if(!state.session||$('#appium-control').hidden)return;
  try{
    const shot=await api('/api/record/screenshot',{session_id:state.session});
    const screen=$('#appium-screen');screen.src=`data:${shot.type};base64,${shot.data}`;
    screen.dataset.logicalWidth=shot.logical_width;screen.dataset.logicalHeight=shot.logical_height;
  }catch(_){}
}

function renderRecordingWarnings(warnings){
  const box=$('#recording-warnings');const items=warnings||[];
  box.hidden=!items.length;
  box.innerHTML=items.map(item=>`<p>${escapeHtml(item)}</p>`).join('');
}

async function updateRecordingStatus(){
  if(!state.session)return;
  try{
    const status=await api('/api/record/status',{session_id:state.session});
    $('#recording-count').textContent=`${status.frames} screens · ${Math.round(status.seconds)}s`;
    $('#appium-control').hidden=!status.remote_control;
    if(status.remote_control)$('#guided-control-label').textContent=`Guided control ${status.control_kind==='adb'?'ADB':'Appium'}: tap or drag on the screen. Evidence is stored before and after each action.`;
    renderRecordingWarnings(status.warnings);
    if(status.error)showToast(status.error,true);
  }catch(_){}
}
let appiumPointer=null;
function appiumPoint(event){const screen=$('#appium-screen');const rect=screen.getBoundingClientRect();const width=Number(screen.dataset.logicalWidth);const height=Number(screen.dataset.logicalHeight);return{x:Math.max(0,Math.min(width,Math.round((event.clientX-rect.left)*width/rect.width))),y:Math.max(0,Math.min(height,Math.round((event.clientY-rect.top)*height/rect.height)))}}
async function finishAppiumGesture(event){if(!appiumPointer||!state.session)return;const end=appiumPoint(event);const start=appiumPointer;appiumPointer=null;const type=Math.abs(end.x-start.x)+Math.abs(end.y-start.y)<12?'tap':'swipe';try{await api('/api/record/action',{session_id:state.session,type,start,end});await Promise.all([updateRecordingStatus(),refreshGuidedScreen()])}catch(error){showToast(error.message,true)}}
async function sendAppiumText(){const input=$('#appium-text');if(!state.session||!input.value)return;const button=$('#appium-send-text');button.disabled=true;try{await api('/api/record/action',{session_id:state.session,type:'text',text:input.value});input.value='';await Promise.all([updateRecordingStatus(),refreshGuidedScreen()])}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
function analysisRecoveryHint(message){
  const text=String(message||'').toLowerCase();
  if(text.includes('429')||text.includes('usage limit')||text.includes('allowance'))return 'The provider allowance is unavailable. Retry later, or choose an authorised fallback in Settings.';
  if(text.includes('401')||text.includes('403')||text.includes('sign in')||text.includes('api key'))return 'Authentication was rejected. Run Preflight, then sign in or update the configured credential.';
  if(text.includes('timeout')||text.includes('could not reach')||text.includes('network'))return 'The service could not be reached. Check your network, then retry; the captured journey is still preserved.';
  if(text.includes('no screen was captured'))return 'No evidence was captured. Resume the recording, wait for a screen to settle, then retry.';
  return 'The captured journey is still preserved. Fix the reported condition, then select Retry analysis.';
}
async function continueUpdate(){
  const button=$('#continue-update');
  if(!state.session){
    if(!state.preflightReady)return showToast('Run Preflight and resolve the blocked checks before recording.',true);
    const deviceId=$('#device-select').value;if(!deviceId)return showToast('Select a device.',true);button.disabled=true;
    try{const payload={platform:selectedPlatform(),device_id:deviceId,case_id:state.currentCase.id,package:$('#android-package').value,deep_link:$('#android-deep-link').value,reset_data:$('#android-reset-data').checked};if(payload.reset_data&&!window.confirm('This wipes the app local data on the selected Android device. Continue?')){button.disabled=false;return}await rememberDeviceChoice();await api('/api/device/open',payload);const session=await api('/api/record/start',payload);state.session=session.session_id;state.evidencePreview=null;$('#device-step').hidden=true;$('#recording-step').hidden=false;$('#recording-step h3').textContent='Recording journey';$('#recording-step>p').textContent='Do one action at a time and let the screen settle. QA Sync compares each state to reconstruct the journey.';$('#analysis-progress').hidden=true;button.textContent='Finish journey';$('#cancel-update').textContent='Save & close';state.timer=setInterval(updateRecordingStatus,1000);state.screenTimer=setInterval(refreshGuidedScreen,2500);updateRecordingStatus()}
    catch(error){showToast(error.message,true)}finally{button.disabled=false}return;
  }
  if(!state.evidencePreview){
    button.disabled=true;
    try{await api('/api/record/stop',{session_id:state.session});const preview=await api('/api/record/evidence-preview',{session_id:state.session});renderEvidencePreview(preview);state.sessionPreserved=true;state.preservedSession={id:state.session,case_id:state.currentCase.id};$('#recording-step').hidden=true;$('#evidence-step').hidden=false;$('#defer-update').hidden=false;button.textContent='Analyze selected screens';$('#cancel-update').textContent='Close and keep recording'}catch(error){showToast(`${error.message} ${analysisRecoveryHint(error.message)}`,true)}finally{button.disabled=false}return;
  }
  const selectedFrames=selectedEvidenceFrames();
  if(!selectedFrames.length){showToast('Select at least one screen before sending data to AI.',true);button.disabled=false;return}
  if(!$('#evidence-sensitive-reviewed').checked){$('#evidence-sensitive-reviewed').focus();showToast('Review the selected screens for visible secrets before sending them to AI.');return}
  button.disabled=true;button.textContent='Generating proposal';state.analysisInProgress=true;state.analysisMinimized=false;$('#minimize-update').hidden=false;$('#cancel-update').hidden=true;clearInterval(state.timer);clearInterval(state.screenTimer);
  try{await showAnalysisProgress();await new Promise(resolve=>requestAnimationFrame(resolve));const result=await api('/api/record/analyze',{session_id:state.session,case_id:state.currentCase.id,context:$('#context').value,project_id:state.activeRun?.project_id||$('#project-select').value,target_config:$('#target-config').value,force_reanalyze:$('#force-reanalyze').checked,selected_frames:selectedFrames,include_test_credentials:document.querySelector('input[name="credential-policy"]:checked')?.value==='include'});state.proposal=result;state.analysisSession=state.session;state.lastEvidenceSessionId=state.session;state.lastEvidencePreview=state.evidencePreview;state.session=null;state.evidencePreview=null;state.sessionPreserved=false;state.preservedSession=null;$('#update-dialog').close();renderProposal();playCompletionSound();showUndoToast(`Proposal for C${result.case_id} is ready.`, 'View proposal', viewGeneratedProposal)}
  catch(error){showToast(`${error.message} ${analysisRecoveryHint(error.message)}`,true)}finally{state.analysisInProgress=false;state.analysisMinimized=false;$('#analysis-task').hidden=true;$('#minimize-update').hidden=true;$('#cancel-update').hidden=false;hideAnalysisProgress();button.disabled=false;button.textContent=state.session?'Retry analysis':'Continue'}
}

const selectedEvidenceFrames=()=>[...document.querySelectorAll('#evidence-grid input:checked')].map(input=>Number(input.value));
async function saveDeferredEvidence(){
  const caseId=state.queueReviewCaseId||state.currentCase?.id;
  if(!state.session||!caseId)return showToast('No captured TC is open.',true);
  const button=$('#defer-update');button.disabled=true;
  try{
    const targetConfig=state.queueReviewId?state.queueReviewTargetConfig:$('#target-config').value;
    const queued=state.queueReviewId?{item:{id:state.queueReviewId}}:await api('/api/deferred/add',{session_id:state.session,case_id:caseId,project_id:state.activeRun?.project_id||$('#project-select').value||null,context:$('#context').value,target_config:targetConfig});
    const selected=selectedEvidenceFrames();
    const reviewed=$('#evidence-sensitive-reviewed').checked&&selected.length>0;
    if(reviewed)await api('/api/deferred/review',{id:queued.item.id,selected_frames:selected,sensitive_reviewed:true,include_test_credentials:document.querySelector('input[name="credential-policy"]:checked')?.value==='include',context:$('#context').value,target_config:targetConfig});
    clearInterval(state.timer);clearInterval(state.screenTimer);
    state.session=null;state.sessionPreserved=false;state.preservedSession=null;state.queueReviewId=null;state.queueReviewCaseId=null;state.queueReviewTargetConfig='';state.evidencePreview=null;
    $('#update-dialog').close();
    showToast(reviewed?'TC queued with reviewed screens. No AI was called.':'TC saved locally without AI. Review its screens in AI queue before analysis.');
    await openDeferredQueue();
  }catch(error){showToast(error.message,true)}finally{button.disabled=false}
}
async function exportSelectedEvidence(){
  const selected=selectedEvidenceFrames();
  if(!state.session)return showToast('The local recording is no longer available.',true);
  if(!selected.length)return showToast('Select at least one screen to export.',true);
  const button=$('#export-evidence');button.disabled=true;button.textContent='Preparing evidence…';
  try{
    const evidence=await api('/api/record/evidence-export',{session_id:state.session,selected_frames:selected});
    const payload={version:1,mode:'evidence_only',exported_at:new Date().toISOString(),case_id:evidence.case_id,platform:evidence.platform,captured_frames:evidence.captured_frames,selected_frames:evidence.selected_frames,frames:evidence.frames};
    const href=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
    const link=document.createElement('a');link.href=href;link.download=`qa-sync-C${evidence.case_id||'local'}-evidence-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(href),1000);
    showToast(`${evidence.selected_frames} original screens exported locally. Nothing was sent to AI or TestRail.`);
  }catch(error){showToast(error.message,true)}finally{button.disabled=false;button.textContent='Export selected evidence only'}
}
async function importEvidenceFile(event){
  const file=event.target.files?.[0];event.target.value='';
  if(!file)return;
  if(!state.currentCase)return showToast('Select the TestRail case that this evidence belongs to first.',true);
  if(file.size>45*1024*1024)return showToast('The evidence package is larger than 45 MB.',true);
  try{
    const evidence=JSON.parse(await file.text());
    if(evidence.mode!=='evidence_only')throw new Error('Choose an evidence-only export from QA Sync.');
    if(evidence.case_id&&Number(evidence.case_id)!==Number(state.currentCase.id)&&!window.confirm(`This package was exported for C${evidence.case_id}. Continue with C${state.currentCase.id}?`))return;
    const session=await api('/api/record/evidence-import',{case_id:state.currentCase.id,evidence});
    const preview=await api('/api/record/evidence-preview',{session_id:session.session_id});
    state.session=session.session_id;state.evidencePreview=preview;state.sessionPreserved=true;state.preservedSession={id:state.session,case_id:state.currentCase.id};
    $('#dialog-case').textContent=`C${state.currentCase.id} · ${state.currentCase.title}`;$('#device-step').hidden=true;$('#recording-step').hidden=true;$('#evidence-step').hidden=false;$('#defer-update').hidden=false;$('#continue-update').textContent='Analyze selected screens';$('#cancel-update').textContent='Close and keep evidence';renderEvidencePreview(preview);$('#update-dialog').showModal();
    showToast(`${preview.captured_frames} screens imported and encrypted locally. Nothing was sent to AI.`);
  }catch(error){showToast(`Evidence import failed: ${error.message}`,true)}
}
async function reanalyzeSelection(){if(!state.analysisSession)return showToast('The retained local evidence is no longer available.',true);try{const preview=await api('/api/record/evidence-preview',{session_id:state.analysisSession});state.session=state.analysisSession;state.evidencePreview=preview;state.sessionPreserved=true;state.preservedSession={id:state.session,case_id:state.currentCase.id};$('#device-step').hidden=true;$('#recording-step').hidden=true;$('#evidence-step').hidden=false;renderEvidencePreview(preview);$('#defer-update').hidden=false;$('#continue-update').textContent='Analyze selected screens';$('#cancel-update').textContent='Close and keep recording';$('#update-dialog').showModal()}catch(error){showToast(error.message,true)}}
function updateEvidenceSummary(event){if(!state.evidencePreview)return;if(event?.target?.closest('.evidence-frame'))$('#evidence-sensitive-reviewed').checked=false;const budget=state.evidencePreview.budget;let selected=selectedEvidenceFrames().length;if(selected>budget&&event?.target?.checked){event.target.checked=false;selected-=1;showToast(`Select up to ${budget} screens for this project.`,true)}const total=state.evidencePreview.captured_frames,batches=Math.ceil(selected/4),calls=batches+(batches>1?1:0);$('#evidence-summary').textContent=`${selected} of ${total} captured screens selected · ${selected?`about ${batches} batch${batches===1?'':'es'}${calls>batches?' + final synthesis':''}`:'no AI calls yet'}. Analyze sends only these screens to AI. Limit: ${budget}. Export stays local.`}
document.querySelectorAll('input[name="credential-policy"]').forEach(input=>input.addEventListener('change',()=>{$('#evidence-sensitive-reviewed').checked=false;updateEvidenceSummary()}));
function renderEvidencePreview(data){state.evidencePreview=data;$('#defer-update').hidden=false;$('#continue-update').hidden=Boolean(state.queueReviewId);$('#evidence-sensitive-reviewed').checked=false;document.querySelector('input[name="credential-policy"][value="redact"]').checked=true;$('#evidence-grid').innerHTML=(data.frames||[]).map(frame=>`<div class="evidence-frame"><label title="Select screen ${frame.index+1}"><input type="checkbox" value="${frame.index}" ${frame.selected?'checked':''}><img src="data:${frame.type};base64,${frame.data}" alt="Captured screen ${frame.index+1}"><span>Screen ${frame.index+1}</span></label><button class="secondary evidence-expand" type="button" data-evidence-zoom="${frame.index}" aria-label="Expand screen ${frame.index+1}">Expand</button></div>`).join('');$('#evidence-grid').onchange=updateEvidenceSummary;$('#export-evidence').onclick=exportSelectedEvidence;updateEvidenceSummary()}
let evidenceZoomPosition=0;
function showEvidenceZoom(position){
  const frames=state.evidencePreview?.frames||[];if(!frames.length)return;
  evidenceZoomPosition=Math.max(0,Math.min(position,frames.length-1));const frame=frames[evidenceZoomPosition];
  $('#evidence-zoom-title').textContent=`Screen ${frame.index+1} · ${evidenceZoomPosition+1} of ${frames.length}`;
  $('#evidence-zoom-image').src=`data:${frame.type};base64,${frame.data}`;
  $('#evidence-zoom-toggle').textContent=document.querySelector(`#evidence-grid input[value="${frame.index}"]`)?.checked?'Remove from selection':'Select for AI';
  $('#evidence-zoom-prev').disabled=evidenceZoomPosition===0;$('#evidence-zoom-next').disabled=evidenceZoomPosition===frames.length-1;
  if(!$('#evidence-zoom').open)$('#evidence-zoom').showModal();
}
function setSuggestedEvidence(restore){
  const suggested=new Set((state.evidencePreview?.frames||[]).filter(frame=>frame.selected).map(frame=>frame.index));
  document.querySelectorAll('#evidence-grid input').forEach(input=>{input.checked=restore&&suggested.has(Number(input.value))});
  $('#evidence-sensitive-reviewed').checked=false;updateEvidenceSummary();
}

async function openDeferredQueue(){
  const dialog=$('#deferred-dialog');if(!dialog.open)dialog.showModal();
  state.deferredSnapshot='';await refreshDeferredQueue();
  clearInterval(state.deferredTimer);state.deferredTimer=setInterval(refreshDeferredQueue,2500);
}
function closeDeferredQueue(){clearInterval(state.deferredTimer);state.deferredTimer=null;state.deferredRequestId++;state.deferredRefreshQueued=false;$('#deferred-dialog').close()}
async function openMyWork(){
  const dialog=$('#work-dialog');if(!dialog.open)dialog.showModal();
  const box=$('#work-list');box.innerHTML='<div class="skeleton"></div>';$('#work-summary').textContent='Loading local work…';
  try{
    const [queued,saved,recovered]=await Promise.all([getJson('/api/deferred'),api('/api/draft/list'),getJson('/api/recovery')]);
    const groups=new Map(),listedDrafts=new Set();
    const add=(caseId,row)=>{const key=String(caseId||'Unassigned');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(row)};
    for(const item of queued.items||[]){
      const label={needs_review:'Captured · needs screen review',ready:'Reviewed · ready for AI',scheduled:'Queued · waiting its turn',running:'AI analysis in progress',waiting_limit:'Waiting for provider allowance',completed:'Draft ready',failed:'Needs attention'}[item.state]||item.state;
      const action=item.draft_id?'Open draft':['needs_review','ready'].includes(item.state)?'Review screens':'Open queue';
      add(item.case_id,{label,detail:`${item.platform} · ${item.selected_frames?.length||0} selected screens${item.error?` · ${item.error}`:''}`,when:item.updated_at,
        action,kind:item.draft_id?'draft':action==='Review screens'?'review':'queue',id:item.draft_id||item.id});
      if(item.draft_id)listedDrafts.add(item.draft_id);
    }
    for(const draft of saved.drafts||[]){if(listedDrafts.has(draft.id))continue;add(draft.case_id,{label:'Draft ready',detail:`${draft.name||'Local draft'} · ${draft.steps||0} steps`,when:draft.updated_at,action:'Open draft',kind:'draft',id:draft.id})}
    if(state.proposal)add(state.proposal.case_id,{label:'Current proposal',detail:'Local edits; not sent to TestRail',when:Date.now()/1000,action:'Continue proposal',kind:'proposal',id:''});
    else if(recovered.proposal&&!groups.get(String(recovered.proposal.case_id))?.some(row=>row.kind==='draft'))add(recovered.proposal.case_id,{label:'Latest local proposal',detail:'Not sent to TestRail',when:0,action:'Open proposal',kind:'proposal',id:''});
    for(const session of recovered.sessions||[])if(session.case_id)add(session.case_id,{label:'Captured · needs review',detail:`${session.platform} · ${session.frames||0} screens`,when:session.ended_at||session.started_at||0,action:'Review evidence',kind:'session',id:session.session_id});
    const entries=[...groups.entries()].sort((a,b)=>Math.max(...b[1].map(row=>row.when||0))-Math.max(...a[1].map(row=>row.when||0)));
    $('#work-summary').textContent=`${entries.length} TC${entries.length===1?'':'s'} with local work. Captures and drafts stay on this machine; no AI or TestRail update starts from this view.`;
    box.innerHTML=entries.length?entries.map(([caseId,rows])=>`<section class="work-case"><h3>${caseId==='Unassigned'?'Unassigned':`C${escapeHtml(caseId)}`}</h3>${rows.sort((a,b)=>(b.when||0)-(a.when||0)).map(row=>`<article class="work-row"><div><strong>${escapeHtml(row.label)}</strong><p>${escapeHtml(row.detail)}</p><small>${row.when?escapeHtml(fmtWhen(row.when)):'Saved locally'}</small></div><button class="secondary" type="button" data-work-kind="${escapeHtml(row.kind)}" data-work-id="${escapeHtml(row.id)}">${escapeHtml(row.action)}</button></article>`).join('')}</section>`).join(''):'<div class="empty"><p>No local TC work yet. Capture a journey or save a draft to see it here.</p></div>';
    state.workRecovery=recovered;
  }catch(error){$('#work-summary').textContent='Could not load local work.';box.innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}
}
async function workAction(event){
  const button=event.target.closest('button[data-work-kind]');if(!button)return;
  const kind=button.dataset.workKind,id=button.dataset.workId;$('#work-dialog').close();
  if(kind==='draft')return openDraft(id);
  if(kind==='review')return openDeferredReview(id);
  if(kind==='queue')return openDeferredQueue();
  if(kind==='proposal'){state.proposal=state.proposal||state.workRecovery?.proposal;if(state.proposal){if(state.lastEvidenceSessionId!==state.proposal.evidence_session_id)await loadProposalEvidence();renderProposal();$('#proposal-content').scrollIntoView({block:'start'})}return}
  if(kind==='session'){
    const session=state.workRecovery?.sessions?.find(row=>row.session_id===id);if(!session)return showToast('The saved evidence is no longer available.',true);
    try{state.currentCase=(await api('/api/case',{case_id:session.case_id})).case;state.session=id;state.preservedSession={id,case_id:session.case_id};state.sessionPreserved=true;state.queueReviewId=null;const preview=await api('/api/record/evidence-preview',{session_id:id});$('#dialog-case').textContent=`C${session.case_id} · ${state.currentCase.title}`;$('#device-step').hidden=true;$('#recording-step').hidden=true;$('#evidence-step').hidden=false;$('#continue-update').hidden=false;$('#continue-update').textContent='Analyze selected screens';$('#cancel-update').textContent='Save & close';renderEvidencePreview(preview);$('#update-dialog').showModal()}catch(error){showToast(`Could not open evidence: ${error.message}`,true)}
  }
}
function updateDeferredButtons(){const any=Boolean(document.querySelector('#deferred-list input[data-queue-select]:checked'));$('#deferred-sequential').disabled=!any}
async function refreshDeferredQueue(){
  if(!$('#deferred-dialog').open)return;
  if(state.deferredLoading){state.deferredRefreshQueued=true;return}
  state.deferredLoading=true;
  const requestId=++state.deferredRequestId;
  try{
    const data=await getJson('/api/deferred');const items=data.items||[];const queue=data.queue||{};
    if(requestId!==state.deferredRequestId||!$('#deferred-dialog').open)return;
    const snapshot=JSON.stringify(data);
    if(snapshot===state.deferredSnapshot)return;
    const list=$('#deferred-list'),scrollTop=list.scrollTop;
    const selected=new Set([...list.querySelectorAll('input[data-queue-select]:checked')].map(input=>input.value));
    const focused=list.contains(document.activeElement)?document.activeElement:null;
    const focusAttribute=focused&&['data-queue-select','data-deferred-review','data-deferred-start','data-deferred-retry-now','data-deferred-draft','data-deferred-remove','data-deferred-unschedule','data-deferred-move'].find(name=>focused.hasAttribute(name));
    const focusValue=focusAttribute?(focusAttribute==='data-queue-select'?focused.value:focused.getAttribute(focusAttribute)):null;
    state.deferredSnapshot=snapshot;
    const active=items.filter(item=>['running','waiting_limit','scheduled'].includes(item.state)).sort((a,b)=>Number(a.queue_order||0)-Number(b.queue_order||0));
    const scheduled=active.filter(item=>item.state==='scheduled');
    const other=items.filter(item=>!['running','waiting_limit','scheduled'].includes(item.state)).sort((a,b)=>Number(b.updated_at||0)-Number(a.updated_at||0));
    const ordered=[...active,...other],positions=new Map(active.map((item,index)=>[item.id,index+1]));
    const running=active.find(item=>item.state==='running'),waiting=active.find(item=>item.state==='waiting_limit');
    const next=active.find(item=>item.state==='scheduled');
    const status=queue.paused?(queue.paused_reason==='limit_attempts'?'Paused after repeated provider limits. Resume when your allowance is available.':'Paused by you. An analysis already running will finish.'):(running?`Analysing C${Number(running.case_id)} now.`:waiting?`Waiting for provider allowance on C${Number(waiting.case_id)}.`:next?`Next: C${Number(next.case_id)}.`:'No analysis in progress.');
    const retry=waiting?.retry_at&&!queue.paused?` Next attempt: ${new Date(Number(waiting.retry_at)*1000).toLocaleString()}.`:'';
    $('#deferred-summary').textContent=`${status} ${Number(queue.remaining||0)} remaining · ${Number(queue.completed||0)} completed · ${Number(queue.failed||0)} failed.${retry} One TC at a time; TestRail is unchanged.`;
    if(queue.paused_reason==='uncertain_call')$('#deferred-summary').textContent='Paused after an interrupted provider call. Review the failed TC before retrying; an uncheckpointed call may use allowance again. '+$('#deferred-summary').textContent;
    if(document.activeElement!==$('#deferred-retry-minutes'))$('#deferred-retry-minutes').value=String(queue.retry_minutes||15);
    if(document.activeElement!==$('#deferred-max-attempts'))$('#deferred-max-attempts').value=String(queue.max_limit_attempts||24);
    $('#deferred-pause').hidden=Boolean(queue.paused);$('#deferred-pause').disabled=!queue.remaining;
    $('#deferred-resume').hidden=!queue.paused;$('#deferred-resume').disabled=false;
    $('#deferred-cancel').disabled=!items.some(item=>['scheduled','waiting_limit'].includes(item.state));
    list.innerHTML=ordered.length?ordered.map(item=>{
      const ready=['ready','failed'].includes(item.state)&&item.reviewed&&Boolean(item.selected_frames?.length);
      const busy=['running','scheduled','waiting_limit'].includes(item.state);
      const label={needs_review:'Needs screen review',ready:'Ready · no AI sent',scheduled:'Waiting its turn',running:'Analysing…',waiting_limit:queue.paused?'Paused · provider limit reached':'Waiting for provider allowance',completed:'Draft ready',failed:'Failed · evidence retained'}[item.state]||item.state;
      const itemRetry=item.state==='waiting_limit'&&item.retry_at?` · next attempt ${new Date(Number(item.retry_at)*1000).toLocaleString()}`:'';
      const place=positions.has(item.id)?`Queue #${positions.get(item.id)} · `:'';
      const screenCount=item.selected_frames?.length||0;
      const p=item.progress||{};const stage=String(p.stage||'').replace('_cached','_complete');
      const progressText=stage==='batch'?`Sending batch ${Number(p.current)}/${Number(p.total)}${p.provider?` to ${p.provider}`:''}…`:stage==='batch_complete'?`Batch ${Number(p.current)}/${Number(p.total)} complete`:stage==='synthesis'?'Synthesizing all batches…':stage==='synthesis_complete'?'Synthesis complete':stage==='analysis'?'Analyzing selected screens…':stage==='analysis_complete'?'Analysis complete':stage==='review'?'Checking visual review…':stage==='review_complete'?'Visual review complete':stage==='cache_hit'?'Reusing matching local analysis':stage==='saving_draft'?'Saving draft locally':stage==='preparing'?'Preparing evidence…':'';
      const scheduledIndex=scheduled.findIndex(row=>row.id===item.id);
      return `<article class="history-item deferred-item"><label class="deferred-main"><input data-queue-select type="checkbox" value="${escapeHtml(item.id)}" ${ready?'':'disabled'} ${selected.has(item.id)&&ready?'checked':''}><span><strong>C${Number(item.case_id)}${item.test_id?` · T${Number(item.test_id)}`:''}</strong><small>${place}${escapeHtml(item.platform)} · ${escapeHtml(label+itemRetry)} · ${screenCount} ${screenCount===1?'screen':'screens'} selected</small>${progressText?`<small role="status">${escapeHtml(progressText)}</small>`:''}${item.error?`<small class="deferred-error">${escapeHtml(item.error)}</small>`:''}${item.remedy?`<small>${escapeHtml(item.remedy)}</small>`:''}</span></label><div class="deferred-actions"><button class="secondary" data-deferred-review="${escapeHtml(item.id)}" type="button" ${busy?'disabled':''}>Review screens</button>${ready?`<button class="secondary" data-deferred-start="${escapeHtml(item.id)}" type="button">${item.state==='failed'?'Retry analysis':'Analyze now'}</button>`:''}${item.error_code==='configuration'?'<button class="secondary" data-deferred-settings type="button">Open Settings</button>':''}${item.state==='scheduled'?`<button class="secondary" data-deferred-move="${escapeHtml(item.id)}" data-direction="up" type="button" ${scheduledIndex<=0?'disabled':''} aria-label="Move C${Number(item.case_id)} up">↑</button><button class="secondary" data-deferred-move="${escapeHtml(item.id)}" data-direction="down" type="button" ${scheduledIndex>=scheduled.length-1?'disabled':''} aria-label="Move C${Number(item.case_id)} down">↓</button>`:''}${['scheduled','waiting_limit'].includes(item.state)?`<button class="secondary" data-deferred-unschedule="${escapeHtml(item.id)}" type="button">Unschedule</button>`:''}${item.state==='waiting_limit'&&!queue.paused?`<button class="secondary" data-deferred-retry-now="${escapeHtml(item.id)}" type="button">Try now</button>`:''}${item.draft_id?`<button class="primary" data-deferred-draft="${escapeHtml(item.draft_id)}" type="button">Open draft</button>`:''}<button class="secondary" data-deferred-remove="${escapeHtml(item.id)}" type="button" ${busy?'disabled':''}>Remove</button></div></article>`;
    }).join(''):'<div class="empty"><p>No queued cases. Finish an Execute with “Keep evidence” or save a Refresh for later.</p></div>';
    list.scrollTop=scrollTop;
    if(focusAttribute){const replacement=[...list.querySelectorAll(`[${focusAttribute}]`)].find(element=>(focusAttribute==='data-queue-select'?element.value:element.getAttribute(focusAttribute))===focusValue);replacement?.focus({preventScroll:true})}
    updateDeferredButtons();
  }catch(error){if(requestId===state.deferredRequestId&&$('#deferred-dialog').open){$('#deferred-summary').textContent='Queue status unavailable. Captures remain local; reconnect before taking action.';$('#deferred-list').textContent=`Queue unavailable: ${error.message}`;for(const id of ['deferred-sequential','deferred-pause','deferred-resume','deferred-cancel'])$(`#${id}`).disabled=true}}
  finally{state.deferredLoading=false;if(state.deferredRefreshQueued&&$('#deferred-dialog').open){state.deferredRefreshQueued=false;refreshDeferredQueue()}}
}
async function openDeferredReview(id){
  try{
    const item=((await getJson('/api/deferred')).items||[]).find(row=>row.id===id);
    if(!item)return showToast('That queued case is no longer available.',true);
    const preview=await api('/api/record/evidence-preview',{session_id:item.session_id});
    closeDeferredQueue();
    state.session=item.session_id;state.sessionPreserved=true;state.preservedSession={id:item.session_id,case_id:item.case_id};state.queueReviewId=id;state.queueReviewCaseId=item.case_id;state.queueReviewTargetConfig=item.target_config||'';
    $('#dialog-case').textContent=`C${item.case_id} · queued journey`;
    $('#device-step').hidden=true;$('#recording-step').hidden=true;$('#evidence-step').hidden=false;
    $('#defer-update').hidden=false;$('#continue-update').hidden=true;$('#cancel-update').textContent='Close and keep evidence';
    $('#context').value=item.context||'';
    renderEvidencePreview(preview);
    if(item.reviewed){const selected=new Set(item.selected_frames||[]);document.querySelectorAll('#evidence-grid input').forEach(input=>input.checked=selected.has(Number(input.value)));$('#evidence-sensitive-reviewed').checked=true;document.querySelector(`input[name="credential-policy"][value="${item.include_test_credentials?'include':'redact'}"]`).checked=true;updateEvidenceSummary()}
    $('#update-dialog').showModal();
  }catch(error){showToast(error.message,true)}
}
async function startDeferred(ids,mode){
  if(!ids.length)return showToast('Select at least one reviewed TC.',true);
  const retryMinutes=Number($('#deferred-retry-minutes').value),maxAttempts=Number($('#deferred-max-attempts').value);
  if(!Number.isInteger(retryMinutes)||retryMinutes<5||retryMinutes>120||!Number.isInteger(maxAttempts)||maxAttempts<1||maxAttempts>40)return showToast('Use 5–120 retry minutes and 1–40 limit attempts.',true);
  if(!window.confirm(`Start AI analysis for ${ids.length} TC${ids.length===1?'':'s'}, one at a time? After a provider limit, retry every ${retryMinutes} minutes (up to ${maxAttempts} limit responses). This permission survives a server restart. Pause or cancel pending work at any time; TestRail is unchanged.`))return;
  try{const result=await api('/api/deferred/start',{ids,mode,retry_minutes:retryMinutes,max_limit_attempts:maxAttempts});showToast(`Queued ${ids.length} TC${ids.length===1?'':'s'} for one-at-a-time analysis.${result.paused?' The queue is paused; press Resume queue when ready.':' Drafts appear here when complete.'}`);state.deferredSnapshot='';await refreshDeferredQueue()}catch(error){showToast(error.message,true)}
}
async function controlDeferred(action){
  if(action==='cancel'&&!window.confirm('Cancel all pending analysis? Captures stay in the local queue for later review. A TC already analysing will finish.'))return;
  try{const result=await api(`/api/deferred/${action}`);showToast(action==='pause'?'Queue will pause after the current TC.':action==='resume'?'Queue resumed.':`${result.cancelled} pending TC${result.cancelled===1?'':'s'} unscheduled; evidence kept.${result.running_continues?' The current analysis will finish.':''}`);state.deferredSnapshot='';await refreshDeferredQueue()}catch(error){showToast(error.message,true)}
}
async function deferredAction(event){
  const button=event.target.closest('button');if(!button)return;
  if(button.dataset.deferredReview)return openDeferredReview(button.dataset.deferredReview);
  if(button.dataset.deferredStart)return startDeferred([button.dataset.deferredStart],'sequential');
  if(button.hasAttribute('data-deferred-settings')){closeDeferredQueue();$('#open-settings').click();return}
  if(button.dataset.deferredUnschedule||button.dataset.deferredMove){
    button.disabled=true;
    const moving=Boolean(button.dataset.deferredMove);
    try{await api(moving?'/api/deferred/move':'/api/deferred/unschedule',moving?{id:button.dataset.deferredMove,direction:button.dataset.direction}:{id:button.dataset.deferredUnschedule});showToast(moving?'Queue order updated.':'TC unscheduled; captured evidence kept.');state.deferredSnapshot='';await refreshDeferredQueue()}catch(error){showToast(error.message,true);button.disabled=false}
    return;
  }
  if(button.dataset.deferredRetryNow){
    button.disabled=true;
    try{await api('/api/deferred/retry-now',{id:button.dataset.deferredRetryNow});showToast('Retry requested. This TC remains first in the queue.');state.deferredSnapshot='';await refreshDeferredQueue()}catch(error){showToast(error.message,true);button.disabled=false}
    return;
  }
  if(button.dataset.deferredDraft){closeDeferredQueue();return openDraft(button.dataset.deferredDraft)}
  if(button.dataset.deferredRemove){
    if(!window.confirm('Remove this case from the AI queue? Its captures will return to the normal local retention period; its saved draft, if any, stays.'))return;
    try{await api('/api/deferred/remove',{id:button.dataset.deferredRemove});state.deferredSnapshot='';await refreshDeferredQueue()}catch(error){showToast(error.message,true)}
  }
}

const pretty=value=>Array.isArray(value)?value.map((step,index)=>`${index+1}. ${step.content}\n   Esperado: ${step.expected}`).join('\n\n'):(value===null||value===undefined||value===''?'—':typeof value==='object'?JSON.stringify(value,null,2):String(value));
function renderProposal(preserveHistory=false){
  const data=state.proposal;$('#case-empty').hidden=true;$('#case-loading').hidden=true;$('#case-content').hidden=true;$('#proposal-content').hidden=false;
  const proposedSteps=Array.isArray(data.changes[data.steps_field])?data.changes[data.steps_field]:[];
  const selectedIndices=new Set(data.usage?.selected_frame_indices||[]);
  const visual=state.lastEvidenceSessionId===data.evidence_session_id?state.lastEvidencePreview?.frames?.filter(frame=>selectedIndices.has(frame.index))||[]:[];
  const preKey=data.preconditions_field;
  const stepMarkup=(step,index)=>{const linked=data.evidence_links?.[index];const frame=visual.find(item=>item.index===linked);const unavailable=Number.isInteger(linked)&&!frame;return `<article class="edit-step" data-edit-step><div class="step-toolbar"><strong>Step ${index+1}</strong><div><button class="step-move secondary" data-direction="up" type="button" aria-label="Move step up">↑</button><button class="step-move secondary" data-direction="down" type="button" aria-label="Move step down">↓</button><button class="step-delete secondary" type="button">Delete</button></div></div><label>Action<textarea class="edit-action" maxlength="5000">${escapeHtml(String(step.content||'').replace(/^\[optional\]\s*|^\[opcional\]\s*/i,''))}</textarea></label><label>Expected result<textarea class="edit-expected" maxlength="5000">${escapeHtml(step.expected||'')}</textarea></label><label class="inline-check"><input class="optional-check" type="checkbox" ${/^\[(optional|opcional)\]/i.test(step.content||'')?'checked':''}> Optional step</label><label>Supporting capture · linked by reviewer<select class="step-evidence"><option value="">Not linked</option>${visual.map(item=>`<option value="${item.index}" ${item.index===linked?'selected':''}>Screen ${item.index+1}</option>`).join('')}${unavailable?`<option value="${linked}" selected>Screen ${linked+1} · unavailable</option>`:''}</select></label><div class="step-evidence-preview">${frame?`<img src="data:${frame.type};base64,${frame.data}" alt="Manually linked screen ${frame.index+1}"><span>Screen ${frame.index+1} · reviewer-selected, not AI-verified</span>`:unavailable?'<span>Linked capture is no longer available locally.</span>':'<span>No capture linked to this step.</span>'}</div><div class="device-select-row"><select class="step-feedback"><option value="">Review this step…</option><option value="accepted">Accepted</option><option value="edited">Edited</option><option value="rejected">Rejected / hallucinated</option></select><input class="step-feedback-reason" maxlength="500" placeholder="Reason (recommended for edited/rejected)"></div></article>`};
  const editor=`<section class="proposal-editor"><label>Title<input id="edit-title" maxlength="250" value="${escapeHtml(data.changes.title||'')}"></label><label>Preconditions<textarea id="edit-preconditions" maxlength="10000">${escapeHtml(data.changes[preKey]||'')}</textarea></label><div class="steps-editor-head"><h3>Proposed steps</h3><button id="add-step" class="secondary" type="button">Add step</button></div><div id="steps-editor">${proposedSteps.map(stepMarkup).join('')}</div></section><section class="proposal-preview" id="proposal-preview" hidden></section>`;
  const simulation=data.write_mode==='review_only';
  const quality=data.vision_quality==='maximum'?'maximum':data.vision_quality==='economical'?'efficient':'high';
  const usage=data.usage||{};const usageText=usage.model_calls?` · ${usage.frames_analyzed}/${usage.frames_received} screens · ${usage.model_calls} call${usage.model_calls===1?'':'s'}${usage.cost_usd?` · $${Number(usage.cost_usd).toFixed(4)}`:''}${usage.duration_ms?` · ${(usage.duration_ms/1000).toFixed(1)}s`:''}`:'';
  const reanalyze=state.analysisSession?'<button id="reanalyze-selection" class="secondary" type="button">Adjust captures & reanalyse</button>':'';
  $('#proposal-content').innerHTML=`<button id="back-case" class="secondary back-button" type="button">Back to case</button><div class="proposal-head"><div><p class="overline">PROPOSAL FOR C${data.case_id}</p><h2>Review and edit the update</h2></div><span class="confidence">${Math.round(data.confidence*100)}% confidence</span></div><div class="preview-toggle"><button id="undo-edit" class="secondary" type="button" title="Undo last edit (⌘/Ctrl+Z)">Undo</button><button id="redo-edit" class="secondary" type="button" title="Redo edit (⌘/Ctrl+Shift+Z)">Redo</button><button id="toggle-preview" class="secondary" type="button">Preview as TestRail</button></div><p id="editor-history-status" class="editor-history-status" role="status" aria-live="polite">Changes stay local until Update TestRail. Use Undo or ⌘/Ctrl+Z to recover an edit.</p><p id="autosave-status" class="editor-history-status" role="status">Autosave ready.</p><div id="edit-lease" class="warnings" role="status" hidden><span id="edit-lease-message"></span> <button id="take-over-edit" class="secondary" type="button" hidden>Take over editing</button></div><div id="autosave-actions" class="dialog-inline-actions" hidden><button id="retry-autosave" class="secondary" type="button">Retry save</button><button id="export-unsaved" class="secondary" type="button">Export local edits</button><button id="load-latest-proposal" class="secondary" type="button" hidden>Discard edits & load latest</button></div><div id="impact-summary" class="impact-summary"></div><details class="proposal-comparison" open><summary>Original versus proposal · review changes</summary><p class="visual-evidence-note">Step changes are compared by exact action and expected result. Captures are chronological context, not proof automatically linked to individual steps.</p><div id="proposal-comparison-grid" class="comparison-grid"></div></details>${data.cache_hit?'<div class="warnings">Identical encrypted analysis reused · no vision call was made.</div>':''}${data.provider_used?`<p class="provider-used">Analysed with ${escapeHtml(data.provider_used)} · ${quality}${usageText}</p>`:''}${simulation?'<div class="warnings">Dry run is on: you can review and edit, but nothing is written to TestRail.</div>':''}${data.warnings.length?`<div class="warnings">${data.warnings.map(escapeHtml).join('<br>')}</div>`:''}${editor}<div class="approval"><label for="confirmation">${simulation?'Updating is blocked by configuration.':`Type ${escapeHtml(data.confirmation)} to update TestRail.`}</label><div class="approval-row"><input id="confirmation" autocomplete="off" placeholder="Exact confirmation" ${simulation?'disabled':''}><button id="submit-feedback" class="secondary" type="button">Save AI feedback</button><button id="save-draft" class="secondary" type="button">Save draft</button><button id="apply-update" class="primary" type="button" ${simulation?'disabled':''}>Update TestRail</button></div></div>`;
  $('#back-case').addEventListener('click',async()=>{if(await ensureProposalSaved())renderCase()});$('#apply-update').addEventListener('click',applyProposal);$('#submit-feedback').addEventListener('click',submitProposalFeedback);const previewButton=$('#toggle-preview');if(previewButton)previewButton.addEventListener('click',togglePreview);if(reanalyze){document.querySelector('.preview-toggle').insertAdjacentHTML('beforeend',reanalyze);$('#reanalyze-selection').addEventListener('click',reanalyzeSelection)}$('#undo-edit').addEventListener('click',undoEditor);$('#redo-edit').addEventListener('click',redoEditor);const draftButton=$('#save-draft');if(draftButton)draftButton.addEventListener('click',saveDraft);$('#add-step').addEventListener('click',()=>{const wrapper=document.createElement('div');wrapper.innerHTML=stepMarkup({content:'',expected:''},document.querySelectorAll('[data-edit-step]').length);$('#steps-editor').append(wrapper.firstElementChild);bindStepEditor();recordEditorState('Step added.')});bindStepEditor();if(!preserveHistory)startEditorHistory();else updateEditorHistoryButtons();renderImpact();
  renderVisualEvidence(visual);
  $('#retry-autosave').addEventListener('click',()=>{flushEditorHistory();flushAutosave()});
  $('#export-unsaved').addEventListener('click',exportUnsavedEdits);
  $('#load-latest-proposal').addEventListener('click',loadLatestProposal);
  $('#take-over-edit').addEventListener('click',()=>{claimEditorLease(true);showToast('This tab now controls editing. Review local changes before saving.')});
  claimEditorLease();updateAutosaveActions();
}
function renderVisualEvidence(frames){if(!frames.length)return;const markup=`<details class="visual-evidence"><summary>Visual evidence timeline · ${frames.length} selected screens</summary><p class="visual-evidence-note">Chronological evidence used for this proposal. This is a review trail, not a claim that every adjacent screen is a separate action.</p><div class="visual-evidence-grid">${frames.map((frame,index)=>`<figure><img src="data:${frame.type};base64,${frame.data}" alt="Evidence screen ${frame.index+1}"><figcaption>${index?'Then → ':'Start → '}screen ${frame.index+1}</figcaption></figure>`).join('')}</div></details>`;document.querySelector('.preview-toggle').insertAdjacentHTML('afterend',markup)}
async function submitProposalFeedback(){const entries=[...document.querySelectorAll('[data-edit-step]')].map((step,index)=>({step_index:index,verdict:step.querySelector('.step-feedback').value,reason:step.querySelector('.step-feedback-reason').value})).filter(item=>item.verdict);if(!entries.length)return showToast('Review at least one step first.',true);try{const data=await api('/api/quality/feedback',{proposal_token:state.proposal.proposal_token,entries});showToast(`${data.saved} step reviews saved locally.`)}catch(error){showToast(error.message,true)}}
function renumberSteps(){const steps=[...document.querySelectorAll('[data-edit-step]')];steps.forEach((step,index)=>{step.querySelector('.step-toolbar strong').textContent=`Step ${index+1}`;step.querySelector('[data-direction="up"]').disabled=index===0;step.querySelector('[data-direction="down"]').disabled=index===steps.length-1})}
function bindStepEditor(){document.querySelectorAll('.step-move').forEach(button=>{button.onclick=()=>{const step=button.closest('[data-edit-step]');const sibling=button.dataset.direction==='up'?step.previousElementSibling:step.nextElementSibling;if(!sibling)return;if(button.dataset.direction==='up')step.parentElement.insertBefore(step,sibling);else step.parentElement.insertBefore(sibling,step);renumberSteps();recordEditorState('Step moved.')}});document.querySelectorAll('.step-delete').forEach(button=>{button.onclick=()=>{if(document.querySelectorAll('[data-edit-step]').length===1)return showToast('A proposal must keep at least one step.',true);button.closest('[data-edit-step]').remove();renumberSteps();recordEditorState('Step deleted.')}});document.querySelectorAll('#edit-title,#edit-preconditions,.edit-action,.edit-expected').forEach(field=>field.oninput=queueEditorHistory);document.querySelectorAll('.optional-check').forEach(field=>field.onchange=()=>recordEditorState('Optional status changed.'));document.querySelectorAll('.step-evidence').forEach(field=>field.onchange=()=>{updateStepEvidencePreview(field.closest('[data-edit-step]'));recordEditorState('Supporting capture linked.')});renumberSteps()}
function updateStepEvidencePreview(step){const selected=step.querySelector('.step-evidence').value;const allowed=new Set(state.proposal?.usage?.selected_frame_indices||[]);const frame=state.lastEvidencePreview?.frames?.find(item=>allowed.has(item.index)&&String(item.index)===selected);const box=step.querySelector('.step-evidence-preview');box.replaceChildren();if(frame){const img=document.createElement('img');img.src=`data:${frame.type};base64,${frame.data}`;img.alt=`Manually linked screen ${frame.index+1}`;box.append(img)}const label=document.createElement('span');label.textContent=frame?`Screen ${frame.index+1} · reviewer-selected, not AI-verified`:'No capture linked to this step.';box.append(label)}
function proposalEdits(){const steps=[...document.querySelectorAll('[data-edit-step]')];return{proposal_token:state.proposal.proposal_token,revision:state.proposal.revision||0,title:$('#edit-title').value,preconditions:$('#edit-preconditions').value,steps:steps.map(step=>{const raw=step.querySelector('.edit-action').value;const action=raw.replace(/^\[(optional|opcional)\]\s*/i,'');return{content:step.querySelector('.optional-check').checked?`[Optional] ${action}`:action,expected:step.querySelector('.edit-expected').value}}),evidence_links:steps.map(step=>{const value=step.querySelector('.step-evidence').value;return value===''?null:Number(value)})}}
function editorSnapshot(){const edits=proposalEdits();return{title:edits.title,preconditions:edits.preconditions,steps:edits.steps,evidence_links:edits.evidence_links}}
function sameEditorSnapshot(left,right){return JSON.stringify(left)===JSON.stringify(right)}
function startEditorHistory(){editorHistory={past:[],future:[],current:editorSnapshot(),timer:null};updateEditorHistoryButtons()}
function queueEditorHistory(){if(!editorHistory)return;clearTimeout(editorHistory.timer);editorHistory.timer=setTimeout(recordEditorState,350)}
function flushEditorHistory(){if(!editorHistory)return;clearTimeout(editorHistory.timer);editorHistory.timer=null;recordEditorState()}
function renderImpact(){const box=$('#impact-summary');if(!box||!state.proposal)return;const before=state.proposal.current?.[state.proposal.steps_field]||[];const after=editorSnapshot().steps;const signature=step=>`${step.content}\u0000${step.expected}`;const old=new Set(before.map(signature)),fresh=new Set(after.map(signature));const added=after.filter(step=>!old.has(signature(step))).length,removed=before.filter(step=>!fresh.has(signature(step))).length,optional=after.filter(step=>/^\[optional\]/i.test(step.content)).length;box.textContent=`Impact: ${added} added or edited · ${removed} removed or edited · ${optional} optional · ${after.length} proposed steps.`;renderComparison(before,after)}
function renderComparison(before,after){
  const grid=$('#proposal-comparison-grid');if(!grid)return;
  const current=state.proposal.current||{},snapshot=editorSnapshot(),signature=step=>`${step.content||''}\u0000${step.expected||''}`;
  const readable=value=>{const source=String(value||'');if(!/<[a-z][^>]*>/i.test(source))return source;const node=document.createElement('textarea');node.innerHTML=source.replace(/<br\s*\/?\s*>/gi,'\n').replace(/<\/(p|li|ul|ol|div)>/gi,'\n').replace(/<[^>]*>/g,'');return node.value.replace(/\n{3,}/g,'\n\n').trim()};
  const count=steps=>{const map=new Map();for(const step of steps)map.set(signature(step),(map.get(signature(step))||0)+1);return map};
  const beforeCount=count(before),afterCount=count(after);
  const column=(title,caseTitle,preconditions,steps,otherCount,changedLabel)=>`<section class="comparison-column"><h3>${title}</h3><p><strong>Title</strong><br>${escapeHtml(readable(caseTitle)||'—')}</p><p><strong>Preconditions</strong><br>${escapeHtml(readable(preconditions)||'—')}</p><ol>${steps.map(step=>{const key=signature(step),matching=otherCount.get(key)||0;if(matching)otherCount.set(key,matching-1);return `<li class="${matching?'comparison-same':'comparison-changed'}"><span>${matching?'Unchanged':changedLabel}</span><strong>${escapeHtml(readable(step.content)||'—')}</strong><small>Expected: ${escapeHtml(readable(step.expected)||'—')}</small></li>`}).join('')}</ol></section>`;
  grid.innerHTML=column('Current TestRail case',current.title,current[state.proposal.preconditions_field],before,new Map(afterCount),'Removed or edited')+column('Proposed update',snapshot.title,snapshot.preconditions,after,new Map(beforeCount),'Added or edited');
}
function setAutosaveStatus(message){const status=$('#autosave-status');if(status)status.textContent=message;updateAutosaveActions()}
function updateAutosaveActions(){const box=$('#autosave-actions');if(!box)return;box.hidden=!autosaveError;$('#retry-autosave').hidden=autosaveError?.status===409||!ownsEditorLease();$('#load-latest-proposal').hidden=autosaveError?.status!==409}
function exportUnsavedEdits(){if(!state.proposal||!$('#edit-title'))return;const edits=proposalEdits();const data={version:1,exported_at:new Date().toISOString(),case_id:state.proposal.case_id,revision:edits.revision,title:edits.title,preconditions:edits.preconditions,steps:edits.steps,evidence_links:edits.evidence_links};const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));link.download=`C${data.case_id}-local-edits.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);showToast('Local edits exported. Keep the file private; it may contain test data.')}
async function loadLatestProposal(){if(!state.proposal||!window.confirm('Discard unsaved edits in this tab and load the latest saved proposal? Export first if you need a copy.'))return;const token=state.proposal.proposal_token;try{const latest=await api('/api/proposal/get',{proposal_token:token});clearTimeout(autosaveTimer);pendingAutosavePayload=null;autosaveError=null;autosaveRevision++;state.proposal=latest;renderProposal();setAutosaveStatus('Latest local version loaded. Not sent to TestRail.')}catch(error){showToast(error.message,true)}}
function queueAutosave(){
  if(!state.proposal||!$('#edit-title'))return;
  pendingAutosavePayload=proposalEdits();autosaveRevision++;autosaveError=null;
  setAutosaveStatus(ownsEditorLease()?'Unsaved local edits · saving shortly…':'Unsaved local edits · this tab is not editing. Export or take over.');
  clearTimeout(autosaveTimer);if(ownsEditorLease())autosaveTimer=setTimeout(flushAutosave,1200);
}
async function flushAutosave(){
  clearTimeout(autosaveTimer);autosaveTimer=null;
  if(!ownsEditorLease()){autosaveError=new Error('Another tab controls editing. Export your local changes or take over.');setAutosaveStatus(`Not saved locally: ${autosaveError.message}`);return false}
  if(pendingAutosavePayload){
    const payload=pendingAutosavePayload,revision=autosaveRevision;pendingAutosavePayload=null;
    autosaveOutstanding++;
    autosaveChain=autosaveChain.catch(()=>{}).then(async()=>{
      if(state.proposal?.proposal_token!==payload.proposal_token)return;
      if(!ownsEditorLease()){if(revision===autosaveRevision){pendingAutosavePayload=payload;autosaveError=new Error('Another tab controls editing. Export your local changes or take over.');setAutosaveStatus(`Not saved locally: ${autosaveError.message}`)}return}
      payload.revision=state.proposal.revision||0;
      setAutosaveStatus('Saving locally…');
      try{
        const saved=await api('/api/proposal/revise',payload);
        if(state.proposal?.proposal_token===payload.proposal_token){state.proposal.revision=saved.revision;if(revision===autosaveRevision){state.proposal=saved;autosaveError=null;setAutosaveStatus('Saved locally. Not sent to TestRail.')}}
      }catch(error){
        if(revision===autosaveRevision){pendingAutosavePayload=payload;autosaveError=error;setAutosaveStatus(error.status===409?'Another tab saved a newer version. Export your edits or load latest; nothing was overwritten.':`Not saved locally: ${error.message}. Retry or export before leaving.`)}
      }finally{autosaveOutstanding--}
    });
  }
  await autosaveChain;
  return !pendingAutosavePayload&&!autosaveError;
}
async function ensureProposalSaved(){
  if(editorHistory&&$('#edit-title')&& !$('#proposal-content').hidden)flushEditorHistory();
  if(autosaveError?.status===409){showToast('Another tab saved a newer version. Export local edits or load the latest version.',true);return false}
  if(!pendingAutosavePayload&&!autosaveError&&!autosaveOutstanding)return true;
  if(await flushAutosave())return true;
  showToast(`Edits were not saved locally. Stay here and retry: ${autosaveError?.message||'save pending'}`,true);
  return false;
}
function recordEditorState(undoNotice=''){if(!editorHistory)return;const next=editorSnapshot();if(sameEditorSnapshot(next,editorHistory.current))return;editorHistory.past.push(editorHistory.current);if(editorHistory.past.length>50)editorHistory.past.shift();editorHistory.current=next;editorHistory.future=[];updateEditorHistoryButtons();renderImpact();queueAutosave();if(undoNotice)showUndoToast(undoNotice);else invalidateUndoToast()}
function updateEditorHistoryButtons(){const undo=$('#undo-edit'),redo=$('#redo-edit'),status=$('#editor-history-status');if(undo)undo.disabled=!editorHistory?.past.length;if(redo)redo.disabled=!editorHistory?.future.length;if(status&&editorHistory)status.textContent=`Changes stay local until Update TestRail. ${editorHistory.past.length} undo and ${editorHistory.future.length} redo ${editorHistory.past.length===1?'step':'steps'} available.`}
function restoreEditorSnapshot(snapshot){state.proposal.changes.title=snapshot.title;state.proposal.changes[state.proposal.preconditions_field]=snapshot.preconditions;state.proposal.changes[state.proposal.steps_field]=snapshot.steps.map(step=>({...step}));state.proposal.evidence_links=[...(snapshot.evidence_links||[])];renderProposal(true);queueAutosave()}
function undoEditor(){flushEditorHistory();if(!editorHistory?.past.length){showToast('There is no earlier local edit to undo.');return}editorHistory.future.push(editorHistory.current);editorHistory.current=editorHistory.past.pop();restoreEditorSnapshot(editorHistory.current);showToast('Last local edit undone. Nothing was sent to TestRail.')}
function redoEditor(){flushEditorHistory();if(!editorHistory?.future.length){showToast('There is no local edit to redo.');return}editorHistory.past.push(editorHistory.current);editorHistory.current=editorHistory.future.pop();restoreEditorSnapshot(editorHistory.current);showToast('Local edit restored. Nothing was sent to TestRail.')}
// Un paso sin resultado esperado no es verificable. El servidor lo rechaza, pero
// avisar aquí señala cuál campo falta en vez de dar un mensaje suelto.
function firstIncompleteStep(){
  const steps=[...document.querySelectorAll('[data-edit-step]')];
  steps.forEach(step=>step.querySelectorAll('.edit-action,.edit-expected').forEach(field=>field.classList.remove('invalid')));
  for(const [index,step] of steps.entries()){
    for(const [selector,label] of [['.edit-action','an action'],['.edit-expected','an expected result']]){
      const field=step.querySelector(selector);
      if(field&&!field.value.trim())return{number:index+1,field,label};
    }
  }
  return null;
}

async function applyProposal(){
  if(!await ensureProposalSaved())return;
  const missing=firstIncompleteStep();
  if(missing){
    missing.field.classList.add('invalid');missing.field.focus();
    missing.field.scrollIntoView({block:'center',behavior:'smooth'});
    return showToast(`Step ${missing.number} needs ${missing.label}.`,true);
  }
  const button=$('#apply-update');button.disabled=true;const optionalSteps=[...document.querySelectorAll('[data-edit-step]')].flatMap((step,index)=>step.querySelector('.optional-check').checked?[index]:[]);try{state.proposal=await api('/api/proposal/revise',proposalEdits());const result=await api('/api/apply',{proposal_token:state.proposal.proposal_token,revision:state.proposal.revision,confirmation:$('#confirmation').value,optional_steps:optionalSteps,draft_id:state.draftId||'',draft_updated_at:state.draftUpdatedAt||''});if(!result.draft_retained){state.draftId='';state.draftUpdatedAt=0}showToast(result.draft_retained?`C${result.case_id} updated. A newer draft was kept.`:`C${result.case_id} updated.`);if(state.activeTest)await selectTest(state.activeTest.id);else{state.currentCase=(await api('/api/case',{case_id:result.case_id})).case;renderCase()}}catch(error){showToast(error.message,true);button.disabled=false}}


// Plantilla y borradores viven juntos: la plantilla dice qué forma debe tener un
// caso y los borradores son ese trabajo a medias, agrupados por caso.
const fmtWhen=value=>{const ms=Number(value||0)*1000;if(!ms)return '';const days=Math.floor((Date.now()-ms)/86400000);return days<=0?'today':days===1?'yesterday':`${days} days ago`};

function renderSpend(spend){
  const box=$('#spend-summary');
  if(!box)return;
  if(!spend){box.innerHTML='';return}
  const avg=spend.average||{};
  const rows=[
    ['Applied cases', `${spend.applied?.cases||0}`],
    ['Pending drafts', `${spend.drafts?.cases||0}`],
    ['Total cost', `$${(spend.cost_usd||0).toFixed(4)}`],
  ];
  if(avg.cost_usd!==undefined)rows.push([`Average cost (${avg.measured_cases} measured)`,`$${avg.cost_usd.toFixed(4)}`]);
  if(avg.seconds!==undefined)rows.push([`Average time (${avg.timed_cases} timed)`,`${avg.seconds}s`]);
  if(avg.time_cost_usd!==undefined)rows.push([`Average time at $${spend.hourly_rate_usd}/h`,`$${avg.time_cost_usd.toFixed(2)}`]);
  box.innerHTML=`<strong>Spend</strong>${rows.map(([k,v])=>`<div class="spend-row"><span>${escapeHtml(k)}</span><span>${escapeHtml(v)}</span></div>`).join('')}<p class="spend-note">${escapeHtml(spend.note||'')}</p>`;
}

function renderDrafts(drafts){
  const box=$('#drafts-list');
  if(!drafts.length){box.innerHTML='<div class="empty"><p>No drafts saved yet.</p></div>';return}
  // Agrupados por caso: un mismo caso puede tener uno por dispositivo.
  const byCase=new Map();
  for(const draft of drafts){
    if(!byCase.has(draft.case_id))byCase.set(draft.case_id,[]);
    byCase.get(draft.case_id).push(draft);
  }
  box.innerHTML=[...byCase.entries()].map(([caseId,items])=>
    `<div class="draft-case-head"><p class="overline">C${caseId} · ${items.length} draft${items.length>1?'s':''}</p><button class="secondary" data-export-draft-case="${caseId}" type="button">Export C${caseId}</button></div>`+
    items.map(item=>{
      const cost=Number(item.usage?.cost_usd||0);
      const meta=[item.target_config,item.device_name,item.device_version,`${item.steps} steps`,fmtWhen(item.updated_at),cost?`$${cost.toFixed(4)}`:''].filter(Boolean).join(' · ');
      return `<div class="draft-item"><div><strong>${escapeHtml(item.name)}</strong><p>${escapeHtml(meta)}</p></div><div class="draft-actions"><button class="secondary" data-open-draft="${escapeHtml(item.id)}" type="button">Open</button><button class="secondary" data-delete-draft="${escapeHtml(item.id)}" data-draft-revision="${escapeHtml(item.updated_at)}" type="button">Delete</button></div></div>`;
    }).join('')
  ).join('');
  document.querySelectorAll('[data-open-draft]').forEach(button=>button.addEventListener('click',()=>openDraft(button.dataset.openDraft)));
  document.querySelectorAll('[data-delete-draft]').forEach(button=>button.addEventListener('click',()=>deleteDraft(button.dataset.deleteDraft,button.dataset.draftRevision)));
  document.querySelectorAll('[data-export-draft-case]').forEach(button=>button.addEventListener('click',()=>exportDrafts(button.dataset.exportDraftCase)));
}

async function refreshDrafts(){
  try{
    const [drafts,spend]=await Promise.all([api('/api/draft/list'),getJson('/api/spend').catch(()=>null)]);
    renderDrafts(drafts.drafts||[]);
    renderSpend(spend?.spend);
  }catch(error){showToast(error.message,true)}
}

async function openDraftsDialog(){
  try{const settings=await getJson('/api/settings');$('#case-template').value=settings.case_template||'';$('#test-procedures').value=settings.test_procedures||''}catch(_){}
  $('#drafts-dialog').showModal();
  refreshDrafts();
}

async function exportDrafts(caseId=''){try{const data=await api('/api/draft/export',caseId?{case_id:Number(caseId)}:{});const drafts=data.drafts||[];const blob=new Blob([JSON.stringify({...data,exported_at:new Date().toISOString()},null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`qa-sync-${caseId?`c${caseId}-`:''}drafts-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);showToast(`${drafts.length} complete local draft${drafts.length===1?'':'s'} exported${caseId?` for C${caseId}`:''}. Keep this file private; it can contain test data.`)}catch(error){showToast(error.message,true)}}

async function openPreflight(){
  $('#preflight-dialog').showModal();
  $('#preflight-list').innerHTML='<div class="skeleton"></div><div class="skeleton"></div>';
  try{
    const data=await getJson('/api/preflight');
    $('#preflight-list').innerHTML=data.checks.map(item=>`<article class="history-item"><div><strong>${escapeHtml(item.name)}</strong><p>${escapeHtml(item.detail)}</p></div><span class="optional-badge">${escapeHtml(item.status)}</span></article>`).join('');
  }catch(error){$('#preflight-list').innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}
}
async function downloadSupportReport(){const button=$('#download-support-report');button.disabled=true;button.textContent='Preparing report…';try{const report=await getJson('/api/support-report');const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`qa-sync-support-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);showToast('Support report downloaded. Review it before sharing outside your team.')}catch(error){showToast(error.message,true)}finally{button.disabled=false;button.textContent='Download support report'}}

async function saveTemplate(){
  const button=$('#save-template');button.disabled=true;
  try{await api('/api/settings',{case_template:$('#case-template').value});showToast('Template saved. It is sent with every analysis.')}
  catch(error){showToast(error.message,true)}
  finally{button.disabled=false}
}

async function saveProcedures(){
  const button=$('#save-procedures');button.disabled=true;
  try{await api('/api/settings',{test_procedures:$('#test-procedures').value});showToast('Procedures saved. They are sent with every analysis.')}
  catch(error){showToast(error.message,true)}
  finally{button.disabled=false}
}

// Las mismas reglas del ejemplo de al lado: se ve el resultado y se parte de él.
const PROCEDURES_EXAMPLE=['Use the QA account and verification code from the team secret manager; never write their values.',
  'Every case ends by logging out and confirming the login screen.',
  'Steps that only apply to tablets start with [Optional].',
  'Use Tap for touches and Enter for typing, never Click.',
  'Preconditions identify the QA account without copying its credentials.'].map(rule=>'- '+rule).join('\n');

function loadProceduresExample(){
  const field=$('#test-procedures');
  if(field.value.trim()&&!confirm('Replace what you wrote with the example?'))return;
  field.value=PROCEDURES_EXAMPLE;
  field.focus();
}

async function loadProposalEvidence(){state.lastEvidencePreview=null;state.lastEvidenceSessionId='';const id=state.proposal?.evidence_session_id;if(!id)return;try{state.lastEvidencePreview=await api('/api/record/evidence-preview',{session_id:id});state.lastEvidenceSessionId=id}catch(_){/* The configured capture retention may have expired. Keep the proposal usable. */}}
async function openDraft(draftId){
  if(!await ensureProposalSaved())return;
  try{
    state.proposal=await api('/api/draft/open',{draft_id:draftId});
    state.draftId=draftId;
    state.draftUpdatedAt=state.proposal.draft_updated_at||0;
    state.analysisSession=null;await loadProposalEvidence();
    $('#drafts-dialog').close();
    renderProposal();
    showToast('Draft reopened. Applying re-checks the case in TestRail first.');
  }catch(error){showToast(error.message,true)}
}

async function deleteDraft(draftId,draftUpdatedAt){
  if(!window.confirm('Delete this draft? The work in it is lost.'))return;
  try{const data=await api('/api/draft/delete',{draft_id:draftId,draft_updated_at:draftUpdatedAt||''});renderDrafts(data.drafts||[])}
  catch(error){showToast(error.message,true)}
}

async function saveDraft(){
  if(!state.proposal)return;
  if(!await ensureProposalSaved())return;
  const name=window.prompt('Name this draft', state.proposal.changes?.title||`C${state.proposal.case_id}`);
  if(name===null)return;
  const button=$('#save-draft');
  if(button)button.disabled=true;
  try{
    // Se guardan las ediciones a mano primero: si no, el borrador guarda lo que
    // generó el modelo y se pierde lo que la persona acaba de corregir.
    state.proposal=await api('/api/proposal/revise',proposalEdits());
    const saved=await api('/api/draft/save',{proposal_token:state.proposal.proposal_token,revision:state.proposal.revision,name,draft_id:state.draftId||'',draft_updated_at:state.draftUpdatedAt||''});
    state.draftId=saved.draft_id;
    state.draftUpdatedAt=saved.draft_updated_at||0;
    showToast('Draft saved. Nothing was written to TestRail.');
  }catch(error){showToast(error.message,true)}
  finally{if(button)button.disabled=false}
}

const settingIds={
  testrail_url:'setting-testrail-url',testrail_email:'setting-testrail-email',testrail_project_id:'setting-project-id',
  vision_provider:'setting-vision-provider',vision_quality:'setting-vision-quality',openai_model:'setting-openai-model',codex_model:'setting-codex-model',claude_model:'setting-claude-model',max_images:'setting-max-images',ai_max_images:'setting-ai-max-images',max_recording_seconds:'setting-max-recording-seconds',capture_interval:'setting-capture-interval',hourly_rate_usd:'setting-hourly-rate',testrail_steps_field:'setting-steps-field',
  testrail_preconditions_field:'setting-preconditions-field',testrail_platform_field:'setting-platform-field',
  testrail_android_value:'setting-android-value',testrail_ios_value:'setting-ios-value',
  appium_url:'setting-appium-url',ios_bundle_id:'setting-ios-bundle-id',developer_dir:'setting-developer-dir',appium_capabilities_json:'setting-appium-capabilities',ios_devices_json:'setting-ios-devices',write_mode:'setting-write-mode',min_apply_confidence:'setting-min-confidence',min_verification_confidence:'setting-verification-confidence',capture_retention_hours:'setting-capture-retention',cache_retention_hours:'setting-cache-retention',draft_retention_days:'setting-draft-retention',history_retention_days:'setting-history-retention'
};
function updateProviderFields(){const provider=$('#setting-vision-provider').value;document.querySelectorAll('[data-provider-field]').forEach(field=>field.hidden=field.dataset.providerField!==provider)}
function updateFallbackFields(){const enabled=$('#setting-allow-fallback').checked;$('#fallback-provider-wrap').hidden=!enabled;const primary=$('#setting-vision-provider').value;[...$('#setting-fallback-provider').options].forEach(option=>option.disabled=option.value===primary&&option.value!=='')}
async function loadProviderStatus(){try{const data=await getJson('/api/providers');$('#provider-status').innerHTML=data.providers.map(item=>`<span class="provider-pill ${item.authenticated?'ready':''}">${item.provider==='openai_api'?'OpenAI API':escapeHtml(item.provider)} · ${item.authenticated?'available':item.installed?'not signed in':'not installed'} · remaining allowance not exposed</span>`).join('')+`<small>${escapeHtml(data.usage_note)}</small>`}catch(error){$('#provider-status').textContent=error.message}}
async function refreshTrustedTools(){const box=$('#trusted-tools-list');if(!box)return;box.innerHTML='<div class="skeleton"></div>';try{const data=await getJson('/api/trusted-tools');box.innerHTML=data.tools.map(tool=>{const status=tool.trusted?'trusted':tool.installed?'review needed':'not installed';const detail=tool.installed?`${tool.path} · SHA-256 ${tool.sha256}`:tool.detail;const action=tool.installed&&!tool.trusted?`<button class="secondary" data-trust-tool="${escapeHtml(tool.name)}" data-trust-hash="${escapeHtml(tool.sha256)}" type="button">Trust this build</button>`:'';return `<article class="history-item"><div><strong>${escapeHtml(tool.name)} · ${escapeHtml(status)}</strong><p>${escapeHtml(detail)}</p></div>${action}</article>`}).join('');document.querySelectorAll('[data-trust-tool]').forEach(button=>button.addEventListener('click',async()=>{const name=button.dataset.trustTool;const hash=button.dataset.trustHash;if(!window.confirm(`Trust ${name} with this exact SHA-256? This only approves the current local build.`))return;button.disabled=true;try{await api('/api/trusted-tools/trust',{name,sha256:hash});showToast(`${name} is trusted locally.`);await refreshTrustedTools();await loadProviderStatus()}catch(error){showToast(error.message,true);button.disabled=false}}))}catch(error){box.innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}}
async function refreshAnalysisCache(){const box=$('#analysis-cache-status');if(!box)return;try{const data=await getJson('/api/analysis-cache');const expiry=data.next_expiry?new Date(data.next_expiry*1000).toLocaleString():'—';box.textContent=`${data.entries} entries · ${(data.bytes/1024).toFixed(1)} KB · ${data.cache_hits} hits · ${data.model_calls_avoided} model calls avoided · next expiry: ${expiry} · TTL ${Math.round(data.ttl_seconds/3600)}h.`}catch(error){box.textContent=error.message}}
async function refreshProfiles(){const data=await getJson('/api/profiles');const select=$('#profile-select');const selected=select.value;select.innerHTML='<option value="">Current profile, unnamed</option>'+data.profiles.map(item=>`<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}${item.project_id?` · project ${escapeHtml(item.project_id)}`:''}</option>`).join('');if([...select.options].some(option=>option.value===selected))select.value=selected}
function fillSettings(settings){Object.entries(settingIds).forEach(([key,id])=>{$(`#${id}`).value=settings[key]??''});$('#setting-allow-fallback').checked=settings.allow_provider_fallback===true;$('#setting-fallback-provider').value=settings.fallback_provider||'';updateProviderFields();updateFallbackFields();$('#setting-openai-key').value='';$('#setting-testrail-key').value='';$('#setting-openai-key').placeholder=settings.openai_api_key_set?'Set · leave empty to keep':'Paste your API key';$('#setting-testrail-key').placeholder=settings.testrail_api_key_set?'Set · leave empty to keep':'Paste your API key';$('#secret-storage-note').textContent=`Codex and Claude reuse their local CLI sessions. API keys are stored in ${settings.secret_storage} and never sent back to the browser.`}
async function openSettings(){
  try{
    const settings=await getJson('/api/settings');
    fillSettings(settings);await refreshProfiles();loadProviderStatus();refreshTrustedTools();refreshAnalysisCache();
    if(!$('#settings-dialog').open)$('#settings-dialog').showModal();
  }catch(error){showToast(error.message,true)}
}
function closeSettings(){if($('#settings-dialog').open)$('#settings-dialog').close()}
async function saveSettings(event){
  event.preventDefault();const button=$('#save-settings');button.disabled=true;button.textContent='Saving…';
  const payload={};Object.entries(settingIds).forEach(([key,id])=>payload[key]=$(`#${id}`).value);for(const key of ['max_images','max_recording_seconds','min_apply_confidence','min_verification_confidence','capture_retention_hours','cache_retention_hours','draft_retention_days','history_retention_days'])payload[key]=Number(payload[key]);payload.openai_api_key=$('#setting-openai-key').value;payload.testrail_api_key=$('#setting-testrail-key').value;payload.allow_provider_fallback=$('#setting-allow-fallback').checked;payload.fallback_provider=payload.allow_provider_fallback?$('#setting-fallback-provider').value:'';
  try{await api('/api/settings',payload);const validation=await api('/api/config/validate');if(!validation.valid)throw new Error(validation.errors.join(' '));closeSettings();showToast(validation.warnings.length?`Configuration is valid. ${validation.warnings.join(' ')}`:'Configuration validated and saved.');state.activeRun=null;state.currentCase=null;showCaseEmpty();$('#run-content').hidden=true;$('#run-empty').hidden=false;const connection=$('#connection');connection.classList.add('ready');connection.innerHTML=`<span></span>${payload.vision_provider==='codex'?'Codex':payload.vision_provider==='claude'?'Claude':'OpenAI API'}`;await loadProjects()}
  catch(error){showToast(error.message,true)}finally{button.disabled=false;button.textContent='Save settings'}
}

$('#discover-wireless').addEventListener('click',discoverWireless);
$('#usb-to-wireless').addEventListener('click',usbToWireless);
$('#disconnect-wireless').addEventListener('click',disconnectWireless);
$('#run-locator').addEventListener('input',renderRuns);
$('#run-locator').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();openLocatorRun()}});
$('#project-select').addEventListener('change',async()=>{const prior=String(state.activeRun?.project_id||state.workspace.project_id||'');if(!await ensureProposalSaved()){if(prior)$('#project-select').value=prior;return}state.activeRun=null;state.pastedRun=null;showCaseEmpty();$('#run-content').hidden=true;$('#run-empty').hidden=false;saveWorkspace({project_id:$('#project-select').value});loadRuns()});
window.addEventListener('beforeunload',event=>{if(pendingAutosavePayload||autosaveOutstanding){event.preventDefault();event.returnValue=''}else releaseEditorLease()});
$('#refresh-runs').addEventListener('click',loadRuns);$('#case-search').addEventListener('input',renderTests);$('#update-case').addEventListener('click',openUpdateDialog);$('#execute-case').addEventListener('click',openExecution);$('#close-dialog').addEventListener('click',closeUpdateDialog);$('#cancel-update').addEventListener('click',closeUpdateDialog);$('#minimize-update').addEventListener('click',minimizeAnalysis);$('#restore-analysis').addEventListener('click',restoreAnalysis);$('#continue-update').addEventListener('click',continueUpdate);$('#refresh-devices').addEventListener('click',refreshDevices);document.querySelectorAll('input[name="platform"]').forEach(input=>input.addEventListener('change',()=>{state.preferredDeviceId='';renderDevices();rememberDeviceChoice()}));$('#device-select').addEventListener('change',()=>{state.preferredDeviceId=$('#device-select').value;rememberDeviceChoice()});$('#target-config').addEventListener('change',rememberDeviceChoice);$('#update-dialog').addEventListener('cancel',event=>{event.preventDefault();if(state.analysisInProgress)minimizeAnalysis();else closeUpdateDialog()});
$('#defer-update').addEventListener('click',saveDeferredEvidence);
$('#open-work').addEventListener('click',openMyWork);$('#close-work').addEventListener('click',()=>$('#work-dialog').close());$('#work-list').addEventListener('click',workAction);
$('#open-deferred').addEventListener('click',openDeferredQueue);$('#close-deferred').addEventListener('click',closeDeferredQueue);$('#deferred-dialog').addEventListener('cancel',event=>{event.preventDefault();closeDeferredQueue()});$('#deferred-list').addEventListener('click',deferredAction);
$('#deferred-list').addEventListener('change',updateDeferredButtons);
$('#deferred-sequential').addEventListener('click',()=>startDeferred([...document.querySelectorAll('#deferred-list input[data-queue-select]:checked')].map(input=>input.value),'sequential'));
$('#deferred-pause').addEventListener('click',()=>controlDeferred('pause'));
$('#deferred-resume').addEventListener('click',()=>controlDeferred('resume'));
$('#deferred-cancel').addEventListener('click',()=>controlDeferred('cancel'));
$('#import-evidence').addEventListener('click',()=>$('#import-evidence-file').click());$('#import-evidence-file').addEventListener('change',importEvidenceFile);
$('#evidence-suggested').addEventListener('click',()=>setSuggestedEvidence(true));$('#evidence-clear').addEventListener('click',()=>setSuggestedEvidence(false));
$('#evidence-grid').addEventListener('click',event=>{const button=event.target.closest('[data-evidence-zoom]');if(!button)return;showEvidenceZoom((state.evidencePreview?.frames||[]).findIndex(frame=>frame.index===Number(button.dataset.evidenceZoom)))});
$('#evidence-zoom-close').addEventListener('click',()=>$('#evidence-zoom').close());$('#evidence-zoom-prev').addEventListener('click',()=>showEvidenceZoom(evidenceZoomPosition-1));$('#evidence-zoom-next').addEventListener('click',()=>showEvidenceZoom(evidenceZoomPosition+1));$('#evidence-zoom-toggle').addEventListener('click',()=>{const frame=state.evidencePreview?.frames?.[evidenceZoomPosition];if(!frame)return;const input=document.querySelector(`#evidence-grid input[value="${frame.index}"]`);if(!input)return;input.checked=!input.checked;updateEvidenceSummary({target:input});showEvidenceZoom(evidenceZoomPosition)});
document.querySelectorAll('input[name="execution-platform"]').forEach(input=>input.addEventListener('change',renderExecutionDevices));$('#start-execution').addEventListener('click',startExecution);$('#close-execution').addEventListener('click',closeExecution);$('#execution-dialog').addEventListener('cancel',event=>{event.preventDefault();closeExecution()});$('#execution-screen').addEventListener('pointerdown',event=>{event.preventDefault();executionPointer=executionPoint(event);event.currentTarget.setPointerCapture(event.pointerId)});$('#execution-screen').addEventListener('pointerup',finishExecutionGesture);$('#execution-screen').addEventListener('pointercancel',()=>{executionPointer=null});$('#execution-send-text').addEventListener('click',sendExecutionText);$('#execution-text').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();sendExecutionText()}});$('#show-execution-locators').addEventListener('click',showExecutionLocators);$('#verify-execution-step').addEventListener('click',verifyExecutionStep);$('#execution-next').addEventListener('click',()=>{state.executionReviewIndex=null;renderExecution();refreshExecutionScreen()});document.querySelectorAll('[data-execution-outcome]').forEach(button=>button.addEventListener('click',()=>setExecutionOutcome(button.dataset.executionOutcome)));$('#finish-execution').addEventListener('click',finishExecution);$('#export-execution').addEventListener('click',downloadExecutionReport);$('#reconcile-execution').addEventListener('click',reconcileExecutionPublication);
$('#history-case').addEventListener('click',openHistory);$('#close-history').addEventListener('click',()=>$('#history-dialog').close());
$('#connect-wireless').addEventListener('click',connectWireless);
$('#export-drafts').addEventListener('click',exportDrafts);
$('#import-drafts').addEventListener('click',()=>$('#import-drafts-file').click());$('#import-drafts-file').addEventListener('change',async event=>{const file=event.target.files?.[0];event.target.value='';if(!file)return;if(file.size>10*1024*1024)return showToast('The draft file is larger than 10 MB.',true);try{const parsed=JSON.parse(await file.text());const data=await api('/api/draft/import',{drafts:parsed.drafts});renderDrafts(data.drafts||[]);showToast(`${data.imported} draft${data.imported===1?'':'s'} imported locally. Nothing was sent to TestRail.`)}catch(error){showToast(`Draft import failed: ${error.message}`,true)}});
$('#start-android-avd').addEventListener('click',()=>startLocalDevice('android'));
$('#forget-device').addEventListener('click',forgetRememberedDevice);
$('#start-ios-simulator').addEventListener('click',()=>startLocalDevice('ios'));
$('#open-preflight').addEventListener('click',openPreflight);$('#close-preflight').addEventListener('click',()=>$('#preflight-dialog').close());$('#download-support-report').addEventListener('click',downloadSupportReport);
$('#resume-recovery').addEventListener('click',resumeRecovery);$('#dismiss-recovery').addEventListener('click',()=>$('#recovery-banner').hidden=true);
$('#recovery-all-work').addEventListener('click',openMyWork);
if(window.location.port&&window.location.port!=='8787')$('#alternate-instance').hidden=false;
document.addEventListener('keydown',event=>{if(!state.proposal||$('#proposal-content').hidden||!(event.metaKey||event.ctrlKey)||event.altKey)return;if(event.key.toLowerCase()==='z'){event.preventDefault();if(event.shiftKey)redoEditor();else undoEditor()}else if(event.key.toLowerCase()==='y'){event.preventDefault();redoEditor()}});
$('#open-drafts').addEventListener('click',openDraftsDialog);$('#close-drafts').addEventListener('click',()=>$('#drafts-dialog').close());$('#save-template').addEventListener('click',saveTemplate);$('#save-procedures').addEventListener('click',saveProcedures);$('#load-procedures-example').addEventListener('click',loadProceduresExample);$('#open-matrix').addEventListener('click',async()=>{$('#matrix-dialog').showModal();$('#matrix-list').innerHTML='<div class="skeleton"></div>';try{const data=await getJson('/api/device-matrix');$('#matrix-list').innerHTML=data.matrix.length?data.matrix.map(item=>`<article class="history-item"><div><strong>${escapeHtml(item.device_name||item.device_id)}</strong><p>${escapeHtml(item.platform)} · ${escapeHtml(item.version||'version not detected')} · ${item.cases.length} casos</p></div><span class="optional-badge">${new Date(item.last_tested_at*1000).toLocaleDateString()}</span></article>`).join(''):'<div class="empty"><p>The matrix appears after the first update.</p></div>'}catch(error){$('#matrix-list').innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}});$('#close-matrix').addEventListener('click',()=>$('#matrix-dialog').close());
$('#open-quality').addEventListener('click',async()=>{$('#quality-dialog').showModal();const box=$('#quality-list');box.innerHTML='<div class="skeleton"></div>';try{const q=(await getJson('/api/quality')).quality;const pct=value=>value===null?'—':`${Math.round(value*100)}%`;const x=q.execution||{};box.innerHTML=`<article class="history-item"><div><strong>${q.steps} reviewed steps</strong><p>${q.reviews} review sessions · prompt v${q.prompt_version}</p></div></article><article class="history-item"><div><strong>${pct(q.acceptance_rate)} accepted</strong><p>${q.accepted} accepted · ${q.edited} edited · ${q.rejected} rejected/hallucinated</p></div></article><article class="history-item"><div><strong>${pct(q.edit_rate)} edited · ${pct(q.rejection_rate)} rejected</strong><p>Measured only from explicit reviewer feedback.</p></div></article><article class="history-item"><div><strong>${x.executions||0} deterministic executions</strong><p>${x.steps||0} final steps · ${x.ai_verdicts||0} AI verdicts · ${x.manual_verdicts||0} manual verdicts · ${x.needs_review||0} needs review</p></div></article><article class="history-item"><div><strong>${pct(x.ai_final_rate)} AI final rate</strong><p>Average settle: ${x.average_settle_seconds===null||x.average_settle_seconds===undefined?'—':`${x.average_settle_seconds}s`} · verifier latency: ${x.ai_duration_seconds||0}s · cost: $${Number(x.ai_cost_usd||0).toFixed(4)}</p></div></article>`}catch(error){box.innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}});$('#close-quality').addEventListener('click',()=>$('#quality-dialog').close());
$('#appium-screen').addEventListener('pointerdown',event=>{event.preventDefault();appiumPointer=appiumPoint(event);event.currentTarget.setPointerCapture(event.pointerId)});$('#appium-screen').addEventListener('pointerup',finishAppiumGesture);$('#appium-screen').addEventListener('pointercancel',()=>{appiumPointer=null});
$('#appium-send-text').addEventListener('click',sendAppiumText);$('#appium-text').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();sendAppiumText()}});
$('#open-settings').addEventListener('click',openSettings);$('#close-settings').addEventListener('click',closeSettings);$('#cancel-settings').addEventListener('click',closeSettings);$('#settings-form').addEventListener('submit',saveSettings);
$('#setting-vision-provider').addEventListener('change',updateProviderFields);
$('#setting-vision-provider').addEventListener('change',updateFallbackFields);$('#setting-allow-fallback').addEventListener('change',updateFallbackFields);
$('#export-audit').addEventListener('click',async()=>{try{const report=await getJson('/api/audit');const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`qa-sync-auditoria-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);showToast(`${report.count} registros exportados.`)}catch(error){showToast(error.message,true)}});
function downloadAuditCsv(report){const columns=['audit_id','case_id','created_at','updated_at','state','previous_title','updated_title','changed_fields','platform','device_name','device_version','provider','target_config','cost_usd','input_tokens','output_tokens','duration_ms'];const quote=value=>`"${String(value??'').replaceAll('"','""')}"`;const csvValue=value=>{const text=String(value??'');return quote(/^[=+\-@]/.test(text)?`'${text}`:text)};const rows=(report.records||[]).map(record=>columns.map(key=>key==='changed_fields'?csvValue((record.changed_fields||[]).join(', ')):csvValue(record.usage?.[key]??record[key])).join(','));const blob=new Blob(['\uFEFF'+columns.join(',')+'\n'+rows.join('\n')+'\n'],{type:'text/csv;charset=utf-8'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`qa-sync-auditoria-${new Date().toISOString().slice(0,10)}.csv`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000)}
$('#export-audit-csv').addEventListener('click',async()=>{try{const report=await getJson('/api/audit');downloadAuditCsv(report);showToast(`${report.count} audit records exported as CSV.`)}catch(error){showToast(error.message,true)}});
$('#clear-analysis-cache').addEventListener('click',async()=>{if(!window.confirm('Clear every encrypted cached analysis on this machine?'))return;try{const data=await api('/api/analysis-cache/clear');showToast(`${data.cleared} cached analyses removed.`);await refreshAnalysisCache()}catch(error){showToast(error.message,true)}});
$('#save-profile').addEventListener('click',async()=>{const name=$('#profile-name').value.trim();if(!name)return showToast('Give the profile a name.',true);try{await api('/api/profile/save',{name});await refreshProfiles();$('#profile-select').value=name;showToast('Profile saved without credentials.')}catch(error){showToast(error.message,true)}});
$('#load-profile').addEventListener('click',async()=>{const name=$('#profile-select').value;if(!name)return showToast('Select a profile first.',true);try{const settings=await api('/api/profile/activate',{name});fillSettings(settings);loadProviderStatus();showToast(`Profile ${name} activated.`)}catch(error){showToast(error.message,true)}});
$('#delete-profile').addEventListener('click',async()=>{const name=$('#profile-select').value;if(!name)return showToast('Select a profile first.',true);if(!window.confirm(`Delete the local profile ${name}?`))return;try{await api('/api/profile/delete',{name});await refreshProfiles();showToast('Profile deleted.')}catch(error){showToast(error.message,true)}});
function showRecovery(title,detail,resumable=false,actionLabel='Continue',kind='LOCAL WORK'){$('#recovery-kind').textContent=kind;$('#recovery-title').textContent=title;$('#recovery-detail').textContent=detail+(state.recoveryItemCount>1?` · ${state.recoveryItemCount} local items found; View all work to see the rest.`:'');$('#resume-recovery').textContent=actionLabel;$('#resume-recovery').hidden=!resumable;$('#recovery-banner').hidden=false}
async function resumeRecovery(){if(state.recoveryQueue){state.recoveryQueue=false;$('#recovery-banner').hidden=true;await openDeferredQueue();return}if(state.proposal){renderProposal();$('#recovery-banner').hidden=true;return}if(state.execution){$('#recovery-banner').hidden=true;$('#execution-title').textContent=`Resume C${state.execution.case_id} · T${state.execution.test_id}`;$('#execution-setup').hidden=true;$('#execution-active').hidden=false;$('#execution-dialog').showModal();renderExecution();await refreshExecutionScreen();state.executionTimer=setInterval(refreshExecutionScreen,2200);return}if(!state.session&&state.preservedSession){state.session=state.preservedSession.id;state.recoveredSessionCaseId=state.preservedSession.case_id;state.sessionPreserved=true}if(!state.session)return;if(!state.currentCase&&state.recoveredSessionCaseId)state.currentCase=(await api('/api/case',{case_id:state.recoveredSessionCaseId})).case;if(!state.currentCase)return showToast('The recovered case could not be loaded. The evidence remains preserved.',true);try{const preview=await api('/api/record/evidence-preview',{session_id:state.session});state.evidencePreview=preview;state.sessionPreserved=true;$('#recovery-banner').hidden=true;$('#dialog-case').textContent=`C${state.currentCase.id} · ${state.currentCase.title}`;$('#dialog-target').hidden=true;$('#device-step').hidden=true;$('#recording-step').hidden=true;$('#evidence-step').hidden=false;$('#continue-update').textContent='Analyze selected screens';$('#cancel-update').textContent='Close and keep evidence';renderEvidencePreview(preview);$('#update-dialog').showModal()}catch(error){showToast(`Could not open recovered evidence: ${error.message}`,true)}}
async function restoreLocalWork(){try{const recovered=await getJson('/api/recovery');state.recoveryItemCount=Number(Boolean(recovered.execution))+Number(Boolean(recovered.proposal))+(recovered.sessions?.length||0)+(recovered.deferred_count||0);if(recovered.execution){state.execution=recovered.execution;state.currentCase=(await api('/api/case',{case_id:recovered.execution.case_id})).case;renderCase();showRecovery(`Recovered execution for T${recovered.execution.test_id}`,`${recovered.execution.platform} · C${recovered.execution.case_id} · ${recovered.execution.current_index}/${recovered.execution.steps.length} steps`,true,'Resume execution','EXECUTION');return}if(recovered.proposal){state.proposal=recovered.proposal;state.currentCase=(await api('/api/case',{case_id:recovered.proposal.case_id})).case;await loadProposalEvidence();renderProposal();showRecovery(`Recovered proposal for C${recovered.proposal.case_id}`,`${recovered.proposal.device_name||'Device not recorded'} · ${recovered.proposal.device_version||'version not recorded'}`,true,'Open proposal','LOCAL PROPOSAL');return}const session=recovered.sessions?.[0];if(session?.case_id){state.preservedSession={id:session.session_id,case_id:session.case_id};state.recoveredSessionCaseId=session.case_id;state.currentCase=(await api('/api/case',{case_id:session.case_id})).case;renderCase();const env=session.environment||{};showRecovery(`Recovered evidence for C${session.case_id}`,`${session.platform} · ${env.model||session.device_id} · ${env.os_version||'version not recorded'} · ${session.frames} screens`,true,'Review evidence','LOCAL EVIDENCE');return}if(recovered.deferred_count){state.recoveryQueue=true;showRecovery(`${recovered.deferred_count} TC${recovered.deferred_count===1?'':'s'} waiting in AI queue`,'Captured locally. Review and start analysis only when you choose to use the provider.',true,'Open AI queue','DEFERRED WORK')}}catch(error){showToast(error.message,true)}}
async function watchServerRestart(){
  try{
    const status=await getJson('/api/status');
    const id=String(status.server_instance_id||'');
    if(!id||!state.serverInstanceId){state.serverInstanceId=id;return}
    if(id===state.serverInstanceId)return;
    state.serverInstanceId=id;
    if(state.session||state.execution){showToast('QA Sync restarted. Your local execution/recording was recovered; resume it from the banner.',true);return}
    showToast('QA Sync restarted. Refreshing to synchronise the interface…');
    setTimeout(()=>window.location.reload(),700);
  }catch(_error){/* The next heartbeat retries after a transient restart. */}
}
getJson('/api/status').then(async status=>{state.serverInstanceId=String(status.server_instance_id||'');const el=$('#connection');if(status.vision_ready&&status.testrail_ready){el.classList.add('ready');const provider=status.vision_provider==='codex'?'Codex':status.vision_provider==='claude'?'Claude':'OpenAI API';el.innerHTML=`<span></span>${status.write_mode==='review_only'?`Dry run · ${provider}`:provider}`;await loadProjects();await restoreLocalWork();setInterval(watchServerRestart,10000)}else{el.innerHTML='<span></span>Setup pending';openSettings();setInterval(watchServerRestart,10000)}}).catch(error=>showToast(error.message,true));
