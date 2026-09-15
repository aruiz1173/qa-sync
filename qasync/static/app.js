const $=selector=>document.querySelector(selector);
const state={projects:[],runs:[],plans:[],planRuns:{},expandedPlan:null,pastedRun:null,tests:[],activeRun:null,activeTest:null,currentCase:null,proposal:null,devices:{android:[],ios:[]},session:null,timer:null,screenTimer:null,mirrors:{}};
const escapeHtml=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
const showToast=(message,error=false)=>{const el=$('#toast');el.textContent=message;el.className=`toast show${error?' error':''}`;clearTimeout(showToast.timer);showToast.timer=setTimeout(()=>el.className='toast',4200)};
const api=async(path,body={})=>{const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await response.json().catch(()=>({error:'Respuesta inválida del servidor.'}));if(!response.ok)throw new Error(data.error||`Error HTTP ${response.status}`);return data};
const getJson=async path=>{const response=await fetch(path);const data=await response.json().catch(()=>({error:'Respuesta inválida del servidor.'}));if(!response.ok)throw new Error(data.error||`Error HTTP ${response.status}`);return data};
const totalForRun=run=>['passed_count','blocked_count','untested_count','retest_count','failed_count','custom_status1_count','custom_status2_count'].reduce((sum,key)=>sum+Number(run[key]||0),0);
const passedPercent=run=>{const total=totalForRun(run);return total?Math.round(Number(run.passed_count||0)*100/total):0};

async function loadProjects(){
  try{
    const data=await api('/api/projects');state.projects=data.projects;
    const select=$('#project-select');select.innerHTML=state.projects.map(p=>`<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');select.disabled=!state.projects.length;
    const preferred=String(data.preferred_project_id||'');if(preferred&&state.projects.some(p=>String(p.id)===preferred))select.value=preferred;
    if(state.projects.length)await loadRuns();else $('#runs-list').innerHTML='<div class="empty"><p>No hay proyectos activos.</p></div>';
  }catch(error){$('#runs-list').innerHTML='<div class="empty"><h2>Configura TestRail</h2><p>Completa las credenciales en el archivo .env y reinicia QA Sync.</p></div>';showToast(error.message,true)}
}

async function loadRuns(){
  const projectId=$('#project-select').value;if(!projectId)return;
  $('#runs-list').innerHTML='<div class="skeleton tall"></div><div class="skeleton tall"></div>';
  try{const data=await api('/api/runs',{project_id:projectId});state.runs=data.runs;state.plans=data.plans||[];state.planRuns={};state.expandedPlan=null;renderRuns()}
  catch(error){$('#runs-list').innerHTML='<div class="empty"><p>No se pudieron cargar los runs.</p></div>';showToast(error.message,true)}
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
    const nested=open?`<div class="plan-runs">${inside.map(runItemHtml).join('')||'<div class="run-meta">Sin runs que coincidan.</div>'}</div>`:'';
    return `<button class="run-item plan-item" data-plan="${plan.id}" type="button"><strong>${open?'▾':'▸'} ${escapeHtml(plan.name)}<span class="plan-badge">PLAN</span></strong><div class="run-meta"><span>P${plan.id}</span><span>${plan.passed_count||0} de ${totalForRun(plan)} passed</span></div></button>${nested}`;
  }).join('');
  const body=pasted+runs+plans;
  const empty=query
    ?`<div class="empty"><h2>Sin coincidencias</h2><p>Nada con “${escapeHtml($('#run-locator').value.trim())}”. Si es la URL de un run, pulsa Enter para abrirlo.</p></div>`
    :'<div class="empty"><h2>Sin runs activos</h2><p>Este proyecto no tiene runs ni planes abiertos.</p></div>';
  $('#runs-list').innerHTML=body||empty;
  document.querySelectorAll('[data-run]').forEach(button=>button.addEventListener('click',()=>selectRun(Number(button.dataset.run))));
  document.querySelectorAll('[data-plan]').forEach(button=>button.addEventListener('click',()=>togglePlan(Number(button.dataset.plan))));
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

async function selectRun(id){
  state.activeRun=knownRuns().find(run=>run.id===id);if(!state.activeRun)return;
  state.activeTest=null;state.currentCase=null;renderRuns();
  $('#run-empty').hidden=true;$('#run-content').hidden=false;$('#run-label').textContent=[`RUN R${id}`,state.activeRun.plan_id?`PLAN P${state.activeRun.plan_id}`:'',runConfig(state.activeRun)].filter(Boolean).join(' · ');$('#run-name').textContent=state.activeRun.name;
  $('#run-progress').style.width=`${passedPercent(state.activeRun)}%`;$('#run-summary').textContent=`${state.activeRun.passed_count||0} passed · ${state.activeRun.failed_count||0} failed · ${state.activeRun.untested_count||0} untested`;
  $('#tests-list').innerHTML='<div class="skeleton"></div><div class="skeleton"></div>';showCaseEmpty();
  try{const data=await api('/api/tests',{run_id:id});state.tests=data.tests;renderTests()}
  catch(error){$('#tests-list').innerHTML='<div class="empty"><p>No se pudieron cargar los casos.</p></div>';showToast(error.message,true)}
}

function renderTests(){
  const query=$('#case-search').value.trim().toLowerCase();const tests=state.tests.filter(test=>`${test.title} c${test.case_id}`.toLowerCase().includes(query));
  $('#tests-list').innerHTML=tests.map(test=>`<button class="test-item${state.activeTest?.id===test.id?' active':''}" data-test="${test.id}" type="button"><span class="status-dot status-${test.status_id}"></span><span class="test-copy"><strong>${escapeHtml(test.title)}</strong><span>${test.refs?escapeHtml(test.refs):'Sin referencias'}</span></span><span class="test-id">C${test.case_id}</span></button>`).join('')||'<div class="empty"><p>No hay coincidencias.</p></div>';
  document.querySelectorAll('[data-test]').forEach(button=>button.addEventListener('click',()=>selectTest(Number(button.dataset.test))));
}

function showCaseEmpty(){$('#case-empty').hidden=false;$('#case-loading').hidden=true;$('#case-content').hidden=true;$('#proposal-content').hidden=true}
async function selectTest(id){
  state.activeTest=state.tests.find(test=>test.id===id);renderTests();$('#case-empty').hidden=true;$('#case-content').hidden=true;$('#proposal-content').hidden=true;$('#case-loading').hidden=false;
  try{const data=await api('/api/case',{case_id:state.activeTest.case_id});state.currentCase=data.case;renderCase()}
  catch(error){showCaseEmpty();showToast(error.message,true)}
}

function renderCase(){
  const item=state.currentCase;$('#case-loading').hidden=true;$('#proposal-content').hidden=true;$('#case-content').hidden=false;
  $('#case-id').textContent=`CASE C${item.id}`;$('#case-title').textContent=item.title;$('#case-refs').textContent=item.refs||'Sin referencias';$('#case-estimate').textContent=item.estimate||'Sin estimación';
  $('#case-preconditions').textContent=item.preconditions||'Sin precondiciones documentadas.';
  const steps=item.steps||[];$('#case-steps').innerHTML=steps.length?steps.map(step=>{const content=String(step.content||'');const optional=/^\[opcional\]\s*/i.test(content);return `<li><div>${optional?'<span class="optional-badge">Opcional</span>':''}<p class="step-action">${escapeHtml(content.replace(/^\[opcional\]\s*/i,''))}</p><p class="step-expected">${escapeHtml(step.expected||'Sin resultado esperado')}</p></div></li>`}).join(''):'<li><div><p class="step-action">Este caso no tiene pasos separados.</p></div></li>';
}

async function openHistory(){
  if(!state.currentCase)return;
  $('#history-title').textContent=`Historial de C${state.currentCase.id}`;
  $('#history-list').innerHTML='<div class="skeleton"></div>';
  $('#history-dialog').showModal();
  try{
    const data=await api('/api/history',{case_id:state.currentCase.id});
    $('#history-list').innerHTML=data.history.length?data.history.map(item=>`<article class="history-item"><div><strong>${escapeHtml(item.proposed_title||`C${item.case_id}`)}</strong><p>${new Date(item.created_at*1000).toLocaleString()} · ${escapeHtml(item.state)}</p></div>${item.state==='rolled_back'?'<span class="optional-badge">Restaurado</span>':`<button class="secondary" data-rollback="${item.id}" data-confirmation="${escapeHtml(item.confirmation)}" type="button">Restaurar</button>`}</article>`).join(''):'<div class="empty"><p>Aún no hay respaldos para este caso.</p></div>';
    document.querySelectorAll('[data-rollback]').forEach(button=>button.addEventListener('click',()=>rollbackBackup(button)));
  }catch(error){$('#history-list').innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}
}
async function rollbackBackup(button){
  const expected=button.dataset.confirmation;const confirmation=window.prompt(`Escribe ${expected} para restaurar el caso.`,'');
  if(confirmation===null)return;
  button.disabled=true;
  try{await api('/api/rollback',{backup_id:button.dataset.rollback,confirmation});showToast('Caso restaurado correctamente.');$('#history-dialog').close();await selectTest(state.activeTest.id)}
  catch(error){showToast(error.message,true);button.disabled=false}
}

const selectedPlatform=()=>document.querySelector('input[name="platform"]:checked').value;
function renderDevices(){const platform=selectedPlatform();const list=state.devices[platform]||[];const unavailable=state.devices[`${platform}_unavailable`]||[];const mirrors=state.devices.mirrors||{};const ready=list.map(d=>`<option value="${escapeHtml(d.id)}">${escapeHtml(d.name)} · ${escapeHtml(d.kind)}${mirrors[d.id]?' · espejo abierto':''}</option>`);const blocked=unavailable.map(d=>`<option value="" disabled>${escapeHtml(d.name)} · ${escapeHtml(d.kind)}</option>`);$('#device-select').innerHTML=ready.length||blocked.length?[...ready,...blocked].join(''):'<option value="">Ningún dispositivo disponible</option>'}
async function refreshDevices(){$('#refresh-devices').disabled=true;try{state.devices=await getJson('/api/devices');renderDevices();const relevant=(state.devices.errors||[]).filter(item=>item.toLowerCase().startsWith(selectedPlatform()));if(relevant.length)showToast(relevant.join(' '),true)}catch(error){showToast(error.message,true)}finally{$('#refresh-devices').disabled=false}}
async function discoverWireless(){
  const button=$('#discover-wireless');button.disabled=true;
  try{
    const data=await api('/api/device/android-discover');
    const services=(data.services||[]).filter(item=>item.kind==='pairing'||item.kind==='connect');
    $('#wireless-found').innerHTML=services.length?services.map(item=>
      `<button type="button" data-host="${escapeHtml(item.host)}" data-port="${escapeHtml(item.port)}">${escapeHtml(item.host)}:${escapeHtml(item.port)} · ${item.kind==='pairing'?'emparejar':'conectar'}</button>`
    ).join(''):'<p class="dialog-intro">Ningún dispositivo anunciándose. Activa Wireless Debugging en el teléfono.</p>';
    document.querySelectorAll('#wireless-found [data-host]').forEach(item=>item.addEventListener('click',()=>{
      $('#wireless-host').value=item.dataset.host;$('#wireless-port').value=item.dataset.port;
    }));
  }catch(error){showToast(error.message,true)}finally{button.disabled=false}
}

async function usbToWireless(){
  const deviceId=$('#device-select').value;
  if(!deviceId)return showToast('Selecciona primero el dispositivo USB en la lista.',true);
  const button=$('#usb-to-wireless');button.disabled=true;button.textContent='Pasando a Wi‑Fi';
  try{
    const result=await api('/api/device/android-tcpip',{device_id:deviceId});
    const [host,port]=result.endpoint.split(':');
    $('#wireless-host').value=host;$('#wireless-port').value=port;
    showToast(`Ahora también por Wi‑Fi: ${result.endpoint}`);await refreshDevices();
  }catch(error){showToast(error.message,true)}
  finally{button.disabled=false;button.textContent='Pasar el USB seleccionado a Wi‑Fi'}
}

async function disconnectWireless(){
  const host=$('#wireless-host').value.trim(),port=$('#wireless-port').value.trim();
  if(!host||!port)return showToast('Indica IP y puerto del dispositivo a desconectar.',true);
  const button=$('#disconnect-wireless');button.disabled=true;
  try{const result=await api('/api/device/android-disconnect',{endpoint:`${host}:${port}`});showToast(`Desconectado: ${result.endpoint}`);await refreshDevices()}
  catch(error){showToast(error.message,true)}finally{button.disabled=false}
}

async function connectWireless(){const button=$('#connect-wireless');button.disabled=true;try{const result=await api('/api/device/android-wireless',{host:$('#wireless-host').value,port:$('#wireless-port').value,pairing_code:$('#wireless-code').value});$('#wireless-code').value='';showToast(`Android conectado: ${result.endpoint}`);await refreshDevices()}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
function openUpdateDialog(){if(!state.currentCase)return;$('#dialog-case').textContent=`C${state.currentCase.id} · ${state.currentCase.title}`;$('#dialog-target').textContent=runConfig(state.activeRun)?`Este run apunta a: ${runConfig(state.activeRun)}`:'';$('#dialog-target').hidden=!runConfig(state.activeRun);$('#device-step').hidden=false;$('#recording-step').hidden=true;$('#continue-update').textContent='Adelante';$('#cancel-update').textContent='Cancelar';$('#update-dialog').showModal();refreshDevices()}
async function closeUpdateDialog(){
  if(state.session){
    if(!window.confirm('¿Cancelar la grabación? Las capturas temporales se eliminarán.'))return;
    clearInterval(state.timer);clearInterval(state.screenTimer);
    try{await api('/api/record/cancel',{session_id:state.session})}catch(error){showToast(error.message,true);return}
    state.session=null;
  }
  $('#update-dialog').close();
}

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
    $('#recording-count').textContent=`${status.frames} pantallas · ${Math.round(status.seconds)}s`;
    $('#appium-control').hidden=!status.remote_control;
    if(status.remote_control)$('#guided-control-label').textContent=`Control guiado ${status.control_kind==='adb'?'ADB':'Appium'}: toca o arrastra sobre la pantalla. Se guarda evidencia antes y después de cada acción.`;
    renderRecordingWarnings(status.warnings);
    if(status.error)showToast(status.error,true);
  }catch(_){}
}
let appiumPointer=null;
function appiumPoint(event){const screen=$('#appium-screen');const rect=screen.getBoundingClientRect();const width=Number(screen.dataset.logicalWidth);const height=Number(screen.dataset.logicalHeight);return{x:Math.max(0,Math.min(width,Math.round((event.clientX-rect.left)*width/rect.width))),y:Math.max(0,Math.min(height,Math.round((event.clientY-rect.top)*height/rect.height)))}}
async function finishAppiumGesture(event){if(!appiumPointer||!state.session)return;const end=appiumPoint(event);const start=appiumPointer;appiumPointer=null;const type=Math.abs(end.x-start.x)+Math.abs(end.y-start.y)<12?'tap':'swipe';try{await api('/api/record/action',{session_id:state.session,type,start,end});await Promise.all([updateRecordingStatus(),refreshGuidedScreen()])}catch(error){showToast(error.message,true)}}
async function sendAppiumText(){const input=$('#appium-text');if(!state.session||!input.value)return;const button=$('#appium-send-text');button.disabled=true;try{await api('/api/record/action',{session_id:state.session,type:'text',text:input.value});input.value='';await Promise.all([updateRecordingStatus(),refreshGuidedScreen()])}catch(error){showToast(error.message,true)}finally{button.disabled=false}}
async function continueUpdate(){
  const button=$('#continue-update');
  if(!state.session){
    const deviceId=$('#device-select').value;if(!deviceId)return showToast('Selecciona un dispositivo.',true);button.disabled=true;
    try{const payload={platform:selectedPlatform(),device_id:deviceId,case_id:state.currentCase.id,package:$('#android-package').value,deep_link:$('#android-deep-link').value,reset_data:$('#android-reset-data').checked};if(payload.reset_data&&!window.confirm('Se eliminarán los datos locales de esta app en el Android seleccionado. ¿Continuar?')){button.disabled=false;return}await api('/api/device/open',payload);const session=await api('/api/record/start',payload);state.session=session.session_id;$('#device-step').hidden=true;$('#recording-step').hidden=false;button.textContent='Finalizar recorrido';$('#cancel-update').textContent='Cancelar grabación';state.timer=setInterval(updateRecordingStatus,1000);state.screenTimer=setInterval(refreshGuidedScreen,2500);updateRecordingStatus()}
    catch(error){showToast(error.message,true)}finally{button.disabled=false}return;
  }
  button.disabled=true;button.textContent='Generando propuesta';clearInterval(state.timer);clearInterval(state.screenTimer);
  try{await api('/api/record/stop',{session_id:state.session});const result=await api('/api/record/analyze',{session_id:state.session,case_id:state.currentCase.id,context:$('#context').value,project_id:state.activeRun?.project_id||$('#project-select').value});state.proposal=result;state.session=null;$('#update-dialog').close();renderProposal()}
  catch(error){showToast(`${error.message} Puedes reintentar sin repetir el recorrido.`,true)}finally{button.disabled=false;button.textContent=state.session?'Reintentar análisis':'Adelante'}
}

const pretty=value=>Array.isArray(value)?value.map((step,index)=>`${index+1}. ${step.content}\n   Esperado: ${step.expected}`).join('\n\n'):(value===null||value===undefined||value===''?'—':typeof value==='object'?JSON.stringify(value,null,2):String(value));
function renderProposal(){
  const data=state.proposal;$('#case-content').hidden=true;$('#proposal-content').hidden=false;
  const proposedSteps=Array.isArray(data.changes[data.steps_field])?data.changes[data.steps_field]:[];
  const preKey=data.preconditions_field;
  const stepMarkup=(step,index)=>`<article class="edit-step" data-edit-step><div class="step-toolbar"><strong>Paso ${index+1}</strong><div><button class="step-move secondary" data-direction="up" type="button" aria-label="Subir paso">↑</button><button class="step-move secondary" data-direction="down" type="button" aria-label="Bajar paso">↓</button><button class="step-delete secondary" type="button">Eliminar</button></div></div><label>Acción<textarea class="edit-action" maxlength="5000">${escapeHtml(String(step.content||'').replace(/^\[opcional\]\s*/i,''))}</textarea></label><label>Resultado esperado<textarea class="edit-expected" maxlength="5000">${escapeHtml(step.expected||'')}</textarea></label><label class="inline-check"><input class="optional-check" type="checkbox" ${/^\[opcional\]/i.test(step.content||'')?'checked':''}> Paso opcional</label></article>`;
  const editor=`<section class="proposal-editor"><label>Título<input id="edit-title" maxlength="250" value="${escapeHtml(data.changes.title||'')}"></label><label>Precondiciones<textarea id="edit-preconditions" maxlength="10000">${escapeHtml(data.changes[preKey]||'')}</textarea></label><div class="steps-editor-head"><h3>Pasos propuestos</h3><button id="add-step" class="secondary" type="button">Agregar paso</button></div><div id="steps-editor">${proposedSteps.map(stepMarkup).join('')}</div></section>`;
  const simulation=data.write_mode==='review_only';
  const quality=data.vision_quality==='maximum'?'máxima · 2 llamadas':data.vision_quality==='economical'?'eficiente · 1 llamada':'alta · 1 llamada';
  const usage=data.usage||{};const usageText=usage.model_calls?` · ${usage.frames_analyzed}/${usage.frames_received} pantallas · ${usage.model_calls} llamada${usage.model_calls===1?'':'s'}`:'';
  $('#proposal-content').innerHTML=`<button id="back-case" class="secondary back-button" type="button">Volver al caso</button><div class="proposal-head"><div><p class="overline">PROPUESTA PARA C${data.case_id}</p><h2>Revisa y edita la actualización</h2></div><span class="confidence">${Math.round(data.confidence*100)}% confianza</span></div>${data.provider_used?`<p class="provider-used">Analizado con ${escapeHtml(data.provider_used)} · ${quality}${usageText}</p>`:''}${simulation?'<div class="warnings">Modo simulación activo: puedes revisar y editar, pero TestRail no recibirá escrituras.</div>':''}${data.warnings.length?`<div class="warnings">${data.warnings.map(escapeHtml).join('<br>')}</div>`:''}${editor}<div class="approval"><label for="confirmation">${simulation?'La actualización está bloqueada por configuración.':`Escribe ${escapeHtml(data.confirmation)} para actualizar TestRail.`}</label><div class="approval-row"><input id="confirmation" autocomplete="off" placeholder="Confirmación exacta" ${simulation?'disabled':''}><button id="apply-update" class="primary" type="button" ${simulation?'disabled':''}>Actualizar TestRail</button></div></div>`;
  $('#back-case').addEventListener('click',renderCase);$('#apply-update').addEventListener('click',applyProposal);$('#add-step').addEventListener('click',()=>{const wrapper=document.createElement('div');wrapper.innerHTML=stepMarkup({content:'',expected:''},document.querySelectorAll('[data-edit-step]').length);$('#steps-editor').append(wrapper.firstElementChild);bindStepEditor()});bindStepEditor();
}
function renumberSteps(){const steps=[...document.querySelectorAll('[data-edit-step]')];steps.forEach((step,index)=>{step.querySelector('.step-toolbar strong').textContent=`Paso ${index+1}`;step.querySelector('[data-direction="up"]').disabled=index===0;step.querySelector('[data-direction="down"]').disabled=index===steps.length-1})}
function bindStepEditor(){document.querySelectorAll('.step-move').forEach(button=>{button.onclick=()=>{const step=button.closest('[data-edit-step]');const sibling=button.dataset.direction==='up'?step.previousElementSibling:step.nextElementSibling;if(!sibling)return;if(button.dataset.direction==='up')step.parentElement.insertBefore(step,sibling);else step.parentElement.insertBefore(sibling,step);renumberSteps()}});document.querySelectorAll('.step-delete').forEach(button=>{button.onclick=()=>{if(document.querySelectorAll('[data-edit-step]').length===1)return showToast('La propuesta debe conservar al menos un paso.',true);button.closest('[data-edit-step]').remove();renumberSteps()}});renumberSteps()}
function proposalEdits(){return{proposal_token:state.proposal.proposal_token,title:$('#edit-title').value,preconditions:$('#edit-preconditions').value,steps:[...document.querySelectorAll('[data-edit-step]')].map(step=>({content:step.querySelector('.edit-action').value,expected:step.querySelector('.edit-expected').value}))}}
async function applyProposal(){const button=$('#apply-update');button.disabled=true;const optionalSteps=[...document.querySelectorAll('[data-edit-step]')].flatMap((step,index)=>step.querySelector('.optional-check').checked?[index]:[]);try{state.proposal=await api('/api/proposal/revise',proposalEdits());const result=await api('/api/apply',{proposal_token:state.proposal.proposal_token,confirmation:$('#confirmation').value,optional_steps:optionalSteps});showToast(`C${result.case_id} actualizado correctamente.`);if(state.activeTest)await selectTest(state.activeTest.id);else{state.currentCase=(await api('/api/case',{case_id:result.case_id})).case;renderCase()}}catch(error){showToast(error.message,true);button.disabled=false}}

const settingIds={
  testrail_url:'setting-testrail-url',testrail_email:'setting-testrail-email',testrail_project_id:'setting-project-id',
  vision_provider:'setting-vision-provider',vision_quality:'setting-vision-quality',openai_model:'setting-openai-model',codex_model:'setting-codex-model',claude_model:'setting-claude-model',max_images:'setting-max-images',max_recording_seconds:'setting-max-recording-seconds',testrail_steps_field:'setting-steps-field',
  testrail_preconditions_field:'setting-preconditions-field',testrail_platform_field:'setting-platform-field',
  testrail_android_value:'setting-android-value',testrail_ios_value:'setting-ios-value',
  appium_url:'setting-appium-url',ios_bundle_id:'setting-ios-bundle-id',appium_capabilities_json:'setting-appium-capabilities',ios_devices_json:'setting-ios-devices',write_mode:'setting-write-mode'
};
function updateProviderFields(){const provider=$('#setting-vision-provider').value;document.querySelectorAll('[data-provider-field]').forEach(field=>field.hidden=field.dataset.providerField!==provider)}
function updateFallbackFields(){const enabled=$('#setting-allow-fallback').checked;$('#fallback-provider-wrap').hidden=!enabled;const primary=$('#setting-vision-provider').value;[...$('#setting-fallback-provider').options].forEach(option=>option.disabled=option.value===primary&&option.value!=='')}
async function loadProviderStatus(){try{const data=await getJson('/api/providers');$('#provider-status').innerHTML=data.providers.map(item=>`<span class="provider-pill ${item.authenticated?'ready':''}">${item.provider==='openai_api'?'OpenAI API':escapeHtml(item.provider)} · ${item.authenticated?'disponible':item.installed?'sin sesión':'no instalado'} · límite restante no expuesto</span>`).join('')+`<small>${escapeHtml(data.usage_note)}</small>`}catch(error){$('#provider-status').textContent=error.message}}
async function refreshProfiles(){const data=await getJson('/api/profiles');const select=$('#profile-select');const selected=select.value;select.innerHTML='<option value="">Perfil actual sin nombre</option>'+data.profiles.map(item=>`<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}${item.project_id?` · proyecto ${escapeHtml(item.project_id)}`:''}</option>`).join('');if([...select.options].some(option=>option.value===selected))select.value=selected}
function fillSettings(settings){Object.entries(settingIds).forEach(([key,id])=>{$(`#${id}`).value=settings[key]??''});$('#setting-allow-fallback').checked=settings.allow_provider_fallback===true;$('#setting-fallback-provider').value=settings.fallback_provider||'';updateProviderFields();updateFallbackFields();$('#setting-openai-key').value='';$('#setting-testrail-key').value='';$('#setting-openai-key').placeholder=settings.openai_api_key_set?'Configurada · dejar vacío para conservar':'Pega tu API key';$('#setting-testrail-key').placeholder=settings.testrail_api_key_set?'Configurada · dejar vacío para conservar':'Pega tu API key';$('#secret-storage-note').textContent=`Codex y Claude usan la sesión de sus CLIs locales. Las API keys se guardan en ${settings.secret_storage} y nunca se devuelven al navegador.`}
async function openSettings(){
  try{
    const settings=await getJson('/api/settings');
    fillSettings(settings);await refreshProfiles();loadProviderStatus();
    if(!$('#settings-dialog').open)$('#settings-dialog').showModal();
  }catch(error){showToast(error.message,true)}
}
function closeSettings(){if($('#settings-dialog').open)$('#settings-dialog').close()}
async function saveSettings(event){
  event.preventDefault();const button=$('#save-settings');button.disabled=true;button.textContent='Conectando';
  const payload={};Object.entries(settingIds).forEach(([key,id])=>payload[key]=$(`#${id}`).value);payload.max_images=Number(payload.max_images);payload.max_recording_seconds=Number(payload.max_recording_seconds);payload.openai_api_key=$('#setting-openai-key').value;payload.testrail_api_key=$('#setting-testrail-key').value;payload.allow_provider_fallback=$('#setting-allow-fallback').checked;payload.fallback_provider=payload.allow_provider_fallback?$('#setting-fallback-provider').value:'';
  try{await api('/api/settings',payload);const validation=await api('/api/config/validate');if(!validation.valid)throw new Error(validation.errors.join(' '));closeSettings();showToast(validation.warnings.length?`Configuración válida. ${validation.warnings.join(' ')}`:'Configuración validada y guardada.');state.activeRun=null;state.currentCase=null;showCaseEmpty();$('#run-content').hidden=true;$('#run-empty').hidden=false;const connection=$('#connection');connection.classList.add('ready');connection.innerHTML=`<span></span>${payload.vision_provider==='codex'?'Codex':payload.vision_provider==='claude'?'Claude':'OpenAI API'}`;await loadProjects()}
  catch(error){showToast(error.message,true)}finally{button.disabled=false;button.textContent='Guardar y conectar'}
}

$('#discover-wireless').addEventListener('click',discoverWireless);
$('#usb-to-wireless').addEventListener('click',usbToWireless);
$('#disconnect-wireless').addEventListener('click',disconnectWireless);
$('#run-locator').addEventListener('input',renderRuns);
$('#run-locator').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();openLocatorRun()}});
$('#project-select').addEventListener('change',()=>{state.activeRun=null;showCaseEmpty();$('#run-content').hidden=true;$('#run-empty').hidden=false;loadRuns()});
$('#refresh-runs').addEventListener('click',loadRuns);$('#case-search').addEventListener('input',renderTests);$('#update-case').addEventListener('click',openUpdateDialog);$('#close-dialog').addEventListener('click',closeUpdateDialog);$('#cancel-update').addEventListener('click',closeUpdateDialog);$('#continue-update').addEventListener('click',continueUpdate);$('#refresh-devices').addEventListener('click',refreshDevices);document.querySelectorAll('input[name="platform"]').forEach(input=>input.addEventListener('change',renderDevices));$('#update-dialog').addEventListener('cancel',event=>{if(state.session){event.preventDefault();showToast('Finaliza el recorrido antes de cerrar.',true)}});
$('#history-case').addEventListener('click',openHistory);$('#close-history').addEventListener('click',()=>$('#history-dialog').close());
$('#connect-wireless').addEventListener('click',connectWireless);
$('#open-matrix').addEventListener('click',async()=>{$('#matrix-dialog').showModal();$('#matrix-list').innerHTML='<div class="skeleton"></div>';try{const data=await getJson('/api/device-matrix');$('#matrix-list').innerHTML=data.matrix.length?data.matrix.map(item=>`<article class="history-item"><div><strong>${escapeHtml(item.device_name||item.device_id)}</strong><p>${escapeHtml(item.platform)} · ${escapeHtml(item.version||'versión no detectada')} · ${item.cases.length} casos</p></div><span class="optional-badge">${new Date(item.last_tested_at*1000).toLocaleDateString()}</span></article>`).join(''):'<div class="empty"><p>La matriz aparecerá después de la primera actualización.</p></div>'}catch(error){$('#matrix-list').innerHTML=`<div class="warnings">${escapeHtml(error.message)}</div>`}});$('#close-matrix').addEventListener('click',()=>$('#matrix-dialog').close());
$('#appium-screen').addEventListener('pointerdown',event=>{event.preventDefault();appiumPointer=appiumPoint(event);event.currentTarget.setPointerCapture(event.pointerId)});$('#appium-screen').addEventListener('pointerup',finishAppiumGesture);$('#appium-screen').addEventListener('pointercancel',()=>{appiumPointer=null});
$('#appium-send-text').addEventListener('click',sendAppiumText);$('#appium-text').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();sendAppiumText()}});
$('#open-settings').addEventListener('click',openSettings);$('#close-settings').addEventListener('click',closeSettings);$('#cancel-settings').addEventListener('click',closeSettings);$('#settings-form').addEventListener('submit',saveSettings);
$('#setting-vision-provider').addEventListener('change',updateProviderFields);
$('#setting-vision-provider').addEventListener('change',updateFallbackFields);$('#setting-allow-fallback').addEventListener('change',updateFallbackFields);
$('#export-audit').addEventListener('click',async()=>{try{const report=await getJson('/api/audit');const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`qa-sync-auditoria-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);showToast(`${report.count} registros exportados.`)}catch(error){showToast(error.message,true)}});
$('#save-profile').addEventListener('click',async()=>{const name=$('#profile-name').value.trim();if(!name)return showToast('Escribe un nombre para el perfil.',true);try{await api('/api/profile/save',{name});await refreshProfiles();$('#profile-select').value=name;showToast('Perfil guardado sin credenciales.')}catch(error){showToast(error.message,true)}});
$('#load-profile').addEventListener('click',async()=>{const name=$('#profile-select').value;if(!name)return showToast('Selecciona un perfil.',true);try{const settings=await api('/api/profile/activate',{name});fillSettings(settings);loadProviderStatus();showToast(`Perfil ${name} activado.`)}catch(error){showToast(error.message,true)}});
$('#delete-profile').addEventListener('click',async()=>{const name=$('#profile-select').value;if(!name)return showToast('Selecciona un perfil.',true);if(!window.confirm(`¿Eliminar el perfil local ${name}?`))return;try{await api('/api/profile/delete',{name});await refreshProfiles();showToast('Perfil eliminado.')}catch(error){showToast(error.message,true)}});
async function restoreLocalWork(){try{const recovered=await getJson('/api/recovery');if(recovered.proposal){state.proposal=recovered.proposal;state.currentCase=(await api('/api/case',{case_id:recovered.proposal.case_id})).case;renderProposal();showToast('Se recuperó la propuesta pendiente del último inicio.');return}const session=recovered.sessions?.[0];if(session?.case_id){state.session=session.session_id;state.currentCase=(await api('/api/case',{case_id:session.case_id})).case;renderCase();showToast('Se recuperó una grabación pendiente; puedes terminarla y analizarla.')}}catch(error){showToast(error.message,true)}}
getJson('/api/status').then(async status=>{const el=$('#connection');if(status.vision_ready&&status.testrail_ready){el.classList.add('ready');const provider=status.vision_provider==='codex'?'Codex':status.vision_provider==='claude'?'Claude':'OpenAI API';el.innerHTML=`<span></span>${status.write_mode==='review_only'?`Simulación · ${provider}`:provider}`;await loadProjects();await restoreLocalWork()}else{el.innerHTML='<span></span>Configuración pendiente';openSettings()}}).catch(error=>showToast(error.message,true));
