"use strict";

// Execute in the guided demo uses synthetic canvas frames only. No device,
// TestRail endpoint, or AI provider is contacted. PNGs stay in IndexedDB.
(() => {
  const databaseName = "qa-sync-guided-demo-evidence-v1";
  const state = {caseId:null,stepIndex:0,screenIndex:0,actionDone:false,results:[],touched:new Set(),busy:false,storageError:""};
  let databasePromise;
  let evidenceRevision=0;
  const key = (caseId,index,phase) => `${caseId}:${index}:${phase}`;

  function database(){
    if(!databasePromise)databasePromise=new Promise((resolve,reject)=>{
      if(!window.indexedDB)return reject(new Error("IndexedDB is unavailable in this browser."));
      const request=indexedDB.open(databaseName,1);
      request.onupgradeneeded=()=>request.result.createObjectStore("captures",{keyPath:"key"});
      request.onsuccess=()=>resolve(request.result);
      request.onerror=()=>reject(request.error||new Error("Browser storage could not open."));
    });
    return databasePromise;
  }
  async function put(record){
    const db=await database();
    return new Promise((resolve,reject)=>{
      const transaction=db.transaction("captures","readwrite");
      transaction.objectStore("captures").put(record);
      transaction.oncomplete=resolve;
      transaction.onerror=()=>reject(transaction.error||new Error("Screenshot could not be stored."));
    });
  }
  async function read(keyValue){
    const db=await database();
    return new Promise((resolve,reject)=>{
      const request=db.transaction("captures","readonly").objectStore("captures").get(keyValue);
      request.onsuccess=()=>resolve(request.result||null);
      request.onerror=()=>reject(request.error||new Error("Screenshot could not be read."));
    });
  }
  function releaseUrls(){evidenceRevision++}
  function drawScreen(){
    const canvas=document.querySelector("#demo-exec-canvas");if(!canvas)return;
    const ctx=canvas.getContext("2d"),step=currentCase().steps[state.stepIndex];
    ctx.fillStyle="#f7f8fc";ctx.fillRect(0,0,360,620);
    ctx.fillStyle="#25233a";ctx.fillRect(0,0,360,78);
    ctx.fillStyle="#fff";ctx.font="bold 18px sans-serif";ctx.fillText("DEMO DEVICE",20,32);
    ctx.font="12px sans-serif";ctx.fillText(`C${state.caseId} · ${currentRun().platform.toUpperCase()}`,20,54);
    ctx.fillStyle="#6457d9";ctx.fillRect(20,103,320,49);
    ctx.fillStyle="#fff";ctx.font="bold 15px sans-serif";ctx.fillText(state.actionDone?"After simulated action":"Before simulated action",33,133);
    ctx.fillStyle="#25233a";ctx.font="bold 17px sans-serif";ctx.fillText(`Step ${state.stepIndex+1} of ${currentCase().steps.length}`,20,192);
    ctx.font="12px sans-serif";
    const lines=wrap(ctx,step.content,310);
    lines.slice(0,3).forEach((line,index)=>ctx.fillText(line,20,225+index*18));
    const labels=state.actionDone?["Modes and settings","Single mode","No device assigned"]:["More","Modes and settings","Open mode details"];
    labels.forEach((label,index)=>{
      const y=305+index*77;
      ctx.fillStyle="#fff";ctx.fillRect(20,y,320,63);
      ctx.strokeStyle="#dedee8";ctx.strokeRect(20,y,320,63);
      ctx.fillStyle="#25233a";ctx.font="bold 13px sans-serif";ctx.fillText(label,34,y+37);
    });
    ctx.fillStyle="#77768d";ctx.font="11px sans-serif";ctx.fillText("SYNTHETIC SCREEN · NOT A DEVICE CAPTURE",20,587);
  }
  function wrap(ctx,text,width){
    const words=String(text).split(/\s+/),lines=[];let line="";
    for(const word of words){const next=line?`${line} ${word}`:word;if(ctx.measureText(next).width>width&&line){lines.push(line);line=word}else line=next}
    if(line)lines.push(line);return lines;
  }
  async function capture(phase){
    if(state.storageError)throw new Error(state.storageError);
    const caseId=state.caseId,stepIndex=state.stepIndex;
    const canvas=document.querySelector("#demo-exec-canvas");if(!canvas)throw new Error("The synthetic screen is unavailable.");
    drawScreen();
    const blob=await new Promise((resolve,reject)=>canvas.toBlob(value=>value?resolve(value):reject(new Error("Screenshot encoding failed.")),"image/png"));
    const record={key:key(caseId,stepIndex,phase),caseId,stepIndex,phase,blob,createdAt:new Date().toISOString(),state:"pending"};
    await put(record);
    if(state.caseId===caseId&&state.stepIndex===stepIndex&&demo.stage==="execute"){
      state.touched.add(record.key);
      recordAudit(`Saved synthetic ${phase} screenshot locally for step ${stepIndex+1}`);
      await refreshEvidence();
    }
  }
  function recordAudit(action){record(action)}
  async function refreshEvidence(){
    const box=document.querySelector("#demo-exec-evidence");if(!box)return;
    const caseId=state.caseId,index=state.stepIndex,revision=++evidenceRevision;
    try{
      const records=await Promise.all(["before","after"].map(phase=>read(key(caseId,index,phase))));
      const images=await Promise.all(records.map(item=>item?blobDataUrl(item.blob):null));
      if(revision!==evidenceRevision||demo.stage!=="execute"||state.caseId!==caseId||state.stepIndex!==index)return;
      box.innerHTML=records.map((item,position)=>{
        const phase=position?"After":"Before";
        if(!item)return `<div class="execute-shot empty"><strong>${phase}</strong><span>No local screenshot yet</span></div>`;
        const current=state.touched.has(item.key);
        return `<div class="execute-shot"><strong>${phase} · ${current?item.state==="used"?"attached to report":"pending local":"previous local capture"}</strong><img src="${images[position]}" alt="Synthetic ${phase.toLowerCase()} screenshot"><span>${new Date(item.createdAt).toLocaleString()}</span></div>`;
      }).join("");
    }catch(error){box.textContent=`Local screenshots unavailable: ${error.message}`}
  }
  function render(){
    if(demo.stage!=="execute"||state.caseId!==demo.caseId)return;
    releaseUrls();
    const item=currentCase(),done=state.stepIndex>=item.steps.length;
    const progress=state.results.filter(Boolean).length;
    if(done){
      const count=outcome=>state.results.filter(result=>result?.outcome===outcome).length;
      document.querySelector("#demo-detail").innerHTML=`<div id="demo-execution"><div class="detail-head"><div><span class="eyebrow">SIMULATION COMPLETE · C${item.id}</span><h2>Review the illustrative result</h2><p>${progress} of ${item.steps.length} example steps · no device, AI or TestRail calls</p></div><button class="button" data-execute="close" type="button">Back to case</button></div><div class="demo-note">These verdicts and synthetic PNGs belong only to the optional browser simulation. No real TC was executed. Export or overwrite them if needed.</div><div class="execute-summary"><strong>${count("passed")} illustrative passed · ${count("failed")} illustrative failed · ${count("blocked")} illustrative blocked · ${count("skipped")} optional skipped</strong>${state.results.map((result,index)=>`<p>Example step ${index+1}: ${escapeHtml(result.outcome)}${result.reason?` · ${escapeHtml(result.reason)}`:""} · ${result.evidenceCount} synthetic image(s) attached</p>`).join("")}</div><div class="proposal-actions"><button class="button primary" data-execute="export" type="button">Export simulation JSON</button><button class="button" data-execute="close" type="button">Back to case</button></div></div>`;
      return;
    }
    const step=item.steps[state.stepIndex];
    document.querySelector("#demo-detail").innerHTML=`<div id="demo-execution"><div class="detail-head"><div><span class="eyebrow">DETERMINISTIC EXECUTION · C${item.id}</span><h2>Execute step ${state.stepIndex+1} of ${item.steps.length}</h2><p>${progress} completed · ${escapeHtml(currentRun().device)}</p></div><button class="button" data-execute="close" type="button">Close · keep local screenshots</button></div><div class="demo-note">Synthetic device only. Before/after screenshots are PNGs saved to this browser's IndexedDB; no image is sent to an AI provider. Recapture replaces the screenshot for this case, step and phase. Private browsing may discard them when the window closes; export the report if you need a durable copy.</div>${state.storageError?`<div class="demo-note">Storage error: ${escapeHtml(state.storageError)}. No screenshot is saved until browser storage works.</div>`:""}<div class="execute-step"><h3>${escapeHtml(step.content)}</h3><p><strong>Expected:</strong> ${escapeHtml(step.expected)} ${step.optional?'<span class="small-badge">Optional</span>':""}</p></div><div class="execute-layout"><div class="execute-device"><canvas id="demo-exec-canvas" width="360" height="620" role="img" aria-label="Synthetic device screen for local screenshot capture"></canvas><div class="proposal-actions"><button class="button primary" data-execute="perform" type="button">${state.actionDone?"Perform again & overwrite after":"Perform mock action & capture after"}</button><button class="button" data-execute="capture" type="button">Recapture ${state.actionDone?"after":"before"}</button></div></div><div class="execute-review"><h3>Local screenshots</h3><div id="demo-exec-evidence" class="execute-evidence"></div><label>Reason for failed or blocked step<input id="demo-exec-reason" maxlength="1000" placeholder="What differed or prevented execution"></label><div class="proposal-actions" id="demo-execution-verdicts"><button class="button" data-execute-verdict="passed" type="button">Pass</button><button class="button" data-execute-verdict="failed" type="button">Fail</button><button class="button" data-execute-verdict="blocked" type="button">Blocked</button>${step.optional?'<button class="button" data-execute-verdict="skipped" type="button">Skip optional</button>':""}</div><p class="demo-bottom-note">The verdict attaches pending screenshots to the local report. You can also record a manual verdict without a screenshot; the report will show that evidence gap.</p></div></div></div>`;
    document.querySelector("#demo-execution .eyebrow").textContent=`OPTIONAL EXECUTE SIMULATION · C${item.id}`;
    document.querySelector("#demo-execution h2").textContent=`Simulated step ${state.stepIndex+1} of ${item.steps.length}`;
    drawScreen();refreshEvidence();
  }
  async function open(){
    const item=currentCase();if(!item)return;
    state.caseId=item.id;state.stepIndex=0;state.screenIndex=0;state.actionDone=false;state.results=[];state.touched.clear();state.storageError="";
    demo.stage="execute";render();resetDetailScroll();recordAudit("Opened synthetic deterministic execution");
    try{await database()}catch(error){state.storageError=error.message;render()}
    if(!state.storageError)try{await capture("before")}catch(error){state.storageError=error.message;render();toast(`Screenshot not saved: ${error.message}`)}
  }
  async function perform(){
    if(state.busy)return;state.busy=true;
    try{state.actionDone=true;state.screenIndex++;render();await capture("after");toast("Synthetic after screenshot saved locally.")}
    catch(error){state.storageError=error.message;render();toast(`Screenshot not saved: ${error.message}`)}
    finally{state.busy=false}
  }
  async function recapture(){
    if(state.busy)return;state.busy=true;
    try{await capture(state.actionDone?"after":"before");toast("Local screenshot replaced for this step.")}
    catch(error){state.storageError=error.message;render();toast(`Screenshot not saved: ${error.message}`)}
    finally{state.busy=false}
  }
  async function verdict(outcome){
    if(state.busy)return;const item=currentCase(),step=item.steps[state.stepIndex];
    if(!step)return;
    if(outcome==="skipped"&&!step.optional)return toast("Only an optional step can be skipped.");
    const reason=document.querySelector("#demo-exec-reason")?.value.trim()||"";
    if(["failed","blocked"].includes(outcome)&&!reason)return toast("Explain why the step failed or was blocked.");
    state.busy=true;
    try{
      let evidenceCount=0;
      for(const phase of ["before","after"]){
        const recordKey=key(item.id,state.stepIndex,phase);
        if(!state.touched.has(recordKey))continue;
        const itemRecord=await read(recordKey);
        if(itemRecord){itemRecord.state="used";await put(itemRecord);evidenceCount++}
      }
      state.results[state.stepIndex]={outcome,reason,evidenceCount};
      recordAudit(`Step ${state.stepIndex+1} ${outcome}; ${evidenceCount} local screenshots attached`);
      state.stepIndex++;state.actionDone=false;state.screenIndex++;
      render();resetDetailScroll();
      if(state.stepIndex<item.steps.length&&!state.storageError)await capture("before");
      toast(`Step ${state.stepIndex} recorded. Screenshots stayed local.`);
    }catch(error){state.storageError=error.message;render();toast(`Local evidence error: ${error.message}`)}
    finally{state.busy=false}
  }
  function blobDataUrl(blob){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(reader.error);reader.readAsDataURL(blob)})}
  async function exportReport(){
    const evidence=[];
    for(const recordKey of state.touched){const item=await read(recordKey);if(item?.state==="used")evidence.push({step_index:item.stepIndex,phase:item.phase,captured_at:item.createdAt,image_data_url:await blobDataUrl(item.blob)})}
    downloadJson(`qa-sync-DEMO-execute-C${state.caseId}.json`,{demo:true,mode:"local_execution",case_id:state.caseId,run_id:currentRun().id,exported_at:new Date().toISOString(),results:state.results,evidence});
    recordAudit(`Exported local execution with ${evidence.length} screenshots`);
    toast("Local execution exported. No screenshot was sent to AI.");
  }
  document.querySelector("#demo-detail").addEventListener("click",event=>{
    const button=event.target.closest("[data-execute],[data-execute-verdict]");if(!button)return;
    if(button.dataset.executeVerdict){verdict(button.dataset.executeVerdict);return}
    if(button.dataset.execute==="perform")perform();
    else if(button.dataset.execute==="capture")recapture();
    else if(button.dataset.execute==="export")exportReport().catch(error=>toast(error.message));
    else if(button.dataset.execute==="close"){demo.stage="case";renderDetail();resetDetailScroll();releaseUrls();toast("Synthetic screenshots remain stored locally.")}
  });
  window.demoExecution={open,render,leave:releaseUrls};
})();
