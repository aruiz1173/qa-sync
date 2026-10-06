/* Guided tour of the actual workspace. It never fabricates cases or invokes writes. */
(() => {
  'use strict';

  const byId = id => document.getElementById(id);
  const visible = id => { const node = byId(id); return Boolean(node && !node.hidden && node.getClientRects().length); };
  const displayedCaseId = () => Number((byId('case-id')?.textContent || '').match(/C(\d+)/i)?.[1] || 0);
  const selectedCaseId = () => tour.caseId || (visible('case-content') ? displayedCaseId() : 0);
  const proposalForCase = () => visible('proposal-content') &&
    Number((document.querySelector('#proposal-content .proposal-head .overline')?.textContent || '').match(/C(\d+)/i)?.[1] || 0) === selectedCaseId();
  const safeText = value => String(value || '').replace(/\s+/g, ' ').trim();
  const queueForCase = () => tour.queue.filter(item => Number(item.case_id) === selectedCaseId()).at(-1);
  const tour = {active: false, mode: '', index: 0, queue: [], queueError: '', timer: null,
                lastTarget: null, casesSignature: '', caseId: 0, observed: new Set(), explained: new Set()};

  const definitions = {
    readiness: {title: 'Conexiones y preparación reales', target: '#open-preflight',
      body: 'Preflight revisa TestRail, proveedor y herramientas locales. El tour no crea cuentas ni cambia Settings. Si algo falta, arréglalo antes de capturar.',
      action: 'Abrir Preflight', done: () => byId('connection')?.classList.contains('ready')},
    run: {title: 'Elige un run de TestRail', target: '#run-locator',
      body: 'Usa un run activo o pega su URL/R-number. Si el proyecto no tiene runs abiertos, aquí no aparecerá ninguno inventado.',
      done: () => visible('run-content')},
    case: {title: 'Selecciona un TC real', target: '#tests-list',
      body: 'La lista proviene del run seleccionado. Abajo aparecen hasta 20 TCs visibles para abrir uno durante la presentación; no son fixtures.',
      done: () => visible('case-content')},
    path: {title: 'Escoge el flujo que vas a mostrar', target: '#case-content',
      body: 'Execute documenta veredictos manuales y puede dejar la evidencia en cola sin IA. Refresh graba el recorrido para proponer cambios. Elige una ruta abajo.',
      done: () => Boolean(tour.mode)},
    executeOpen: {title: 'Abre Execute del TC seleccionado', target: '#execute-case',
      body: 'Éste es el Execute real del run. Abrirlo no inicia el dispositivo ni gasta límite de IA.',
      action: 'Abrir Execute', done: () => byId('execution-dialog')?.open},
    executeCapture: {title: 'Conecta el dispositivo e inicia capture-only', target: '#execution-setup',
      body: 'Elige Android o iOS, confirma el dispositivo y conserva “Capture-only”. Al pulsar Start execution se inicia captura real por ADB/Appium; el tour no lo pulsa por ti.',
      done: () => byId('execution-dialog')?.open && visible('execution-active')},
    executeVerdicts: {title: 'Recorre y marca cada paso', target: '#execution-active',
      body: 'Interactúa con la app y marca Pass, Fail, Blocked o Skip optional. QA Sync conserva capturas y checkpoints por paso. Verify with AI está bloqueado en capture-only.',
      done: () => byId('execution-dialog')?.open && visible('execution-finish')},
    executePark: {title: 'Termina y conserva este TC', target: '#execution-finish',
      body: 'Mantén “Keep this TC…” marcado y pulsa Finish execution. Publicar un resultado en TestRail es una casilla aparte, desmarcada inicialmente. La captura quedará en AI queue.',
      done: () => Boolean(queueForCase())},
    refreshOpen: {title: 'Abre Refresh del TC seleccionado', target: '#update-case',
      body: 'Éste es el flujo real para actualizar pasos. Abrir el diálogo no inicia captura ni hace llamadas a IA.',
      action: 'Abrir Refresh', done: () => byId('update-dialog')?.open},
    refreshCapture: {title: 'Captura el recorrido real', target: '#device-step',
      body: 'Selecciona dispositivo y comienza. Usa la app paso a paso; cuando termines, pulsa Finish journey. La captura todavía es local.',
      done: () => byId('update-dialog')?.open && visible('recording-step')},
    refreshReview: {title: 'Revisa las pantallas capturadas', target: '#evidence-step',
      body: 'Selecciona únicamente las pantallas útiles y revisa datos sensibles. Puedes guardar para después sin gastar IA o analizar ahora, si tienes límite.',
      done: () => byId('update-dialog')?.open && visible('evidence-step')},
    refreshPark: {title: 'Deja el recorrido pendiente', target: '#defer-update',
      body: 'Pulsa “Save for later · no AI”. El TC y la selección se conservan localmente; no se envía nada al proveedor en este paso.',
      done: () => Boolean(queueForCase())},
    queue: {title: 'Abre la cola real', target: '#open-deferred',
      body: 'Cada fila corresponde a una captura del workspace. El estado se consulta del servidor local, incluso después de reiniciar.',
      action: 'Abrir AI queue', done: () => byId('deferred-dialog')?.open},
    queueReview: {title: 'Revisión humana antes de IA', target: '#deferred-dialog',
      body: 'Abre Review screens, decide qué imágenes mandar y confirma la revisión de datos sensibles. Guardar la revisión no llama a IA.',
      done: () => ['ready', 'scheduled', 'running', 'completed'].includes(queueForCase()?.state)},
    analysis: {title: 'Análisis sólo cuando tú lo autorices', target: '#deferred-dialog', optional: true,
      body: 'Puedes analizar este TC, varios en orden o hasta dos simultáneos. Este tour nunca pulsa Analyze. Si no hay límite, explica esta etapa y continúa; la evidencia seguirá intacta.',
      done: () => queueForCase()?.state === 'completed' || proposalForCase()},
    draft: {title: 'Revisa un draft generado de verdad', target: '#open-drafts', optional: true,
      body: 'Cuando termine el análisis, abre el draft desde la cola o Drafts. Edita, marca pasos opcionales y revisa el preview. Sin análisis real no mostramos una propuesta falsa.',
      action: 'Abrir Drafts', done: proposalForCase},
    approval: {title: 'La decisión final sigue siendo humana', target: '#proposal-content', optional: true,
      body: 'Sólo Update TestRail, con la confirmación exacta, escribe el caso. En una presentación puedes detenerte aquí sin publicar nada.',
      done: proposalForCase},
    audit: {title: 'Calidad, historial y auditoría', target: '#open-quality', optional: true,
      body: 'Quality muestra métricas reales; History y Audit muestran registros reales cuando existen. El tour no genera cifras ni aprobaciones ficticias.',
      action: 'Abrir Quality', done: () => byId('quality-dialog')?.open}
  };

  const steps = () => [
    'readiness', 'run', 'case', 'path',
    ...(tour.mode === 'execute' ? ['executeOpen', 'executeCapture', 'executeVerdicts', 'executePark'] :
       tour.mode === 'refresh' ? ['refreshOpen', 'refreshCapture', 'refreshReview', 'refreshPark'] : []),
    'queue', 'queueReview', 'analysis', 'draft', 'approval', 'audit'
  ];

  function clearHighlight() {
    if (tour.lastTarget) tour.lastTarget.classList.remove('live-tour-target');
    tour.lastTarget = null;
  }

  function highlight(selector) {
    let node = selector ? document.querySelector(selector) : null;
    if (node && !node.getClientRects().length) node = null;
    if (node === tour.lastTarget) return;
    clearHighlight();
    if (!node) return;
    tour.lastTarget = node;
    node.classList.add('live-tour-target');
    node.scrollIntoView({block: 'nearest', inline: 'nearest', behavior: 'smooth'});
  }

  function keepAboveDialogs() {
    const panel = byId('live-tour');
    const openDialog = [...document.querySelectorAll('dialog[open]')].at(-1);
    const destination = openDialog || document.body;
    if (panel.parentElement !== destination) destination.append(panel);
  }

  function caseChoices() {
    const nodes = [...document.querySelectorAll('#tests-list [data-test]')].slice(0, 20);
    const signature = nodes.map(node => `${node.dataset.test}:${safeText(node.textContent)}`).join('|');
    if (tour.casesSignature === signature) return;
    tour.casesSignature = signature;
    const box = byId('live-tour-cases');
    box.replaceChildren();
    box.hidden = !nodes.length;
    if (!nodes.length) return;
    const label = document.createElement('strong');
    label.textContent = `${nodes.length} TC${nodes.length === 1 ? '' : 's'} reales visibles en este run`;
    box.append(label);
    for (const node of nodes) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary';
      button.textContent = safeText(node.textContent).slice(0, 120);
      button.addEventListener('click', () => node.click());
      box.append(button);
    }
  }

  function liveFacts() {
    const project = safeText(byId('project-select')?.selectedOptions?.[0]?.textContent) || 'sin proyecto';
    const run = visible('run-content') ? safeText(byId('run-name')?.textContent) : 'sin run seleccionado';
    const caseId = selectedCaseId();
    const caseLabel = caseId ? `C${caseId}` : 'sin TC seleccionado';
    const queued = queueForCase();
    return `Proyecto: ${project} · Run: ${run} · TC: ${caseLabel} · Cola: ${queued?.state || (tour.queueError ? 'no disponible' : 'sin captura para este TC')}`;
  }

  function render() {
    if (!tour.active) return;
    if (visible('case-content')) tour.caseId = displayedCaseId();
    keepAboveDialogs();
    const order = steps();
    tour.index = Math.min(tour.index, order.length - 1);
    const key = order[tour.index];
    const step = definitions[key];
    const done = Boolean(step.done());
    byId('live-tour-count').textContent = `${tour.index + 1} / ${order.length}`;
    byId('live-tour-title').textContent = step.title;
    byId('live-tour-body').textContent = step.body;
    byId('live-tour-facts').textContent = liveFacts();
    byId('live-tour-state').textContent = done ? 'Observado en el workspace real' : step.optional ? 'Opcional · aún no observado' : 'Esperando una acción real';
    byId('live-tour-state').className = `live-tour-state${done ? ' complete' : ''}`;
    byId('live-tour-back').disabled = tour.index === 0;
    byId('live-tour-next').disabled = !done;
    byId('live-tour-next').textContent = tour.index === order.length - 1 ? 'Terminar tour' : 'Siguiente';
    byId('live-tour-explain').hidden = done || tour.index === order.length - 1;
    byId('live-tour-action').hidden = !step.action;
    byId('live-tour-action').textContent = step.action || '';
    const choices = byId('live-tour-paths');
    choices.hidden = key !== 'path';
    choices.querySelectorAll('button').forEach(button => button.classList.toggle('chosen', button.dataset.path === tour.mode));
    byId('live-tour-cases').hidden = key !== 'case';
    if (key === 'case') caseChoices();
    highlight(step.target);
  }

  async function pollQueue() {
    if (!tour.active) return;
    try {
      const response = await fetch('/api/deferred', {cache: 'no-store'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      tour.queue = Array.isArray(data.items) ? data.items : [];
      tour.queueError = '';
    } catch (_) {
      tour.queueError = 'La cola local no responde.';
    }
    render();
  }

  function setMode(mode) {
    if (!['execute', 'refresh'].includes(mode)) return;
    tour.mode = mode;
    render();
  }

  function advance(explained = false) {
    const order = steps();
    const key = order[tour.index];
    if (explained) tour.explained.add(key);
    else if (definitions[key].done()) tour.observed.add(key);
    else return;
    if (tour.index === order.length - 1) { stop(); return; }
    tour.index += 1;
    render();
  }

  function start() {
    if (tour.active) { render(); return; }
    tour.active = true;
    tour.mode = '';
    tour.index = 0;
    tour.queue = [];
    tour.queueError = '';
    tour.casesSignature = '';
    tour.caseId = 0;
    tour.observed.clear();
    tour.explained.clear();
    byId('live-tour').hidden = false;
    tour.timer = setInterval(() => { render(); pollQueue(); }, 3000);
    pollQueue();
    render();
  }

  function stop() {
    tour.active = false;
    clearInterval(tour.timer);
    tour.timer = null;
    clearHighlight();
    const panel = byId('live-tour');
    if (panel.parentElement !== document.body) document.body.append(panel);
    panel.hidden = true;
    const url = new URL(location.href);
    if (url.searchParams.has('tour')) {
      url.searchParams.delete('tour');
      history.replaceState(null, '', url.pathname + url.search + url.hash);
    }
  }

  byId('start-live-tour').addEventListener('click', start);
  byId('live-tour-close').addEventListener('click', stop);
  byId('live-tour-back').addEventListener('click', () => { if (tour.index > 0) { tour.index -= 1; render(); } });
  byId('live-tour-next').addEventListener('click', () => advance(false));
  byId('live-tour-explain').addEventListener('click', () => advance(true));
  byId('live-tour-action').addEventListener('click', () => {
    const step = definitions[steps()[tour.index]];
    const target = document.querySelector(step.target);
    if (!target || !target.getClientRects().length) return;
    const modal = document.querySelector('dialog[open]');
    if (modal && !modal.contains(target)) {
      byId('live-tour-state').textContent = 'Cierra primero el diálogo actual.';
      return;
    }
    target.click();
    render();
  });
  byId('live-tour-paths').addEventListener('click', event => {
    const button = event.target.closest('[data-path]');
    if (button) setMode(button.dataset.path);
  });
  byId('live-tour-move').addEventListener('click', () => byId('live-tour').classList.toggle('left'));
  document.querySelectorAll('dialog').forEach(dialog => dialog.addEventListener('close', () => { if (tour.active) render(); }));
  if (new URL(location.href).searchParams.get('tour') === '1') start();
})();
