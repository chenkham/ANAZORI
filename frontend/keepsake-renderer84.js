import {drawMotionCard, prepareMotionCard} from './motion-card.js';

const builtWorkerUrl = typeof __KEEPSAKE_WORKER_URL84__ === 'string' ? __KEEPSAKE_WORKER_URL84__ : '/assets/2026/keepsake-worker84.js';

// Keep the display canvas on the page so a failed worker can fall back without
// replacing DOM or losing MP4 capture. Only one bitmap and one latest request wait.
export function createMotionCardRenderer(canvas, ticket, {workerUrl = builtWorkerUrl, useWorker = true} = {}) {
  const context = canvas.getContext('2d');
  if (!context) throw new Error('Canvas unavailable');
  let worker = null, active = null, queued = null, timer = 0, sequence = 0, disposed = false, engine = 'starting';
  let readyResolve;
  const ready = new Promise(resolve => { readyResolve = resolve; });
  const mainReady = () => Promise.allSettled([prepareMotionCard(ticket), document.fonts?.load('500 44px Satoshi')]);
  const markReady = value => { engine = value; canvas.dataset.renderEngine = value; clearTimeout(timer); readyResolve(); };
  const complete = job => { job?.resolve(true); active = null; if (queued) { const next = queued; queued = null; send(next); } };
  const fallback = async () => {
    if (disposed || engine === 'main' || engine === 'fallback') return;
    engine = 'fallback'; clearTimeout(timer); worker?.terminate(); worker = null;
    await mainReady();
    if (disposed) return;
    markReady('main');
    if (active) { const job = active; drawMotionCard(context, job.ticket, job.time); complete(job); }
  };
  const send = job => {
    if (disposed) { job.resolve(false); return; }
    active = job;
    if (engine === 'worker') {
      timer = setTimeout(fallback, 5000);
      try { worker.postMessage({type:'draw', id:job.id, ticket:job.ticket, time:job.time}); } catch { fallback(); }
    } else { drawMotionCard(context, job.ticket, job.time); complete(job); }
  };
  if (useWorker && typeof Worker === 'function' && typeof OffscreenCanvas === 'function' && typeof createImageBitmap === 'function') {
    try {
      worker = new Worker(workerUrl, {type:'module', name:'Anazori keepsake'});
      worker.onerror = event => { event.preventDefault(); fallback(); };
      worker.onmessage = ({data: message}) => {
        if (disposed || engine === 'fallback' || engine === 'main') { message.bitmap?.close(); return; }
        if (message.type === 'failed') { fallback(); return; }
        if (message.type === 'ready') { markReady('worker'); return; }
        if (message.type === 'frame') {
          try { if (active?.id === message.id && !queued) context.drawImage(message.bitmap, 0, 0); }
          finally { message.bitmap.close(); }
          clearTimeout(timer); complete(active);
        }
      };
      timer = setTimeout(fallback, 10000);
      worker.postMessage({type:'init', width:canvas.width, height:canvas.height, ticket});
    } catch { fallback(); }
  } else fallback();
  return {
    ready,
    async draw(data, time) {
      await ready;
      if (disposed) return false;
      return new Promise(resolve => {
        const job = {ticket:{...data}, time, id:++sequence, resolve};
        if (active) { queued?.resolve(false); queued = job; } else send(job);
      });
    },
    destroy() {
      disposed = true; clearTimeout(timer); worker?.terminate(); worker = null;
      active?.resolve(false); queued?.resolve(false); active = queued = null; readyResolve();
    }
  };
}
