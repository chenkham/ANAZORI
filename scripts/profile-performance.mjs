import {chromium} from 'playwright';
import {spawn} from 'node:child_process';
import {mkdir, writeFile} from 'node:fs/promises';
import {resolve, join} from 'node:path';

// Identical local assets, viewport, CPU throttling and scroll path for both runs.
const label = process.argv[2] || 'after';
if (!/^[a-z0-9-]+$/.test(label)) throw new Error('Invalid profile label');
const cpuRate = Number(process.argv[3] || 6);
if (!Number.isFinite(cpuRate) || cpuRate < 1 || cpuRate > 20) throw new Error('Invalid CPU slowdown');
const eventSlug=process.argv[4] || '';
if(eventSlug && !/^[a-z0-9-]+$/.test(eventSlug)) throw new Error('Invalid event slug');
const staticSprites=process.argv[5]==='static-sprites';
const output = resolve('.local/performance');
await mkdir(output, {recursive: true});
const base = 'http://127.0.0.1:8111';
const server = spawn('php', ['-S', '127.0.0.1:8111', '-t', 'src', 'scripts/router.php'], {
  cwd: resolve('.'), env: {...process.env, ANAZORI_DB_PATH: join(output, 'profile.sqlite')}, windowsHide: true, stdio: 'ignore'
});
let browser;
try {
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(base)).ok) { ready = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!ready) throw new Error('Profile server unavailable');
  browser = await chromium.launch();
  const context = await browser.newContext({viewport: {width: 390, height: 844}, deviceScaleFactor: 1, isMobile: true, hasTouch: true});
  await context.addInitScript(() => {
    localStorage.setItem('anazori-motion', 'on');
    localStorage.setItem('anazori-sound', 'off');
    window.__profile = {longTasks: [], frames: []};
    new PerformanceObserver(list => list.getEntries().forEach(entry => window.__profile.longTasks.push({start: entry.startTime, duration: entry.duration}))).observe({type: 'longtask', buffered: true});
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send('Emulation.setCPUThrottlingRate', {rate: cpuRate});
  await cdp.send('Performance.enable');
  await page.goto(base, {waitUntil: 'networkidle'});
  await page.evaluate(() => document.fonts.ready);
  if(eventSlug){
    if(!await page.locator(`[data-programme-pane="${eventSlug}"]`).count()) throw new Error('Unknown event slug');
    const count=await page.locator('.programme-pane').count();
    for(let i=0;i<count && !await page.locator(`[data-programme-pane="${eventSlug}"]`).isVisible();i++) await page.getByRole('button',{name:'Next event',exact:true}).click();
    await page.locator(`[data-programme-pane="${eventSlug}"] img`).evaluateAll(async images=>{await Promise.all(images.map(img=>img.decode()));});
    await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
  }
  // Profile the new animations after decoding, including their full sprite atlases.
  for(const selector of ['.character-chase','#culture-tech']){
    const scene=page.locator(selector);
    if(await scene.locator('[data-sprite-src]').count()){
      await scene.scrollIntoViewIfNeeded();
      await page.waitForFunction(selector=>document.querySelector(selector)?.classList.contains('sprites-ready'),selector);
    }
  }
  for(const selector of ['.clock-card','#experiences','#culture-tech']) {
    const scene=page.locator(selector);
    if(await scene.count() && await scene.locator('[data-performance-play=loop]').count()) {
      await scene.scrollIntoViewIfNeeded();
      await page.waitForFunction(selector=>[...document.querySelectorAll(selector+' [data-performance-play=loop]')].filter(e=>!e.closest('[hidden]')).every(e=>e.classList.contains('is-animated')),selector);
      await scene.locator('.is-animated img').evaluateAll(async images=>{await Promise.all(images.map(img=>img.decode()));});
    }
  }
  await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
  if(staticSprites) {await page.addStyleTag({content:'.sprite-sheet,.chase-runner{animation:none!important;transform:none!important}'});await page.evaluate(()=>{document.body.dataset.sceneMotion='off';document.dispatchEvent(new Event('anazori:motion'));});}
  await page.waitForTimeout(1200);
  const before = await cdp.send('Performance.getMetrics');
  const trace = [];
  cdp.on('Tracing.dataCollected', ({value}) => trace.push(...value));
  await cdp.send('Tracing.start', {categories: 'devtools.timeline,disabled-by-default-devtools.timeline.frame', transferMode: 'ReportEvents'});
  const run = await page.evaluate(async () => {
    window.__profile.longTasks = [];
    const start = performance.now(), duration = 12000;
    const extent = document.documentElement.scrollHeight - innerHeight;
    let previous = start;
    await new Promise(resolve => {
      const frame = now => {
        window.__profile.frames.push(now - previous); previous = now;
        const progress = Math.min(1, (now - start) / duration);
        // Traverse the entire festival and then reverse to exercise both directions.
        scrollTo({top: extent * (progress < .5 ? progress * 2 : (1 - progress) * 2), behavior: 'instant'});
        if (progress < 1) requestAnimationFrame(frame); else resolve();
      };
      requestAnimationFrame(frame);
    });
    return {elapsed: performance.now() - start, extent, ...window.__profile,
      engine: document.documentElement.dataset.scrollEngine || 'manual',
      scrollTimeline: typeof ScrollTimeline === 'function',
      activeAnimations: document.getAnimations().length,
      opacity: [...document.querySelectorAll('[data-scroll-motion]')].filter(e => !e.closest('[hidden]')).map(e => ({name: e.dataset.scrollMotion, value: getComputedStyle(e).opacity}))};
  });
  const after = await cdp.send('Performance.getMetrics');
  const completed = new Promise(resolve => cdp.once('Tracing.tracingComplete', resolve));
  await cdp.send('Tracing.end'); await completed;
  const metrics = Object.fromEntries(after.metrics.map(entry => [entry.name, entry.value - (before.metrics.find(old => old.name === entry.name)?.value || 0)]));
  const names = ['Layout', 'UpdateLayoutTree', 'Paint', 'PrePaint', 'FunctionCall', 'FireAnimationFrame'];
  const traceTotals = Object.fromEntries(names.map(name => {
    const events = trace.filter(event => event.name === name && event.ph === 'X');
    return [name, {count: events.length, durationMs: events.reduce((sum, event) => sum + (event.dur || 0) / 1000, 0)}];
  }));
  const sorted = run.frames.slice(1).sort((a,b) => a-b);
  const result = {label, conditions: `Headless Chromium; 390x844; DPR 1; ${cpuRate}x CPU throttle; local network; motion on; original video/assets; chase sprites and visible native SVGs decoded; ${staticSprites?'scene motion disabled for diagnostic baseline; ':''}12s full-page down/up scroll`,
    engine: run.engine, selectedEvent:eventSlug || 'first', elapsedMs: run.elapsed, scrollExtent: run.extent, frameCount: sorted.length,
    frameIntervalP50: sorted[Math.floor(sorted.length * .5)], frameIntervalP95: sorted[Math.floor(sorted.length * .95)],
    framesOver34ms: sorted.filter(value => value > 34).length,
    longTaskCount: run.longTasks.length, longTaskMs: run.longTasks.reduce((sum, entry) => sum + entry.duration, 0),
    scriptMs: metrics.ScriptDuration * 1000, taskMs: metrics.TaskDuration * 1000,
    layoutMs: metrics.LayoutDuration * 1000, styleMs: metrics.RecalcStyleDuration * 1000,
    traceTotals, activeAnimations: run.activeAnimations, errors};
  await writeFile(join(output, `${label}.json`), JSON.stringify(result, null, 2));
  await writeFile(join(output, `${label}-trace.json`), JSON.stringify({traceEvents: trace}));
  console.log(JSON.stringify(result, null, 2));
  if (errors.length) process.exitCode = 1;
} finally {
  await browser?.close();
  if (server.exitCode === null) { const exit = new Promise(resolve => server.once('exit', resolve)); server.kill(); await exit; }
}
