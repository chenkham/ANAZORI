import {chromium} from 'playwright';
import {readFile,mkdir,writeFile} from 'node:fs/promises';

// Profile the actual local preview with identical content, DPR, motion and
// traversal. --baseline serves the retained pre-change entry and stylesheet;
// its lazy chunks are saved alongside the original entry for repeatability.
const label=process.argv[2]||'after94',baseline=process.argv.includes('--baseline');
if(!/^[a-z0-9-]+$/.test(label))throw Error('Invalid output label');
const base=process.env.ANAZORI_QA_BASE||'http://127.0.0.1:8000';
const cpu=Number(process.env.ANAZORI_QA_CPU||6),dpr=Number(process.env.ANAZORI_QA_DPR||3);
const out='.local/mobile94';await mkdir(out,{recursive:true});
const browser=await chromium.launch();
try {
 const context=await browser.newContext({viewport:{width:390,height:844},deviceScaleFactor:dpr,isMobile:true,hasTouch:true});
 await context.addInitScript(()=>{localStorage.setItem('anazori-motion','on');localStorage.setItem('anazori-sound','off');window.__long=[];new PerformanceObserver(list=>window.__long.push(...list.getEntries().map(e=>e.duration))).observe({type:'longtask'});});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 if(baseline)for(const [name,type]of [['site.js','text/javascript'],['public.css','text/css']]){
  const body=await readFile('.local/backups/mobile94/assets/'+name);
  await page.route('**/assets/2026/'+name+'*',route=>route.fulfill({contentType:type,body}));
 }
 if(baseline)await page.route('**/assets/2026/chunks/*.js',async route=>{
  const name=new URL(route.request().url()).pathname.split('/').pop();
  try {const body=await readFile('.local/backups/mobile94/assets/chunks/'+name);await route.fulfill({contentType:'text/javascript',body});}
  catch {await route.continue();}
 });
 const cdp=await context.newCDPSession(page);await cdp.send('Emulation.setCPUThrottlingRate',{rate:cpu});await cdp.send('Performance.enable');
 await page.goto(base,{waitUntil:'networkidle'});await page.evaluate(()=>document.fonts.ready);
 await page.waitForFunction(()=>document.documentElement.dataset.scrollEngine);
 for(const selector of ['.clock-card','#experiences','#culture-tech','#partners','#visit'])if(await page.locator(selector).count()){
  await page.locator(selector).scrollIntoViewIfNeeded();await page.waitForTimeout(400);
 }
 await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));await page.waitForTimeout(600);
 const before=await cdp.send('Performance.getMetrics');
 const run=await page.evaluate(async()=>{
  window.__long=[];const start=performance.now(),extent=document.documentElement.scrollHeight-innerHeight,frames=[];let last=start;
  await new Promise(resolve=>{function tick(now){frames.push(now-last);last=now;const p=Math.min(1,(now-start)/12000);scrollTo({top:extent*(p<.5?p*2:(1-p)*2),behavior:'instant'});if(p<1)requestAnimationFrame(tick);else resolve();}requestAnimationFrame(tick);});
  return{frames:frames.slice(1),long:window.__long,extent,engine:document.documentElement.dataset.scrollEngine};
 });
 const after=await cdp.send('Performance.getMetrics'),metric=key=>(after.metrics.find(e=>e.name===key).value-before.metrics.find(e=>e.name===key).value)*1000;
 const frames=run.frames.sort((a,b)=>a-b),result={label,baseline,conditions:{browser:'Headless Chromium',width:390,height:844,dpr,cpuSlowdown:cpu,durationMs:12000,motion:'on',traversal:'Full page down and back; assets warmed; local network'},engine:run.engine,scrollExtent:run.extent,frameCount:frames.length,p50:frames[Math.floor(frames.length*.5)],p95:frames[Math.floor(frames.length*.95)],framesOver34ms:frames.filter(n=>n>34).length,longTasks:run.long.length,longTaskMs:run.long.reduce((a,b)=>a+b,0),scriptMs:metric('ScriptDuration'),styleMs:metric('RecalcStyleDuration'),layoutMs:metric('LayoutDuration'),taskMs:metric('TaskDuration'),errors};
 await writeFile(out+'/'+label+'.json',JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
 if(errors.length)process.exitCode=1;
}finally{await browser.close();}
