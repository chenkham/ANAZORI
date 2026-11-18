import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,rm,readFile} from 'node:fs/promises';
import {join} from 'node:path';import {tmpdir} from 'node:os';
const temp=await mkdtemp(join(tmpdir(),'anazori-cast-'));
const server=spawn('php',['-S','127.0.0.1:8122','-t','src','scripts/router.php'],{env:{...process.env,ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'secret'),ANAZORI_TEST_MODE:'1'},windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch();const base='http://127.0.0.1:8122',out='.local/content-cast';const errors=[];let checks=0;
const ok=m=>{checks++;console.log('PASS '+m)};
try{
 await mkdir(out,{recursive:true});for(let i=0;i<60;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const context=await browser.newContext({viewport:{width:390,height:844},hasTouch:true});
 await context.addInitScript(()=>{const connection=new EventTarget();connection.saveData=false;Object.defineProperty(navigator,'connection',{value:connection,configurable:true});window.__connection=connection;});
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));const requests=[];page.on('request',r=>requests.push(r.url()));
 await page.goto(base,{waitUntil:'networkidle'});await page.evaluate(()=>document.fonts.ready);
 assert.equal(requests.some(u=>/-motion\.svg/.test(u)),false,'Hidden and offscreen performances do not download');
 assert.equal(await page.locator('.theatre-photo,.power-companion').count(),0);
 assert.equal(await page.locator('[data-programme-pane=goc] [data-performance=roz-code]').count(),1);
 assert.equal(await page.locator('[data-programme-pane="paper-presentation"] [data-performance=baymax-help]').count(),1);
 assert.equal(await page.locator('.record-musician[data-performance=coco-guitar]').count(),1);
 assert.equal(await page.locator('[data-programme-pane=workshops] [data-performance=walle-build]').count(),1);
 assert.equal(await page.locator('.programme-index').isVisible(),false);
 await page.locator('#experiences').scrollIntoViewIfNeeded();await page.waitForFunction(()=>document.querySelector('[data-programme-pane=goc] .content-performance').classList.contains('is-animated'));
 assert.equal(requests.some(u=>/walle-build-motion\.svg/.test(u)),false);
 assert.equal(await page.locator('[data-programme-pane=goc] img').evaluate(e=>e.currentSrc.endsWith('.svg?v=2026.43')),true);
 for(let i=0;i<4;i++)await page.locator('[data-programme-step="1"]').click();
 await page.waitForFunction(()=>document.querySelector('[data-programme-pane=workshops] .content-performance').classList.contains('is-animated'));
 assert.equal(await page.locator('[data-programme-pane=goc] .content-performance').evaluate(e=>e.classList.contains('is-animated')),false);
 await page.screenshot({path:out+'/workshops-mobile.png'});ok('Correct content mapping, transparent SVG artwork, lazy selection and mobile event navigation.');
 await page.locator('#culture-tech').scrollIntoViewIfNeeded();await page.waitForFunction(()=>document.querySelector('.record-musician').classList.contains('is-animated'));
 const bounds=await page.locator('.record-musician').boundingBox();assert(bounds.width<=160&&bounds.height<=160,'Coco stays beside the record');
 await page.locator('#culture-tech').screenshot({path:out+'/vinyl-mobile.png'});
 await page.emulateMedia({reducedMotion:'reduce'});await page.waitForFunction(()=>!document.querySelector('.is-animated'));await page.emulateMedia({reducedMotion:'no-preference'});
 await page.evaluate(()=>{window.__connection.saveData=true;window.__connection.dispatchEvent(new Event('change'));});assert.equal(await page.locator('.is-animated').count(),0);
 await page.evaluate(()=>{window.__connection.saveData=false;window.__connection.dispatchEvent(new Event('change'));});ok('Coco remains small; reduced motion and Save-Data retain SVG stills.');
 await page.locator('.signal-companion').scrollIntoViewIfNeeded();await page.waitForFunction(()=>document.querySelector('[data-performance=stitch-light]').classList.contains('is-animated'));await page.locator('#partners').screenshot({path:out+'/partners-mobile.png'});
 await page.locator('#visit').scrollIntoViewIfNeeded();await page.locator('.faq details summary').first().click();await page.waitForFunction(()=>document.querySelector('.faq-helper .content-performance').classList.contains('is-animated'));await page.locator('#visit').screenshot({path:out+'/visit-mobile.png'});
 await page.locator('[data-passport-open]').click();await page.locator('[data-passport-start]').click();await page.waitForFunction(()=>document.querySelector('[data-performance=mario-discovery]').classList.contains('is-animated'));
 await page.locator('#festival-passport .dialog-close').click();assert.equal(await page.locator('[data-performance=mario-discovery]').evaluate(e=>e.classList.contains('is-animated')),false);
 ok('Sponsor, FAQ and passport actions activate bounded SVG scenes and stop on dialog close.');
 for(const width of [320,390,768,1440]){
  await page.setViewportSize({width,height:900});
  for(const selector of ['#experiences','#culture-tech','#partners','#visit']){await page.locator(selector).scrollIntoViewIfNeeded();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${selector} at ${width}`);}
  if(width===1440){await page.locator('#experiences').scrollIntoViewIfNeeded();await page.locator('[data-programme-select=goc]').focus();await page.locator('#experiences').screenshot({path:out+'/goc-desktop.png'});await page.locator('#culture-tech').screenshot({path:out+'/vinyl-desktop.png'});}
 }
 await page.goto(base+'/events.php',{waitUntil:'domcontentloaded'});assert.equal(await page.locator('.event-guide .character-pikachu').count(),1);
 assert.equal(await page.locator('.event-guide .content-performance').count(),0);
 assert.equal(await page.locator('[data-performance]').evaluateAll(nodes=>nodes.every(n=>n.querySelector('img').dataset.performanceSrc.includes('.svg?'))),true);
 const manifest=JSON.parse(await readFile('src/assets/2026/vector/sources.json','utf8'));
 for(const item of manifest){const svg=await readFile('src/assets/2026/vector/'+item.id+'-motion.svg','utf8');assert(!/<image|<script|data:image/i.test(svg));assert(svg.includes('<animate'));}
 const compressed=await fetch(base+'/assets/2026/vector/coco-guitar-motion.svg',{headers:{'Accept-Encoding':'gzip'}});
 assert.equal(compressed.headers.get('content-encoding'),'gzip');
 const cached=await fetch(base+'/assets/2026/vector/coco-guitar-motion.svg',{headers:{'Accept-Encoding':'gzip','If-None-Match':compressed.headers.get('etag')}});assert.equal(cached.status,304);
 const plain=await fetch(base+'/assets/2026/vector/coco-guitar-motion.svg',{headers:{'Accept-Encoding':'gzip;q=0, identity'}});assert.equal(plain.headers.get('content-encoding'),null);
 const counts={};
 const identities={'minion':'stuart','doraemon-run':'doraemon','pikachu-run':'pikachu','coco-guitar':'coco','baymax-help':'baymax','walle-build':'walle','stitch-light':'stitch','totoro-visit':'totoro','roz-code':'roz','mario-discovery':'mario','deadpool-photo':'deadpool'};
 for(const route of ['/','/events.php','/gallery.php','/teams.php','/event/joystick']) {
  const html=await(await fetch(base+route)).text();
  const matches=[...html.matchAll(/class="festival-character (?:vector-character )?character-([a-z-]+)/g),...html.matchAll(/data-sprite-identity="([a-z-]+)"/g),...html.matchAll(/data-performance="([a-z-]+)"/g)];
  for(const match of matches){if(match[1]==='festival-snow')continue;const identity=identities[match[1]]||match[1];counts[identity]=(counts[identity]||0)+1;}
 }
 assert(Object.values(counts).every(n=>n<=2),JSON.stringify(counts));assert.equal(counts.coco,1);assert.equal(counts.stuart,2);assert.equal(counts.pikachu,2);assert.equal(counts.baymax,2);
 assert.deepEqual(errors,[]);ok('Four widths fit; Events uses static Pikachu; SVG compression/cache work; each character appears at most twice.');
 console.log(`${checks} content-cast check groups passed.`);
}finally{await browser.close();if(server.exitCode===null){const ended=new Promise(r=>server.once('exit',r));server.kill();await ended;}await rm(temp,{recursive:true,force:true});}
