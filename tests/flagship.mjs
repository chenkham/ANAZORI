import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import {spawn} from 'node:child_process';
import {mkdtemp,rm,writeFile,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const temp=await mkdtemp(join(tmpdir(),'anazori-flagship-'));
const base='http://127.0.0.1:8098';
const server=spawn('php',['-S','127.0.0.1:8098','-t','src','scripts/router.php'],{env:{...process.env,ANAZORI_DB_PATH:join(temp,'qa.sqlite')},windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch();let passed=0;const ok=s=>{console.log('PASS '+s);passed++;};
const errors=[],accessibility=[];
try {
 for(let i=0;i<40;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const context=await browser.newContext({viewport:{width:1440,height:1000}});const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('#hero-film').currentTime>0);
 await page.locator('.site-footer .motion-toggle').evaluate(e=>e.click());assert.equal(await page.locator('#hero-film').evaluate(v=>v.paused),true);
 assert.equal(await page.locator('.site-footer .motion-toggle').getAttribute('aria-pressed'),'true');
 await page.locator('.site-footer .motion-toggle').evaluate(e=>e.click());await page.waitForFunction(()=>!document.querySelector('#hero-film').paused);
 assert.equal(await page.locator('#sound-toggle').count(),0);assert.equal(await page.locator('#ambient-audio').evaluate(v=>v.loop),false);
 await page.locator('#about').evaluate(e=>window.scrollTo({top:e.offsetTop+150,behavior:'instant'}));await page.waitForFunction(()=>document.querySelector('#connection-sculpture').classList.contains('sculpture-ready'));await page.waitForFunction(()=>document.querySelector('#hero-film').paused);
 ok('Video plays, motion controls, one-shot audio configuration and off-screen video pausing work.');
 await context.addInitScript(()=>localStorage.setItem('anazori-motion','paused')); 
 for(const width of [360,390,768,1024,1440]){
  await page.setViewportSize({width,height:900});
  for(const route of ['/','/events.php','/event.php?name=goc','/gallery.php','/teams.php']){
   await page.goto(base+route,{waitUntil:'networkidle'});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${width} ${route} overflow`);
   assert.deepEqual(await page.evaluate(()=>[...document.images].filter(i=>i.getAttribute('src')&&i.complete&&i.naturalWidth===0).map(i=>i.src)),[]);
  }
 }
 ok('Five public routes fit 360, 390, 768, 1024, and 1440 pixels without overflow or broken loaded images.');
 await page.setViewportSize({width:390,height:844});await page.goto(base);await page.locator('.menu-button').click();await page.locator('#mobile-menu').waitFor({state:'visible'});await page.keyboard.press('Escape');assert.equal(await page.locator('.menu-button').getAttribute('aria-expanded'),'false');
 await page.locator('.menu-button').click();await page.locator('#mobile-menu a[href="/events.php"]').click();await page.waitForURL('**/events.php');
 assert.equal(await page.locator('.filter-toolbar,#event-search').count(),0);assert.equal(await page.locator('.event-card:visible').count(),7);
 await page.locator('.event-card-link').first().click();await page.locator('[data-interest]').click();await page.locator('#interest-name').fill('Flagship Browser QA');await page.locator('#interest-email').fill('flagship-qa@example.com');await page.locator('#interest-college').fill('Isolated browser test');await page.locator('[name="consent"]').check();await page.locator('#interest-form [type="submit"]').click();await page.locator('#interest-success').waitFor({state:'visible'});assert.match(await page.locator('#interest-reference').textContent(),/^AZ26-/);await page.locator('.dialog-done').click();
 ok('Mobile menu, Escape, complete event catalogue, and interest submission work against an isolated database.');
 await page.goto(base+'/gallery.php');await page.locator('.gallery-item').first().click();const first=await page.locator('#lightbox-count').textContent();await page.keyboard.press('ArrowRight');assert.notEqual(await page.locator('#lightbox-count').textContent(),first);await page.keyboard.press('Escape');assert.equal(await page.locator('#gallery-dialog').evaluate(d=>d.open),false);
 ok('Gallery opens, advances with keyboard arrows, and closes with Escape.');
 for(const route of ['/','/events.php','/event.php?name=goc','/gallery.php','/teams.php']){await page.goto(base+route,{waitUntil:'networkidle'});await page.evaluate(()=>{document.getAnimations().forEach(a=>{if(a.effect.getTiming().iterations!==Infinity)a.finish();});});const scan=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();accessibility.push({route,violations:scan.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))}))});}
 const reduced=await browser.newPage({reducedMotion:'reduce'});await reduced.goto(base,{waitUntil:'networkidle'});assert.equal(await reduced.locator('#hero-film').getAttribute('src'),null);assert.equal(await reduced.locator('.site-footer .motion-toggle').getAttribute('aria-pressed'),'true');await reduced.close();
 const noGL=await browser.newPage();await noGL.addInitScript(()=>{window.__webGLProbes=0;const get=HTMLCanvasElement.prototype.getContext;HTMLCanvasElement.prototype.getContext=function(type,...args){if(String(type).startsWith('webgl')){window.__webGLProbes++;return null;}return get.call(this,type,...args);};});await noGL.goto(base);await noGL.locator('#about').scrollIntoViewIfNeeded();await noGL.waitForTimeout(300);assert.equal(await noGL.evaluate(()=>window.__webGLProbes),0,'Video/static intro must not allocate unnecessary WebGL contexts');assert.equal(await noGL.locator('#about h2').isVisible(),true);assert.equal(await noGL.locator('#connection-sculpture').evaluate(e=>e.classList.contains('sculpture-ready')),true);await noGL.close();
 const noJS=await browser.newPage({javaScriptEnabled:false});await noJS.goto(base);await noJS.getByRole('link',{name:'Explore the experiences',exact:true}).waitFor({state:'visible'});assert.equal(await noJS.locator('#hero-title').isVisible(),true);await noJS.close();
 ok('Reduced-motion, missing WebGL, and JavaScript-disabled fallbacks keep the site usable.');
 assert.deepEqual(errors,[]);ok('No uncaught browser errors.');
 await mkdir('.local/flagship',{recursive:true});await writeFile('.local/flagship/accessibility.json',JSON.stringify(accessibility,null,2));
 assert.deepEqual(accessibility.flatMap(p=>p.violations.map(v=>({route:p.route,...v}))),[],'Accessibility findings');ok('WCAG A/AA automated checks pass across five public routes.');
 console.log(passed+' browser check groups passed.');
}finally{await browser.close();if(server.exitCode===null){const exit=new Promise(r=>server.once('exit',r));server.kill();await exit;}await rm(temp,{recursive:true,force:true});}
