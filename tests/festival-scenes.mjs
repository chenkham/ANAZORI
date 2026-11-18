import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const temp=await mkdtemp(join(tmpdir(),'anazori-scenes-'));
const env={...process.env,ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'secret'),ANAZORI_TEST_MODE:'1'};
const base='http://127.0.0.1:8116',out='.local/festival-scenes';
const server=spawn('php',['-S','127.0.0.1:8116','-t','src','scripts/router.php'],{env,windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch();let checks=0;const errors=[],scans=[];
const ok=message=>{checks++;console.log('PASS '+message);};
const php=code=>execFileSync('php',['-r',`require 'includes/cms.php';${code}`],{env,encoding:'utf8'});
const settings=values=>php(`$site=cms_settings();$updates=json_decode('${JSON.stringify(values)}',true);foreach($updates as $key=>$value)$site[$key]=$value;cms_db()->prepare("UPDATE cms_settings SET value=? WHERE setting_key='site'")->execute([json_encode($site)]);`);
try {
 await mkdir(out,{recursive:true});
 for(let i=0;i<60;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 const context=await browser.newContext({viewport:{width:1440,height:960}});
 await context.addInitScript(()=>{window.__gl=0;const get=HTMLCanvasElement.prototype.getContext;HTMLCanvasElement.prototype.getContext=function(type,...args){if(String(type).startsWith('webgl'))window.__gl++;return get.call(this,type,...args);};});
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base,{waitUntil:'networkidle'});await page.evaluate(()=>document.fonts.ready);
 assert.equal(await page.locator('.programme-link').count(),7);
 assert.equal(await page.locator('.world-atlas,.partner-logo-card,.hero-particles').count(),0);
 await page.locator('#experiences').scrollIntoViewIfNeeded();
 const slugs=await page.locator('[data-programme-select]').evaluateAll(links=>links.map(link=>link.dataset.programmeSelect));
 for(const slug of slugs){await page.locator(`[data-programme-select="${slug}"]`).focus();assert.equal(await page.locator(`[data-programme-pane="${slug}"]`).isVisible(),true);assert.equal(await page.locator('.programme-pane:visible').count(),1);}
 await page.locator('[data-programme-select="goc"]').focus();
 await page.locator('[data-discovery="cable"]').click();assert.equal(await page.locator('.programme-theatre').evaluate(e=>e.classList.contains('is-powered')),true);
 assert.equal(await page.evaluate(()=>window.__gl),0);
 ok('Seven real event links, keyboard artwork previews, crew reaction and zero WebGL contexts.');
 await page.locator('#experiences').screenshot({path:out+'/programme-desktop.png'});
 await page.locator('#about').screenshot({path:out+'/intro-desktop.png'});
 await page.locator('#partners').screenshot({path:out+'/sponsors-desktop.png'});
 await page.locator('[data-programme-select="joystick"]').focus();
 await page.locator('[data-programme-pane="joystick"] .gaming-character').evaluateAll(async images=>{await Promise.all(images.map(img=>img.decode()));});
 assert.deepEqual(await page.locator('[data-programme-pane="joystick"] .gaming-character').evaluateAll(images=>images.map(img=>new URL(img.src).pathname)),['/assets/2026/characters/mlbb-gusion.webp']);
 assert.equal(await page.locator('[data-programme-pane="joystick"] .character-gengar').count(),0);
 await page.locator('#experiences').screenshot({path:out+'/joystick-desktop.png'});
 const mobileContext=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,deviceScaleFactor:1});
 const mobile=await mobileContext.newPage();mobile.on('pageerror',e=>errors.push(e.message));
 const requests=[];mobile.on('request',request=>requests.push(request.url()));
 await mobile.goto(base,{waitUntil:'networkidle'});
 await mobile.locator('.programme-theatre').scrollIntoViewIfNeeded();
 assert.equal(await mobile.locator('.programme-index').isVisible(),false);
 assert.equal(await mobile.getByRole('region',{name:'Festival events'}).isVisible(),true);
 assert.equal(requests.some(url=>/mlbb-gusion|bgmi-royal-aurum/.test(url)),false,'Gaming art stays deferred until Joystick is selected');
 const cdp=await mobileContext.newCDPSession(mobile);
 const touchSwipe=async(dx,dy=0)=>{
  const box=await mobile.locator('.programme-theatre').boundingBox();
  const start={x:box.x+box.width*(dx<0?.8:.2),y:box.y+110};
  await cdp.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[start]});
  for(let i=1;i<=6;i++){await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:start.x+dx*i/6,y:start.y+dy*i/6}]});await mobile.waitForTimeout(18);}
  await cdp.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
 };
 await touchSwipe(-160);assert.equal(await mobile.locator('[data-programme-pane="prativa"]').isVisible(),true);
 await touchSwipe(160);assert.equal(await mobile.locator('[data-programme-pane="goc"]').isVisible(),true);
 await mobile.waitForTimeout(310);
 await mobile.getByRole('button',{name:'Previous event',exact:true}).click();assert.match(await mobile.locator('[data-programme-count]').innerText(),/^7 \/ 7$/);
 await mobile.getByRole('button',{name:'Next event',exact:true}).click();assert.match(await mobile.locator('[data-programme-count]').innerText(),/^1 \/ 7$/);
 for(const [index,slug] of slugs.entries()){
  assert.equal(await mobile.locator('.programme-pane:visible').getAttribute('data-programme-pane'),slug);
  assert.equal(await mobile.locator('.programme-pane:visible .theatre-caption a').getAttribute('href'),'/event.php?name='+slug);
  assert.equal(await mobile.locator('[data-programme-count]').innerText(),`${index+1} / 7`);
  if(slug==='joystick'){
   await mobile.locator('.gaming-character').evaluateAll(async images=>{await Promise.all(images.map(img=>img.decode()));});
   await mobile.locator('#experiences').screenshot({path:out+'/joystick-mobile.png'});
  }
  await mobile.getByRole('button',{name:'Next event',exact:true}).click();
 }
 await mobile.getByRole('region',{name:'Festival events'}).focus();await mobile.keyboard.press('ArrowRight');assert.equal(await mobile.locator('[data-programme-pane="prativa"]').isVisible(),true);
 await mobile.locator('.programme-theatre').scrollIntoViewIfNeeded();
 const beforeScroll=await mobile.evaluate(()=>scrollY);await touchSwipe(0,-170);await mobile.waitForTimeout(180);
 assert((await mobile.evaluate(()=>scrollY))>beforeScroll+50,'Vertical touch still scrolls the document');
 assert.equal(await mobile.locator('[data-programme-pane="prativa"]').isVisible(),true,'Vertical gestures do not change events');
 assert.equal(new URL(mobile.url()).pathname,'/','Swiping does not accidentally follow the event link');
 await mobile.setViewportSize({width:1100,height:900});assert.equal(await mobile.locator('.programme-index').isVisible(),true);assert.equal(await mobile.locator('.programme-swipe-controls').isVisible(),false);assert.equal(await mobile.locator('[data-programme-pane="prativa"]').isVisible(),true);
 await mobileContext.close();
 ok('Mobile Legends artwork loads on demand; real touch swipes, arrows, wrapping and keyboard navigation preserve vertical scrolling and desktop previews.');
 for(const width of [320,390,768,1440]){
  await page.setViewportSize({width,height:900});
  for(const route of ['/','/gallery.php','/events.php','/teams.php','/account.php']){
   await page.goto(base+route,{waitUntil:'networkidle'});
   const overflow=await page.evaluate(()=>({width:innerWidth,extent:document.documentElement.scrollWidth,items:[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().right>innerWidth+1).slice(0,8).map(e=>({tag:e.tagName,cls:e.className,right:e.getBoundingClientRect().right}))}));
   assert(overflow.extent<=width,`${route} ${JSON.stringify(overflow)}`);
   // Decode lazy photos before checking them; navigating can cancel a previous lazy request.
   await page.locator('img[src]').evaluateAll(images=>Promise.all(images.map(img=>{img.loading='eager';return img.decode();})));
   assert.deepEqual(await page.evaluate(()=>[...document.images].filter(img=>img.getAttribute('src')&&img.complete&&img.naturalWidth===0).map(img=>img.src)),[]);
   if(width===390&&route==='/'){await page.locator('#experiences').screenshot({path:out+'/programme-mobile.png'});await page.locator('#partners').screenshot({path:out+'/sponsors-mobile.png'});await page.locator('#about').screenshot({path:out+'/intro-mobile.png'});}
   if(route==='/gallery.php'&&(width===390||width===1440)){assert.equal(await page.locator('.filter-toolbar').count(),0);await page.locator('.gallery-item').first().scrollIntoViewIfNeeded();await page.screenshot({path:out+`/gallery-${width}.png`});}
  }
 }
 ok('Five routes fit 320, 390, 768 and 1440px without overflow or broken source images.');
 await page.setViewportSize({width:1440,height:960});await page.goto(base);
 await page.locator('[data-passport-open]').click();await page.locator('[data-passport-start]').click();await page.keyboard.press('Escape');
 for(const slug of slugs)await page.goto(base+'/event.php?name='+slug);
 await page.goto(base+'/teams.php');await page.goto(base+'/gallery.php');
 await page.locator('[data-discovery="guardian"]').click();await page.locator('.gallery-item').first().click();await page.keyboard.press('ArrowRight');assert.match(await page.locator('#lightbox-count').innerText(),/^02/);await page.keyboard.press('Escape');
 await page.goto(base);await page.locator('#about').scrollIntoViewIfNeeded();await page.locator('[data-discovery="door"]').click();await page.locator('[data-discovery="cable"]').click();await page.locator('#visit').scrollIntoViewIfNeeded();await page.locator('[data-discovery="leaf"]').click();
 await page.locator('[data-passport-open]').click();assert.equal(await page.locator('[data-passport-score]').innerText(),'100');assert.equal(await page.locator('[data-passport-runes]').innerText(),'4 / 4');
 const download=page.waitForEvent('download');await page.locator('[data-passport-download]').click();assert.equal((await download).suggestedFilename(),'anazori-festival-postcard.svg');
 await page.locator('#festival-passport').screenshot({path:out+'/passport-complete.png'});
 scans.push({route:'passport',violations:(await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze()).violations});
 await page.locator('.passport-checklist a[href="/#about"]').click();assert.equal(await page.locator('#festival-passport').evaluate(e=>e.open),false);
 await page.evaluate(()=>{
  const season=document.querySelector('#festival-passport').dataset.passportSeason;
  localStorage.setItem('anazori-passport-'+season,JSON.stringify({enabled:true,events:['goc'],actions:[]}));
  dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));
  dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
 });
 await page.locator('[data-passport-open]').click();assert.equal(await page.locator('[data-passport-event-count]').innerText(),'1 / 7');assert.equal(await page.locator('[data-passport-runes]').innerText(),'0 / 4');await page.keyboard.press('Escape');
 await page.locator('[data-passport-open]').click();await page.locator('[data-passport-reset]').click();assert.equal(await page.locator('.passport-start').isVisible(),true);await page.keyboard.press('Escape');
 ok('Passport completes once per action, survives navigation, downloads a keepsake, follows clues and resets.');
 await page.locator('.sponsor-installation').scrollIntoViewIfNeeded();await page.waitForFunction(()=>document.querySelector('.sponsor-installation').classList.contains('scene-running'));
 await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));await page.waitForFunction(()=>document.querySelector('.sponsor-installation').classList.contains('scene-dormant'));
 await page.emulateMedia({reducedMotion:'reduce'});await page.locator('#experiences').scrollIntoViewIfNeeded();await page.locator('[data-discovery="cable"]').click();assert.equal(await page.locator('.scene-running').count(),0);assert.equal(await page.locator('.scene-reacting').count(),0);
 await page.emulateMedia({reducedMotion:'no-preference'});
 const noJS=await browser.newPage({javaScriptEnabled:false,viewport:{width:390,height:844}});await noJS.goto(base);assert.equal(await noJS.locator('.programme-link:visible').count(),7);assert.equal(await noJS.locator('.passport-invitation').isVisible(),false);await noJS.close();
 const blocked=await browser.newPage();await blocked.addInitScript(()=>{Object.defineProperty(window,'localStorage',{get(){throw new Error('Blocked');}});});await blocked.goto(base);await blocked.locator('[data-passport-open]').click();await blocked.locator('[data-passport-start]').click();assert.match(await blocked.locator('.passport-note').innerText(),/unavailable/);await blocked.close();
 ok('Offscreen/reduced-motion suspension, no-JavaScript navigation and blocked-storage fallback.');
 php(`$fields=['image'=>'/assets/logo.png','tier'=>'Festival partner','description'=>'Test','link'=>'https://example.com'];cms_db()->prepare("INSERT INTO cms_content(type,slug,title,data,status,sort_order,created_by,updated_at) VALUES('sponsor','qa-partner','QA Partner',?,'PUBLISHED',0,0,?)")->execute([json_encode($fields),gmdate('c')]);`);
 await page.goto(base);assert.equal(await page.locator('a.sponsor-mark').count(),1);assert.equal(await page.locator('.partner-preview-note').count(),0);
 settings({show_characters:'0',show_passport:'0',scene_motion:'0'});await page.reload();assert.equal(await page.locator('.festival-character').count(),0);assert.equal(await page.locator('#festival-passport').count(),0);assert.equal(await page.locator('.programme-link').count(),7);assert.equal(await page.locator('.scene-running').count(),0);
 settings({show_characters:'1',show_passport:'1',scene_motion:'1'});
 ok('Real CMS sponsors use the folded poster; Studio switches disable characters, scenes and passport independently.');
 for(const route of ['/','/gallery.php','/events.php']){await page.goto(base+route,{waitUntil:'networkidle'});scans.push({route,violations:(await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze()).violations});}
 await writeFile(out+'/accessibility.json',JSON.stringify(scans,null,2));
 assert.deepEqual(scans.flatMap(scan=>scan.violations.map(v=>({route:scan.route,id:v.id,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))}))),[]);
 assert.deepEqual(errors,[]);ok('Automated WCAG checks and runtime error checks pass.');
 console.log(`${checks} scene check groups passed.`);
}finally{await browser.close();if(server.exitCode===null){const exited=new Promise(resolve=>server.once('exit',resolve));server.kill();await exited;}await rm(temp,{recursive:true,force:true});}
