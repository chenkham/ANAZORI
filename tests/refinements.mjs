import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const temp=await mkdtemp(join(tmpdir(),'anazori-refinements-'));
const env={...process.env,ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'secret'),ANAZORI_TEST_MODE:'1'};
const base='http://127.0.0.1:8115';
const fixture=JSON.parse(execFileSync('php',['-r',`require 'includes/cms.php';$db=cms_db();$db->prepare("UPDATE users SET password_hash=?,must_change_password=0 WHERE role='SUPERADMIN'")->execute([password_hash('Refinement-QA-2026!',PASSWORD_DEFAULT)]);echo json_encode(['master'=>ANAZORI_SUPER_EMAIL]);`],{env,encoding:'utf8'}));
const server=spawn('php',['-S','127.0.0.1:8115','-t','src','scripts/router.php'],{env,windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch();const errors=[],scans=[];let passed=0;
const ok=message=>{passed++;console.log('PASS '+message);};
const out='.local/refinements';await mkdir(out,{recursive:true});
try{
 for(let i=0;i<70;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const context=await browser.newContext({viewport:{width:1440,height:960}});
 const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
 await page.goto(base);await page.evaluate(()=>document.fonts.ready);
 assert.match(await page.locator('#hero-title').evaluate(e=>getComputedStyle(e).fontFamily),/Satoshi/);
 assert.equal(await page.evaluate(()=>document.fonts.check('700 32px "Satoshi"')),true);
 assert.equal(await page.locator('.ticker').innerText(),'');
 assert.equal(await page.locator('.ticker').getAttribute('aria-hidden'),'true');
 assert.equal(await page.locator('.energy-packet').count(),0);
 assert.equal(await page.locator('.chase-fireball').count(),1);
 assert.equal(await page.locator('.character-chase').evaluate(e=>getComputedStyle(e).getPropertyValue('--chase-cycle').trim()),'8s');
 assert.equal(await page.locator('#sound-toggle,.floating-sound').count(),0);
 await page.screenshot({path:out+'/home-desktop.png'});
 await page.locator('#about').scrollIntoViewIfNeeded();
 const ratio=await page.locator('.video-stage').evaluate(e=>e.getBoundingClientRect().width/e.getBoundingClientRect().height);
 assert(Math.abs(ratio-16/9)<.02,'Festival film has a true 16:9 frame');
 assert.equal(await page.locator('#intro-video').count(),1);
 assert.equal(await page.locator('#hero-film').count(),0);
 await page.locator('#about').screenshot({path:out+'/about-desktop.png'});
 // Exercise the existing CMS film setting as well as its empty state.
 execFileSync('php',['-r',`require 'includes/cms.php';$site=cms_settings();$site['intro_video']=setting('hero_video');$site['intro_video_autoplay']='0';$db=cms_db();$db->prepare("UPDATE cms_settings SET value=? WHERE setting_key='site'")->execute([json_encode($site)]);`],{env,encoding:'utf8'});
 await page.reload();assert.equal(await page.locator('#intro-video').count(),1);assert.equal(await page.locator('#intro-video').evaluate(e=>e.controls),true);
 assert(Math.abs(await page.locator('.video-stage').evaluate(e=>e.getBoundingClientRect().width/e.getBoundingClientRect().height)-16/9)<.02,'Published film retains 16:9');
 execFileSync('php',['-r',`require 'includes/cms.php';$site=cms_settings();$site['intro_video']='';cms_db()->prepare("UPDATE cms_settings SET value=? WHERE setting_key='site'")->execute([json_encode($site)]);`],{env,encoding:'utf8'});
 await page.reload();
 assert.equal(await page.locator('.film-placeholder-label').isVisible(),true);
 await page.locator('#partners').scrollIntoViewIfNeeded();await page.waitForTimeout(200);
 assert.equal(await page.locator('.sponsor-installation').count(),1);
 assert.equal(await page.locator('.sponsor-light>span').first().evaluate(e=>getComputedStyle(e).animationPlayState),'running');
 await page.locator('#partners').screenshot({path:out+'/sponsors-desktop.png'});
 await page.locator('#hero-title').scrollIntoViewIfNeeded();await page.waitForTimeout(150);
 assert.equal(await page.locator('.sponsor-light>span').first().evaluate(e=>getComputedStyle(e).animationPlayState),'paused');
 ok('Monument headings, supplied character chase, framed film placeholder and offscreen-paused sponsor motion.');
 for(const width of [320,390,768,1440]){
  await page.setViewportSize({width,height:900});
  for(const route of ['/','/events.php','/gallery.php','/teams.php','/login.php']){
   await page.goto(base+route);await page.evaluate(()=>document.fonts.ready);
   if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)){
    console.log('OVERFLOW',width,route,await page.evaluate(()=>({extent:document.documentElement.scrollWidth,elements:[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().right>innerWidth+1).map(e=>({tag:e.tagName,classes:e.className,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width})).slice(0,12)})));
    await page.screenshot({path:out+'/overflow.png',fullPage:true});
   }
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${width} ${route} overflow`);
   if(route==='/'){
    const fit=await page.locator('.hero-title-text').evaluate(e=>{const r=e.getBoundingClientRect();return r.left>=-1&&r.right<=innerWidth+1;});
    assert(fit,`${width} hero wordmark is fully visible`);
   }
  }
 }
 ok('Public routes and Studio login fit four widths, including 320px phones.');
 await page.setViewportSize({width:1440,height:960});
 for(const [route,name] of [['/events.php','events'],['/teams.php','people'],['/gallery.php','gallery'],['/login.php','login']]){
  await page.goto(base+route);await page.evaluate(()=>document.fonts.ready);
  if(name==='events'){
   assert.equal(await page.locator('.filter-toolbar,#event-search').count(),0);
   assert.equal(await page.locator('.event-card:visible').count(),7);
   assert.equal(await page.locator('.event-card .arcane-frame').count(),7);
   assert.match(await page.locator('.event-card h3').first().evaluate(e=>getComputedStyle(e).fontFamily),/Satoshi/);
   await page.locator('.event-card').first().scrollIntoViewIfNeeded();
  }
  if(name==='people'){assert.equal(await page.locator('.person-card .arcane-frame').count(),await page.locator('.person-card').count());await page.locator('.person-card').first().scrollIntoViewIfNeeded();}
  if(name==='gallery'){
   assert.doesNotMatch(await page.locator('.gallery-grid').innerText(),/2024|v14\.0/i);
   for(const caption of await page.locator('.gallery-item').evaluateAll(items=>items.map(e=>e.dataset.caption)))assert.doesNotMatch(caption,/2024|v14\.0/i);
   await page.locator('.gallery-item').last().click();assert.doesNotMatch(await page.locator('#lightbox-caption').innerText(),/2024|v14\.0/i);await page.keyboard.press('Escape');
  }
  await page.screenshot({path:out+'/'+name+'-desktop.png'});
  const scan=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();scans.push({route,violations:scan.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)}))});
 }
 await page.locator('#login-user').fill(fixture.master);await page.locator('#login-pass').fill('Refinement-QA-2026!');await page.locator('[type=submit]').click();await page.waitForURL('**/admin.php');
 assert.equal(await page.locator('.studio-nav-group[open]').count(),1);
 const finance=page.locator('[data-group=finance]');await finance.locator('summary').focus();await page.keyboard.press('Enter');assert.equal(await finance.evaluate(e=>e.open),true);
 await page.keyboard.press('Space');assert.equal(await finance.locator('a').first().isVisible(),false);
 await page.goto(base+'/admin.php?section=settings');
 assert.equal(await page.locator('.settings-panel[open]').count(),0);
 const first=page.locator('.settings-panel').first();await first.locator('summary').click();assert.equal(await first.locator('form').isVisible(),true);await first.locator('summary').click();assert.equal(await first.locator('form').isVisible(),false);
 const jump=page.locator('.settings-jumps a').nth(2);await jump.click();const target=page.locator(await jump.getAttribute('href'));assert.equal(await target.evaluate(e=>e.open),true);
 await page.goto(base+'/admin.php?section=users');await page.locator('.staff-disclosure>summary').click();
 const permissions=page.locator('.permission-group').first();assert.equal(await permissions.evaluate(e=>e.open),false);await permissions.locator('summary').click();assert.equal(await permissions.locator('input').first().isVisible(),true);
 await page.getByRole('button',{name:'Event coordinator',exact:true}).click();assert.match(await permissions.locator('.disclosure-count').innerText(),/\d+ enabled/);
 await page.screenshot({path:out+'/studio-team-desktop.png'});
 for(const section of ['overview','settings','users','integrations']){
  await page.goto(base+'/admin.php?section='+section);
  // Scan both the closed summary state and the expanded editors.
  if(section!=='overview')await page.locator('details.studio-disclosure').evaluateAll(items=>items.forEach(e=>e.open=true));
  const scan=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();scans.push({route:'studio/'+section,violations:scan.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)}))});
 }
 await page.goto(base+'/admin.php');await page.screenshot({path:out+'/studio-desktop.png'});
 await page.setViewportSize({width:390,height:844});await page.goto(base+'/admin.php');await page.locator('.studio-menu-button').click();
 await page.locator('[data-group=finance]>summary').click();assert.equal(await page.locator('[data-group=finance] a').first().isVisible(),true);
 await page.keyboard.press('Escape');assert.equal(await page.locator('.studio-menu-button').evaluate(e=>e===document.activeElement),true);
 await page.screenshot({path:out+'/studio-mobile.png'});
 await context.clearCookies();await page.goto(base+'/login.php');await page.screenshot({path:out+'/login-mobile.png'});
 await page.goto(base);await page.locator('#about').screenshot({path:out+'/about-mobile.png'});await page.locator('#partners').screenshot({path:out+'/sponsors-mobile.png'});
 ok('Native keyboard accordions, settings jumps, permission presets and mobile Studio drawer work.');
 const soundContext=await browser.newContext();
 await soundContext.addInitScript(()=>{
  window.__soundPlays=0;window.__soundAttempts=0;window.__soundAllowed=false;
  const original=HTMLMediaElement.prototype.play;
  HTMLMediaElement.prototype.play=function(){if(this.id!=='ambient-audio')return original.call(this);window.__soundAttempts++;if(!window.__soundAllowed)return Promise.reject(new DOMException('Gesture required','NotAllowedError'));window.__soundPlays++;return Promise.resolve();};
 });
 const sound=await soundContext.newPage();await sound.goto(base);await sound.waitForFunction(()=>window.__soundAttempts===1);
 assert.equal(await sound.evaluate(()=>sessionStorage.getItem('anazori-entry-sound-played')),null);
 await sound.evaluate(()=>window.__soundAllowed=true);await sound.locator('#hero-title').click();await sound.waitForFunction(()=>window.__soundPlays===1);
 assert.equal(await sound.locator('#ambient-audio').evaluate(e=>e.loop),false);
 await sound.locator('#hero-title').click();assert.equal(await sound.evaluate(()=>window.__soundPlays),1);
 await sound.evaluate(()=>document.querySelector('#ambient-audio').dispatchEvent(new Event('ended')));await sound.locator('#hero-title').click();assert.equal(await sound.evaluate(()=>window.__soundPlays),1);
 await sound.reload();assert.equal(await sound.evaluate(()=>window.__soundAttempts),0);
 await sound.goto(base+'/events.php');assert.equal(await sound.locator('#ambient-audio').count(),0);
 await soundContext.close();
 execFileSync('php',['-r',`require 'includes/cms.php';$site=cms_settings();$site['sound_default']='0';cms_put_setting('site',json_encode($site));`],{env,encoding:'utf8'});
 const quiet=await browser.newPage();await quiet.goto(base);await quiet.locator('#hero-title').click();assert.equal(await quiet.locator('#ambient-audio').getAttribute('src'),null);await quiet.close();
 execFileSync('php',['-r',`require 'includes/cms.php';$site=cms_settings();$site['sound_default']='1';cms_put_setting('site',json_encode($site));`],{env,encoding:'utf8'});
 ok('Sound plays once after an allowed gesture; ending, repeat clicks and reloads never restart it.');
 const reduced=await browser.newPage({reducedMotion:'reduce'});await reduced.goto(base);await reduced.locator('#partners').scrollIntoViewIfNeeded();
 assert.equal(await reduced.locator('.sponsor-light>span').first().evaluate(e=>getComputedStyle(e).animationName),'none');assert.equal(await reduced.locator('.chase-runner-pikachu').evaluate(e=>e.getAnimations().length),0);await reduced.close();
 await writeFile(out+'/accessibility.json',JSON.stringify(scans,null,2));assert.deepEqual(scans.flatMap(s=>s.violations.map(v=>({route:s.route,...v}))),[]);assert.deepEqual(errors,[]);
 ok('Expanded Studio forms and public pages pass WCAG A/AA checks; reduced motion and runtime errors checked.');
 console.log(`PASS ${passed} refinement check groups. Screenshots: ${out}`);
}finally{await browser.close();server.kill();await new Promise(r=>setTimeout(r,350));await rm(temp,{recursive:true,force:true});}
