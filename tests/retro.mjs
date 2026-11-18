import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const temp=await mkdtemp(join(tmpdir(),'anazori-retro-'));
const env={...process.env,ANAZORI_DB_PATH:join(temp,'qa.sqlite')};
const base='http://127.0.0.1:8103';
const server=spawn('php',['-S','127.0.0.1:8103','-t','src','scripts/router.php'],{env,windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch();
const errors=[];
await mkdir('.local/retro',{recursive:true});
try {
  for(let i=0;i<50;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  const context=await browser.newContext({viewport:{width:1440,height:960}});
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base,{waitUntil:'networkidle'});
  assert.match(await page.locator('#hero-title').textContent(),/ANAZORI\s+V16\.0/);
  assert.equal(await page.getByText('Say hello',{exact:false}).count(),0);
  assert.equal(await page.locator('.event-card-body > .eyebrow').count(),0);
  assert.equal(await page.locator('.social-row').evaluate(e=>getComputedStyle(e).display),'flex');
  assert.equal(await page.locator('.desktop-nav a').first().evaluate(e=>Number(getComputedStyle(e).fontWeight)),700);
  await page.screenshot({path:'.local/retro/hero-desktop.png'});
  await page.locator('#culture-tech').scrollIntoViewIfNeeded();
  const initial=await page.locator('#culture-tech').evaluate(e=>getComputedStyle(e,':before').filter);
  await page.locator('#frequency-mix').focus();await page.keyboard.press('End');
  assert.equal(await page.locator('#frequency-status').textContent(),'Wired for tomorrow');
  await page.waitForFunction(before=>getComputedStyle(document.querySelector('#culture-tech'),':before').filter!==before,initial);
  await page.keyboard.press('Home');assert.equal(await page.locator('#frequency-status').textContent(),'Rooted in culture');
  await page.keyboard.press('ArrowRight');assert.equal(await page.locator('#frequency-mix').inputValue(),'1');
  await page.locator('#frequency-mix').evaluate(e=>{e.value='50';e.dispatchEvent(new Event('input',{bubbles:true}));});
  await page.locator('#culture-tech').screenshot({path:'.local/retro/culture-desktop.png'});
  await page.locator('#partners').scrollIntoViewIfNeeded();await page.waitForTimeout(850);
  await page.locator('#partners').screenshot({path:'.local/retro/sponsors-desktop.png'});
  await page.locator('.site-footer').screenshot({path:'.local/retro/footer-desktop.png'});
  assert.equal(await page.locator('.site-header').evaluate(e=>getComputedStyle(e).position),'absolute','Navigation stays at the beginning of the document');
  assert(await page.locator('.site-header').evaluate(e=>e.getBoundingClientRect().bottom<0),'Navigation scrolls away with the page');
  await page.goto(base+'/events.php',{waitUntil:'networkidle'});
  await page.locator('.event-grid').scrollIntoViewIfNeeded();await page.waitForTimeout(700);
  await page.screenshot({path:'.local/retro/events-desktop.png'});
  await page.locator('.event-card-link').first().focus();
  assert.notEqual(await page.locator('.event-card').first().evaluate(e=>getComputedStyle(e).outlineStyle),'none','Ticket frame exposes keyboard focus');
  for(const [route,name] of [['/gallery.php','gallery'],['/teams.php','people'],['/event.php?name=goc','event-detail']]){
    await page.goto(base+route,{waitUntil:'networkidle'});await page.screenshot({path:`.local/retro/${name}-desktop.png`,fullPage:true});
  }
  console.log('PASS Retro wordmarks, bold navigation, social row, sponsor grid and keyboard-operated frequency mixing.');
  for(const width of [360,390,768,1024,1440]){
    await page.setViewportSize({width,height:900});await page.goto(base,{waitUntil:'networkidle'});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${width} home overflow`);
    await page.goto(base+'/account.php?mode=signup',{waitUntil:'networkidle'});
    assert.equal(await page.locator('.site-footer').isVisible(),width>700);
    assert.equal(await page.locator('.floating-sound').count(),0);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${width} signup overflow`);
  }
  await page.setViewportSize({width:390,height:844});await page.goto(base);
  await page.waitForTimeout(1200);
  await page.screenshot({path:'.local/retro/hero-mobile.png'});
  await page.locator('#culture-tech').screenshot({path:'.local/retro/culture-mobile.png'});
  await page.locator('#partners').scrollIntoViewIfNeeded();await page.waitForTimeout(850);
  await page.locator('#partners').screenshot({path:'.local/retro/sponsors-mobile.png'});
  await page.goto(base+'/account.php?mode=signup');await page.screenshot({path:'.local/retro/signup-mobile.png'});
  await page.locator('#account-name').fill('Retro QA');await page.locator('#account-email').fill('retro@example.com');await page.locator('#account-password').fill('Retro-QA-Password-2026!');
  await page.getByRole('button',{name:/^Create account/}).click();
  await page.goto(base+'/dashboard.php');assert.equal(await page.locator('.site-footer').isVisible(),false);
  await page.screenshot({path:'.local/retro/dashboard-mobile.png'});
  console.log('PASS Responsive home and signup fit five widths; mobile signup and dashboard hide footer and sound controls.');
  await page.setViewportSize({width:800,height:375});await page.goto(base);await page.locator('.menu-button').click();
  const landscapeMenu=await page.locator('#mobile-menu').evaluate(e=>({top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom,height:e.clientHeight,content:e.scrollHeight}));
  assert(landscapeMenu.top>=100&&landscapeMenu.bottom<=375&&landscapeMenu.content>landscapeMenu.height,'Landscape menu fits and scrolls');
  await page.keyboard.press('Escape');assert.equal(await page.locator('.menu-button').evaluate(e=>e===document.activeElement),true);
  await page.setViewportSize({width:960,height:800});await page.locator('.menu-button').click();
  await page.setViewportSize({width:1024,height:800});assert.equal(await page.locator('#mobile-menu').isVisible(),false);
  assert.equal(await page.locator('.desktop-nav').isVisible(),true);
  console.log('PASS Stationary navigation, keyboard card focus, landscape menu and tablet-to-desktop menu transition.');
  execFileSync('php',['-r',"require 'includes/cms.php';cms_db()->exec('UPDATE users SET must_change_password=0');"],{env,stdio:'pipe'});
  await page.goto(base+'/login.php');await page.locator('#login-user').fill('chenkhamchowlu@gmail.com');await page.locator('#login-pass').fill('admin123');await page.locator('[type=submit]').click();await page.waitForURL('**/admin.php');
  await page.setViewportSize({width:1440,height:1000});await page.reload();
  assert.equal(await page.locator('.studio-nav-group').count(),4);
  assert.equal(await page.locator('a[href*="section=checkin"]').count(),0);
  assert.equal((await page.request.get(base+'/admin.php?section=checkin')).status(),403);
  await page.goto(base+'/admin.php');await page.screenshot({path:'.local/retro/studio-desktop.png'});
  for(const width of [360,390,768,1024,1440]){
    await page.setViewportSize({width,height:900});await page.goto(base+'/admin.php');
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${width} studio overflow`);
  }
  await page.setViewportSize({width:390,height:844});await page.reload();await page.screenshot({path:'.local/retro/studio-mobile.png'});
  console.log('PASS Studio tools are grouped, fit five widths, and the website scanner route is disabled.');
  const reduced=await browser.newPage({reducedMotion:'reduce'});await reduced.goto(base);
  assert.equal(await reduced.locator('.flash-wordmark').first().evaluate(e=>getComputedStyle(e).animationName),'none');
  await reduced.close();assert.deepEqual(errors,[]);
  console.log('PASS Reduced motion and no uncaught browser errors. Screenshots saved in .local/retro.');
} finally {
  await browser.close();if(server.exitCode===null){const exited=new Promise(r=>server.once('exit',r));server.kill();await exited;}
  await rm(temp,{recursive:true,force:true});
}
