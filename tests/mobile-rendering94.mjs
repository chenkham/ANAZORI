import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {PNG} from 'pngjs';

// Run the local preview first. This test only reads public pages and never
// submits forms or alters the site's database.
const base=process.argv[2]||'http://127.0.0.1:8000';
const out='.local/mobile94';await mkdir(out,{recursive:true});
const browser=await chromium.launch(),errors=[],checks=[];
const check=name=>{checks.push(name);console.log('PASS '+name);};
try {
 const context=await browser.newContext({viewport:{width:390,height:844},deviceScaleFactor:3,isMobile:true,hasTouch:true});
 await context.addInitScript(()=>{localStorage.setItem('anazori-motion','on');localStorage.setItem('anazori-sound','off');});
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base,{waitUntil:'networkidle'});
 await page.waitForFunction(()=>document.documentElement.dataset.scrollEngine);
 await page.evaluate(()=>document.fonts.ready);
 const initialHeight=await page.evaluate(()=>document.documentElement.scrollHeight);
 assert.equal(await page.evaluate(()=>document.documentElement.dataset.scrollEngine),'native');
 assert.equal(await page.locator('body').evaluate(e=>getComputedStyle(e).backgroundAttachment),'scroll');
 assert.notEqual(await page.locator('.festival-glass-background').evaluate(e=>getComputedStyle(e).transform),'none');
 check('Native scrolling uses the retained background layer.');
 const cdp=await context.newCDPSession(page);
 await cdp.send('Emulation.setCPUThrottlingRate',{rate:4});
 const swipe=async down=>{
  for(let n=0;n<7;n++){
   const start=down?700:150,end=down?150:700;
   await cdp.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[{x:195,y:start,id:1}]});
   for(let i=1;i<=7;i++){await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:195,y:start+(end-start)*i/7,id:1}]});await page.waitForTimeout(16);}
   await cdp.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
  }
 };
 await swipe(true);
 const touchPosition=await page.evaluate(()=>({y:scrollY,root:getComputedStyle(document.documentElement).overflow,body:getComputedStyle(document.body).overflow,loading:document.documentElement.className}));
 assert(touchPosition.y>1500,'Fast touch scrolling advances the page: '+JSON.stringify(touchPosition));
 await swipe(false);
 await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
 assert.equal(Math.round(await page.evaluate(()=>scrollY)),0);
 assert(Math.abs(await page.evaluate(()=>document.documentElement.scrollHeight)-initialHeight)<64,'Fast scrolling must not collapse or expand reserved sections.');
 check('Fast touch gestures and reverse scrolling remain responsive with motion enabled.');
 await cdp.send('Emulation.setCPUThrottlingRate',{rate:1});
 for(const selector of ['.pixel-workshop','#culture-tech']) {
  await page.locator(selector).scrollIntoViewIfNeeded();
  await page.waitForFunction(selector=>document.querySelector(selector).classList.contains('scene-running'),selector);
  const clocks=await page.locator(selector).evaluate(e=>e.getAnimations({subtree:true}).filter(a=>a.playState==='running').length);
  assert(clocks>0,selector+' keeps its existing animated clocks.');
 }
 await page.waitForFunction(()=>document.querySelector('.record-musician').classList.contains('is-animated'));
 assert.match(await page.locator('.record-musician img').getAttribute('src'),/coco-guitar-motion\.svg/);
 await page.screenshot({path:out+'/music-mobile.png'});
 check('Pixel performances, vinyl motion and the original SVG guitarist still animate.');
 await page.locator('#experiences').scrollIntoViewIfNeeded();
 const before=await page.locator('.programme-pane:not([hidden])').getAttribute('data-programme-pane');
 await page.getByRole('button',{name:'Next event',exact:true}).click();
 assert.notEqual(await page.locator('.programme-pane:not([hidden])').getAttribute('data-programme-pane'),before);
 assert.equal(await page.locator('.programme-pane:not([hidden])').count(),1);
 check('Mobile event navigation keeps one usable active pane.');
 await page.locator('#culture-tech').scrollIntoViewIfNeeded();
 await page.emulateMedia({reducedMotion:'reduce'});
 await page.waitForFunction(()=>!document.querySelector('.record-musician.is-animated'));
 await page.emulateMedia({reducedMotion:'no-preference'});
 await page.waitForFunction(()=>document.querySelector('.record-musician.is-animated'));
 await page.evaluate(()=>dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true})));
 assert.equal(await page.locator('.record-musician.is-animated').count(),0);
 await page.evaluate(()=>dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true})));
 await page.waitForFunction(()=>document.querySelector('.record-musician.is-animated'));
 check('Reduced motion and browser-back restoration stop and resume the original scenes.');
 await page.locator('[data-keepsake-studio]').scrollIntoViewIfNeeded();
 await page.waitForFunction(()=>['worker','main'].includes(document.querySelector('[data-keepsake-studio] canvas').dataset.renderEngine));
 await page.getByRole('button',{name:'Pause ticket preview',exact:true}).click();
 await page.waitForTimeout(300);
 await page.evaluate(()=>{window.__ticketBefore94=document.querySelector('[data-keepsake-studio] canvas').toDataURL();});
 await page.getByLabel('Enter your name',{exact:true}).fill('Mobile performance check');
 await page.waitForFunction(()=>document.querySelector('[data-keepsake-studio] canvas').toDataURL()!==window.__ticketBefore94);
 await page.getByRole('button',{name:'Play ticket preview',exact:true}).click();
 check('The built keepsake renderer updates names and resumes its animated preview.');
 for(const width of [320,390,768,1440]){
  await page.setViewportSize({width,height:900});
  for(const selector of ['.hero','#experiences','#culture-tech','#partners','.site-footer']){
   await page.locator(selector).scrollIntoViewIfNeeded();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,width+'px has no horizontal overflow at '+selector);
  }
 }
 check('The layout and overlapping artwork remain intact at four responsive widths.');
 const fallback=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
 await fallback.addInitScript(()=>{Object.defineProperty(window,'ScrollTimeline',{value:undefined,configurable:true});localStorage.setItem('anazori-motion','on');});
 const older=await fallback.newPage();older.on('pageerror',e=>errors.push(e.message));
 await older.goto(base,{waitUntil:'networkidle'});
 await older.waitForFunction(()=>document.documentElement.dataset.scrollEngine==='fallback');
 await older.locator('#culture-tech').scrollIntoViewIfNeeded();
 assert(await older.locator('#culture-heading').isVisible());
 assert.equal(await older.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 check('Browsers without ScrollTimeline retain the cached fallback and readable content.');
 // Compare stationary frames using the original CSS from the recovery copy.
 // This catches a changed backdrop or clipped artwork, separately from animation timing.
 const oldCSS=await readFile('.local/backups/mobile94/assets/public.css','utf8');
 const comparisons=[];
 for(const width of [390,1440]) {
  const shots=[];
  for(const original of [true,false]) {
   const staticContext=await browser.newContext({viewport:{width,height:900},deviceScaleFactor:1});
   await staticContext.addInitScript(()=>localStorage.setItem('anazori-motion','paused'));
   const staticPage=await staticContext.newPage();
   if(original)await staticPage.route('**/assets/2026/public.css*',route=>route.fulfill({contentType:'text/css',body:oldCSS}));
   await staticPage.goto(base,{waitUntil:'networkidle'});await staticPage.evaluate(()=>document.fonts.ready);
   await staticPage.waitForFunction(()=>!document.documentElement.classList.contains('festival-loading81'));
   shots.push(PNG.sync.read(await staticPage.screenshot({path:out+`/hero-${width}-${original?'before':'after'}.png`})));
   await staticContext.close();
  }
  let delta=0;for(let i=0;i<shots[0].data.length;i+=4)for(let c=0;c<3;c++)delta+=Math.abs(shots[0].data[i+c]-shots[1].data[i+c]);
  const mean=delta/(shots[0].width*shots[0].height*3);comparisons.push({width,meanChannelError:mean});
  assert(mean<1,'The retained background must preserve the existing appearance: '+mean);
 }
 check('Mobile and desktop screenshots preserve the original background and hero appearance.');
 assert.deepEqual(errors,[]);
 await writeFile(out+'/verification.json',JSON.stringify({checks,comparisons,errors},null,2));
 console.log(checks.length+' mobile rendering checks passed.');
} finally {await browser.close();}
