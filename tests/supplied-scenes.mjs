import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PNG} from 'pngjs';
const temp=await mkdtemp(join(tmpdir(),'anazori-supplied-'));
const env={...process.env,ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'secret'),ANAZORI_TEST_MODE:'1'};
const base='http://127.0.0.1:8117',out='.local/supplied-scenes';
const server=spawn('php',['-S','127.0.0.1:8117','-t','src','scripts/router.php'],{env,windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch();let checks=0;const errors=[];
const ok=text=>{checks++;console.log('PASS '+text);};
const setMotion=value=>execFileSync('php',['-r',`require 'includes/cms.php';$s=cms_settings();$s['scene_motion']='${value}';cms_db()->prepare("UPDATE cms_settings SET value=? WHERE setting_key='site'")->execute([json_encode($s)]);`],{env,encoding:'utf8'});
const artState=(page,selector)=>page.locator(selector).evaluate(img=>({src:img.src,transform:getComputedStyle(img).transform,state:getComputedStyle(img).animationPlayState,width:img.naturalWidth,height:img.naturalHeight}));
try{
 await mkdir(out,{recursive:true});
 for(let i=0;i<60;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const context=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,deviceScaleFactor:1});
 await context.addInitScript(()=>{
  window.__webgl=0;const original=HTMLCanvasElement.prototype.getContext;HTMLCanvasElement.prototype.getContext=function(type,...args){if(String(type).startsWith('webgl'))window.__webgl++;return original.call(this,type,...args);};
  const connection=new EventTarget();connection.saveData=false;Object.defineProperty(navigator,'connection',{value:connection,configurable:true});window.__connection=connection;
 });
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 const requests=[];page.on('request',r=>requests.push(r.url()));
 await page.goto(base,{waitUntil:'networkidle'});
 assert.equal(requests.some(url=>url.endsWith('/coco-guitar.webp')),false,'Guitar atlas stays unloaded above the music section');
 assert.equal(await page.locator('.chase-dinosaur').count(),0);assert.equal(await page.locator('.chase-door').count(),1);assert.equal(await page.locator('.chase-fireball').count(),0);assert.equal(await page.locator('.energy-packet').count(),0);
 await page.locator('.character-chase').scrollIntoViewIfNeeded();
 await page.waitForFunction(()=>document.querySelector('.character-chase').classList.contains('sprites-ready'));
 assert.equal(await page.locator('.character-chase').evaluate(e=>e.previousElementSibling.matches('.hero')&&e.nextElementSibling.matches('.festival-clock,.intro')),true,'Chase replaces the existing strip below the hero');
 await page.waitForFunction(()=>{
  const door=document.querySelector('.chase-door').getBoundingClientRect(),pika=document.querySelector('.chase-pikachu').getBoundingClientRect(),dora=document.querySelector('.chase-doraemon').getBoundingClientRect();return dora.x>door.right&&pika.x>dora.x&&pika.right<innerWidth;
 });
 assert.match(await page.locator('.chase-door-leaf').evaluate(e=>getComputedStyle(e).transform),/^matrix3d\(-0\.309/,'The door stays open while the runners exit');
 const flight=await page.locator('.chase-runner-pikachu').evaluate(e=>e.getAnimations()[0]?.currentTime);await page.waitForTimeout(180);assert((await page.locator('.chase-runner-pikachu').evaluate(e=>e.getAnimations()[0]?.currentTime))>flight);
 const before=await artState(page,'.chase-pikachu .sprite-sheet');await page.waitForTimeout(65);assert.notEqual((await artState(page,'.chase-pikachu .sprite-sheet')).transform,before.transform,'Supplied running poses advance');
 assert.equal(await page.locator('.chase-doraemon .sprite-sheet').evaluate(e=>getComputedStyle(e).animationPlayState),'running');
 assert.equal(await page.locator('canvas').count(),1);assert.equal(await page.evaluate(()=>window.__webgl),0);
 assert.equal(requests.some(url=>/lottie|\.wasm|animation-source/.test(url)),false,'No animation runtime or source JSON ships to phones');
 await page.locator('.character-chase').screenshot({path:out+'/chase-mobile.png'});
 ok('Pikachu and Doraemon emerge from the open door in order, with animated running poses.');
 await page.locator('#culture-tech').scrollIntoViewIfNeeded();
 await page.waitForFunction(()=>document.querySelector('.record-musician').classList.contains('is-animated'));
 assert.equal(await page.locator('.record-musician').count(),1);assert.equal(await page.locator('.record-companion').count(),0);
 assert.match(await page.locator('.record-musician img').getAttribute('src'),/coco-guitar-motion\.svg/);
 assert.equal(await page.locator('.character-chase .sprite-sheet').first().evaluate(e=>getComputedStyle(e).animationPlayState),'paused');
 const musician=await page.locator('.record-musician').boundingBox(),label=await page.locator('.record-label').boundingBox();assert(musician.x>=label.x+label.width-2,'Guitarist stays beside the central label');
 await page.locator('#culture-tech').screenshot({path:out+'/music-mobile.png'});
 // Canvas draws an animated SVG's initial image, not its current displayed SMIL
 // frame. Inspect the actual browser paint and exclude the moving background.
 const pixels=async()=>{const png=PNG.sync.read(await page.locator('.record-musician').screenshot());const art=[];for(let i=0;i<png.data.length;i+=4){const [r,g,b]=png.data.subarray(i,i+3);if(r>180&&g>70&&b<90 || r>120&&b>120&&g<100)art.push(i,r,g,b);}return art;};
 await page.locator('.record-musician img').evaluate(e=>e.decode());await page.waitForTimeout(900);
 const old=await pixels();assert(old.length>100,'The performer is visible');await page.waitForTimeout(350);assert.notDeepEqual(await pixels(),old,'Original SVG poses advance');
 await page.evaluate(()=>{window.__connection.saveData=true;window.__connection.dispatchEvent(new Event('change'));});assert.equal(await page.locator('.record-musician.is-animated').count(),0);
 assert.match(await page.locator('.record-musician img').getAttribute('src'),/coco-guitar-still\.svg/);
 await page.evaluate(()=>{window.__connection.saveData=false;window.__connection.dispatchEvent(new Event('change'));});
 await page.evaluate(()=>{dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));});assert.equal(await page.locator('.record-musician.is-animated').count(),0);
 await page.evaluate(()=>{dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));});await page.waitForFunction(()=>document.querySelector('.record-musician').classList.contains('is-animated'));
 await page.emulateMedia({reducedMotion:'reduce'});await page.waitForFunction(()=>!document.querySelector('.record-musician.is-animated'));await page.emulateMedia({reducedMotion:'no-preference'});
 ok('The transparent SVG guitarist stays beside the vinyl; original poses and all motion guards work.');
 for(const width of [320,390,768,1440]){
  await page.setViewportSize({width,height:900});
  for(const selector of ['.character-chase','#culture-tech']){
   await page.locator(selector).scrollIntoViewIfNeeded();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   if(width===1440)await page.locator(selector).screenshot({path:out+(selector.startsWith('.')?'/chase-desktop.png':'/music-desktop.png')});
  }
 }
 const identities={};
 for(const route of ['/','/gallery.php','/events.php','/teams.php']){
  const html=await (await fetch(base+route)).text();
  for(const match of html.matchAll(/class="festival-character character-(\w+)/g)){const id=match[1]==='minion'?'stuart':match[1];identities[id]=(identities[id]||0)+1;}
  for(const match of html.matchAll(/data-sprite-identity="([a-z-]+)"/g)){const id={'doraemon-run':'doraemon','pikachu-run':'pikachu','coco-guitar':'coco'}[match[1]];identities[id]=(identities[id]||0)+1;}
 }
 assert(Object.values(identities).every(n=>n<=2),JSON.stringify(identities));
 const manifest=JSON.parse(await readFile('src/assets/2026/animations/sources.json','utf8'));assert.deepEqual(manifest.slice(0,3).map(m=>m.frames),[18,25,150]);assert(manifest.filter(m=>m.atlas).every(m=>m.cell*m.columns<=4096));
 ok('All layouts fit four widths; every authored frame is retained and cartoon repetition stays at two.');
 const staticPage=await browser.newPage({javaScriptEnabled:false,viewport:{width:390,height:844}});await staticPage.goto(base);for(const img of await staticPage.locator('.sprite-poster').all()){
  await img.scrollIntoViewIfNeeded();assert.equal(await img.isVisible(),true);await img.evaluate(e=>e.decode());
  const pixels=await img.evaluate(e=>{const c=document.createElement('canvas');c.width=c.height=160;const ctx=c.getContext('2d');ctx.drawImage(e,0,0);return ctx.getImageData(0,0,160,160).data.filter((v,i)=>i%4===3&&v>64).length;});
  assert(pixels>500,'Every fallback poster contains visible source artwork');
 }await staticPage.close();
 const failed=await browser.newPage({viewport:{width:390,height:844}});await failed.route('**/coco-guitar-motion.svg*',r=>r.abort());await failed.goto(base);await failed.locator('.record-musician').scrollIntoViewIfNeeded();await failed.waitForTimeout(200);assert.equal(await failed.locator('.record-musician img').isVisible(),true);assert.match(await failed.locator('.record-musician img').getAttribute('src'),/coco-guitar-still\.svg/);assert.equal(await failed.locator('.record-musician.is-animated').count(),0);await failed.close();
 setMotion('0');await page.reload();await page.locator('.character-chase').scrollIntoViewIfNeeded();assert.equal(await page.locator('.sprite-ready').count(),0);assert.equal(await page.locator('.chase-runner-pikachu').evaluate(e=>e.getAnimations().length),0);
 assert.deepEqual(errors,[]);ok('No-JavaScript posters and Studio motion-off keep the scenes clean and readable.');
 console.log(`${checks} supplied-animation check groups passed.`);
}finally{await browser.close();if(server.exitCode===null){const ended=new Promise(r=>server.once('exit',r));server.kill();await ended;}await rm(temp,{recursive:true,force:true});}
