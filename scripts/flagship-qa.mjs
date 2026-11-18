import {chromium} from 'playwright';
import {mkdir,writeFile} from 'node:fs/promises';
await mkdir('.local/flagship',{recursive:true});
const browser=await chromium.launch({headless:true});
const errors=[];const results=[];
for(const width of [1440,390]){
 const page=await browser.newPage({viewport:{width,height:width===390?844:1000}});
 page.on('pageerror',e=>errors.push({width,message:e.message}));
 page.on('response',r=>{if(r.status()>=400)errors.push({width,status:r.status(),url:r.url()});});
 await page.goto('http://127.0.0.1:8088/',{waitUntil:'networkidle'});
 await page.evaluate(()=>Promise.all([...document.querySelectorAll('.hero-wordmark,.hero-copy,.hero-side')].flatMap(e=>e.getAnimations()).map(a=>a.finished.catch(()=>{}))));
 await page.waitForFunction(()=>document.querySelector('#hero-film').readyState>=2);
 await page.locator('.hero .motion-toggle').click();
 await page.locator('#hero-film').evaluate(async v=>{v.currentTime=3;await new Promise(r=>v.addEventListener('seeked',r,{once:true}));});
 await page.waitForTimeout(250);
 await page.screenshot({path:`.local/flagship/home-${width}.png`});
 await page.locator('#about').scrollIntoViewIfNeeded();await page.waitForFunction(()=>document.querySelector('#connection-sculpture').classList.contains('sculpture-ready'));await page.waitForTimeout(700);
 await page.screenshot({path:`.local/flagship/sculpture-${width}.png`});
 for(let y=0;y<await page.evaluate(()=>document.documentElement.scrollHeight);y+=750){await page.evaluate(y=>scrollTo(0,y),y);await page.waitForTimeout(160);}
 await page.evaluate(()=>scrollTo(0,0));await page.waitForTimeout(800);
 await page.screenshot({path:`.local/flagship/home-full-${width}.png`,fullPage:true});
 for(const route of ['/', '/events.php','/event.php?name=goc','/gallery.php','/teams.php','/login.php']){
  await page.goto('http://127.0.0.1:8088'+route,{waitUntil:'networkidle'});
  await page.waitForTimeout(850);
  const state=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,broken:[...document.images].filter(i=>i.getAttribute('src')&&i.complete&&i.naturalWidth===0).map(i=>i.src),heading:document.querySelector('h1')?.textContent}));
  results.push({width,route,...state});
  if(route!== '/')await page.screenshot({path:`.local/flagship/${route.split('?')[0].replace(/\W/g,'')}-${width}.png`});
 }
 await page.close();
}
await writeFile('.local/flagship/layout-results.json',JSON.stringify({results,errors},null,2));console.log(JSON.stringify({results,errors},null,2));await browser.close();
