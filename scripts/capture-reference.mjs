import {chromium} from 'playwright';
import {mkdir} from 'node:fs/promises';
await mkdir('.local/reference',{recursive:true});
const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1000},ignoreHTTPSErrors:true});
for (const [name,url] of [['previous-live','https://anazori.ccsdu.in'],['before-redesign','http://127.0.0.1:8088']]) {
 try {
  await page.goto(url,{waitUntil:'domcontentloaded',timeout:45000});
  await page.waitForTimeout(name==='previous-live'?15000:2500);
  for(let y=0;y<await page.evaluate(()=>document.body.scrollHeight);y+=850){await page.evaluate(y=>scrollTo(0,y),y);await page.waitForTimeout(180);}
  await page.evaluate(()=>scrollTo(0,0));await page.waitForTimeout(800);
  await page.screenshot({path:`.local/reference/${name}-full.png`,fullPage:true});
  await page.screenshot({path:`.local/reference/${name}-hero.png`});
  console.log(name,JSON.stringify(await page.evaluate(()=>({title:document.title,height:document.body.scrollHeight,headings:[...document.querySelectorAll('h1,h2')].map(e=>e.innerText),videos:[...document.querySelectorAll('video')].map(v=>({src:v.currentSrc,poster:v.poster}))}))));
 } catch(e){console.log(name,e.message);}
}
await browser.close();
