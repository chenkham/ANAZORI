import {chromium} from 'playwright';
const browser=await chromium.launch();const page=await browser.newPage({viewport:{width:1440,height:1000},ignoreHTTPSErrors:true});
await page.goto('https://anazori.ccsdu.in',{waitUntil:'domcontentloaded',timeout:45000});await page.waitForTimeout(16000);
const height=await page.evaluate(()=>document.documentElement.scrollHeight);
for(let y=0;y<height;y+=700){await page.evaluate(y=>window.scrollTo({top:y,behavior:'instant'}),y);await page.waitForTimeout(900);}
await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));await page.waitForTimeout(2000);
// Reveal scroll-animated content for a readable full-page reference, without changing the live site.
await page.evaluate(()=>{for(const el of document.querySelectorAll('main *,#root *')){const s=getComputedStyle(el);if(s.opacity==='0'&&el.getBoundingClientRect().height>0&&s.position!=='fixed'){el.style.setProperty('opacity','1','important');el.style.setProperty('transform','none','important');}}});
await page.screenshot({path:'.local/reference/previous-live-full.png',fullPage:true,animations:'disabled'});
await page.screenshot({path:'.local/reference/previous-live-hero.png',animations:'disabled'});
console.log('Previous homepage captured at',height,'pixels high, with scroll reveals expanded for reference.');await browser.close();
