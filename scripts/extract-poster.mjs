import {chromium} from 'playwright';
const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1600,height:900}});
await page.goto('http://127.0.0.1:8088/',{waitUntil:'networkidle'});
await page.waitForFunction(()=>document.querySelector('#hero-film').currentTime>3);
const data=await page.locator('#hero-film').evaluate(v=>{const c=document.createElement('canvas');c.width=1600;c.height=900;c.getContext('2d').drawImage(v,0,0,1600,900);return c.toDataURL('image/jpeg',.87).split(',')[1];});
const {writeFile}=await import('node:fs/promises');await writeFile('assets/2026/hero-poster.jpg',Buffer.from(data,'base64'));console.log('Saved a poster frame from the original Anazori film.');await browser.close();
