import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {readFile,mkdir,writeFile} from 'node:fs/promises';

// Compare the authored animation with the recovery copy at the same times.
// Pixel reads use separate canvases from timing, avoiding readback-induced
// changes to the browser's canvas acceleration during the benchmark.
const base=process.argv[2]||'http://127.0.0.1:8000',out='.local/mobile94';
await mkdir(out,{recursive:true});
const before=await readFile('.local/backups/mobile94/frontend/motion-card.js');
const after=await readFile('frontend/motion-card.js');
const browser=await chromium.launch();
try {
 const page=await browser.newPage();
 await page.route('**/__card-qa94/**',route=>{
  const name=new URL(route.request().url()).pathname.split('/').pop();
  route.fulfill(name==='before.js'||name==='after.js'
   ?{contentType:'text/javascript',body:name==='before.js'?before:after}
   :{contentType:'text/html',body:'<canvas id="before" width="1280" height="720"></canvas><canvas id="after" width="1280" height="720"></canvas>'});
 });
 await page.goto(new URL('/__card-qa94/',base).href);
 const result=await page.evaluate(async()=>{
  const before=await import('/__card-qa94/before.js'),after=await import('/__card-qa94/after.js');
  const font=new FontFace('Satoshi','url(/assets/fonts/satoshi/Satoshi-Variable.woff2)',{weight:'100 900'});document.fonts.add(await font.load());
  const ticket={name:'Your name',festival:'ANAZORI',logo:'/assets/logo.png',edition:'V16.0',year:'2026',date:'October 2026',notice:'Keepsake only · Not valid for event entry'};
  await Promise.all([before.prepareMotionCard(ticket),after.prepareMotionCard(ticket)]);
  const a=document.querySelector('#before').getContext('2d'),b=document.querySelector('#after').getContext('2d'),samples=[];
  const compare=(time,name)=>{
   ticket.name=name;before.drawMotionCard(a,ticket,time);after.drawMotionCard(b,ticket,time);
   const aa=a.getImageData(0,0,1280,720).data,bb=b.getImageData(0,0,1280,720).data;let error=0,large=0;
   for(let i=0;i<aa.length;i+=4){let max=0;for(let c=0;c<3;c++){const d=Math.abs(aa[i+c]-bb[i+c]);error+=d;max=Math.max(max,d);}if(max>20)large++;}
   samples.push({time,name,meanChannelError:error/(1280*720*3),pixelsOver20:large});
  };
  for(const time of [0,1500,4200,6500,8700,11000])compare(time,'Your name');
  compare(0,'A completely different and longer festival name');
  compare(6500,'A completely different and longer festival name');
  const canvasA=document.createElement('canvas'),canvasB=document.createElement('canvas');
  canvasA.width=canvasB.width=1280;canvasA.height=canvasB.height=720;
  const ctxA=canvasA.getContext('2d'),ctxB=canvasB.getContext('2d');
  const bench=(module,ctx)=>{const start=performance.now();for(let i=0;i<90;i++)module.drawMotionCard(ctx,ticket,i*130);return performance.now()-start;};
  bench(before,ctxA);bench(after,ctxB);
  const baselineMs=bench(before,ctxA),optimizedMs=bench(after,ctxB);
  return{samples,benchmark:{frames:90,baselineMs,optimizedMs}};
 });
 for(const sample of result.samples){assert(sample.meanChannelError<.5);assert.equal(sample.pixelsOver20,0);}
 await page.locator('#after').screenshot({path:out+'/keepsake-after.png'});
 await writeFile(out+'/card-cache.json',JSON.stringify(result,null,2));
 console.log('PASS Front, back, foil, waveform, glow and edited names preserve the authored frames.');
 console.log(JSON.stringify(result.benchmark));
} finally {await browser.close();}
