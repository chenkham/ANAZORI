// Lottie is a development-only exporter. The public site plays composited sprite sheets.
import {chromium} from 'playwright';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
const requested=new Set(process.argv.slice(2));
const sources=JSON.parse(await readFile('.local/animation-source/sources.json','utf8')).filter(s=>!requested.size||requested.has(s.id));
const browser=await chromium.launch();
try{
 const page=await browser.newPage({viewport:{width:640,height:640},deviceScaleFactor:1});
 await page.setContent('<style>html,body{margin:0;background:transparent}#art{width:640px;height:640px}</style><div id="art"></div>');
 await page.addScriptTag({path:resolve('node_modules/lottie-web/build/player/lottie_canvas.min.js')});
 for(const source of sources){
  const data=JSON.parse(await readFile('.local/animation-source/'+source.id+'.json','utf8'));
  await page.evaluate(async data=>{
   window.__art?.destroy();
   window.__art=lottie.loadAnimation({container:document.querySelector('#art'),renderer:'canvas',loop:false,autoplay:false,animationData:data,rendererSettings:{clearCanvas:true,dpr:1}});
   await new Promise(resolve=>window.__art.addEventListener('DOMLoaded',resolve));
   window.__art.setSubframe(false);
  },data);
  // Remove only export floating-point noise; keep every authored whole frame.
  const count=Math.ceil(Number((source.end-source.start).toFixed(4)));
  const folder='.local/animation-frames/'+source.id;await mkdir(folder,{recursive:true});
  for(let i=0;i<count;i++){
   // goToAndStop takes a frame relative to ip. Non-zero source in-points
   // (WALL-E and Baymax) must not be added a second time by the player.
   const frame=Math.min(i,source.end-source.start-.01);
   const url=await page.evaluate(frame=>{window.__art.goToAndStop(frame,true);return document.querySelector('#art canvas').toDataURL('image/png');},frame);
   await writeFile(folder+'/'+String(i).padStart(3,'0')+'.png',Buffer.from(url.split(',')[1],'base64'));
  }
  console.log('Rendered '+source.id+': '+count+' frames');
 }
}finally{await browser.close();}
