import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {homedir} from 'node:os';
import {pathToFileURL} from 'node:url';
const root=resolve(import.meta.dirname,'..'),out=join(root,'output/auth-ticket99');
const require=createRequire(import.meta.url);
let native;
try{native=require('@napi-rs/canvas');}catch{
 const dependencyRoot=process.env.ANAZORI_CANVAS_MODULES||join(homedir(),'.cache/codex-runtimes/codex-primary-runtime/dependencies/node');
 native=createRequire(join(dependencyRoot,'package.json'))('@napi-rs/canvas');
}
const {createCanvas,loadImage,GlobalFonts}=native;
GlobalFonts.registerFromPath(join(root,'src/assets/fonts/satoshi/Satoshi-Variable.woff2'),'Satoshi');
await mkdir(out,{recursive:true});
const originalFetch=globalThis.fetch,originalBitmap=globalThis.createImageBitmap,originalOffscreen=globalThis.OffscreenCanvas;
const ticket={name:'Your name',festival:'ANAZORI',logo:'/assets/logo.png',edition:'V16.0',year:'2026',date:'02 Nov 2026',notice:'Keepsake only · Not valid for event entry'};
let artworkSize=2160,missing=false,rectangles=[];
const source=await readFile(join(root,'src/assets/2026/anazori-main-font.png'));
globalThis.OffscreenCanvas=function(width,height){
 const canvas=createCanvas(width,height),getContext=canvas.getContext.bind(canvas);
 canvas.getContext=type=>{
  const ctx=getContext(type);
  if(!ctx.__tracked99){
   ctx.__tracked99=true;const draw=ctx.drawImage.bind(ctx);
   ctx.drawImage=(image,...coordinates)=>{
    if(coordinates.length===8&&(coordinates[6]===580||coordinates[6]===430))rectangles.push({width:image.width,height:image.height,coordinates});
    return draw(image,...coordinates);
   };
  }
  return ctx;
 };
 return canvas;
};
globalThis.createImageBitmap=buffer=>loadImage(buffer);
globalThis.fetch=async url=>{
 if(String(url).includes('anazori-main-font.png')){
  if(missing)throw new Error('Simulated unavailable artwork');
  if(artworkSize===2160)return {ok:true,blob:async()=>source};
  const image=await loadImage(source),scaled=createCanvas(artworkSize,artworkSize);
  scaled.getContext('2d').drawImage(image,0,0,artworkSize,artworkSize);
  return {ok:true,blob:async()=>scaled.toBuffer('image/png')};
 }
 return {ok:true,blob:async()=>readFile(join(root,'src',String(url)))};
};
async function render(mode,size,time){
 artworkSize=size;missing=mode==='fallback';rectangles=[];
 const module=await import(pathToFileURL(join(root,'frontend/motion-card.js')).href+'?check99='+mode+'-'+time);
 await module.prepareMotionCard(ticket);
 const canvas=createCanvas(module.CARD_WIDTH,module.CARD_HEIGHT),context=canvas.getContext('2d');
 module.drawMotionCard(context,ticket,time);
 await writeFile(join(out,mode+'-'+(time===0?'front':'back')+'.png'),canvas.toBuffer('image/png'));
 return {pixels:context.getImageData(0,0,canvas.width,canvas.height).data,rectangles:[...rectangles]};
}
function difference(first,second,region){
 let total=0,count=0;
 for(let y=region[1];y<region[3];y++)for(let x=region[0];x<region[2];x++)for(let channel=0;channel<3;channel++){const i=(y*1280+x)*4+channel;total+=Math.abs(first[i]-second[i]);count++;}
 return total/count;
}
try{
 const originalFront=await render('original',2160,0),resizedFront=await render('hosted-size',1600,0);
 const originalBack=await render('original',2160,6000),resizedBack=await render('hosted-size',1600,6000);
 for(const frame of [resizedFront,resizedBack]){
  assert(frame.rectangles.length,'Artwork is drawn');
  for(const {width,height,coordinates:c} of frame.rectangles){
   assert.equal(width,1600);assert.equal(height,1600);
   assert(c[0]>=0&&c[1]>=0&&c[0]+c[2]<=width&&c[1]+c[3]<=height,'The wordmark crop fits the resized image');
   assert(Math.abs(c[0]/width-336/2160)<1e-9);assert(Math.abs(c[1]/height-908/2160)<1e-9);
  }
 }
 const frontDifference=difference(originalFront.pixels,resizedFront.pixels,[170,140,810,330]),backDifference=difference(originalBack.pixels,resizedBack.pixels,[170,100,850,300]);
 assert(frontDifference<7,'Resized front preserves its wordmark: '+frontDifference);
 assert(backDifference<7,'Resized back preserves its wordmark: '+backDifference);
 const fallback=await render('fallback',1600,0);assert.equal(fallback.rectangles.length,0);
 const fallbackDifference=difference(resizedFront.pixels,fallback.pixels,[170,140,810,330]);
 assert(fallbackDifference>3,'Full artwork is visibly present, distinct from the text fallback');
 await writeFile(join(out,'render-checks.json'),JSON.stringify({frontDifference,backDifference,fallbackDifference},null,2));
 console.log('PASS Both ticket faces preserve the supplied wordmark at 2160 and the hosted 1600 pixel size; image-failure text fallback still renders.');
 console.log('Canvas artifacts: '+out);
}finally{
 globalThis.fetch=originalFetch;globalThis.createImageBitmap=originalBitmap;globalThis.OffscreenCanvas=originalOffscreen;
}
