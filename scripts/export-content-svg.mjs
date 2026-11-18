// Export supplied vector layers to standalone SVG/SMIL. No public Lottie runtime.
import {chromium} from 'playwright';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {compressContentSvg} from './compress-content-svg.mjs';
import {repairTransformAnimations} from './svg-transform-animation.mjs';
const sources=JSON.parse(await readFile('.local/animation-source/sources.json','utf8'));
const requested=new Set(process.argv.slice(2));
const browser=await chromium.launch();
// A targeted re-export must retain provenance for the other supplied scenes.
const manifest=new Map((JSON.parse(await readFile('src/assets/2026/vector/sources.json','utf8').catch(()=>'[]'))).map(item=>[item.id,item]));
try {
 const page=await browser.newPage({viewport:{width:640,height:640}});
 await page.setContent('<style>body{margin:0}#art{width:640px;height:640px}</style><div id="art"></div>');
 await page.addScriptTag({path:resolve('node_modules/lottie-web/build/player/lottie_svg.min.js')});
 await mkdir('src/assets/2026/vector',{recursive:true});
 for(const source of sources) {
  if(source.id==='doraemon-run' || (requested.size&&!requested.has(source.id))) continue;
  const data=JSON.parse(await readFile('.local/animation-source/'+source.id+'.json','utf8'));
  const result=await page.evaluate(async ({data,source})=>{
   const ns='http://www.w3.org/2000/svg';window.__art?.destroy();
   data.layers=data.layers.filter(layer=>!(/background|^bg$|fond/i.test(layer.nm||'') || layer.ty===1&&layer.sw>=data.w&&layer.sh>=data.h));
   window.__art=lottie.loadAnimation({container:document.querySelector('#art'),renderer:'svg',loop:false,autoplay:false,animationData:data});
   await new Promise(resolve=>window.__art.addEventListener('DOMLoaded',resolve));
   window.__art.setSubframe(false);
   const svg=document.querySelector('#art svg');
   if(svg.querySelector('image')) throw Error('Raster content in '+source.id);
   const count=Math.ceil(Number((source.end-source.start).toFixed(4))),duration=(source.end-source.start)/source.fps;
   const attributes=['transform','d','opacity','fill','stroke','stroke-width','stroke-dasharray','cx','cy','r','rx','ry','x','y','width','height','points','stop-color','stop-opacity'];
   const nodes=[...svg.querySelectorAll('g,path,ellipse,circle,rect,polygon,line,linearGradient,radialGradient,stop')];
   const tracks=nodes.map(()=>new Map());let bounds=null,poster=0,area=0,still='';
   for(let i=0;i<count;i++) {
    window.__art.goToAndStop(Math.min(i,source.end-source.start-.01),true);
    const box=svg.getBBox();
    if(box.width&&box.height) {
     bounds=bounds?[Math.min(bounds[0],box.x),Math.min(bounds[1],box.y),Math.max(bounds[2],box.x+box.width),Math.max(bounds[3],box.y+box.height)]:[box.x,box.y,box.x+box.width,box.y+box.height];
     if(box.width*box.height>area){area=box.width*box.height;poster=i;still=svg.outerHTML;}
    }
    nodes.forEach((node,index)=>{
     for(const attr of attributes){let value=node.getAttribute(attr);if(value!==null){
      // Precision below a rendered pixel adds payload without adding detail.
      if(['d','transform','points','opacity','stroke-width','cx','cy','r','rx','ry','x','y','width','height'].includes(attr))value=value.replace(/-?\d*\.\d+(?:e[+-]?\d+)?/gi,n=>String(Number(Number(n).toFixed(attr==='transform'?4:attr==='d'&&source.id==='stitch-light'?0:2))));
      if(!tracks[index].has(attr))tracks[index].set(attr,Array(i).fill(value));tracks[index].get(attr).push(value);
     }}
     const display=node.style.display||node.getAttribute('display')||'inline';if(!tracks[index].has('display'))tracks[index].set('display',Array(i).fill(display));tracks[index].get('display').push(display);
    });
   }
   if(!bounds)throw Error('Blank supplied SVG '+source.id);
   const pad=12,viewBox=[bounds[0]-pad,bounds[1]-pad,bounds[2]-bounds[0]+pad*2,bounds[3]-bounds[1]+pad*2].join(' ');
   const clean=element=>{element.removeAttribute('style');element.removeAttribute('width');element.removeAttribute('height');element.setAttribute('viewBox',viewBox);element.setAttribute('preserveAspectRatio','xMidYMax meet');element.setAttribute('xmlns',ns);};
   const parser=new DOMParser();const stillSvg=parser.parseFromString(still,'image/svg+xml').documentElement;clean(stillSvg);
   for(const node of stillSvg.querySelectorAll('*'))for(const attr of ['d','transform','points','opacity','stroke-width','cx','cy','r','rx','ry','x','y','width','height'])if(node.hasAttribute(attr))node.setAttribute(attr,node.getAttribute(attr).replace(/-?\d*\.\d+(?:e[+-]?\d+)?/gi,n=>String(Number(Number(n).toFixed(attr==='transform'?4:attr==='d'&&source.id==='stitch-light'?0:2)))));
   for(const hidden of [...stillSvg.querySelectorAll('[style]')])if(hidden.style.display==='none')hidden.remove();
   nodes.forEach((node,index)=>{
    node.style.removeProperty('display');
    for(const [attribute,values] of tracks[index]) {
     if(values.length!==count)continue;
     node.setAttribute(attribute,values[poster]);
     if(new Set(values).size<2)continue;
     const changes=[];for(let i=0;i<count;i++)if(!i||values[i]!==values[i-1])changes.push(i);
     const animation=document.createElementNS(ns,'animate');animation.setAttribute('attributeName',attribute);animation.setAttribute('dur',duration+'s');animation.setAttribute('repeatCount','indefinite');animation.setAttribute('calcMode','discrete');
     animation.setAttribute('values',[...changes.map(i=>values[i]),values[0]].join(';'));animation.setAttribute('keyTimes',[...changes.map(i=>(i/source.fps/duration).toFixed(6)),'1'].join(';'));node.append(animation);
    }
   });clean(svg);
   return {still:stillSvg.outerHTML,motion:svg.outerHTML,frames:count,duration,poster,paths:svg.querySelectorAll('path').length};
  },{data,source});
  result.motion=repairTransformAnimations(result.motion);
  await writeFile('src/assets/2026/vector/'+source.id+'-still.svg',result.still);
  await writeFile('src/assets/2026/vector/'+source.id+'-motion.svg',result.motion);
  const item={id:source.id,source:source.source,source_sha256:source.source_sha256,frames:result.frames,duration:result.duration,poster:result.poster,paths:result.paths,bytes:Buffer.byteLength(result.motion),raster:false};manifest.set(item.id,item);console.log(JSON.stringify(item));
 }
 await writeFile('src/assets/2026/vector/sources.json',JSON.stringify([...manifest.values()],null,2));
 await compressContentSvg();
} finally {await browser.close();}
