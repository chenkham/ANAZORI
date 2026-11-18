import {createTaskQueue} from './task-scheduler83.js';

export function initPerformance81(){
 const root=document.documentElement,queue=createTaskQueue();
 let destroyed=false;
 const start=load=>load().then(init=>queue(()=>{if(!destroyed)init();})).catch(error=>console.warn('Anazori animation could not start.',error));
 const near=[
  ['.culture-tech',()=>import('./retro.js').then(m=>m.initRetro)],
  ['#intro-video',()=>import('./intro-video.js').then(m=>m.initIntroVideo)],
  ['[data-keepsake-studio]',()=>import('./festival-sharing.js').then(m=>m.initFestivalSharing)]
 ];
 const pending=new Map();
 const observer=typeof IntersectionObserver==='function'?new IntersectionObserver(entries=>{
  for(const entry of entries)if(entry.isIntersecting){const load=pending.get(entry.target);if(load){pending.delete(entry.target);observer.unobserve(entry.target);start(load);}}
 },{rootMargin:'600px'}):null;
 const boot=()=>{
  if(destroyed)return;
  // Fetch the small core modules together; initialize them in separate browser tasks.
  start(()=>import('./ambient-motion.js').then(m=>m.initAmbientMotion));
  if(document.querySelector('[data-festival-scene]'))start(()=>import('./festival-scenes.js').then(m=>m.initFestivalScenes));
  start(()=>import('./motion.js').then(m=>m.initMotion));
  if(document.querySelector('#festival-clock,.hero-particles'))start(()=>import('./experience.js').then(m=>m.initExperience));
  start(()=>import('./designer.js').then(m=>m.initDesigner));
  start(()=>import('./world.js').then(m=>m.initWorld));
  if(document.body.matches('.page-home,.page-events,.page-gallery,.page-teams'))start(()=>import('./scroll-motion.js').then(m=>m.initScrollMotion));
  for(const [selector,load] of near){const node=document.querySelector(selector);if(!node)continue;if(observer){pending.set(node,load);observer.observe(node);}else start(load);}
 };
 if(root.classList.contains('festival-loading81'))document.addEventListener('anazori:ready',boot,{once:true});else boot();
 const hide=event=>{if(event.persisted)return;destroyed=true;observer?.disconnect();pending.clear();document.removeEventListener('anazori:ready',boot);removeEventListener('pagehide',hide);};
 addEventListener('pagehide',hide);
}
