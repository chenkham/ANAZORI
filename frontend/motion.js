import {initReadingProgress} from './reading-progress86.js';

export function initMotion() {
 const root=document.documentElement;
 const paused=()=>root.classList.contains('motion-paused');
 const video=document.querySelector('#hero-film');
 const song=document.querySelector('#hero-song'),sound=document.querySelector('#sound-toggle'),soundStatus=document.querySelector('#sound-status');
 let audible=video?.dataset.sound==='1',playGeneration=0;
 const hero=document.querySelector('.hero');
 const art=document.querySelector('#connection-sculpture canvas.connection-canvas')?.closest('#connection-sculpture');
 let heroVisible=true,artVisible=false,scene=null,loading=false,destroyed=false;
 const saveData=!!navigator.connection?.saveData;
 const animations=new Set();
 const shouldPlay=()=>heroVisible&&!paused()&&!document.hidden&&!document.querySelector('dialog[open]')&&(!saveData||root.dataset.motionOptIn==='true');
 function updateSound(){if(!sound)return;const playing=audible&&!video.paused&&(!song||!song.paused);sound.setAttribute('aria-pressed',String(playing));sound.querySelector('.sound-label').textContent=playing?'Mute sound':'Enable sound';}
 async function syncVideo(){
  if(!video)return;
  const generation=++playGeneration;
  if(shouldPlay()) {
   if(!video.getAttribute('src'))video.src=video.dataset.src;
   if(song&&audible&&!song.getAttribute('src'))song.src=song.dataset.src;
   video.muted=!!song||!audible;if(song)song.muted=!audible;
   try {await Promise.all([video.play(),...(song&&audible?[song.play()]:[])]);if(generation!==playGeneration||!shouldPlay()){if(!shouldPlay()){video.pause();song?.pause();}return;}if(soundStatus)soundStatus.textContent='';}
   catch {if(generation!==playGeneration)return;audible=false;video.muted=true;song?.pause();if(shouldPlay()){try{await video.play();}catch{}}if(soundStatus)soundStatus.textContent='Enable sound to hear the festival.';}
  }else {video.pause();song?.pause();}
  updateSound();
 }
 sound?.addEventListener('click',()=>{if(sound.getAttribute('aria-pressed')==='true'){audible=false;video.muted=true;song?.pause();updateSound();}else{audible=true;if(paused())document.dispatchEvent(new CustomEvent('anazori:resume'));syncVideo();}});
 video?.addEventListener('error',()=>{if(soundStatus)soundStatus.textContent='The film is unavailable. Please try again later.';updateSound();});
 async function loadSculpture(){
  if(!art||scene||loading||saveData||destroyed)return;
  loading=true;
  try {const {createSculpture}=await import('./sculpture.js');if(destroyed)return;scene=createSculpture(art);syncScene();}
  catch {art.classList.remove('sculpture-ready');}
 }
 function syncScene(){scene?.setActive(artVisible&&!paused()&&!document.hidden);}
 const mediaObserver=new IntersectionObserver(entries=>{for(const e of entries){if(e.target===hero){heroVisible=e.isIntersecting;syncVideo();}if(e.target===art){artVisible=e.isIntersecting;if(artVisible)loadSculpture();syncScene();}}},{rootMargin:'80px'});
 if(hero)mediaObserver.observe(hero);if(art)mediaObserver.observe(art);
 const revealObserver=new IntersectionObserver(entries=>{for(const e of entries){if(!e.isIntersecting)continue;revealObserver.unobserve(e.target);if(paused())continue;const a=e.target.animate([{opacity:.25,transform:'translateY(22px)'},{opacity:1,transform:'translateY(0)'}],{duration:750,easing:'cubic-bezier(.2,.75,.25,1)'});animations.add(a);a.onfinish=()=>animations.delete(a);}},{threshold:.12});
 document.querySelectorAll('[data-reveal],.section-heading,.event-card,.memory-main,.memory-side,.person-card').forEach(e=>revealObserver.observe(e));
 if(hero&&!paused()){
  ['.hero-topline','.hero-wordmark','.hero-copy','.hero-side'].forEach((selector,i)=>{const el=hero.querySelector(selector);if(!el)return;const a=el.animate([{opacity:0,transform:'translateY(20px)'},{opacity:1,transform:'translateY(0)'}],{duration:900,delay:i*100,easing:'cubic-bezier(.2,.75,.25,1)',fill:'backwards'});animations.add(a);a.onfinish=()=>animations.delete(a);});
 }
 const stopProgress=initReadingProgress(document.querySelector('.reading-progress'));
 const onMotion=()=>{if(!paused())root.dataset.motionOptIn='true';for(const a of animations)a.finish();animations.clear();syncVideo();syncScene();};
 document.addEventListener('anazori:motion',onMotion);
 const onVisibility=()=>{syncVideo();syncScene();};document.addEventListener('visibilitychange',onVisibility);
 const dialogs=new MutationObserver(syncVideo);document.querySelectorAll('dialog').forEach(d=>dialogs.observe(d,{attributes:true,attributeFilter:['open']}));
 addEventListener('pagehide',e=>{playGeneration++;video?.pause();song?.pause();scene?.setActive(false);if(e.persisted)return;destroyed=true;scene?.dispose();mediaObserver.disconnect();revealObserver.disconnect();dialogs.disconnect();stopProgress();document.removeEventListener('anazori:motion',onMotion);document.removeEventListener('visibilitychange',onVisibility);});
 addEventListener('pageshow',e=>{if(e.persisted){syncVideo();syncScene();}});
}
