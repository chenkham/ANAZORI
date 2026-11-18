import {CARD_DURATION} from './motion-card.js';
import {createMotionCardRenderer} from './keepsake-renderer84.js';
import {supportedMp4Type, mp4DownloadFile} from './keepsake-video.js';

export function initFestivalSharing(){
 const station=document.querySelector('[data-keepsake-studio]');if(!station)return;
 const data=JSON.parse(station.dataset.keepsakeStudio);
 const canvas=station.querySelector('canvas'),player=station.querySelector('video'),renderer=createMotionCardRenderer(canvas,data);
 const form=station.querySelector('[data-keepsake-form]'),nameInput=station.querySelector('[data-keepsake-name]'),saveButton=station.querySelector('[data-video-save]'),pauseButton=station.querySelector('[data-preview-pause]');
 const status=station.querySelector('[role=status]'),progress=station.querySelector('progress'),download=station.querySelector('[data-ready-download]');
 const reduced=matchMedia('(prefers-reduced-motion: reduce)');
 const mime=typeof MediaRecorder!=='undefined'&&typeof canvas.captureStream==='function'?supportedMp4Type(MediaRecorder):null;
 const mp4Unavailable='MP4 download is unavailable in this browser. Please try the latest Chrome or Edge.';
 let paused=false,visible=false,raf=0,elapsed=0,last=0,exporting=false,cachedFile=null,cachedName='',objectUrl=null,cancelExport=null,rendererReady=false,playVersion=0;
 const draw=()=>renderer.draw(data,elapsed);
 const motionAllowed=()=>!paused&&!reduced.matches&&!document.documentElement.classList.contains('motion-paused')&&document.body.dataset.sceneMotion!=='off';
 const shouldPlay=()=>visible&&!document.hidden&&motionAllowed();
 const tick=async(now,version)=>{raf=0;if(version!==playVersion||!shouldPlay()||!rendererReady)return;const tier=document.documentElement.dataset.motionQuality,interval=tier==='low'?1000/15:tier==='medium'?1000/24:0;if(now-last<interval){raf=requestAnimationFrame(now=>tick(now,version));return;}elapsed=(elapsed+Math.min(now-last,80))%CARD_DURATION;last=now;await draw();if(version===playVersion&&shouldPlay())raf=requestAnimationFrame(now=>tick(now,version));};
 const sync=()=>{cancelAnimationFrame(raf);raf=0;const version=++playVersion,playing=shouldPlay();pauseButton.textContent=playing?'Ⅱ':'▷';pauseButton.setAttribute('aria-label',playing?'Pause ticket preview':'Play ticket preview');if(!player.hidden){if(playing)player.play().catch(()=>{pauseButton.textContent='▷';pauseButton.setAttribute('aria-label','Play ticket preview');});else player.pause();return;}if(playing&&rendererReady){last=performance.now();raf=requestAnimationFrame(now=>tick(now,version));}else draw();};
 const observer=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;sync();},{threshold:.03});observer.observe(station.querySelector('.keepsake-stage'));
 const discardFile=()=>{cachedFile=null;download.hidden=true;download.removeAttribute('href');player.pause();player.hidden=true;player.removeAttribute('src');player.load();canvas.hidden=false;if(objectUrl){URL.revokeObjectURL(objectUrl);objectUrl=null;}sync();};
 const enteredName=()=>nameInput.value.trim().replace(/\s+/g,' ');
 const updateName=()=>{const name=enteredName();data.name=name||'Your name';nameInput.setCustomValidity('');if(cachedFile&&cachedName!==name)discardFile();canvas.setAttribute('aria-label',`${data.name} — personal Anazori keepsake. Not valid for event entry.`);player.setAttribute('aria-label',`${data.name} — Anazori keepsake video. Not valid for event entry.`);status.textContent=mime?'':mp4Unavailable;draw();};
 nameInput.addEventListener('input',updateName);
 nameInput.addEventListener('change',updateName);updateName();
 const fonts=renderer.ready;
 fonts.then(()=>{rendererReady=true;draw();sync();});
 fonts.finally(()=>{saveButton.disabled=!mime;if(!mime)status.textContent=mp4Unavailable;}).catch(()=>{});
 pauseButton.addEventListener('click',()=>{if(!motionAllowed()){paused=false;if(reduced.matches||document.documentElement.classList.contains('motion-paused')||document.body.dataset.sceneMotion==='off'){status.textContent='Motion is paused in your preferences.';return;}}else paused=true;sync();});
 document.addEventListener('anazori:motion',sync);reduced.addEventListener('change',sync);
 document.addEventListener('visibilitychange',()=>{if(document.hidden&&exporting)cancelExport?.(new Error('Keep this tab open while your video is created.'));sync();});
 function recordVideo(ticket){
  return new Promise((resolve,reject)=>{
   const output=document.createElement('canvas');output.width=1920;output.height=1080;const captureRenderer=createMotionCardRenderer(output,ticket);
   let stream,recorder,frame=0,watchdog=0,done=false,started=0;const chunks=[];
   const cleanup=()=>{clearTimeout(watchdog);cancelAnimationFrame(frame);captureRenderer.destroy();stream?.getTracks().forEach(track=>track.stop());cancelExport=null;};
   const fail=error=>{if(done)return;done=true;if(recorder?.state==='recording')recorder.stop();cleanup();reject(error);};cancelExport=fail;
   (async()=>{
    await captureRenderer.ready;if(done)return;await captureRenderer.draw(ticket,0);if(done)return;stream=output.captureStream(30);recorder=new MediaRecorder(stream,{mimeType:mime,videoBitsPerSecond:8000000});
    recorder.ondataavailable=event=>{if(event.data.size)chunks.push(event.data);};recorder.onerror=()=>fail(new Error('Could not create your video. Please try again.'));
    recorder.onstop=async()=>{if(done)return;done=true;cleanup();try{status.textContent='Finishing your video…';resolve(await mp4DownloadFile(new Blob(chunks,{type:recorder.mimeType||mime}),{expectedDuration:CARD_DURATION/1000}));}catch(error){reject(error);}};
    recorder.onstart=()=>{started=performance.now();const render=async now=>{if(done)return;const time=Math.min(now-started,CARD_DURATION);await captureRenderer.draw(ticket,time);if(done)return;progress.value=Math.round(time/CARD_DURATION*100);if(time>=CARD_DURATION){recorder.stop();return;}frame=requestAnimationFrame(render);};frame=requestAnimationFrame(render);};
    recorder.start(250);watchdog=setTimeout(()=>fail(new Error('Video creation took too long. Keep this tab open and try again.')),25000);
   })().catch(fail);
  });
 }
 const saveFile=()=>download.click();
 async function exportTicket(){
  if(exporting||!mime)return;
  const name=enteredName();nameInput.setCustomValidity(name?'':'Enter your name to download your ticket.');if(!form.reportValidity())return;
  updateName();exporting=true;saveButton.disabled=true;nameInput.disabled=true;station.setAttribute('aria-busy','true');status.textContent='Preparing your ticket…';
  try{
   if(!cachedFile){
    await fonts;if(document.hidden)throw new Error('Keep this tab open while your video is created.');
    progress.hidden=false;progress.value=0;saveButton.textContent='Creating your video…';status.textContent='Keep this tab open for a moment.';
    cachedFile=await recordVideo({...data,name});cachedName=name;objectUrl=URL.createObjectURL(cachedFile);player.src=objectUrl;player.hidden=false;canvas.hidden=true;sync();
   }
   download.href=objectUrl;download.download=cachedFile.name;download.hidden=false;saveFile();status.textContent='Your MP4 keepsake is ready.';
  }catch(error){status.textContent=error.message||'Could not create your ticket. Please try again.';}
  finally{exporting=false;station.removeAttribute('aria-busy');saveButton.disabled=!mime;nameInput.disabled=false;saveButton.innerHTML='Download MP4 <span aria-hidden="true">↓</span>';progress.hidden=true;}
 }
 form.addEventListener('submit',event=>{event.preventDefault();exportTicket();});
 window.addEventListener('pagehide',event=>{cancelExport?.(new Error('Video creation was interrupted.'));cancelAnimationFrame(raf);raf=0;playVersion++;if(!event.persisted)renderer.destroy();});
 window.addEventListener('pageshow',()=>{updateName();if(!mime)status.textContent=mp4Unavailable;sync();});
}
