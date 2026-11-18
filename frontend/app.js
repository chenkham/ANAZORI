import {gsap} from 'gsap';
import {ScrollTrigger} from 'gsap/ScrollTrigger';
import {createIcons,ArrowUpRight,ArrowRight,Orbit,Map,VolumeX,Volume2,SlidersHorizontal,Menu,Layers2,CirclePlay,Code2,AudioLines,Lightbulb,Fingerprint,Gem,Radio,Gamepad2,Shapes,Cpu,ShieldCheck,X,Download} from 'lucide';
import {Soundscape} from './audio.js';
const icons={ArrowUpRight,ArrowRight,Orbit,Map,VolumeX,Volume2,SlidersHorizontal,Menu,Layers2,CirclePlay,Code2,AudioLines,Lightbulb,Fingerprint,Gem,Radio,Gamepad2,Shapes,Cpu,ShieldCheck,X,Download};
const iconize=()=>createIcons({icons});iconize();gsap.registerPlugin(ScrollTrigger);
const $=(s)=>document.querySelector(s), $$=(s)=>[...document.querySelectorAll(s)];
const base=document.body.dataset.base||'',prefsKey='anazori-experience-v1',collectionKey='anazori-gamosas-v1';
const zoneIds=['hub','tech','culture','workshops','heritage'];
const zoneData={hub:['The central portal','The heart of Neo-Axom. Follow a light to discover your next experience.'],tech:['The tech dome','Build something bold. Find hackathons, code, and your next esports squad.'],culture:['Sanskriti arena','Our roots. A new rhythm. Find music, performance, and indigenous design.'],workshops:['The idea islands','Come curious. Explore AI, machine learning, and cybersecurity workshops.'],heritage:['Our roots','Meet the CCSA community at Dibrugarh University — the people behind Anazori.']};
const read=(key,fallback)=>{try{return JSON.parse(localStorage.getItem(key))??fallback;}catch{return fallback;}};
const save=(key,value)=>{try{localStorage.setItem(key,JSON.stringify(value));}catch{}};
const prefs={weather:'dusk',quality:'auto',volume:.25,contrast:false,reduced:matchMedia('(prefers-reduced-motion:reduce)').matches,light:!!navigator.connection?.saveData,chromatic:false,...read(prefsKey,{})};
let collected=new Set((Array.isArray(read(collectionKey,[]))?read(collectionKey,[]):[]).filter(id=>zoneIds.includes(id)));
let world=null,worldPromise=null,currentZone='hub',exploring=false,arrived=true,toastTimer=null;
const audio=new Soundscape(prefs.volume);
function persist(){save(prefsKey,prefs);}
function toast(message){$('#toast').textContent=message;$('#toast').classList.add('visible');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').classList.remove('visible'),4500);}
function openDialog(id){const dialog=$(`#${id}-dialog`);if(!dialog)return;dialog.showModal();document.body.style.overflow='hidden';if(!prefs.reduced)gsap.fromTo(dialog,{opacity:0,y:20},{opacity:1,y:0,duration:.3,ease:'power2.out',clearProps:'transform'});}
$$('[data-open]').forEach(button=>button.addEventListener('click',()=>openDialog(button.dataset.open)));
$$('dialog').forEach(dialog=>{dialog.querySelector('.dialog-close').addEventListener('click',()=>dialog.close());dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close();}});dialog.addEventListener('close',()=>{document.body.style.overflow='';dialog.querySelector('video')?.pause();});});
$('.mobile-menu').addEventListener('click',()=>{const expanded=$('.mobile-menu').getAttribute('aria-expanded')==='true';$('.mobile-menu').setAttribute('aria-expanded',String(!expanded));$('#mobile-nav').hidden=expanded;});
$$('#mobile-nav a,#mobile-nav button').forEach(a=>a.addEventListener('click',()=>{$('#mobile-nav').hidden=true;$('.mobile-menu').setAttribute('aria-expanded','false');}));
function filter(category){$$('[data-filter]').forEach(b=>{const active=b.dataset.filter===category;b.classList.toggle('selected',active);b.setAttribute('aria-pressed',String(active));});$$('.event-card').forEach(card=>card.hidden=category!=='all'&&card.dataset.category!==category);ScrollTrigger.refresh();}
$$('[data-filter]').forEach(b=>b.addEventListener('click',()=>filter(b.dataset.filter)));
function browseZone(id){if(id==='heritage'){$('#heritage').scrollIntoView({behavior:prefs.reduced?'instant':'smooth'});return;}filter(id==='hub'?'all':id==='workshops'?'workshops':id);$('#programme').scrollIntoView({behavior:prefs.reduced?'instant':'smooth'});}
function updateZone(id){currentZone=id;$('#zone-name').textContent=zoneData[id][0];$('#zone-description').textContent=zoneData[id][1];$('#zone-action').innerHTML=`${id==='heritage'?'Meet the community':'Explore programmes'} <i data-lucide="arrow-up-right"></i>`;$$('.destination').forEach(a=>{const selected=a.dataset.zone===id;a.classList.toggle('selected',selected);selected?a.setAttribute('aria-current','true'):a.removeAttribute('aria-current');});updateCollection();iconize();}
function updateCollection(){
  $('#collection-count').textContent=`${collected.size} / 5`;
  $('#collect-crystal').disabled=!arrived||collected.has(currentZone);
  $('#collect-crystal').innerHTML=`<i data-lucide="gem"></i> ${!arrived?'Flying to your next island…':collected.has(currentZone)?'Data-Gamosa collected on this island':'Collect this island’s Data-Gamosa'}`;
  $('#badge-slots').replaceChildren(...zoneIds.map((id,index)=>{const slot=document.createElement('span');slot.className=`badge-slot ${collected.has(id)?'found':''}`;slot.title=`${zoneData[id][0]}: ${collected.has(id)?'collected':'not collected'}`;slot.setAttribute('aria-label',slot.title);slot.textContent=collected.has(id)?'◇':`0${index+1}`;return slot;}));
  $('#download-badge').hidden=collected.size!==5;
  $('#badge-title').textContent=collected.size===5?'Neo-Axom Explorer.':'Follow your curiosity.';
  $('#badge-description').textContent=collected.size===5?'Five islands. Five connections. You’ve discovered every corner of Neo-Axom. This little piece of Anazori is yours.':'Collect a Data-Gamosa on each of the five islands to earn your Neo-Axom Explorer badge.';
  iconize();
}
function collect(id){if(collected.has(id))return;collected.add(id);save(collectionKey,[...collected]);world?.collect(id);updateCollection();audio.tone(880,.5,.06);toast(collected.size===5?'All five found. Your Neo-Axom Explorer badge is unlocked!':`Data-Gamosa found at ${zoneData[id][0].toLowerCase()}. ${collected.size} of 5 collected.`);if(collected.size===5)openDialog('badge');}
$('#collect-crystal').addEventListener('click',()=>{if(arrived)collect(currentZone);});
$('#download-badge').addEventListener('click',()=>{if(collected.size!==5)return;const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000"><rect width="1000" height="1000" rx="60" fill="#12232c"/><rect x="35" y="35" width="930" height="930" rx="40" fill="none" stroke="#dfff99" stroke-width="2"/><g fill="none" stroke="#dfff99" stroke-width="5"><path d="M300 480 500 180 700 480 500 550ZM300 480 500 390 700 480M500 180V550"/><circle cx="500" cy="390" r="250" opacity=".2"/></g><g text-anchor="middle" font-family="sans-serif"><text x="500" y="665" fill="#dfff99" font-size="26" letter-spacing="6">NEO-AXOM EXPLORER</text><text x="500" y="760" fill="#f1f1e9" font-size="72" font-weight="bold">ANAZORI</text><text x="500" y="830" fill="#acbec0" font-size="22">FIVE ISLANDS. ONE SHARED SPIRIT.</text><text x="500" y="915" fill="#acbec0" font-size="18">CCSA · DIBRUGARH UNIVERSITY</text></g></svg>`;const url=URL.createObjectURL(new Blob([svg],{type:'image/svg+xml'}));const link=document.createElement('a');link.href=url;link.download='Anazori-Neo-Axom-Explorer.svg';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
async function loadWorld(){
  if(world)return world;if(worldPromise)return worldPromise;
  $('#render-status').textContent='PREPARING YOUR WORLD';
  worldPromise=import('./world.js').then(({createWorld})=>{world=createWorld($('#world-canvas'),prefs,{onTravel:travel,onArrive:id=>{arrived=true;updateZone(id);},onQuality:text=>$('#render-status').textContent=text,onFailure:message=>{setLight(true);toast(message);}});for(const id of collected)world.collect(id);world.setPaused(prefs.light);$('#render-status').textContent=prefs.light?'LIGHT EXPERIENCE':'LIVE 3D WORLD';return world;}).catch(error=>{console.warn('3D world unavailable:',error);worldPromise=null;setLight(true);toast('Light experience enabled. All programmes are available below.');return null;});return worldPromise;
}
async function travel(id){
  if(!zoneIds.includes(id))return;
  $$('dialog[open]').forEach(d=>d.close());
  if(prefs.light){updateZone(id);collect(id);browseZone(id);return;}
  const scene=await loadWorld();if(!scene){browseZone(id);return;}
  exploring=true;arrived=false;$('#world').classList.add('exploring');$('.exploration-hud').hidden=false;$('.hero-copy').inert=true;$('#joystick').hidden=!(matchMedia('(pointer:coarse)').matches||navigator.maxTouchPoints>0);
  updateZone(id);$('#world').scrollIntoView({behavior:prefs.reduced?'instant':'smooth'});scene.travel(id);audio.travel();
}
$$('[data-zone]').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();travel(a.dataset.zone);}));
$('#explore-world').addEventListener('click',()=>travel('hub'));$('#zone-action').addEventListener('click',()=>browseZone(currentZone));
function leave(){exploring=false;$('#world').classList.remove('exploring');$('.exploration-hud').hidden=true;$('.hero-copy').inert=false;$('#joystick').hidden=true;world?.home();updateZone('hub');}
$('#leave-explore').addEventListener('click',()=>{leave();$('#explore-world').focus({preventScroll:true});});$('#home-view').addEventListener('click',()=>{leave();$('#world').scrollIntoView();});
// Each pointer owns its control. A second finger may steer the camera while the joystick stays captured.
let stickPointer=null;const stick=$('#joystick');
function moveStick(e){if(e.pointerId!==stickPointer)return;const r=stick.getBoundingClientRect(),x=(e.clientX-r.left-r.width/2)/(r.width*.35),z=(e.clientY-r.top-r.height/2)/(r.height*.35);const length=Math.max(1,Math.hypot(x,z));world?.joystick(x/length,z/length);stick.firstElementChild.style.transform=`translate(${x/length*22}px,${z/length*22}px)`;}
stick.addEventListener('pointerdown',e=>{if(stickPointer!==null)return;stickPointer=e.pointerId;stick.setPointerCapture(e.pointerId);moveStick(e);});stick.addEventListener('pointermove',moveStick);for(const name of ['pointerup','pointercancel','lostpointercapture'])stick.addEventListener(name,e=>{if(e.pointerId===stickPointer){stickPointer=null;world?.joystick(0,0);stick.firstElementChild.style.transform='';}});
function setLight(value){prefs.light=value;document.body.classList.toggle('light-mode',value);$('#light-mode').checked=value;$('#mode-toggle').setAttribute('aria-pressed',String(value));$('#mode-toggle').innerHTML=`${value?'Switch to 3D world':'Switch to light mode'} <i data-lucide="layers-2"></i>`;$('#render-status').textContent=value?'LIGHT EXPERIENCE':'LIVE 3D WORLD';if(value){leave();world?.setPaused(true);}else{loadWorld().then(scene=>scene?.setPaused(false));}persist();iconize();}
$('#mode-toggle').addEventListener('click',()=>setLight(!prefs.light));$('#light-mode').addEventListener('change',e=>setLight(e.target.checked));
$('#atmosphere').value=prefs.weather;$('#atmosphere').addEventListener('change',e=>{prefs.weather=e.target.value;world?.setWeather(prefs.weather);document.body.dataset.weather=prefs.weather;persist();});
$('#quality').value=prefs.quality;$('#quality').addEventListener('change',e=>{prefs.quality=e.target.value;world?.setQuality(prefs.quality);persist();});
$('#volume').value=prefs.volume*100;$('#volume').addEventListener('input',e=>{prefs.volume=Number(e.target.value)/100;audio.setVolume(prefs.volume);persist();});
for(const [id,key,className] of [['contrast','contrast','high-contrast'],['reduce-motion','reduced','reduced-motion'],['chromatic','chromatic','chromatic']]){$(`#${id}`).checked=!!prefs[key];document.body.classList.toggle(className,!!prefs[key]);$(`#${id}`).addEventListener('change',e=>{prefs[key]=e.target.checked;document.body.classList.toggle(className,prefs[key]);if(key==='reduced')world?.setReduced(prefs.reduced);persist();});}
async function toggleSound(){try{if(audio.enabled){audio.disable();prefs.sound=false;}else{prefs.sound=await audio.enable();}$('#sound-toggle').setAttribute('aria-pressed',String(audio.enabled));$('#sound-toggle').setAttribute('aria-label',audio.enabled?'Mute ambient sound':'Enable ambient sound');$('#sound-toggle').innerHTML=`<i data-lucide="${audio.enabled?'volume-2':'volume-x'}"></i><span>SOUND</span>`;persist();iconize();}catch{toast('Audio is unavailable in this browser.');}}
$('#sound-toggle').addEventListener('click',toggleSound);
// A saved sound preference is applied on the next explicit interaction, respecting autoplay rules.
if(prefs.sound)document.addEventListener('pointerdown',e=>{if(!e.target.closest('#sound-toggle')&&!audio.enabled)toggleSound();},{once:true});
document.addEventListener('pointerover',e=>{if(e.target.closest('button,a'))audio.tone(540,.04,.007);});document.addEventListener('visibilitychange',()=>{if(!audio.context)return;if(document.hidden)audio.context.suspend();else if(audio.enabled)audio.context.resume().catch(()=>{});});
$$('[data-register]').forEach(button=>button.addEventListener('click',()=>{$('#register-form select').value=button.dataset.register;$('#register-form .form-message').textContent='';openDialog('register');}));
function bindForm(id,endpoint){const form=$(id);form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;const submit=form.querySelector('[type=submit]'),message=form.querySelector('.form-message');submit.disabled=true;message.classList.remove('error');message.textContent='Saving…';const values=Object.fromEntries(new FormData(form));if('consent' in values)values.consent=values.consent==='on';try{const response=await fetch(`${base}/api/${endpoint}.php`,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':$('meta[name=csrf-token]').content},body:JSON.stringify(values),signal:AbortSignal.timeout(15000)});const result=await response.json();if(!response.ok)throw new Error(result.error||'Unable to save. Please try again.');message.textContent=result.message+(result.reference?` Your reference: ${result.reference}`:'');form.reset();audio.tone(660,.5,.04);}catch(error){message.classList.add('error');message.textContent=error.name==='TimeoutError'?'The request timed out. Please check your connection before trying again.':error.message==='Failed to fetch'?'We couldn’t connect. Your entry has not been confirmed. Please try again.':error.message;}finally{submit.disabled=false;}});}
bindForm('#register-form','register');bindForm('#feedback-form','feedback');
const start=Date.parse(document.body.dataset.start);let countdownTimer;if(Number.isFinite(start)){const tick=()=>{const ms=start-Date.now();$('#countdown').textContent=ms>0?`${Math.floor(ms/86400000)}d ${String(Math.floor(ms/3600000)%24).padStart(2,'0')}h ${String(Math.floor(ms/60000)%60).padStart(2,'0')}m · until we meet`:'The festival window has arrived · check the programme';};tick();countdownTimer=setInterval(tick,60000);}
if(!prefs.reduced){gsap.from('.hero-copy > *',{opacity:0,y:15,duration:.8,stagger:.08,ease:'power2.out',clearProps:'all'});gsap.from('.destination-bar',{opacity:0,y:20,duration:1,delay:.4,clearProps:'all'});}
updateCollection();setLight(prefs.light);
window.addEventListener('pagehide',e=>{if(e.persisted){world?.setPaused(true);audio.context?.suspend();}else{world?.dispose();audio.dispose();clearInterval(countdownTimer);ScrollTrigger.getAll().forEach(t=>t.kill());}});window.addEventListener('pageshow',e=>{if(e.persisted)world?.setPaused(prefs.light);});
// Read-only diagnostics for local QA; no personal data is exposed here.
window.anazoriDiagnostics=()=>({mode:prefs.light?'light':'3d',exploring,currentZone,collected:collected.size,world:world?.diagnostics()??null});
