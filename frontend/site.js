import {initPerformance81} from './performance81.js';
import {initGameRegistration105} from './game-registration105.js';
import {initGameForms81} from './game-forms81.js';
import {initAdaptiveMotion95} from './adaptive-motion95.js';
import {initTicketReveal95} from './qr-reveal95.js';
initAdaptiveMotion95();
initGameForms81(document.querySelector('#interest-form'));
(() => {
'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const reduced = matchMedia('(prefers-reduced-motion: reduce)');
const read = (key,fallback) => { try {return localStorage.getItem(key) ?? fallback;} catch {return fallback;} };
const write = (key,value) => {try {localStorage.setItem(key,value);} catch {}};
let motionPaused = read('anazori-motion','') === 'paused' || reduced.matches;
function applyMotion(){document.documentElement.classList.toggle('motion-paused',motionPaused);$$('.motion-toggle').forEach(b=>{b.setAttribute('aria-pressed',String(motionPaused));b.innerHTML=motionPaused?'Resume motion <span>▷</span>':'Pause motion <span>Ⅱ</span>';});document.dispatchEvent(new CustomEvent('anazori:motion',{detail:{paused:motionPaused}}));}
applyMotion();
$$('.motion-toggle').forEach(b=>b.addEventListener('click',()=>{motionPaused=!motionPaused;write('anazori-motion',motionPaused?'paused':'on');applyMotion();}));
reduced.addEventListener('change',e=>{motionPaused=e.matches;applyMotion();});
document.addEventListener('anazori:resume',()=>{motionPaused=false;write('anazori-motion','on');applyMotion();});
const menu=$('.menu-button'),mobile=$('#mobile-menu');
const menuBackdrop=$('.menu-backdrop');let menuCloseTimer;
function closeMenu(){if(!menu||!mobile)return;menu.setAttribute('aria-expanded','false');menu.setAttribute('aria-label','Open navigation');document.body.classList.remove('navigation-open');mobile.inert=true;mobile.classList.add('is-closing');clearTimeout(menuCloseTimer);menuCloseTimer=setTimeout(()=>{mobile.hidden=true;mobile.classList.remove('is-closing');if(menuBackdrop)menuBackdrop.hidden=true;},reduced.matches?0:220);}
menu?.addEventListener('click',()=>{if(menu.getAttribute('aria-expanded')==='true'){closeMenu();return;}clearTimeout(menuCloseTimer);mobile.classList.remove('is-closing');mobile.hidden=false;mobile.inert=false;if(menuBackdrop)menuBackdrop.hidden=false;document.body.classList.add('navigation-open');menu.setAttribute('aria-expanded','true');menu.setAttribute('aria-label','Close navigation');});
mobile?.addEventListener('click',e=>{if(e.target.closest('a'))closeMenu();});
document.addEventListener('keydown',e=>{if(menu?.getAttribute('aria-expanded')!=='true')return;if(e.key==='Escape'){closeMenu();menu.focus();}if(e.key==='Tab'){const items=[menu,...mobile.querySelectorAll('a')],first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}});
document.addEventListener('click',e=>{if(menu?.getAttribute('aria-expanded')==='true'&&!e.target.closest('#mobile-menu,.menu-button'))closeMenu();});
matchMedia('(min-width:961px)').addEventListener('change',e=>{if(e.matches)closeMenu();});
let toastTimer;
function toast(text){const box=$('.toast');box.textContent=text;box.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>box.hidden=true,4500);}
function openDialog(dialog){if(!dialog)return;dialog.showModal();document.body.classList.add('modal-open');}
$$('dialog').forEach(dialog=>{
 dialog.querySelectorAll('.dialog-close,.dialog-done').forEach(b=>b.addEventListener('click',()=>dialog.close()));
 dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close();}});
 dialog.addEventListener('close',()=>{document.body.classList.remove('modal-open');dialog.querySelector('video')?.pause();});
});
document.querySelectorAll('[data-interest]').forEach(b=>b.addEventListener('click',()=>openDialog($('#interest-dialog'))));
initGameRegistration105();
const filterButtons=$$('[data-filter]'),search=$('#event-search'),cards=$$('.event-list .event-card');
if(filterButtons.length){
 const params=new URLSearchParams(location.search);
 let category=filterButtons.some(b=>b.dataset.filter===params.get('category'))?params.get('category'):'all';
 if(search)search.value=params.get('q')||'';
 const items=cards.length?cards:$$('.gallery-item');
 function filter(updateUrl=true){
  let count=0;const query=(search?.value||'').trim().toLowerCase();
  filterButtons.forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.filter===category)));
  items.forEach(card=>{const visible=(category==='all'||card.dataset.category===category)&&(!query||(card.dataset.title||'').includes(query));card.hidden=!visible;if(visible)count++;});
  const status=$('#filter-status');if(status)status.textContent=count+' '+(cards.length?'experiences':'photos');
  const empty=$('.empty-state');if(empty)empty.hidden=count!==0;
  if(updateUrl){const url=new URL(location.href);category==='all'?url.searchParams.delete('category'):url.searchParams.set('category',category);query?url.searchParams.set('q',query):url.searchParams.delete('q');history.replaceState(null,'',url);}
 }
 filterButtons.forEach(b=>b.addEventListener('click',()=>{category=b.dataset.filter;filter();}));
 search?.addEventListener('input',()=>filter());
 $('#reset-filters')?.addEventListener('click',()=>{category='all';if(search)search.value='';filter();});
 window.addEventListener('pageshow',()=>filter(false));
 filter(false);
}
const gallery=$$('.gallery-item'),lightbox=$('#gallery-dialog');
if(lightbox){
 let active=0;
 const visible=()=>gallery.filter(b=>!b.hidden);
 const update=()=>{const list=visible();active=(active+list.length)%list.length;const item=list[active];const img=$('#lightbox-image');img.src=item.dataset.full;img.alt=item.dataset.caption;$('#lightbox-caption').textContent=item.dataset.caption;$('#lightbox-count').textContent=String(active+1).padStart(2,'0')+' / '+String(list.length).padStart(2,'0');};
 gallery.forEach(b=>b.addEventListener('click',()=>{active=visible().indexOf(b);update();openDialog(lightbox);}));
 $('#gallery-prev').addEventListener('click',()=>{active--;update();});
 $('#gallery-next').addEventListener('click',()=>{active++;update();});
 lightbox.addEventListener('keydown',e=>{if(e.key==='ArrowLeft'){e.preventDefault();active--;update();}if(e.key==='ArrowRight'){e.preventDefault();active++;update();}});
 let touchX=null;
 lightbox.addEventListener('touchstart',e=>touchX=e.touches[0].clientX,{passive:true});
 lightbox.addEventListener('touchend',e=>{if(touchX===null)return;const distance=e.changedTouches[0].clientX-touchX;if(Math.abs(distance)>60){active+=distance>0?-1:1;update();}touchX=null;},{passive:true});
}
$$('[data-share]').forEach(b=>b.addEventListener('click',async()=>{
 const url=location.href;
 try{if(navigator.share){await navigator.share({title:document.title,url});}else{await navigator.clipboard.writeText(url);toast('Experience link copied. Share the spark.');}}
 catch(error){if(error.name==='AbortError')return;toast('Copy this page’s address to share the experience.');}
}));
const form=$('#interest-form');
form?.addEventListener('submit',async e=>{
 e.preventDefault();if(!form.reportValidity())return;
 const button=form.querySelector('[type=submit]'),message=$('#form-message');button.disabled=true;const label=button.innerHTML;button.textContent='Making the connection…';message.textContent='';
 try{
  const response=await fetch(form.action,{method:'POST',credentials:'same-origin',body:new FormData(form),headers:{Accept:'application/json'},signal:AbortSignal.timeout(120000)});
  let result;try{result=await response.json();}catch{throw new Error('The service is unavailable. Your interest has not been confirmed. Please try again.');}
  if(!response.ok||!result.success)throw new Error(result.error||'We could not save your details. Please try again.');
  $('#interest-reference').textContent=result.reference;if(result.message)$('#interest-success .small-note').textContent=result.message;$('#interest-content').hidden=true;$('#interest-success').hidden=false;$('#interest-dialog').setAttribute('aria-label','Details saved');$('#interest-dialog').removeAttribute('aria-labelledby');$('#interest-success .dialog-done').focus();form.reset();
 }catch(error){message.textContent=error.name==='TimeoutError'?'The request took too long. Retry with the same details to check your acknowledgement.':error instanceof TypeError?'We could not connect. Check your connection and try again.':error.message;}
 finally{button.disabled=false;button.innerHTML=label;}
});
initPerformance81();
})();
initTicketReveal95();
