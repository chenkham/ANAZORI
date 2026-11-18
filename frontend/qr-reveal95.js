import {downloadPaymentPng108} from './dynamic-payment108.js';
// One reusable modal, with compositor-only expansion and QR settling inspired
// by the supplied pickup-code transition. No QR tokens are cached in storage.
let reveal;
function qrReveal95(){
 if(reveal)return reveal;
 const dialog=document.createElement('dialog');dialog.className='qr-reveal95';dialog.setAttribute('aria-label','Ticket QR code');
 const close=document.createElement('button');close.type='button';close.className='qr-close95';close.innerHTML='<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="m6 6 12 12M6 18 18 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';close.setAttribute('aria-label','Close QR code');
 const panel=document.createElement('div');panel.className='qr-panel95';dialog.append(close,panel);document.body.append(dialog);
 let previous,controller,animations=[];
 const reduced=()=>matchMedia('(prefers-reduced-motion: reduce)').matches||document.documentElement.classList.contains('motion-paused');
 const clean=()=>{controller?.abort();animations.forEach(a=>a.cancel());animations=[];document.body.classList.remove('qr-open95');previous?.focus({preventScroll:true});panel.replaceChildren();};
 dialog.addEventListener('close',clean);close.addEventListener('click',()=>dialog.close());
 dialog.addEventListener('click',e=>{if(e.target===dialog)dialog.close();});
 const animate=(node,keys,options)=>{if(!node?.animate||reduced())return;const a=node.animate(keys,options);animations.push(a);a.finished.catch(()=>{});};
 const open=(trigger,content,label='Ticket QR code')=>{
  controller?.abort();animations.forEach(a=>a.cancel());animations=[];previous=trigger?.matches('a,button,input,select,textarea')?trigger:trigger?.querySelector('input,button,a')||trigger;
  const from=trigger?.getBoundingClientRect();panel.replaceChildren(content);dialog.setAttribute('aria-label',label);
  if(!dialog.open)dialog.showModal();document.body.classList.add('qr-open95');
  const to=panel.getBoundingClientRect(),low=document.documentElement.dataset.motionQuality==='low',duration=low?220:650;
  if(from)animate(panel,[{transform:`translate(${from.left+from.width/2-to.left-to.width/2}px,${from.top+from.height/2-to.top-to.height/2}px) scale(${Math.max(.12,Math.min(.9,from.width/to.width))})`,opacity:.3},{transform:'none',opacity:1}],{duration,easing:'cubic-bezier(.2,.8,.2,1)',fill:'backwards'});
  animate(content.querySelector('.ticket-qr,.native-form-media'),[{transform:`scale(${low?1.08:2.6})`,opacity:0},{transform:'scale(1)',opacity:1}],{duration:low?200:750,delay:low?0:70,easing:'cubic-bezier(.16,1,.3,1)',fill:'backwards'});
  animate(content.querySelector('.qr-details95'),[{transform:'translateY(35px)',opacity:0},{transform:'none',opacity:1}],{duration:low?180:550,delay:low?0:250,easing:'ease-out',fill:'backwards'});
  close.focus({preventScroll:true});document.dispatchEvent(new CustomEvent('anazori:motion'));
 };
 dialog.addEventListener('close',()=>document.dispatchEvent(new CustomEvent('anazori:motion')));
 addEventListener('pagehide',()=>{controller?.abort();if(dialog.open)dialog.close();});
 reveal={dialog,panel,open,request:()=>{controller?.abort();return controller=new AbortController();}};return reveal;
}
export function initTicketReveal95(){
 document.addEventListener('click',async event=>{
  const link=event.target.closest('a[data-ticket-reveal]');
  if(!link||event.defaultPrevented||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey||typeof HTMLDialogElement==='undefined')return;
  event.preventDefault();const modal=qrReveal95(),busy=document.createElement('p');busy.className='qr-loading95';busy.setAttribute('role','status');busy.textContent='Opening your ticket…';modal.open(link,busy);
  const request=modal.request();
  try{
   const response=await fetch(link.href,{credentials:'same-origin',cache:'no-store',signal:request.signal,headers:{Accept:'text/html'}});
   if(!response.ok)throw Error('Ticket unavailable');
   const documentCopy=new DOMParser().parseFromString(await response.text(),'text/html'),card=documentCopy.querySelector('.simple-event-ticket');
   if(!card?.querySelector('.ticket-qr')||card.querySelector('.ticket-id')?.textContent.trim()!==new URL(link.href).searchParams.get('id'))throw Error('Ticket unavailable');
   if(!modal.dialog.open||request.signal.aborted)return;
   card.querySelectorAll('[id]').forEach(node=>node.removeAttribute('id'));
   const brand=card.querySelector('.pass-brand'),qr=card.querySelector('.ticket-qr'),details=document.createElement('div');details.className='qr-details95';
   [...card.children].forEach(node=>{if(node!==brand&&node!==qr)details.append(node);});card.replaceChildren(brand,qr,details);
   const print=card.querySelector('button');print?.addEventListener('click',()=>window.open(link.href,'_blank','noopener'));
   modal.open(link,card,'Your entry ticket QR code');
  }catch(error){if(error.name==='AbortError')return;modal.dialog.close();location.assign(link.href);}
 });
}
export function initPaymentReveal95(form,beforePayment){
 if(!form||typeof HTMLDialogElement==='undefined')return;
 let timer;
 const selected=trigger=>{
  const input=form.querySelector('[name=type]:checked');if(!input)return;
  const row=[...form.querySelectorAll('[data-field-ticket]')].find(row=>(row.dataset.fieldTicket===input.value||row.hasAttribute('data-dynamic-payment108'))&&!row.hidden&&row.querySelector('img'));
  if(!row||row.hidden)return;
  const content=document.createElement('article');content.className='payment-qr-card95';
  const brand=document.createElement('div');brand.className='qr-brand95';
  const wordmark=document.querySelector('.brand-wordmark .anazori-wordmark');if(wordmark)brand.append(wordmark.cloneNode(true));
  const heading=document.createElement('h2');heading.textContent='Scan to pay';
  const picture=row.querySelector('img').cloneNode(true);picture.loading='eager';
  const details=document.createElement('div');details.className='qr-details95';
  const amount=document.createElement('p');amount.className='qr-amount95';amount.textContent=row.querySelector('[data-linked-ticket-amount]')?.textContent||input.closest('label').innerText;
  const note=document.createElement('p');note.textContent='Use this QR for the selected ticket category, then return to attach your payment screenshot. Payment is confirmed after coordinator review.';
  details.append(amount,note);
  row.querySelectorAll('[data-payment-action]').forEach(action=>{
   const link=action.cloneNode(true);link.addEventListener('click',async event=>{
    event.preventDefault();link.setAttribute('aria-busy','true');
    try{await beforePayment();if(link.hasAttribute('data-save-dynamic108'))await downloadPaymentPng108(link.href);else if(link.hasAttribute('download')){const download=document.createElement('a');download.href=link.href;download.download=link.getAttribute('download')||'';download.click();}else location.assign(link.href);}
    catch{note.textContent='Your progress could not be saved. Close this view and try again before paying.';}
    finally{link.removeAttribute('aria-busy');}
   });details.append(link);
  });
  const done=document.createElement('button');done.type='button';done.className='qr-continue95';done.textContent='Continue registration';done.addEventListener('click',()=>qrReveal95().dialog.close());details.append(done);
  content.append(brand,heading,picture,details);qrReveal95().open(trigger,content,'Payment QR for '+amount.textContent);
 };
 const schedule=trigger=>{clearTimeout(timer);timer=setTimeout(()=>selected(trigger),0);};
 form.addEventListener('change',e=>{if(e.target.matches('[name=type][type=radio]'))schedule(e.target.closest('.ticket-option'));});
 form.addEventListener('click',e=>{const option=e.target.closest('.ticket-option');if(option)schedule(option);});
}
