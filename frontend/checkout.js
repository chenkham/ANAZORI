import {updateDynamicPayment108,downloadPaymentPng108} from './dynamic-payment108.js';
import {initRegistrationConditions} from './registration-conditions.js';
import {initRegistrationAutosave} from './registration-autosave88.js';
import {initPaymentReveal95} from './qr-reveal95.js';
const form=document.querySelector('#checkout-form');
const message=document.querySelector('#checkout-message');
const money=amount=>new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR'}).format(amount/100);
let saveProgress=async()=>{},reportDraftError=()=>{},submitted=false,submitting=false;
if(form){
 const entryMap=JSON.parse(form.dataset.entryMap||'{}');
 const autosave=initRegistrationAutosave(form,()=>submitted);
 saveProgress=autosave.save;reportDraftError=autosave.report;
 initRegistrationConditions(form);
 function updateTotal(){
  const type=form.querySelector('[name="type"]:checked')?.value||form.querySelector('[name="type"][type="hidden"]')?.value||'';
  const selected=entryMap[type],fixed=document.querySelector('#checkout-total').dataset.fixedAmount;
  const amount=fixed!==''?Number(fixed):selected?.price;
  const chosen=Boolean(type),ready=selected?.qr_ready!==false;
  form.querySelector('[data-category-prompt]').hidden=chosen;
  form.querySelector('[data-category-label]').textContent=selected?.label||'Choose a category';
  form.querySelector('button[type=submit]').disabled=!chosen||!ready;
  const paymentStatus=form.querySelector('[data-ticket-payment-status]');paymentStatus.hidden=!chosen||ready;paymentStatus.textContent='The team is updating the payment QR for this ticket. Please contact the event coordinator before paying.';
  form.querySelectorAll('[data-linked-ticket-amount]').forEach(label=>{const ticket=entryMap[label.closest('[data-field-ticket]').dataset.fieldTicket];label.textContent=ticket?`${ticket.label} · Pay ${money(fixed!==''?Number(fixed):ticket.price)}`:'';});
  document.querySelector('#checkout-total').textContent=amount===undefined?'Choose a ticket':money(amount);
  const methods=form.querySelector('#payment-method-options');
  if(methods){methods.hidden=!amount;methods.querySelectorAll('input').forEach(input=>{input.disabled=!amount;input.required=Boolean(amount);});}
  form.querySelectorAll('[data-upi-pay]').forEach(link=>{
   if(link.closest('[data-dynamic-payment108]'))return;
   const query=new URLSearchParams({pa:link.dataset.upiPay,pn:link.dataset.payName||'Anazori',cu:'INR',tn:form.dataset.paymentReference108?`Form ${form.dataset.paymentReference108}`:`Anazori ${form.elements.event.value}`});
   if(form.dataset.paymentReference108)query.set('tr',form.dataset.paymentReference108);
   if(amount!==undefined)query.set('am',(amount/100).toFixed(2));link.href='upi://pay?'+query;
  });
  updateDynamicPayment108(form,selected);
 }
 updateTotal();form.addEventListener('change',updateTotal);
 initPaymentReveal95(form,()=>saveProgress(true));
 form.querySelectorAll('[data-payment-action]').forEach(link=>link.addEventListener('click',async event=>{
  event.preventDefault();const url=link.href;
  try{
   await saveProgress(true);
   if(link.hasAttribute('data-save-dynamic108'))await downloadPaymentPng108(url);
   else if(link.hasAttribute('download')){const download=document.createElement('a');download.href=url;download.download=link.getAttribute('download')||'';download.click();}
   else location.assign(url);
  }catch(error){autosave.report(error);form.querySelector('[data-draft-error]')?.scrollIntoView({block:'center'});}
 }));
 form.addEventListener('submit',async event=>{
  event.preventDefault();if(submitting||submitted)return;submitting=true;const button=form.querySelector('[type="submit"]');button.disabled=true;
  try{
   await saveProgress(true);
   submitted=true;message.hidden=false;message.textContent='Submitting your registration…';
   const data=new FormData(form);data.set('response_format','json');
   const response=await fetch(form.action,{method:'POST',body:data,credentials:'same-origin',headers:{Accept:'application/json'}}),result=await response.json();
   if(!response.ok||!result.ok)throw Error(result.error||'Registration could not be submitted.');
   autosave.finish();location.assign(result.url);
  }catch(error){submitted=false;message.hidden=false;message.textContent=error.message;autosave.remember();}finally{submitting=false;button.disabled=false;}
 });
}
document.querySelector('#print-ticket')?.addEventListener('click',()=>window.print());

const gameNavigation=document.querySelector('[data-game-navigation]');
if(gameNavigation){let navigating=false;gameNavigation.addEventListener('submit',async event=>{
 if(navigating)return;event.preventDefault();if(!gameNavigation.reportValidity())return;
 const button=gameNavigation.querySelector('button');button.disabled=true;
 try{await saveProgress(true);navigating=true;gameNavigation.requestSubmit();}catch(error){reportDraftError(error);form?.querySelector('[data-draft-error]')?.scrollIntoView({block:'center'});}finally{button.disabled=false;}
});gameNavigation.querySelector('select').addEventListener('change',()=>gameNavigation.requestSubmit());}
