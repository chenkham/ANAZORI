export function updateDynamicPayment108(form,entry){
 form.querySelectorAll('[data-dynamic-payment108]').forEach(row=>{
  const image=row.querySelector('[data-dynamic-qr108]'),open=row.querySelector('[data-dynamic-qr-link108]'),save=row.querySelector('[data-save-dynamic108]');
  const ready=Boolean(entry?.qr_url&&!row.hidden);
  image.hidden=!ready;
  if(ready){if(image.getAttribute('src')!==entry.qr_url)image.src=entry.qr_url;open.href=entry.qr_url;save.href=entry.qr_url;row.querySelector('[data-upi-pay]').href=entry.upi_url;}
  else{image.removeAttribute('src');open.removeAttribute('href');save.removeAttribute('href');row.querySelector('[data-upi-pay]').removeAttribute('href');}
  row.querySelector('[data-payment-reference108]').textContent=ready?'Form reference: '+form.dataset.paymentReference108:'';
  row.querySelector('[data-linked-ticket-amount]').textContent=ready?entry.label+' · Pay '+new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR'}).format(entry.price/100):'Choose a paid ticket to see its QR.';
 });
}

/** The existing PHP QR renderer supplies SVG; save a phone-gallery-friendly PNG. */
export async function downloadPaymentPng108(url){
 const target=new URL(url,location.href);if(target.origin!==location.origin||target.pathname!=='/payment-qr.php')throw Error('Payment QR unavailable.');
 const response=await fetch(target,{credentials:'same-origin',cache:'no-store'});if(!response.ok||!response.headers.get('content-type')?.includes('image/svg+xml'))throw Error('Payment QR unavailable. Reload and choose your ticket again.');
 const source=URL.createObjectURL(await response.blob());
 try{
  const image=new Image();image.src=source;await image.decode();
  const canvas=document.createElement('canvas');canvas.width=canvas.height=800;const context=canvas.getContext('2d');
  if(!context)throw Error('This browser cannot save the QR. Open it and take a screenshot instead.');
  context.fillStyle='#fff';context.fillRect(0,0,800,800);context.drawImage(image,0,0,800,800);
  const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));if(!blob)throw Error('QR image could not be saved. Try again.');
  const result=URL.createObjectURL(blob),link=document.createElement('a');link.href=result;link.download='anazori-payment.png';link.click();setTimeout(()=>URL.revokeObjectURL(result),2000);
 }finally{URL.revokeObjectURL(source);}
}
