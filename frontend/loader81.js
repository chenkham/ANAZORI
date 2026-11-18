// Runs before styles: a small, independent boot gate also recovers from module failures.
(()=>{const root=document.documentElement,start=performance.now();let closed=false;
 root.classList.add('festival-loading81');
 function finish(){if(closed)return;closed=true;clearTimeout(failsafe);root.classList.remove('festival-loading81');document.querySelector('#festival-loader')?.remove();document.dispatchEvent(new CustomEvent('anazori:ready'));}
 const failsafe=setTimeout(finish,8000);
 addEventListener('pageshow',event=>{if(event.persisted)finish();});
 document.addEventListener('DOMContentLoaded',async()=>{
  document.querySelector('#loader-continue81')?.addEventListener('click',finish,{once:true});
  setTimeout(()=>{const button=document.querySelector('#loader-continue81');if(button)button.hidden=false;},2500);
  const images=[...document.images].filter(img=>img.loading!=='lazy'&&img.getBoundingClientRect().top<innerHeight).slice(0,6);
  const ready=Promise.allSettled([document.fonts?.ready,...images.map(img=>img.decode?.())]);
  await Promise.race([ready,new Promise(resolve=>setTimeout(resolve,2400))]);
  setTimeout(finish,Math.max(0,650-(performance.now()-start)));
 },{once:true});
})();
