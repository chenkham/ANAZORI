// Device hints select a starting point; sustained foreground frame pressure can
// lower detail. The user's explicit pause and reduced-motion preference win.
export function initialMotionTier95({memory,cores,compact,saveData}) {
 if(saveData||(memory&&memory<=2)||(cores&&cores<=2))return 'low';
 if(compact&&((memory&&memory<=4)||(cores&&cores<=4)||(!memory&&!cores)))return 'medium';
 return 'high';
}
export function initAdaptiveMotion95(){
 const root=document.documentElement,connection=navigator.connection;
 const coarse=matchMedia('(pointer: coarse)'),reduced=matchMedia('(prefers-reduced-motion: reduce)');
 const ceiling=initialMotionTier95({memory:navigator.deviceMemory,cores:navigator.hardwareConcurrency,compact:coarse.matches,saveData:false});
 const tiers=['low','medium','high'];let tier=connection?.saveData?'low':ceiling,frame=0,lastSample=-Infinity,lastChange=-Infinity,healthy=0,suspended=false,destroyed=false;
 const set=value=>{if(root.dataset.motionQuality===value)return;tier=value;root.dataset.motionQuality=value;document.dispatchEvent(new CustomEvent('anazori:quality',{detail:{tier:value}}));};
 set(tier);
 const stop=()=>{cancelAnimationFrame(frame);frame=0;};
 const sample=()=>{
  const now=performance.now();if(frame||now-lastSample<15000||destroyed||suspended||document.hidden||reduced.matches||root.classList.contains('motion-paused'))return;
  lastSample=now;let start=0,last=0,total=0,slow=0;
  const tick=now=>{
   frame=0;if(destroyed||suspended||document.hidden||reduced.matches||root.classList.contains('motion-paused'))return;
   if(!start)start=now;
   if(last){total++;if(now-last>40)slow++;}last=now;
   if(now-start<2200){frame=requestAnimationFrame(tick);return;}
   if(total===0||now-lastChange<30000)return;
   const pressure=total<15?1:slow/total;
   if(pressure>.22){healthy=0;const next=tiers[Math.max(0,tiers.indexOf(tier)-1)];if(next!==tier){lastChange=now;set(next);}}
   else if(pressure<.04&&++healthy>=3){healthy=0;const next=tiers[Math.min(tiers.indexOf(connection?.saveData?'low':ceiling),tiers.indexOf(tier)+1)];if(next!==tier){lastChange=now;set(next);}}
   else if(pressure>=.04)healthy=0;
  };frame=requestAnimationFrame(tick);
 };
 const visibility=()=>{if(document.hidden)stop();};
 const network=()=>{if(connection?.saveData)set('low');};
 const hide=event=>{suspended=true;stop();if(event.persisted)return;destroyed=true;removeEventListener('scroll',sample);removeEventListener('pagehide',hide);removeEventListener('pageshow',show);document.removeEventListener('visibilitychange',visibility);connection?.removeEventListener?.('change',network);};
 const show=event=>{if(event.persisted){suspended=false;lastSample=-Infinity;}};
 addEventListener('scroll',sample,{passive:true});addEventListener('pagehide',hide);addEventListener('pageshow',show);
 document.addEventListener('visibilitychange',visibility);connection?.addEventListener?.('change',network);
}
