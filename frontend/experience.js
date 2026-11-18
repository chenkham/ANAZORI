export function countdownState(start,end,now=Date.now()) {
 if(!Number.isFinite(start))return {values:[0,0,0,0],phase:'unannounced'};
 const phase=now<start?'upcoming':Number.isFinite(end)&&now<end?'live':'ended';
 let seconds=Math.max(0,Math.floor(((phase==='upcoming'?start:phase==='live'?end:now)-now)/1000));
 return {values:[Math.floor(seconds/86400),Math.floor(seconds/3600)%24,Math.floor(seconds/60)%60,seconds%60],phase};
}
export function initExperience(){
 const root=document.documentElement;
 const paused=()=>root.classList.contains('motion-paused');
 initCountdown(paused);
 const canvas=document.querySelector('.hero-particles');if(!canvas)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 let width=0,height=0,frame=0,visible=true,time=0,last=0,destroyed=false,grid=null,canvasLeft=0,canvasTop=0;
 let resizeFrame=0,resizePending=false,suspended=false,viewportWidth=innerWidth,lastDpr=0;
 const pointer={x:.5,y:.5,active:false};
 const connection=navigator.connection,parent=canvas.parentElement;
 const dots=Array.from({length:innerWidth<600?26:52},(_,i)=>({x:Math.random(),y:Math.random(),r:.6+Math.random()*1.4,phase:i*.7,color:i%3===0?'#ed85da':i%3===1?'#8bddf2':'#ba9aef'}));
 const measure=()=>{const rect=canvas.getBoundingClientRect();canvasLeft=rect.left+scrollX;canvasTop=rect.top+scrollY;return rect;};
 const makeGrid=target=>{const horizon=height*.7;for(let i=-6;i<=6;i++){target.moveTo(width*.5+i*15,horizon);target.lineTo(width*.5+i*width*.16,height);}for(let i=1;i<=7;i++){const y=horizon+(height-horizon)*(i/7)**2;target.moveTo(0,y);target.lineTo(width,y);}};
 const resize=()=>{
  const rect=measure(),changed=width!==rect.width||height!==rect.height;width=rect.width;height=rect.height;
  const dpr=Math.min(devicePixelRatio||1,1.5),pixelWidth=Math.floor(width*dpr),pixelHeight=Math.floor(height*dpr);
  const densityChanged=dpr!==lastDpr;lastDpr=dpr;viewportWidth=innerWidth;
  const backingChanged=canvas.width!==pixelWidth||canvas.height!==pixelHeight;
  if(backingChanged){canvas.width=pixelWidth;canvas.height=pixelHeight;}
  ctx.setTransform(dpr,0,0,dpr,0,0);
  // The floor is static: retain exactly the same geometry without reconstructing its path every frame.
  if(changed&&typeof Path2D==='function'){grid=new Path2D();makeGrid(grid);}
  if(changed||backingChanged||densityChanged)render();
 };
 const scheduleResize=()=>{
  resizePending=true;
  if(resizeFrame||destroyed||suspended||document.hidden)return;
  resizeFrame=requestAnimationFrame(()=>{resizeFrame=0;if(destroyed||suspended||document.hidden)return;resizePending=false;resize();});
 };
 function render(){
  ctx.clearRect(0,0,width,height);
  ctx.strokeStyle='#83f4ed';ctx.lineWidth=.65;ctx.globalAlpha=.085;
  if(grid)ctx.stroke(grid);else{ctx.beginPath();makeGrid(ctx);ctx.stroke();}
  const pointerX=pointer.x*width,pointerY=pointer.y*height;
  for(const p of dots){const x=(p.x*width+Math.sin(time*.13+p.phase)*18+(pointer.x-.5)*12+width)%width;const y=(p.y*height-time*(5+p.r)+(pointer.y-.5)*10+height*100)%height;
   if(pointer.active){const dx=x-pointerX,dy=y-pointerY,squared=dx*dx+dy*dy;if(squared<24025){const distance=Math.sqrt(squared);ctx.globalAlpha=(1-distance/155)*.22;ctx.beginPath();ctx.moveTo(x,y);ctx.lineTo(pointerX,pointerY);ctx.stroke();}}
   ctx.fillStyle=p.color;ctx.globalAlpha=.28+Math.sin(time+p.phase)**2*.4;ctx.beginPath();ctx.arc(x,y,p.r,0,Math.PI*2);ctx.fill();
  }
  if(pointer.active){ctx.globalAlpha=.3;ctx.beginPath();ctx.arc(pointerX,pointerY,21,0,Math.PI*2);ctx.stroke();ctx.globalAlpha=.15;ctx.beginPath();ctx.arc(pointerX,pointerY,36,-Math.PI*.25,Math.PI*.6);ctx.stroke();}
  ctx.globalAlpha=1;
 }
 function tick(now){frame=0;if(!last)last=now;if(now-last>=33){time+=Math.min((now-last)/1000,.06);last=now;render();}frame=requestAnimationFrame(tick);}
 function sync(){
  if(suspended||document.hidden){cancelAnimationFrame(resizeFrame);resizeFrame=0;}else if(resizePending)scheduleResize();
  const active=visible&&!paused()&&!document.hidden&&!suspended&&!connection?.saveData&&!destroyed;if(active&&!frame){last=0;frame=requestAnimationFrame(tick);}else if(!active){cancelAnimationFrame(frame);frame=0;}
 }
 const observer=new IntersectionObserver(e=>{visible=e[0].isIntersecting;sync();});observer.observe(canvas);
 const sizing=typeof ResizeObserver==='function'?new ResizeObserver(entries=>{
  const box=entries[0]?.contentRect;
  if(box&&(box.width!==width||box.height!==height))scheduleResize();
 }):null;sizing?.observe(canvas);
 const windowResize=()=>{
  // ResizeObserver handles real canvas-size changes. Toolbar-only resizes need no measurement.
  if(!sizing||innerWidth!==viewportWidth||Math.min(devicePixelRatio||1,1.5)!==lastDpr)scheduleResize();
 };
 // Pointer events carry document coordinates, so scrolling needs no layout reads here.
 const move=e=>{if(!width||!height)return;pointer.x=(e.pageX-canvasLeft)/width;pointer.y=(e.pageY-canvasTop)/height;pointer.active=true;};const leave=()=>pointer.active=false;
 parent.addEventListener('pointerenter',measure,{passive:true});parent.addEventListener('pointermove',move,{passive:true});parent.addEventListener('pointerleave',leave);
 addEventListener('resize',windowResize,{passive:true});connection?.addEventListener?.('change',sync);
 document.addEventListener('anazori:motion',sync);document.addEventListener('visibilitychange',sync);resize();sync();
 addEventListener('pagehide',e=>{suspended=true;cancelAnimationFrame(frame);frame=0;cancelAnimationFrame(resizeFrame);resizeFrame=0;resizePending=true;if(e.persisted)return;destroyed=true;observer.disconnect();sizing?.disconnect();parent.removeEventListener('pointerenter',measure);parent.removeEventListener('pointermove',move);parent.removeEventListener('pointerleave',leave);removeEventListener('resize',windowResize);connection?.removeEventListener?.('change',sync);document.removeEventListener('anazori:motion',sync);document.removeEventListener('visibilitychange',sync);});
 addEventListener('pageshow',e=>{if(e.persisted){suspended=false;resizePending=false;resize();sync();}});
}

function initCountdown(paused){
 const clock=document.querySelector('#festival-clock');if(!clock)return;
 const cells=[...clock.querySelectorAll('[data-count]')],message=clock.querySelector('#countdown-message'),original=message?.textContent||'';
 const start=Date.parse(clock.dataset.start),end=Date.parse(clock.dataset.end);
 let visible=false,timer=0,suspended=false,destroyed=false,phase='';
 const captions={unannounced:original,upcoming:'Until we meet. The next chapter is getting closer.',live:'We’re live. Make every moment count — festival ends in:',ended:'This chapter has wrapped. The memories stay with us.'};
 const update=()=>{
  if(document.hidden||suspended||destroyed)return;
  const state=countdownState(start,end);phase=state.phase;
  cells.forEach((el,i)=>{const next=String(state.values[i]).padStart(2,'0');if(el.textContent===next)return;el.textContent=next;if(visible&&!paused())el.animate([{opacity:1,transform:'translateY(-6px)'},{opacity:1,transform:'translateY(0)'}],{duration:350});});
  if(message&&message.textContent!==captions[phase])message.textContent=captions[phase];
  if(clock.dataset.phase!==phase)clock.dataset.phase=phase;
  if(phase==='unannounced'||phase==='ended'){clearInterval(timer);timer=0;}
 };
 const sync=()=>{
  clearInterval(timer);timer=0;
  if(!destroyed&&!suspended&&!document.hidden){update();if(visible&&(phase==='upcoming'||phase==='live'))timer=setInterval(update,1000);}
 };
 const observer=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;sync();},{rootMargin:'80px'});observer.observe(clock);
 document.addEventListener('visibilitychange',sync);update();
 addEventListener('pagehide',event=>{suspended=true;clearInterval(timer);timer=0;if(event.persisted)return;destroyed=true;observer.disconnect();document.removeEventListener('visibilitychange',sync);});
 addEventListener('pageshow',event=>{if(event.persisted){suspended=false;sync();}});
}
