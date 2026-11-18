import * as THREE from 'three';
import {RoomEnvironment} from 'three/addons/environments/RoomEnvironment.js';
import {RoundedBoxGeometry} from 'three/addons/geometries/RoundedBoxGeometry.js';

export function createSculpture(host){
 const canvas=host.querySelector('canvas');let renderer;
 try{renderer=new THREE.WebGLRenderer({canvas,alpha:true,antialias:true,powerPreference:'low-power'});}catch{return null;}
 renderer.setPixelRatio(Math.min(devicePixelRatio,matchMedia('(pointer:coarse)').matches?1.25:1.75));renderer.setClearColor(0x10121b,0);renderer.outputColorSpace=THREE.SRGBColorSpace;renderer.toneMapping=THREE.ACESFilmicToneMapping;renderer.toneMappingExposure=1.1;
 const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(34,1,.1,30);camera.position.set(0,.35,7.8);camera.lookAt(0,.05,0);
 const pmrem=new THREE.PMREMGenerator(renderer),room=new RoomEnvironment(),env=pmrem.fromScene(room,.04);scene.environment=env.texture;room.dispose();pmrem.dispose();
 const resources=[];const keep=x=>(resources.push(x),x);
 const ceramic=keep(new THREE.MeshPhysicalMaterial({color:0xe6ecff,roughness:.3,metalness:.28,clearcoat:.7}));
 const navy=keep(new THREE.MeshStandardMaterial({color:0x102333,roughness:.25,metalness:.45}));
 const cyan=keep(new THREE.MeshBasicMaterial({color:0x7be7fc})),pink=keep(new THREE.MeshStandardMaterial({color:0xe4a2d3,roughness:.35,metalness:.25}));
 const red=keep(new THREE.MeshStandardMaterial({color:0xc22d51,roughness:.7})),fabric=keep(new THREE.MeshStandardMaterial({color:0xfff6e7,roughness:1}));
 const robot=new THREE.Group();scene.add(robot);robot.rotation.y=-.12;
 function mesh(geometry,material,parent=robot,x=0,y=0,z=0){const m=new THREE.Mesh(keep(geometry),material);m.position.set(x,y,z);parent.add(m);return m;}
 function box(w,h,d,r,mat,parent,x,y,z){return mesh(new RoundedBoxGeometry(w,h,d,3,r),mat,parent,x,y,z);}
 const torso=box(1.1,1.05,.73,.28,ceramic,robot,0,-.5,0);
 const head=new THREE.Group();head.position.set(0,.62,0);robot.add(head);
 box(1.68,1.25,.98,.3,ceramic,head,0,.12,0);
 box(1.37,.72,.12,.2,navy,head,0,.11,.5);
 const eyes=[];for(const x of [-.31,.31])eyes.push(box(.14,.22,.04,.065,cyan,head,x,.17,.58));
 const smile=mesh(new THREE.TorusGeometry(.18,.017,8,40,Math.PI),cyan,head,0,-.03,.585);smile.rotation.z=Math.PI;
 for(const x of [-.51,.51]){const cheek=mesh(new THREE.SphereGeometry(.055,12,8),pink,head,x,-.07,.59);cheek.scale.set(1.3,.6,.2);mesh(new THREE.CylinderGeometry(.15,.15,.1,18),pink,head,x*1.72,.12,0).rotation.z=Math.PI/2;}
 mesh(new THREE.CylinderGeometry(.035,.035,.25,10),ceramic,head,0,.85,0);mesh(new THREE.SphereGeometry(.09,16,12),pink,head,0,1.01,0);
 box(.86,.12,.75,.04,fabric,robot,0,.08,.035);
 for(const x of [-.31,.31]){const scarf=new THREE.Group();scarf.position.set(x,-.33,.4);scarf.rotation.z=x>0?-.1:.12;robot.add(scarf);box(.19,.83,.04,.008,fabric,scarf,0,0,0);for(const y of [-.34,-.28,.2,.26])box(.19,.022,.014,.003,red,scarf,0,y,.026);for(const y of [-.16,-.05,.07]){const motif=box(.07,.07,.014,.004,red,scarf,0,y,.028);motif.rotation.z=Math.PI/4;}for(let i=0;i<4;i++)box(.014,.09,.015,.003,fabric,scarf,-.064+i*.042,-.45,0);}
 for(const x of [-.34,.34]){box(.3,.3,.3,.09,navy,robot,x,-1.11,0);box(.43,.24,.65,.1,ceramic,robot,x,-1.3,.1);}
 const waving=new THREE.Group();waving.position.set(.76,-.06,0);robot.add(waving);waving.rotation.z=-.5;
 mesh(new THREE.SphereGeometry(.15,18,12),pink,waving,0,0,0);box(.23,.57,.25,.1,ceramic,waving,0,.32,0);
 const hand=new THREE.Group();hand.position.set(0,.7,0);waving.add(hand);box(.29,.31,.16,.06,ceramic,hand,0,0,0);
 for(let i=0;i<4;i++){const finger=box(.055,.22+(i===1||i===2?.03:0),.065,.025,ceramic,hand,(i-1.5)*.075,.21,0);finger.rotation.z=(1.5-i)*.07;}box(.08,.2,.08,.03,ceramic,hand,-.2,-.02,0).rotation.z=-.7;
 const resting=new THREE.Group();resting.position.set(-.77,-.1,0);resting.rotation.z=-.35;robot.add(resting);mesh(new THREE.SphereGeometry(.14,16,12),pink,resting);box(.23,.67,.25,.1,ceramic,resting,0,-.36,0);box(.29,.3,.2,.08,ceramic,resting,0,-.77,0);
 const pedestal=mesh(new THREE.CylinderGeometry(1.22,1.3,.09,64),navy,scene,0,-1.51,0);
 const ring=mesh(new THREE.TorusGeometry(1.19,.018,8,80),cyan,scene,0,-1.45,0);ring.rotation.x=Math.PI/2;
 const haloMat=keep(new THREE.MeshBasicMaterial({color:0xb491f3,transparent:true,opacity:.2}));const halo=mesh(new THREE.TorusGeometry(1.95,.009,6,100),haloMat,scene,0,.1,-.6);halo.rotation.z=-.3;
 scene.add(new THREE.HemisphereLight(0xe1f3ff,0x322443,2.5));const light=new THREE.DirectionalLight(0xd2eefe,4);light.position.set(-3,5,5);scene.add(light);const rim=new THREE.DirectionalLight(0xc19cf7,3);rim.position.set(4,1,-2);scene.add(rim);
 let active=false,frame=0,time=0,last=0,failed=false,disposed=false,targetX=0,targetY=0;
 const draw=()=>{if(failed||disposed)return;renderer.render(scene,camera);host.classList.add('sculpture-ready');};
 const resize=()=>{const r=host.getBoundingClientRect();if(!r.width||!r.height||disposed)return;renderer.setSize(r.width,r.height,false);camera.aspect=r.width/r.height;camera.position.z=r.width/r.height<.85?8.8:7.8;camera.updateProjectionMatrix();draw();};const observer=new ResizeObserver(resize);observer.observe(host);resize();
 const pointer=e=>{if(!active)return;const r=host.getBoundingClientRect();targetX=((e.clientX-r.left)/r.width-.5)*.42;targetY=((e.clientY-r.top)/r.height-.5)*.12;};const leave=()=>{targetX=targetY=0;};host.addEventListener('pointermove',pointer,{passive:true});host.addEventListener('pointerleave',leave);
 function tick(now){frame=0;if(!active||failed||disposed)return;const dt=last?Math.min((now-last)/1000,.06):0;last=now;time+=dt;waving.rotation.z=-.5+Math.sin(time*3.3)*.23;hand.rotation.z=Math.sin(time*3.3+.4)*.1;head.rotation.y+=(targetX-head.rotation.y)*.035;head.rotation.x+=(targetY-head.rotation.x)*.035;head.rotation.z=Math.sin(time*.9)*.035;robot.position.y=Math.sin(time*1.6)*.035;const blink=Math.sin(time*.55)> .996? .15:1;eyes.forEach(eye=>eye.scale.y=blink);draw();frame=requestAnimationFrame(tick);}
 function setActive(value){active=value&&!failed&&!disposed;if(active&&!frame){last=0;frame=requestAnimationFrame(tick);}if(!active){cancelAnimationFrame(frame);frame=0;last=0;}}
 const lost=e=>{e.preventDefault();failed=true;setActive(false);host.classList.remove('sculpture-ready');};canvas.addEventListener('webglcontextlost',lost);
 return {setActive,dispose(){setActive(false);disposed=true;observer.disconnect();host.removeEventListener('pointermove',pointer);host.removeEventListener('pointerleave',leave);canvas.removeEventListener('webglcontextlost',lost);resources.forEach(r=>r.dispose());env.dispose();renderer.dispose();}};
}
