import {WebGLRenderer,Scene,PerspectiveCamera,Group,TorusGeometry,TorusKnotGeometry,
  IcosahedronGeometry,EdgesGeometry,BufferGeometry,Float32BufferAttribute,
  Mesh,MeshStandardMaterial,MeshBasicMaterial,LineSegments,LineBasicMaterial,
  Points,PointsMaterial,AmbientLight,PointLight,Color,AdditiveBlending} from 'three';

export function createPortalScene(canvas) {
  const mobile = matchMedia('(pointer: coarse)').matches;
  const renderer = new WebGLRenderer({canvas,alpha:true,antialias:!mobile,powerPreference:'low-power'});
  renderer.setClearColor(0x000000,0);
  renderer.setPixelRatio(Math.min(devicePixelRatio||1,mobile?1:1.4));
  const scene = new Scene();
  const camera = new PerspectiveCamera(38,1,.1,40); camera.position.z=9;
  const assembly = new Group(); scene.add(assembly);
  const materials = [], geometries = [];
  const keepG = geometry => { geometries.push(geometry);return geometry; };
  const keepM = material => { materials.push(material);return material; };
  const cool = new Color('#83f4ed'), warm = new Color('#ff9e8c'), violet = new Color('#bca1ff');
  const ringMaterial = keepM(new MeshStandardMaterial({color:cool,metalness:.72,roughness:.22,emissive:cool,emissiveIntensity:.45}));
  const secondMaterial = keepM(new MeshStandardMaterial({color:violet,metalness:.68,roughness:.3,emissive:violet,emissiveIntensity:.5}));
  const ring1 = new Mesh(keepG(new TorusGeometry(2.05,.047,8,120)),ringMaterial);
  const ring2 = new Mesh(keepG(new TorusGeometry(1.72,.034,8,100)),secondMaterial);
  const ring3 = new Mesh(keepG(new TorusGeometry(1.4,.03,8,90)),ringMaterial);
  ring1.rotation.set(.45,.45,0);ring2.rotation.set(1.15,-.35,.2);ring3.rotation.set(-.65,.75,.4);
  assembly.add(ring1,ring2,ring3);
  const glowMaterial = keepM(new MeshBasicMaterial({color:cool,transparent:true,opacity:.08,blending:AdditiveBlending,depthWrite:false}));
  for(const ring of [ring1,ring2]) {
    const halo = new Mesh(ring.geometry,glowMaterial); halo.scale.setScalar(1.04);ring.add(halo);
  }
  const coreGeometry = keepG(new IcosahedronGeometry(.83,1));
  const core = new Mesh(coreGeometry,keepM(new MeshStandardMaterial({color:'#18273e',metalness:.8,roughness:.17,transparent:true,opacity:.65})));
  const coreLines = new LineSegments(keepG(new EdgesGeometry(coreGeometry)),keepM(new LineBasicMaterial({color:cool,transparent:true,opacity:.8})));
  core.add(coreLines);assembly.add(core);
  const thread = new Mesh(keepG(new TorusKnotGeometry(1,.018,150,5,2,3)),secondMaterial);assembly.add(thread);
  const markerGeometry = keepG(new IcosahedronGeometry(.09,0));
  const markers = new Group();assembly.add(markers);
  for(let i=0;i<12;i++) {
    const angle=i*Math.PI/6;
    const marker=new Mesh(markerGeometry,i%2?secondMaterial:ringMaterial);
    marker.position.set(Math.cos(angle)*2.42,Math.sin(angle)*2.42,Math.sin(angle*2)*.18);
    marker.rotation.z=angle;markers.add(marker);
  }
  const dustGeometry = keepG(new BufferGeometry());
  const positions=[];
  for(let i=0;i<(mobile?45:90);i++) { const angle=i*2.39996,r=2.7+(i%13)*.1;positions.push(Math.cos(angle)*r,Math.sin(angle)*r,Math.sin(i)*1.1); }
  dustGeometry.setAttribute('position',new Float32BufferAttribute(positions,3));
  const dust = new Points(dustGeometry,keepM(new PointsMaterial({color:'#b8dfff',size:.018,transparent:true,opacity:.6,blending:AdditiveBlending,depthWrite:false})));scene.add(dust);
  scene.add(new AmbientLight('#aaaaff',1.4));
  const light = new PointLight('#a5fff1',22,18);light.position.set(-3,3,4);scene.add(light);
  const other = new PointLight('#d69dff',16,18);other.position.set(3,-2,3);scene.add(other);

  let frame=0,running=false,disposed=false,last=0,time=0,mix=.5;
  let targetX=0,targetY=0;
  const render = () => { if(!disposed)renderer.render(scene,camera); };
  const resize = () => { const {width,height}=canvas.getBoundingClientRect();if(!width||!height)return;renderer.setSize(width,height,false);camera.aspect=width/height;camera.updateProjectionMatrix();render(); };
  const sizing=new ResizeObserver(resize);sizing.observe(canvas);
  const stage=canvas.parentElement;
  const move = event => { if(mobile)return;const box=stage.getBoundingClientRect();targetY=(event.clientX-box.left)/box.width-.5;targetX=(event.clientY-box.top)/box.height-.5; };
  const leave=()=>{targetX=targetY=0;};stage.addEventListener('pointermove',move,{passive:true});stage.addEventListener('pointerleave',leave);
  function tick(now) {
    frame=0;if(!running||disposed)return;
    const elapsed=now-last;
    if(elapsed>=(mobile?33:22)) {
      time+=Math.min(elapsed/1000,.06);last=now;
      assembly.rotation.y+=(targetY*.3-assembly.rotation.y)*.045;
      assembly.rotation.x+=(targetX*.2-assembly.rotation.x)*.045;
      ring1.rotation.z=time*.11;ring2.rotation.y=-time*.13;ring3.rotation.x=time*.15;
      core.rotation.y=time*.22;core.rotation.z=-time*.1;thread.rotation.y=-time*.15;
      markers.rotation.z=-time*.035;dust.rotation.z=time*.018;
      thread.scale.setScalar(1+Math.sin(time*1.5)*.025);
      render();
    }
    frame=requestAnimationFrame(tick);
  }
  resize();
  return {
    setMix(value) { mix=Math.max(0,Math.min(1,value));ringMaterial.color.copy(warm).lerp(cool,mix);ringMaterial.emissive.copy(ringMaterial.color);glowMaterial.color.copy(ringMaterial.color);coreLines.material.color.copy(ringMaterial.color);light.color.copy(ringMaterial.color);render(); },
    setRunning(value) { if(disposed)return;running=value;if(running&&!frame){last=performance.now();frame=requestAnimationFrame(tick);}else if(!running){cancelAnimationFrame(frame);frame=0;render();} },
    dispose() { if(disposed)return;disposed=true;running=false;cancelAnimationFrame(frame);sizing.disconnect();stage.removeEventListener('pointermove',move);stage.removeEventListener('pointerleave',leave);for(const g of geometries)g.dispose();for(const m of materials)m.dispose();renderer.dispose(); }
  };
}
