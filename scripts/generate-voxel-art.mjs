// Original, deterministic voxel artwork for the public festival backdrop.
import {mkdirSync,writeFileSync} from 'node:fs';
const out='assets/2026/graphics';mkdirSync(out,{recursive:true});
const palettes={
 grass:['#70c7ad','#367d70','#24585b'],grass2:['#56af9b','#2e6c68','#204f57'],
 soil:['#655071','#42364f','#302940'],stone:['#625b82','#403654','#2b2540'],
 ore:['#a47ad0','#71538e','#48365f'],trunk:['#806079','#59445b','#3d354b'],
 leaf:['#69b7a7','#3a807b','#265d65'],leaf2:['#8dcebb','#4a9587','#326f70'],
 lilac:['#b28acb','#7b5b9c','#554478'],water:['#86dfea','#398eac','#286a91'],
 crystal:['#bef5ef','#69d3db','#438bae'],pink:['#ffd1ef','#e485d0','#9b5eaa'],
 lantern:['#fff2c9','#ebb5d3','#aa759f'],base:['#596083','#353952','#25283e']
};
const noise=(x,y,z)=>Math.abs((x*73+y*37+z*19)%17);
function island({small=false}={}){
 const voxels=new Map(),w=small?17:22,h=w/2,d=small?19:24;
 const ox=small?250:420,oy=small?150:175;
 const put=(x,y,z,type)=>voxels.set(`${x},${y},${z}`,{x,y,z,type});
 const get=(x,y,z)=>voxels.has(`${x},${y},${z}`);
 const radius=small?3.3:4.8,cx=small?3:4,cy=small?3:4;
 for(let x=0;x<=cx*2;x++)for(let y=0;y<=cy*2;y++){
  const r=Math.hypot((x-cx)/radius,(y-cy)/(radius*.88));if(r>1)continue;
  const depth=2+Math.floor((1-r)*5);
  for(let z=-depth;z<=0;z++)put(x,y,z,z===0?(noise(x,y,z)%3?'grass':'grass2'):z===-1?'soil':noise(x,y,z)===3?'ore':'stone');
 }
 function tree(x,y,height,lilac=false){
  for(let z=1;z<=height;z++)put(x,y,z,'trunk');
  for(let z=height-1;z<=height+1;z++)for(let a=-1;a<=1;a++)for(let b=-1;b<=1;b++){
   if(z===height+1&&Math.abs(a)+Math.abs(b)>1)continue;
   if(z===height-1&&Math.abs(a)+Math.abs(b)===2)continue;
   put(x+a,y+b,z,lilac?'lilac':noise(x+a,y+b,z)%3?'leaf':'leaf2');
  }
  put(x,y,height+2,lilac?'lilac':'leaf2');
 }
 tree(small?2:2,small?2:3,small?3:4);
 if(!small){tree(5,1,3,true);tree(6,5,3);}
 const waterX=small?4:7,waterY=small?4:5;
 for(let x=waterX-2;x<=waterX;x++)for(let y=waterY-1;y<=waterY;y++)if(get(x,y,0))put(x,y,0,'water');
 put(small?4:4,small?2:5,1,'crystal');put(small?4:4,small?2:5,2,'crystal');
 put(small?3:3,small?2:6,1,'pink');
 if(!small){put(5,6,1,'base');put(5,6,2,'lantern');}
 const p=(x,y,z)=>[ox+(x-y)*w,oy+(x+y)*h-z*d];
 let parts=[];
 function face(points,color){return `<polygon points="${points.map(v=>v.join(',')).join(' ')}" fill="${color}"/>`;}
 for(const v of [...voxels.values()].sort((a,b)=>(a.x+a.y)-(b.x+b.y)||a.z-b.z)){
  const [x,y]=p(v.x,v.y,v.z),c=palettes[v.type];
  if(!get(v.x,v.y+1,v.z)){
   parts.push(face([[x-w,y+h],[x,y+2*h],[x,y+2*h+d],[x-w,y+h+d]],c[1]));
   if(v.z<0&&noise(v.x,v.y,v.z)%3===0)parts.push(face([[x-w+3,y+h+5],[x-w+9,y+h+8],[x-w+9,y+h+14],[x-w+3,y+h+11]],v.type==='ore'?'#c8a6ff':'#9081a3'),`<path d="M${x-8} ${y+2*h+5}v5l5 2v-5Z" fill="#181629" opacity=".2"/>`);
  }
  if(!get(v.x+1,v.y,v.z)){
   parts.push(face([[x,y+2*h],[x+w,y+h],[x+w,y+h+d],[x,y+2*h+d]],c[2]));
   if(v.z<0&&noise(v.x,v.y,v.z)%4===0)parts.push(face([[x+4,y+2*h+7],[x+11,y+2*h+3],[x+11,y+2*h+10],[x+4,y+2*h+14]],v.type==='ore'?'#aa73d1':'#625173'));
  }
  if(!get(v.x,v.y,v.z+1)){
   parts.push(face([[x,y],[x+w,y+h],[x,y+2*h],[x-w,y+h]],c[0]));
   if(['grass','grass2','leaf','leaf2'].includes(v.type))parts.push(face([[x-7,y+5],[x+3,y+10],[x-3,y+13],[x-13,y+8]],'#a3dcca'),face([[x+5,y+8],[x+12,y+11],[x+5,y+15],[x-2,y+12]],c[1]));
  }
 }
 const [fx,fy]=p(waterX,waterY,0),fall=small?115:180;
 parts.push(`<path d="M${fx+2} ${fy+h+5}l${w-3} -${h-2}v${fall}h-5v22h-9v-12h-6Z" fill="#53bdce" opacity=".8"/>`,
  `<path d="M${fx+7} ${fy+h+8}v${fall-20}h5v-31h3v-${fall-40}Z" fill="#a1eff0" opacity=".8"/>`,
  `<path d="M${fx+16} ${fy+2*h+19}v22m-8 19v34m7 22v18" stroke="#d9ffff" stroke-width="3" opacity=".45"/>`);
 const [vx,vy]=p(small?1:1,small?4:5,0);
 parts.push(`<path d="M${vx-w+2} ${vy+h+10}v32h6v24h-3v22" stroke="#478f82" stroke-width="5" fill="none"/>`,
  `<path d="M${vx-w-3} ${vy+h+32}h12v8h-12zm5 24h10v7h-10z" fill="#7db7a0"/>`);
 const points=[...voxels.values()].map(v=>p(v.x,v.y,v.z));
 const minX=Math.min(...points.map(v=>v[0]-w))-24,maxX=Math.max(...points.map(v=>v[0]+w))+24;
 const minY=Math.min(...points.map(v=>v[1]))-24,maxY=Math.max(...points.map(v=>v[1]+2*h+d),fy+h+fall+27)+24;
 return `<svg xmlns="http://www.w3.org/2000/svg" width="${small?500:800}" height="${small?440:620}" viewBox="${minX} ${minY} ${maxX-minX} ${maxY-minY}" shape-rendering="crispEdges">${parts.join('')}</svg>`;
}
writeFileSync(`${out}/voxel-island70.svg`,island());
writeFileSync(`${out}/voxel-island-small70.svg`,island({small:true}));
writeFileSync(`${out}/voxel-relic70.svg`,`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 112" width="144" height="112" shape-rendering="crispEdges"><path d="M72 68 128 88 72 108 16 88Z" fill="#a24bff" opacity=".08"/><path d="m72 60 40 20-40 20-40-20Z" fill="#636181"/><path d="m32 80 40 20v8L32 88Z" fill="#373450"/><path d="m72 100 40-20v8l-40 20Z" fill="#25253f"/><path d="m56 16 16-8 16 8v56l-16 8-16-8Z" fill="#69d3db"/><path d="m72 8 16 8-16 8-16-8Z" fill="#cffbf3"/><path d="m72 24 16-8v56l-16 8Z" fill="#3b819c"/><path d="m80 46 16-8 12 8v32l-16 8-12-8Z" fill="#b38dd2"/><path d="m96 38 12 8-16 8-12-8Z" fill="#e5c9f6"/><path d="m92 54 16-8v32l-16 8Z" fill="#715491"/><path d="m36 54 12-6 12 6v26l-12 6-12-6Z" fill="#e68cc9"/><path d="m48 48 12 6-12 6-12-6Z" fill="#ffceed"/><path d="m48 60 12-6v26l-12 6Z" fill="#aa609e"/><path d="M60 28h4v28h-4z" fill="#d6fffa" opacity=".6"/><path d="M112 22h4v4h4v4h-4v4h-4v-4h-4v-4h4zM26 30h4v4h-4z" fill="#b6eceb" opacity=".65"/></svg>`);
console.log('Generated three original voxel illustrations.');
