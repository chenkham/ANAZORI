import {writeFileSync} from 'node:fs';
// Original mathematical line studies: one distinct construction per discipline.
const line=(d,c,w=1.1,o=.75)=>`<path d="${d}" fill="none" stroke="${c}" stroke-width="${w}" opacity="${o}"/>`;
const svg=(body,c)=>`<svg xmlns="http://www.w3.org/2000/svg" width="600" height="600" viewBox="0 0 600 600"><defs><radialGradient id="light"><stop stop-color="${c}" stop-opacity=".13"/><stop offset="1" stop-color="${c}" stop-opacity="0"/></radialGradient></defs><circle cx="300" cy="300" r="290" fill="url(#light)"/>${body}</svg>`;
let body='';const blue='#98c7cf';
for(let i=-8;i<=8;i++){const y=i*19,rx=Math.sqrt(180**2-y*y);body+=`<ellipse cx="300" cy="${300+y}" rx="${rx}" ry="${rx*.23}" fill="none" stroke="${blue}" opacity=".6"/>`;}
for(let i=0;i<15;i++){body+=`<ellipse cx="300" cy="300" rx="${12+i*12}" ry="180" fill="none" stroke="${blue}" opacity=".6" transform="rotate(-25 300 300)"/>`;}
body+=`<circle cx="300" cy="300" r="180" fill="none" stroke="${blue}"/><circle cx="300" cy="300" r="218" fill="none" stroke="${blue}" stroke-dasharray="2 12" opacity=".3"/>`;
writeFileSync('assets/2026/graphics/ball.svg',svg(body,blue));
body='';const gold='#dbd0a7';
for(let i=0;i<28;i++){const a=i*5.2,sz=260-i*3;body+=`<rect x="${300-sz/2}" y="${300-sz/2}" width="${sz}" height="${sz}" rx="5" fill="none" stroke="${gold}" opacity="${.22+i*.023}" transform="rotate(${a} 300 300)"/>`;}
body+=line('M270 330 335 265M280 265h55v55',gold,4,1);
writeFileSync('assets/2026/graphics/workshop.svg',svg(body,gold));
body='';const violet='#c1b1ed';
for(let i=19;i>=0;i--){const x=i*4,y=i*5;body+=line(`M${175+x} ${130+y} ${375+x} ${180+y} ${310+x} ${375+y} ${110+x} ${325+y}Z`,violet,1.2,.25+(19-i)*.03);}
body+='<path d="m175 130 200 50-65 195-200-50z" fill="#24202d" fill-opacity=".85" stroke="#c1b1ed" stroke-width="2"/>';
for(let i=0;i<6;i++)body+=line(`M${184-i*8} ${181+i*24}l${125-i*7} ${31-i*1.75}`,violet,1.6,.8);
writeFileSync('assets/2026/graphics/paper.svg',svg(body,violet));
body='';const sand='#d4c2ac';
for(let i=0;i<34;i++){let d='';for(let j=0;j<=144;j++){const a=j/144*Math.PI*2,rot=i*.035,r=55+i*3.5+(18+i)*Math.cos(a*8);d+=(j?'L':'M')+(300+Math.cos(a+rot)*r).toFixed(1)+','+(300+Math.sin(a+rot)*r).toFixed(1);}body+=line(d+'Z',sand,1,.27+i*.019);}
writeFileSync('assets/2026/graphics/art.svg',svg(body,sand));
console.log('Generated original sphere, folded research, rotating lattice, and floral wave illustrations.');
