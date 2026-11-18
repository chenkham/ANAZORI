// SVG <animate> cannot animate a transform list in Chromium. Split sampled
// matrices into the transform types supported by <animateTransform> instead.
export function matrixParts(value) {
 const matrix=value.match(/^matrix\(([^)]+)\)$/);
 if(!matrix)throw new Error('Expected a sampled SVG matrix.');
 const [a,b,c,d,x,y]=matrix[1].split(/[ ,]+/).map(Number);
 const sx=Math.hypot(a,b),det=a*d-b*c;
 if(sx<1e-8){if(Math.hypot(c,d)>1e-8)throw new Error('Unsupported singular SVG matrix.');return {translate:[x,y],rotate:[0],skewX:[0],scale:[0,0]};}
 const sy=det/sx,shear=(a*c+b*d)/sx;
 return {translate:[x,y],rotate:[Math.atan2(b,a)*180/Math.PI],skewX:[Math.atan2(shear,sy)*180/Math.PI],scale:[sx,sy]};
}
export function repairTransformAnimations(svg) {
 return svg.replace(/<animate\b([^>]*)(?:\/>|><\/animate>)/g,(original,attributes)=>{
  const attrs=Object.fromEntries([...attributes.matchAll(/([\w:-]+)="([^"]*)"/g)].map(match=>[match[1],match[2]]));
  if(attrs.attributeName!=='transform')return original;
  const frames=attrs.values.split(';').map(matrixParts);
  return ['translate','rotate','skewX','scale'].map((type,index)=>{
   const values=frames.map(frame=>frame[type].map(n=>Number(n.toFixed(7))).join(' ')).join(';');
   return `<animateTransform attributeName="transform" type="${type}" additive="${index?'sum':'replace'}" dur="${attrs.dur}" repeatCount="indefinite" calcMode="discrete" keyTimes="${attrs.keyTimes}" values="${values}"/>`;
  }).join('');
 });
}
