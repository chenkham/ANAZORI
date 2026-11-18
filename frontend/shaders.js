// Shared procedural shaders: no texture or model downloads.
export const waterVertex = /* glsl */`
uniform float uTime; varying vec3 vWorld; varying vec2 vUv;
void main(){vUv=uv;vec3 p=position;p.z+=sin(p.x*.12+uTime*.35)*.7+cos(p.y*.14+uTime*.22)*.45;vec4 w=modelMatrix*vec4(p,1.);vWorld=w.xyz;gl_Position=projectionMatrix*viewMatrix*w;}`;
export const waterFragment = /* glsl */`
uniform float uTime;uniform vec3 uColor;varying vec3 vWorld;varying vec2 vUv;
void main(){vec2 c=vWorld.xz*.14;vec2 g=abs(fract(c-.5)-.5)/max(fwidth(c),vec2(.001));float grid=1.-min(min(g.x,g.y),1.);float river=exp(-pow((vWorld.x-20.-sin(vWorld.z*.023)*24.)/22.,2.));float flow=pow(.5+.5*sin(vWorld.z*.23+vWorld.x*.05+uTime*.5),12.);vec3 col=mix(vec3(.03,.09,.13),uColor,river*.3);col+=uColor*(grid*.22+flow*river*.2);float edge=1.-smoothstep(70.,230.,length(vWorld.xz));gl_FragColor=vec4(col,.85*edge);}`;
export const jaapiVertex = /* glsl */`
varying vec3 vNormal;varying vec3 vPos;varying vec2 vUv;void main(){vUv=uv;vNormal=normalize(normalMatrix*normal);vPos=(modelViewMatrix*vec4(position,1.)).xyz;gl_Position=projectionMatrix*vec4(vPos,1.);}`;
export const jaapiFragment = /* glsl */`
uniform float uTime;uniform vec3 uColor;varying vec3 vNormal;varying vec3 vPos;varying vec2 vUv;
void main(){float rim=pow(1.-abs(dot(normalize(vNormal),normalize(-vPos))),2.);float scan=pow(.5+.5*sin(vUv.y*130.-uTime*1.4),18.);float pulse=.8+.2*sin(uTime*.8);gl_FragColor=vec4(uColor*(.55+rim*1.3+scan*.3),(.13+rim*.36+scan*.12)*pulse);}`;
export const runeFragment = /* glsl */`
uniform float uTime;uniform vec3 uColor;varying vec3 vNormal;varying vec3 vPos;varying vec2 vUv;
void main(){float wave=.65+.35*sin(vUv.x*70.+uTime*1.5);float stitch=step(.65,sin(vUv.x*180.)*sin(vUv.y*60.));gl_FragColor=vec4(uColor*(wave+stitch*.5),.7);}`;
