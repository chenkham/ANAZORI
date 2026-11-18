import assert from 'node:assert/strict';
import {initialMotionTier95,initAdaptiveMotion95} from '../frontend/adaptive-motion95.js';
assert.equal(initialMotionTier95({memory:2,cores:2,compact:true,saveData:false}),'low');
assert.equal(initialMotionTier95({memory:4,cores:4,compact:true,saveData:false}),'medium');
assert.equal(initialMotionTier95({memory:8,cores:8,compact:true,saveData:false}),'high');
const names=['document','navigator','performance','matchMedia','requestAnimationFrame','cancelAnimationFrame','addEventListener','removeEventListener','CustomEvent'];
const saved=new Map(names.map(name=>[name,Object.getOwnPropertyDescriptor(globalThis,name)]));
let now=1000,sequence=0,paused=false;
const frames=new Map(),events=new Map(),documentEvents=new Map(),networkEvents=new Map();
const reduced={matches:false},connection={saveData:false,addEventListener(name,fn){networkEvents.set(name,fn);},removeEventListener(name){networkEvents.delete(name);}};
const root={dataset:{},classList:{contains:()=>paused}};
const document={documentElement:root,hidden:false,dispatchEvent(){},addEventListener(name,fn){documentEvents.set(name,fn);},removeEventListener(name){documentEvents.delete(name);}};
const globals={document,navigator:{deviceMemory:8,hardwareConcurrency:8,connection},performance:{now:()=>now},matchMedia:query=>query.includes('reduced-motion')?reduced:{matches:true},requestAnimationFrame:fn=>{frames.set(++sequence,fn);return sequence;},cancelAnimationFrame:id=>frames.delete(id),addEventListener:(name,fn)=>events.set(name,fn),removeEventListener:name=>events.delete(name),CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail;}}};
const step=milliseconds=>{now+=milliseconds;const pending=[...frames.values()];frames.clear();for(const fn of pending)fn(now);};
function sample(spacing){events.get('scroll')();for(let i=0;frames.size&&i<500;i++)step(spacing);assert.equal(frames.size,0);}
try{
 for(const [name,value] of Object.entries(globals))Object.defineProperty(globalThis,name,{configurable:true,value});
 initAdaptiveMotion95();assert.equal(root.dataset.motionQuality,'high');
 sample(250);assert.equal(root.dataset.motionQuality,'medium','Extremely slow foreground frames must lower quality');
 now+=31000;sample(250);assert.equal(root.dataset.motionQuality,'low');
 console.log('PASS Severe foreground lag lowers motion quality even below seven frames per second.');
 connection.saveData=true;networkEvents.get('change')();
 for(let i=0;i<4;i++){now+=31000;sample(16);}
 assert.equal(root.dataset.motionQuality,'low','Data saver remains the quality ceiling');
 connection.saveData=false;networkEvents.get('change')();
 for(let i=0;i<3;i++){now+=31000;sample(16);}
 assert.equal(root.dataset.motionQuality,'medium');
 console.log('PASS Data saver stays low while enabled, then healthy performance can restore detail.');
 now+=31000;events.get('scroll')();assert(frames.size);paused=true;step(16);assert.equal(frames.size,0);
 paused=false;now+=31000;events.get('scroll')();assert(frames.size);reduced.matches=true;step(16);assert.equal(frames.size,0);
 console.log('PASS Pausing motion or enabling reduced motion stops an in-progress performance sample.');
}finally{
 for(const [name,descriptor] of saved){if(descriptor)Object.defineProperty(globalThis,name,descriptor);else delete globalThis[name];}
}
