import assert from 'node:assert/strict';
import {createMotionCardRenderer} from '../frontend/keepsake-renderer84.js';

// Hold worker messages to exercise slow devices, user edits and navigation.
const workers=[];
class ControlledWorker {
  constructor(){this.messages=[];this.terminated=false;workers.push(this);}
  postMessage(message){this.messages.push(message);}
  terminate(){this.terminated=true;}
  emit(data){this.onmessage({data});}
}
const originals=new Map();
for(const [key,value] of Object.entries({Worker:ControlledWorker,OffscreenCanvas:class{},createImageBitmap:()=>{}})){
  originals.set(key,Object.getOwnPropertyDescriptor(globalThis,key));
  Object.defineProperty(globalThis,key,{value,configurable:true});
}
try{
  const painted=[],canvas={width:1280,height:720,dataset:{},getContext:()=>({drawImage:bitmap=>painted.push(bitmap.id)})};
  const renderer=createMotionCardRenderer(canvas,{name:'Initial'}),worker=workers.at(-1);
  worker.emit({type:'ready'});await renderer.ready;
  const a=renderer.draw({name:'Initial'},0);await Promise.resolve();
  const b=renderer.draw({name:'Typing'},100);await Promise.resolve();
  const c=renderer.draw({name:'Chosen name'},200);await Promise.resolve();
  assert.equal(await b,false,'Superseded frames release their promises.');
  assert.equal(worker.messages.filter(message=>message.type==='draw').length,1,'Slow devices do not accumulate frame messages.');
  let closed=0;
  worker.emit({type:'frame',id:1,bitmap:{id:1,close(){closed++;}}});
  assert.equal(await a,true);assert.deepEqual(painted,[],'An outdated name is not painted over a later edit.');
  const latest=worker.messages.at(-1);assert.equal(latest.ticket.name,'Chosen name');assert.equal(latest.time,200);
  worker.emit({type:'frame',id:latest.id,bitmap:{id:latest.id,close(){closed++;}}});
  assert.equal(await c,true);assert.deepEqual(painted,[latest.id]);assert.equal(closed,2,'Transferred bitmaps are released.');
  const pending=renderer.draw({name:'Leaving'},400);await Promise.resolve();renderer.destroy();
  assert.equal(await pending,false);assert.equal(worker.terminated,true);assert.equal(await renderer.draw({},0),false);
  const starting=createMotionCardRenderer({...canvas,dataset:{}},{}),initializing=workers.at(-1);
  starting.destroy();await starting.ready;assert.equal(initializing.terminated,true,'Navigation during initialization releases the worker.');
  console.log('PASS Slow workers keep only the newest frame, release bitmaps and stop cleanly on navigation.');
}finally{
  for(const [key,descriptor] of originals){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}
}
