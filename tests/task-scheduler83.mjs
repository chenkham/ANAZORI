import assert from 'node:assert/strict';
import {createTaskQueue} from '../frontend/task-scheduler83.js';

const steps=[],queue=createTaskQueue();
const first=queue(()=>steps.push('first'));
const failed=queue(()=>{steps.push('failed');throw new Error('missing asset');});
const recovered=queue(()=>steps.push('recovered'));
const input=new Promise(resolve=>setTimeout(()=>{steps.push('input');resolve();},0));
await Promise.all([first,assert.rejects(failed,/missing asset/),recovered,input]);
assert.deepEqual(steps,['input','first','failed','recovered']);
console.log('PASS Setup yields to other browser work and a failed scene does not block the queue.');

const descriptor=Object.getOwnPropertyDescriptor(globalThis,'scheduler');
try{
 let yields=0;
 Object.defineProperty(globalThis,'scheduler',{value:{yield:async()=>{yields++;}},configurable:true});
 const nativeQueue=createTaskQueue();
 const values=await Promise.all([nativeQueue(()=>1),nativeQueue(()=>2)]);
 assert.deepEqual(values,[1,2]);assert.equal(yields,2);
 console.log('PASS Native scheduling and the timer fallback preserve order and results.');
}finally{if(descriptor)Object.defineProperty(globalThis,'scheduler',descriptor);else delete globalThis.scheduler;}
