import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import vm from 'node:vm';

const root=resolve(import.meta.dirname,'..'),assetRoot=resolve(root,'src/assets/2026');
const expected=['initAmbientMotion','initFestivalScenes','initMotion','initExperience','initDesigner','initWorld','initScrollMotion','initFestivalSharing'];
class Events{
 constructor(){this.listeners=new Map();}
 addEventListener(type,handler){const list=this.listeners.get(type)||[];list.push(handler);this.listeners.set(type,list);}
 removeEventListener(type,handler){this.listeners.set(type,(this.listeners.get(type)||[]).filter(value=>value!==handler));}
 dispatchEvent(event){for(const handler of this.listeners.get(event.type)||[])handler(event);return true;}
}
class Classes{
 constructor(){this.items=new Set();}
 contains(name){return this.items.has(name);}
 add(name){this.items.add(name);}
 remove(name){this.items.delete(name);}
 toggle(name,force){const add=force??!this.items.has(name);add?this.items.add(name):this.items.delete(name);return add;}
}
async function run(interestCount,loaderPending){
 const document=new Events(),window=new Events(),started=[],warnings=[],observers=[];
 const buttons=Array.from({length:interestCount},()=>new Events()),scene={},clock={},keepsake={};
 const classes=new Classes();if(loaderPending)classes.add('festival-loading81');
 document.documentElement={classList:classes,dataset:{}};
 document.body={dataset:{sceneMotion:'on'},matches:()=>true,classList:new Classes()};document.hidden=false;
 document.querySelector=selector=>({
  '[data-interest]':buttons[0]||null,'[data-festival-scene]':scene,'#festival-clock,.hero-particles':clock,'[data-keepsake-studio]':keepsake
 }[selector]||null);
 document.querySelectorAll=selector=>selector==='[data-interest]'?buttons:[];
 const store=new Map(),context=vm.createContext({
  document,navigator:{deviceMemory:8,hardwareConcurrency:8},performance:{now:()=>0},
  matchMedia:()=>Object.assign(new Events(),{matches:false}),
  addEventListener:window.addEventListener.bind(window),removeEventListener:window.removeEventListener.bind(window),
  requestAnimationFrame:()=>1,cancelAnimationFrame:()=>{},setTimeout,clearTimeout,
  localStorage:{getItem:key=>store.get(key)??null,setItem:(key,value)=>store.set(key,value)},
  CustomEvent:class{constructor(type,options){this.type=type;this.detail=options?.detail;}},
  IntersectionObserver:class{constructor(callback){this.callback=callback;this.nodes=[];observers.push(this);}observe(node){this.nodes.push(node);}unobserve(){}disconnect(){}},
  console:{warn:(...args)=>warnings.push(args.map(String).join(' ')),log(){}},URL,URLSearchParams,AbortController
 });
 const modules=new Map();
 async function moduleFor(filename){
  if(modules.has(filename))return modules.get(filename);
  const module=new vm.SourceTextModule(await readFile(filename,'utf8'),{
   identifier:filename,context,
   importModuleDynamically:async()=>{
    const stub=new vm.SyntheticModule(expected,function(){for(const name of expected)this.setExport(name,()=>started.push(name));},{context});
    await stub.link(()=>{});await stub.evaluate();return stub;
   }
  });
  modules.set(filename,module);await module.link((specifier,referrer)=>moduleFor(resolve(dirname(referrer.identifier),specifier)));return module;
 }
 const main=await moduleFor(resolve(assetRoot,'site.js'));await main.evaluate();
 if(loaderPending){assert.equal(started.length,0);document.dispatchEvent({type:'anazori:ready'});}
 for(const observer of observers)observer.callback(observer.nodes.map(target=>({target,isIntersecting:true})));
 for(let attempt=0;attempt<100&&started.length<expected.length;attempt++)await new Promise(done=>setTimeout(done,5));
 assert.deepEqual([...started].sort(),[...expected].sort(),'All home feature initializers must run');
 assert.equal(warnings.length,0,warnings.join('\n'));
 for(const button of buttons)assert.equal(button.listeners.get('click')?.length,1,'Every interest button must receive its handler');
 assert(document.listeners.get('click')?.length,'Later ticket handlers must also initialize');
 return {interestButtons:interestCount,loaderPending,started,uncaughtErrors:0};
}
if(process.argv.includes('--expect-broken')){
 await assert.rejects(run(0,false),/Cannot read properties of null \(reading 'forEach'\)/);
 await assert.rejects(run(1,false),/forEach is not a function/);
 console.log('PASS Reproduced the live startup crash both without an interest button and with one.');
}else{
 const results=[];
 for(const count of [0,1,3])for(const waiting of [false,true])results.push(await run(count,waiting));
 console.log('PASS All six compiled-entry startup cases initialize countdown, motion, event scenes/carousel and keepsake loading.');
 console.log('PASS Empty, single and multiple interest buttons work before and after the loading screen.');
 if(process.env.ANAZORI_STARTUP106_REPORT)await writeFile(process.env.ANAZORI_STARTUP106_REPORT,JSON.stringify(results,null,2)+'\n');
}
