import assert from 'node:assert/strict';
import {initGameForms81} from '../frontend/game-forms81.js';
const saved={document:globalThis.document,fetch:globalThis.fetch};
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const fragment=game=>({html:'<label>'+game+' fields</label>',title:game+' interest',intro:'Your team details',game,button:'Share interest'});
const tick=async()=>{await new Promise(done=>setTimeout(done,0));};
const nodes=new Map([['#interest-title',{textContent:''}],['.dialog-intro',{textContent:''}]]);
const makeElement=tag=>({tagName:tag,textContent:'',children:[],listeners:{},setAttribute(){},append(child){this.children.push(child);},addEventListener(event,call){this.listeners[event]=call;}});
let fetches=[];
function fixture(){
 const select={value:'',listeners:{},addEventListener(event,call){this.listeners[event]=call;}};
 const submit={disabled:false,firstChild:{textContent:''}};
 const target={dataset:{event:'joystick',phase:'interest'},children:[],_html:'',replaceChildren(){this.children=[];this._html='';},append(node){this.children.push(node);},set innerHTML(value){this._html=value;this.children=[];},get innerHTML(){return this._html;}};
 const form={dataset:{},listeners:{},querySelector(selector){return selector==='[data-game-form]'?target:selector==='[name=game]'||selector==='select[name="game"]'?select:selector==='[type=submit]'?submit:null;},querySelectorAll(){return [];},addEventListener(event,call){this.listeners[event]=call;}};
 initGameForms81(form);
 return {form,select,submit,target,change(value){select.value=value;return select.listeners.change();}};
}
try{
 globalThis.document={createElement:makeElement,querySelector:selector=>nodes.get(selector)};
 globalThis.fetch=(url,options)=>{
  const response=deferred(),body=deferred();fetches.push({url,options,response,body});
  return response.promise;
 };
 const first=fixture();
 first.change('bgmi');const stale=fetches.at(-1);
 stale.response.resolve({ok:true,json:()=>stale.body.promise});await tick();
 first.change('');
 stale.body.resolve(fragment('BGMI'));await tick();
 assert.equal(first.submit.disabled,true,'Clearing the game must keep submission disabled after a late response');
 assert.equal(first.target.innerHTML,'','A late response must not restore the cleared game');
 assert.match(first.target.children[0].textContent,/Choose a game/);
 console.log('PASS Clearing a game while its response finishes cannot restore stale questions or enable submission.');
 const second=fixture();
 second.change('bgmi');const old=fetches.at(-1);old.response.resolve({ok:true,json:()=>old.body.promise});await tick();
 second.change('free-fire');const latest=fetches.at(-1);latest.response.resolve({ok:true,json:()=>latest.body.promise});latest.body.resolve(fragment('Free Fire'));await tick();
 old.body.resolve(fragment('BGMI'));await tick();
 assert.match(second.target.innerHTML,/Free Fire/);assert.doesNotMatch(second.target.innerHTML,/BGMI/);assert.equal(second.submit.disabled,false);
 console.log('PASS Rapid game switching displays only the latest game form.');
 const retry=fixture();
 retry.change('mobile-legends');fetches.at(-1).response.reject(new Error('Connection interrupted'));await tick();
 assert.equal(retry.submit.disabled,true);
 const button=retry.target.children.find(node=>node.tagName==='button');assert(button,'A failed request offers a retry button');assert.equal(button.type,'button');
 button.listeners.click();const again=fetches.at(-1);assert.match(again.url,/mobile-legends/);
 again.response.resolve({ok:true,json:async()=>fragment('MLBB')});await tick();
 assert.equal(retry.submit.disabled,false);assert.match(retry.target.innerHTML,/MLBB/);
 console.log('PASS A failed game-form load can be retried without changing the selected game.');
}finally{globalThis.document=saved.document;globalThis.fetch=saved.fetch;}
