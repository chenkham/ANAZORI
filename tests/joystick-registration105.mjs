import assert from 'node:assert/strict';
import {initGameRegistration105} from '../frontend/game-registration105.js';

function fixture({supported=true,throws=false,present=true}={}){
 const callbacks={},state={prevented:0,opened:0,focused:0,locked:0};
 const link={addEventListener:(name,callback)=>callbacks[name]=callback};
 const dialog={open:false,querySelector:()=>({focus:()=>state.focused++})};
 if(supported)dialog.showModal=()=>{if(throws)throw Error('Dialog unavailable');dialog.open=true;state.opened++;};
 const root={querySelector:()=>present?dialog:null,querySelectorAll:()=>[link],body:{classList:{add:name=>{assert.equal(name,'modal-open');state.locked++;}}}};
 initGameRegistration105(root);
 const click=overrides=>callbacks.click?.({button:0,preventDefault:()=>state.prevented++,...overrides});
 return {click,state,dialog};
}
const normal=fixture();normal.click();assert.deepEqual(normal.state,{prevented:1,opened:1,focused:1,locked:1});
normal.click();assert.equal(normal.state.opened,1,'Repeated clicks do not reopen an open dialog.');
console.log('PASS Normal and keyboard-style activation opens the game choices and focuses the first game.');
for(const overrides of [{button:1},{button:2},{ctrlKey:true},{metaKey:true},{shiftKey:true},{altKey:true},{defaultPrevented:true}]){
 const test=fixture();test.click(overrides);assert.deepEqual(test.state,{prevented:0,opened:0,focused:0,locked:0});
}
console.log('PASS Modified links preserve new-tab/window behavior.');
for(const options of [{supported:false},{throws:true},{present:false}]){
 const test=fixture(options);test.click();assert.deepEqual(test.state,{prevented:0,opened:0,focused:0,locked:0});
}
console.log('PASS Unsupported or unavailable dialogs retain the working registration-page fallback.');
