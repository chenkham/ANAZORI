import { initFormBuilder } from './form-builder.js';
initFormBuilder();
const editor=document.querySelector('[data-form-workspace]');
if(editor){
  const phase=editor.dataset.phase,status=editor.querySelector('[data-save-status]');
  let revision=Number(editor.dataset.revision),timer,dirty=false,restoring=false,queue=Promise.resolve();
  const history=[],future=[];
  const resizeText=()=>editor.querySelectorAll('.form-builder-header textarea').forEach(input=>{input.style.height='auto';input.style.height=`${input.scrollHeight}px`;});
  resizeText();editor.addEventListener('input',resizeText);window.addEventListener('resize',resizeText);
  const read=()=>{
    const result={questions:editor.formEditor.questions(),settings:{}};
    ['title','intro','button'].forEach(key=>result[key]=editor.querySelector(`[name="${phase}_${key}"]`).value);
    editor.querySelectorAll(`[name^="${phase}_settings["]`).forEach(input=>{const key=input.name.match(/\[([^\]]+)\]/)[1];result.settings[key]=input.type==='checkbox'?input.checked:input.value;});
    result.prices=Object.fromEntries([...editor.querySelectorAll('[data-ticket-price108]')].map(input=>[input.dataset.ticketPrice108,input.value]));
    return result;
  };
  const historyButtons=()=>{editor.querySelector('[data-form-undo]').disabled=history.length<2;editor.querySelector('[data-form-redo]').disabled=!future.length;};
  history.push(JSON.stringify(read()));
  function changed(){
    if(restoring)return;
    const snapshot=JSON.stringify(read());if(snapshot===history.at(-1))return;
    history.push(snapshot);if(history.length>50)history.shift();future.length=0;historyButtons();dirty=true;status.textContent='Unsaved changes';clearTimeout(timer);timer=setTimeout(()=>save(false),1400);
  }
  function restore(snapshot){
    restoring=true;const data=JSON.parse(snapshot);editor.formEditor.replace(data.questions);
    ['title','intro','button'].forEach(key=>editor.querySelector(`[name="${phase}_${key}"]`).value=data[key]);
    editor.querySelectorAll(`[name^="${phase}_settings["]`).forEach(input=>{const value=data.settings[input.name.match(/\[([^\]]+)\]/)[1]];if(input.type==='checkbox')input.checked=!!value;else input.value=value??'';});
    editor.querySelectorAll('[data-ticket-price108]').forEach(input=>{input.value=data.prices?.[input.dataset.ticketPrice108]??input.value;});
    restoring=false;dirty=true;status.textContent='Unsaved changes';historyButtons();clearTimeout(timer);timer=setTimeout(()=>save(false),1400);
  }
  async function performSave(publish){
    const payload=read(),snapshot=JSON.stringify(payload);status.textContent=publish?'Publishing…':'Saving draft…';
    try{
      const response=await fetch('/api/studio-form.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf_token:editor.querySelector('[name="csrf_token"]').value,event_id:Number(editor.querySelector('[name="id"]').value),phase,game:editor.dataset.game||'',revision,action:publish?'publish':'draft',form:payload})});
      const result=await response.json();if(!response.ok||!result.ok)throw Error(result.error||'Could not save the form.');
      revision=result.revision;dirty=JSON.stringify(read())!==snapshot;status.textContent=dirty?'Unsaved changes':publish?'Published · changes are live':'All changes saved as draft';
      if(dirty){clearTimeout(timer);timer=setTimeout(()=>save(false),1400);}
      return true;
    }catch(error){dirty=true;status.textContent=error.message;editor.querySelector('[data-builder-status]').textContent=error.message;return false;}
  }
  function save(publish){clearTimeout(timer);queue=queue.then(()=>performSave(publish));return queue;}
  ['input','change','builderchange'].forEach(name=>editor.addEventListener(name,changed));
  editor.addEventListener('submit',async event=>{event.preventDefault();if(!editor.reportValidity())return;const button=event.submitter;button.disabled=true;await save(true);button.disabled=false;});
  editor.addEventListener('click',async event=>{
    const button=event.target.closest('button');if(!button)return;
    if(button.hasAttribute('data-save-draft'))save(false);
    if(button.hasAttribute('data-form-undo')&&history.length>1){future.push(history.pop());restore(history.at(-1));}
    if(button.hasAttribute('data-form-redo')&&future.length){const next=future.pop();history.push(next);restore(next);}
    if(button.hasAttribute('data-form-link')){try{await navigator.clipboard.writeText(new URL(button.dataset.url,location.origin).href);status.textContent='Event link copied';}catch{status.textContent=`Event link: ${new URL(button.dataset.url,location.origin).href}`;}}
    if(button.hasAttribute('data-import-open')){editor.querySelector('.form-template-tools').open=true;editor.querySelector('[data-form-import]').click();}
    if(button.hasAttribute('data-workspace-tab'))selectTab(button.dataset.workspaceTab);
  });
  function selectTab(name){
    editor.querySelectorAll('[data-workspace-tab]').forEach(tab=>{const selected=tab.dataset.workspaceTab===name;tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;});
    editor.querySelectorAll('[data-workspace-pane]').forEach(pane=>pane.hidden=pane.dataset.workspacePane!==name);
  }
  editor.addEventListener('invalid',event=>{if(event.target.closest('[data-question-card]'))selectTab('questions');else if(event.target.closest('[data-workspace-pane="settings"]'))selectTab('settings');},true);
  editor.querySelector('[role="tablist"]').addEventListener('keydown',event=>{
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();const tabs=[...editor.querySelectorAll('[data-workspace-tab]')];let i=tabs.indexOf(document.activeElement);i=event.key==='Home'?0:event.key==='End'?tabs.length-1:(i+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;selectTab(tabs[i].dataset.workspaceTab);tabs[i].focus();
  });
  window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
}
