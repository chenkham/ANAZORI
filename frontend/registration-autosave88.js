// Account drafts live on the server. A device outbox bridges offline periods and
// reloads; it contains only this account/event/game's unfinished form values.
function uploadOutbox(key, hash) {
  const database = new Promise(resolve => {
    if (!globalThis.indexedDB) { resolve(null); return; }
    try {
      const request = indexedDB.open('anazori-registration-uploads88', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('drafts');
      request.onsuccess = () => { const db=request.result;db.onversionchange=()=>db.close();resolve(db); };
      request.onerror = () => resolve(null);
      request.onblocked = () => resolve(null);
    } catch { resolve(null); }
  });
  const transaction = async (mode, work) => {
    const db = await database;
    if (!db) throw Error('Device upload storage is unavailable.');
    return new Promise((resolve, reject) => {
      try {
        const tx=db.transaction('drafts', mode), request=work(tx.objectStore('drafts'));
        tx.oncomplete=()=>resolve(request?.result);
        tx.onerror=tx.onabort=()=>reject(tx.error||Error('Device upload storage is unavailable.'));
      } catch (error) { reject(error); }
    });
  };
  let writes = Promise.resolve();
  return {
    read: () => transaction('readonly', store=>store.get(key)).catch(()=>null),
    write(entries, metadata={}) {
      const record={hash,entries,...metadata};
      const result=writes.catch(()=>{}).then(()=>transaction('readwrite',store=>entries.length?store.put(record,key):store.delete(key)));
      writes=result;
      return result;
    }
  };
}

export function initRegistrationAutosave(form, isSubmitted) {
  const errorBox=form.querySelector('[data-draft-error]');
  const key=`anazori:registration:${form.dataset.participant}:${form.dataset.eventId}:${form.elements.edit_order?.value||0}:${form.dataset.game||'event'}`;
  const hash=form.dataset.schemaHash, files=new Map(), fileChanges=new Set();
  const fileInputs=new Map([...form.querySelectorAll('input[type=file][name]')].map(input=>[input.name,input]));
  const requiredFiles=new Map([...fileInputs].map(([name,input])=>[name,input.required]));
  const outbox=uploadOutbox(key,hash);
  const id=()=>globalThis.crypto?.randomUUID?.()||`${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
  const owner=id();
  let revision=Number(form.dataset.draftRevision||0),changes=0,saved=0,timer=0,pending=null,request=null;
  let modifiedAt=Date.now(),dirtySince=0,retryDelay=1500,blocked=false,destroyed=false,leaving=false;
  const fieldName=name=>name.startsWith('answers[')||['type','team_name','payment_method','consent'].includes(name);
  const controls=[...form.querySelectorAll('input[name],select[name],textarea[name]')].filter(input=>fieldName(input.name)&&input.type!=='file');
  const read=()=>controls.flatMap(input=>{
    if (['checkbox','radio'].includes(input.type)&&!input.checked) return [];
    if (input instanceof HTMLSelectElement&&input.multiple) return [...input.selectedOptions].map(option=>[input.name,option.value]);
    return [[input.name,input.value]];
  });
  const report=error=>{
    if (!errorBox) return;
    errorBox.textContent=error?.message||'Your changes could not be saved. Please reconnect and try again.';
    errorBox.hidden=false;
  };
  const clearError=()=>{if(errorBox){errorBox.hidden=true;errorBox.textContent='';}};
  const remember=()=>{
    if(destroyed||isSubmitted())return;
    if(changes<=saved&&!files.size&&!request)return;
    try { localStorage.setItem(key,JSON.stringify({hash,time:modifiedAt,baseRevision:revision,owner,changes,entries:read()})); }
    catch { if(navigator.onLine===false)report(Error('This device cannot keep an offline copy. Reconnect before leaving the form.')); }
  };
  try {
    const local=JSON.parse(localStorage.getItem(key)||'null');
    if(local?.hash===hash&&Array.isArray(local.entries)&&(local.baseRevision===revision||local.time>Date.parse(form.dataset.draftUpdated||'1970-01-01'))){
      const entries=local.entries.filter(entry=>Array.isArray(entry)&&entry.length===2&&entry.every(value=>typeof value==='string'));
      for(const input of controls){
        if(input.readOnly)continue;
        const values=entries.filter(([name])=>name===input.name).map(([,value])=>value);
        if(['checkbox','radio'].includes(input.type))input.checked=values.includes(input.value);
        else if(input instanceof HTMLSelectElement&&input.multiple)[...input.options].forEach(option=>option.selected=values.includes(option.value));
        else input.value=values[0]||'';
      }
      modifiedAt=local.time;changes++;
    }
  } catch {}
  let lastValues=JSON.stringify(read());
  const persistFiles=()=>outbox.write([...files],{time:modifiedAt,baseRevision:revision}).catch(()=>{
    if(files.size&&navigator.onLine===false)report(Error('This device cannot keep the selected files offline. Reconnect before leaving the form.'));
  });
  const showQueued=(name,entry)=>{
    const input=fileInputs.get(name),row=input?.closest('[data-field-id]');if(!input||!row)return;
    let label=row.querySelector('[data-queued-draft-files]');
    if(entry){
      input.required=false;
      if(!label){label=document.createElement('p');label.dataset.queuedDraftFiles='';label.className='account-help';row.append(label);}
      label.textContent=entry.files.map(file=>file.name).join(', ');
    }else{
      label?.remove();input.required=input.dataset.hasExisting==='1'?false:requiredFiles.get(name);
    }
  };
  const showFiles=uploaded=>{
    form.querySelectorAll('[data-field-id]').forEach(row=>{
      const selected=uploaded.filter(file=>file.field_id===row.dataset.fieldId);if(!selected.length)return;
      let list=row.querySelector('[data-saved-draft-files]');
      if(!list){list=document.createElement('div');list.dataset.savedDraftFiles='';row.append(list);}
      list.replaceChildren();
      const input=row.querySelector('input[type=file]');if(input){input.required=false;input.dataset.hasExisting='1';}
      for(const file of selected){
        const link=document.createElement('a');link.href='/registration-file.php?id='+file.id;link.target='_blank';link.rel='noopener';link.className='text-link';link.textContent=file.original_name+' ↗';list.append(link);
      }
    });
  };
  function schedule(delay=650){
    clearTimeout(timer);
    if(destroyed||leaving||isSubmitted()||blocked||navigator.onLine===false)return;
    timer=setTimeout(()=>save().catch(()=>{}),delay);
  }
  const ready=outbox.read().then(record=>{
    if(destroyed||isSubmitted())return;
    if(record?.hash===hash&&(record.baseRevision===revision||record.time>Date.parse(form.dataset.draftUpdated||'1970-01-01'))){
      for(const [name,entry] of Array.isArray(record.entries)?record.entries:[]){
        if(!fileInputs.has(name)||fileChanges.has(name)||!Array.isArray(entry?.files)||!entry.files.length||!entry.files.every(file=>file instanceof File))continue;
        files.set(name,entry);showQueued(name,entry);changes++;
      }
      persistFiles();
    }else if(record){
      persistFiles();
    }
    if(changes>saved){remember();schedule(0);}
  });
  const makeRequest=()=>{
    const data=new FormData(form);
    // Disabled branches also belong to an unfinished draft. Final registration
    // continues to submit only enabled fields and is validated by the server.
    for(const name of new Set([...data.keys()].filter(fieldName)))data.delete(name);
    for(const [name,value] of read())data.append(name,value);
    for(const name of fileInputs.keys())data.delete(name);
    const capturedFiles=new Map(files);
    for(const [name,entry] of capturedFiles)for(const file of entry.files)data.append(name,file,file.name);
    data.set('draft_revision',String(revision));data.set('draft_request',id());
    const size=[...data].reduce((total,[name,value])=>total+name.length*3+256+(typeof value==='string'?new Blob([value]).size:value.size),1024);
    return {data,number:changes,capturedFiles,keepalive:!capturedFiles.size&&size<60000};
  };
  async function save(force=false){
    clearTimeout(timer);await ready;
    if(destroyed||isSubmitted())return;
    if(pending){await pending;if(changes>saved||files.size)return save(force);return;}
    if(!request&&!force&&changes<=saved&&!files.size)return;
    if(navigator.onLine===false)throw Error('Reconnect before continuing to payment or submitting.');
    request ||= makeRequest();
    const captured=request;
    pending=(async()=>{
      const response=await fetch('/api/registration-draft.php',{method:'POST',body:captured.data,credentials:'same-origin',keepalive:captured.keepalive});
      let result;try{result=await response.json();}catch{throw Error('The connection was interrupted. Your changes will sync when it returns.');}
      if(!response.ok||!result.ok){
        const error=Error(result.error||'Your changes could not be saved.');
        error.permanent=response.status>=400&&response.status<500;throw error;
      }
      revision=Number(result.revision);saved=captured.number;form.dataset.draftUpdated=result.updated_at;
      for(const [name,entry] of captured.capturedFiles){
        if(files.get(name)?.token!==entry.token)continue;
        files.delete(name);
        const input=fileInputs.get(name);
        if(input&&input.files.length===entry.files.length&&entry.files.every((file,i)=>input.files[i]===file))input.value='';
        showQueued(name,null);
      }
      showFiles(result.files||[]);persistFiles();
      request=null;retryDelay=1500;blocked=false;clearError();
      if(changes===saved){
        dirtySince=0;
        try{const local=JSON.parse(localStorage.getItem(key)||'null');if(local?.owner===owner&&local.changes<=saved)localStorage.removeItem(key);}catch{}
      }
    })();
    try { await pending; }
    catch(error){
      remember();
      if(error.permanent){request=null;blocked=true;report(error);}
      else{schedule(retryDelay);retryDelay=Math.min(30000,retryDelay*2);}
      throw error;
    }finally{pending=null;}
    if(changes>saved||files.size){if(force)return save(true);schedule(0);}
  }
  const changed=event=>{
    if(destroyed||isSubmitted())return;
    let fileChanged=false;
    const input=event.target;
    if(input.matches?.('input[type=file][name]')){
      const selected=[...input.files],previous=files.get(input.name)?.files||[];
      if(selected.length!==previous.length||selected.some((file,i)=>file!==previous[i])){
        fileChanges.add(input.name);fileChanged=true;
        if(selected.length)files.set(input.name,{files:selected,token:id()});else files.delete(input.name);
        showQueued(input.name,files.get(input.name));
      }
    }
    const values=JSON.stringify(read());if(values===lastValues&&!fileChanged)return;
    lastValues=values;changes++;modifiedAt=Date.now();dirtySince ||= modifiedAt;blocked=false;remember();
    if(fileChanged)persistFiles();
    schedule(fileChanged||event.type==='change'?0:Math.min(650,Math.max(0,1800-(modifiedAt-dirtySince))));
  };
  const online=()=>{blocked=false;save().catch(()=>{});};
  const blur=()=>{if(changes>saved&&!blocked)save().catch(()=>{});};
  const visibility=()=>{
    if(document.hidden){remember();save().catch(()=>{});}
    else if(!leaving){blocked=false;save().catch(()=>{});}
  };
  const hide=()=>{remember();leaving=true;clearTimeout(timer);save().catch(()=>{});};
  const show=event=>{if(event.persisted){leaving=false;blocked=false;save().catch(()=>{});}};
  form.addEventListener('input',changed);form.addEventListener('change',changed);form.addEventListener('focusout',blur);
  addEventListener('online',online);addEventListener('pagehide',hide);addEventListener('pageshow',show);
  document.addEventListener('visibilitychange',visibility);
  function finish(){
    destroyed=true;clearTimeout(timer);files.clear();outbox.write([]).catch(()=>{});
    try{localStorage.removeItem(key);}catch{}
    form.removeEventListener('input',changed);form.removeEventListener('change',changed);form.removeEventListener('focusout',blur);
    removeEventListener('online',online);removeEventListener('pagehide',hide);removeEventListener('pageshow',show);
    document.removeEventListener('visibilitychange',visibility);
  }
  return {save,finish,remember,report};
}
