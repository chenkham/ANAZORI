// Save event details before moving into the independent form editor.
document.querySelectorAll('[data-open-form-setup]').forEach(link=>link.addEventListener('click',async event=>{
 event.preventDefault();const form=link.closest('form'),status=form.querySelector('[data-event-save-status]');
 if(!form.reportValidity())return;
 if(form.dataset.saving==='1')return;form.dataset.saving='1';status.textContent='Saving your event changes before opening Form setup…';
 try{
  const data=new FormData(form);data.set('response_format','json');
  const response=await fetch('/admin.php',{method:'POST',body:data,credentials:'same-origin',headers:{Accept:'application/json'}}),result=await response.json();
  if(!response.ok||!result.ok)throw Error(result.error||'The event could not be saved. Your changes are still here.');
  form.elements.revision.value=result.revision;location.assign(link.href);
 }catch(error){status.textContent=error.message;status.classList.add('notice','error');status.scrollIntoView({block:'center'});}finally{delete form.dataset.saving;}
}));
// Each media field uploads directly into the shared library and selects its result.
document.addEventListener('change',async event=>{
 const input=event.target;if(!input.matches('[data-direct-media]'))return;
 if(!input.files.length)return;
 const field=input.closest('.field'),form=field.closest('form'),select=field.querySelector('select'),status=field.querySelector('[data-upload-status]');
 input.disabled=true;status.textContent='Uploading…';
 try{
  const data=new FormData();data.set('csrf_token',form.elements.csrf_token.value);data.set('file',input.files[0]);data.set('module',input.dataset.module);data.set('kind',input.dataset.kind);data.set('id',form.elements.id?.value||'0');
  const response=await fetch('/api/studio-media.php',{method:'POST',body:data,credentials:'same-origin'}),result=await response.json();
  if(!response.ok||!result.ok)throw Error(result.error||'Upload failed.');
  select.append(new Option(result.media.title,result.media.path,true,true));select.dispatchEvent(new Event('change',{bubbles:true}));status.textContent='Uploaded and selected. Also available in Media library and Gallery photo choices. Save this page to publish the change.';input.value='';
 }catch(error){status.textContent=error.message;}finally{input.disabled=false;}
});
