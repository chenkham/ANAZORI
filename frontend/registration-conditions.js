export function initRegistrationConditions(form){
 if(!form)return ()=>{};
 const lifecycle=new AbortController(),signal=lifecycle.signal;
 const native=form.querySelector('[data-native-form]');
 const sections=native?[...native.querySelectorAll('[data-form-section]')]:[];
 const navigation=native?.querySelector('.native-form-navigation');
 let page=0,visibleSections=[];
 const rows=[...form.querySelectorAll('[data-field-game]')];
 const controls=row=>[...row.querySelectorAll('input,select,textarea')];
 const answer=id=>{
  const inputs=[...form.querySelectorAll('[name]')].filter(input=>input.name===`answers[${id}]`||input.name===`answers[${id}][]`);
  if(inputs.some(input=>input.type==='checkbox'))return inputs.filter(input=>input.checked).map(input=>input.value);
  const checked=inputs.find(input=>input.type==='radio'&&input.checked);
  return checked?.value||inputs.find(input=>input.type!=='radio')?.value||'';
 };
 function showPage(){
  page=Math.max(0,Math.min(page,visibleSections.length-1));
  sections.forEach(section=>{section.hidden=!visibleSections.includes(section)||visibleSections.indexOf(section)!==page;});
  if(!navigation)return;
  navigation.hidden=visibleSections.length<=1;
  const progress=navigation.querySelector('[data-form-progress]');progress.textContent=native.dataset.progress==='1'?`Section ${page+1} of ${visibleSections.length}`:'';
  navigation.querySelector('[data-form-back]').hidden=page===0;
  navigation.querySelector('[data-form-next]').hidden=page>=visibleSections.length-1;
  form.querySelectorAll('button[type=submit]').forEach(button=>{button.hidden=visibleSections.length>1&&page<visibleSections.length-1;});
 }
 function update(){
  const game=form.querySelector('[name="game"]:checked')?.value||form.querySelector('select[name="game"]')?.value||form.querySelector('input[name="game"][type="hidden"]')?.value||'';
  const ticket=form.querySelector('[name="type"]:checked')?.value||form.querySelector('[name="type"][type="hidden"]')?.value||'';
  const ticketMap=JSON.parse(form.dataset.entryMap||'{}'),price=ticketMap[ticket]?.price;
  const shown=new Set();let sectionAllowed=true;
  rows.forEach(row=>{
   let visible=!row.dataset.fieldGame||row.dataset.fieldGame===game;
   if(row.dataset.fieldTicket)visible=visible&&row.dataset.fieldTicket===ticket;
   if(row.dataset.fieldPurpose==='payment'&&form.dataset.entryMap)visible=visible&&price!==undefined&&price>0;
   if(row.dataset.conditionField){const value=answer(row.dataset.conditionField);visible=visible&&shown.has(row.dataset.conditionField)&&(Array.isArray(value)?value.includes(row.dataset.conditionValue):value===row.dataset.conditionValue);}
   if(row.dataset.itemType==='section')sectionAllowed=visible;else visible=visible&&sectionAllowed;
   row.hidden=!visible;controls(row).forEach(input=>{input.disabled=!visible;});
   if(visible&&row.dataset.fieldId)shown.add(row.dataset.fieldId);
  });
  form.querySelectorAll('[data-required-choices]').forEach(group=>{
   const choices=[...group.querySelectorAll('input[type=checkbox]')];
   const other=group.querySelector('.native-other-label input');
   choices[0]?.setCustomValidity(choices[0].disabled||choices.some(input=>input.checked)||Boolean(other?.value.trim())?'':'Choose at least one option.');
  });
  form.querySelectorAll('input[type=file][data-max-files]').forEach(input=>{
   const invalid=input.files.length>Number(input.dataset.maxFiles)||[...input.files].some(file=>file.size>Number(input.dataset.maxMb)*1024*1024);
   input.setCustomValidity(invalid?`Choose up to ${input.dataset.maxFiles} files, ${input.dataset.maxMb} MB each.`:'');
  });
  visibleSections=sections.filter(section=>section.querySelector('[data-ticket-picker]')||[...section.querySelectorAll('[data-field-game]')].some(row=>!row.hidden));showPage();
 }
 if(native?.dataset.shuffle==='1'&&!rows.some(row=>row.dataset.conditionField))sections.forEach(section=>{
  const order=[...section.children];
  const items=order.filter(item=>item.dataset.itemType!=='section'&&!item.matches('[data-ticket-picker]')&&item.dataset.fieldPurpose!=='payment'&&!item.dataset.fieldTicket&&!item.querySelector('[data-payment-action]'));
  const shuffled=[...items];
  for(let i=shuffled.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[shuffled[i],shuffled[j]]=[shuffled[j],shuffled[i]];}
  let index=0;order.forEach(item=>section.append(items.includes(item)?shuffled[index++]:item));
 });
 navigation?.querySelector('[data-form-next]').addEventListener('click',()=>{
  const current=visibleSections[page];if(!current)return;
  const invalid=controls(current).find(input=>!input.disabled&&!input.checkValidity());
  if(invalid){invalid.reportValidity();return;}page++;showPage();native.scrollIntoView({block:'start',behavior:'auto'});
 },{signal});
 navigation?.querySelector('[data-form-back]').addEventListener('click',()=>{page--;showPage();native.scrollIntoView({block:'start',behavior:'auto'});},{signal});
 form.addEventListener('invalid',event=>{const section=event.target.closest('[data-form-section]');if(section&&visibleSections.includes(section)){page=visibleSections.indexOf(section);showPage();}},{capture:true,signal});
 form.addEventListener('change',update,{signal});form.addEventListener('input',update,{signal});
 form.addEventListener('reset',()=>queueMicrotask(update),{signal});update();return ()=>lifecycle.abort();
}
