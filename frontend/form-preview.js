import { initRegistrationConditions } from './registration-conditions.js';
const element=(tag,text='',className='')=>{const node=document.createElement(tag);node.textContent=text;if(className)node.className=className;return node;};
const lines=value=>Array.isArray(value)?value:String(value||'').split(/\r?\n/).filter(Boolean);
export function renderFormPreview(dialog,title,description,questions,phase,buttonText,tickets=[]){
  const body=dialog.querySelector('[data-preview-body]');body.replaceChildren();
  const heading=element('h2',title,'form-preview-title');heading.id='form-preview-title';body.append(heading,element('p',description,'form-preview-description'));
  const form=element('form');form.id='anazori-preview-only';form.addEventListener('submit',event=>event.preventDefault());
  const entries=Object.fromEntries(tickets.map(ticket=>[ticket.id,{label:ticket.label,price:ticket.price}]));if(tickets.length)form.dataset.entryMap=JSON.stringify(entries);
  const native=element('div','','native-registration-form');native.dataset.nativeForm='';native.dataset.progress='1';
  let section=element('section');section.dataset.formSection='';native.append(section);
  let pickerAdded=false;
  const addTicketPicker=()=>{
    if(pickerAdded||!tickets.length)return;pickerAdded=true;
    const picker=element('fieldset','','ticket-categories81');picker.dataset.ticketPicker='';picker.append(element('legend','Choose your ticket'));
    tickets.forEach(ticket=>{const label=element('label','','ticket-option'),input=element('input');input.type='radio';input.name='type';input.value=ticket.id;const copy=element('span');copy.append(element('strong',ticket.label),element('b',new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR'}).format(ticket.price/100)));if(ticket.description)copy.append(element('small',ticket.description));label.append(input,copy);picker.append(label);});section.append(picker);
  };
  if(phase==='registration')section.append(element('p','Name and verified email come from your participant account.','help'));
  else ['Your name','Email address'].forEach(label=>{const field=element('label',label,'form-preview-question');const input=element('input');input.placeholder=label;field.append(input);section.append(field);});
  questions.forEach(data=>{
    if(data.type==='section'){section=element('section');section.dataset.formSection='';native.append(section);}
    if(data.type==='image'&&(data.payment_ticket||data.payment_upi||data.purpose==='payment'))addTicketPicker();
    const group=element('div','','native-form-item form-preview-question');group.dataset.fieldId=data.id;group.dataset.itemType=data.type;group.dataset.conditionField=data.condition_field||'';group.dataset.conditionValue=data.condition_value||'';group.dataset.fieldGame=data.game||'';
    group.dataset.fieldTicket=data.payment_ticket||'';group.dataset.fieldPurpose=data.purpose||'';
    const label=element('h3',`${data.label||'Untitled question'}${data.required?' *':''}`);group.append(label);if(data.help)group.append(element('p',data.help,'help'));
    const choice=(value,type,name=data.id)=>{const label=element('label','','form-preview-choice');const input=element('input');input.type=type;input.name=`answers[${name}]${type==='checkbox'?'[]':''}`;input.value=value;label.append(input,element('span',value));return label;};
    if(['image','video'].includes(data.type)){
      if(data.payment_ticket&&entries[data.payment_ticket]){const ticket=entries[data.payment_ticket];group.append(element('p',`${ticket.label} · Pay ${new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR'}).format(ticket.price/100)}`,'help'));}
      if(data.payment_dynamic){group.append(element('p','Automatic QR: the participant sees the selected ticket’s fixed amount and their registration reference. No image upload is needed.','help'));}
      else if(data.media){const media=element(data.type==='video'?'video':'img','','native-form-media');media.src=data.media;if(data.type==='video')media.controls=true;else media.alt=data.label;group.append(media);}else group.append(element('p','Attach media using More question settings.','help'));
    }else if(['description','section'].includes(data.type)){}
    else if(['radio','multiselect'].includes(data.type)){
      lines(data.options).forEach(value=>group.append(choice(value,data.type==='radio'?'radio':'checkbox')));
      if(data.other){group.append(choice('Other',data.type==='radio'?'radio':'checkbox'));const other=element('input');other.placeholder='Other answer';other.name=`answers[${data.id}-other]`;group.append(other);}
    }else if(['scale','rating'].includes(data.type)){
      const scale=element('div','','native-form-scale');for(let n=Number(data.min||1);n<=Number(data.max||5);n++){const item=choice(String(n),'radio');if(data.type==='rating')item.querySelector('span').textContent='★'.repeat(n);scale.append(item);}group.append(scale,element('p',`${data.low_label||''} — ${data.high_label||''}`,'help'));
    }else if(['grid','checkgrid'].includes(data.type)){
      const wrap=element('div','','native-grid-wrap'),table=element('table','','native-form-grid'),head=element('tr');head.append(element('th'));lines(data.options).forEach(value=>head.append(element('th',value)));const thead=element('thead');thead.append(head);table.append(thead);const tbody=element('tbody');
      lines(data.rows).forEach((row,i)=>{const tr=element('tr');tr.append(element('th',row));lines(data.options).forEach(value=>{const td=element('td');const input=element('input');input.type=data.type==='grid'?'radio':'checkbox';input.name=`answers[${data.id}][${i}]${data.type==='checkgrid'?'[]':''}`;input.value=value;input.setAttribute('aria-label',`${row}: ${value}`);td.append(input);tr.append(td);});tbody.append(tr);});table.append(tbody);wrap.append(table);group.append(wrap);
    }else{
      let input;if(data.type==='select'){input=element('select');const empty=element('option','Choose an option');empty.value='';input.append(empty);lines(data.options).forEach(value=>input.append(element('option',value)));}
      else if(data.type==='textarea'){input=element('textarea');input.rows=3;}
      else {input=element('input');input.type=({text:'text',checkbox:'checkbox',file:'file'})[data.type]||data.type;}
      input.name=`answers[${data.id}]`;input.setAttribute('aria-label',data.label||'Untitled question');input.placeholder=data.placeholder||'';group.append(input);
      if(data.type==='file'){input.multiple=Number(data.file_count)>1;group.append(element('small',`Up to ${data.file_count||1} files · ${data.file_size||5} MB each. Preview uploads are not sent.`));}
    }
    section.append(group);
  });
  addTicketPicker();const navigation=element('div','','native-form-navigation');navigation.dataset.formNavigation='';const back=element('button','Back','quiet-button');back.type='button';back.dataset.formBack='';const progress=element('span');progress.dataset.formProgress='';const next=element('button','Next','primary-button');next.type='button';next.dataset.formNext='';navigation.append(back,progress,next);native.append(navigation);form.append(native);
  const submit=element('button',buttonText||'Submit for approval','primary-button');submit.type='submit';submit.disabled=true;form.append(submit);body.append(form);initRegistrationConditions(form);dialog.showModal();
}
