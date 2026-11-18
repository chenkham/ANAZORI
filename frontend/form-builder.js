import { renderFormPreview } from './form-preview.js';
const choiceTypes = new Set(['select', 'radio', 'multiselect', 'grid', 'checkgrid']);

export function parseFormChoices(value) {
  return [...new Set(value.split(/\r\n|\r|\n/).map(option => option.trim()).filter(option => option !== ''))];
}

export function copiedQuestionLabel(label, labels) {
  const taken = new Set(labels.map(value => value.trim().toLowerCase()));
  const base = label.trim() || 'Untitled question';
  let count = 1;
  let candidate;
  do {
    const suffix = count === 1 ? ' (copy)' : ` (copy ${count})`;
    candidate = [...base].slice(0, 120 - suffix.length).join('') + suffix;
    count++;
  } while (taken.has(candidate.toLowerCase()));
  return candidate;
}

function questionData(card) {
  const data={};
  card.querySelectorAll('input[name],select[name],textarea[name]').forEach(input=>{
    const key=input.name.match(/\[([^\]]+)\]$/)?.[1];if(!key)return;
    if(input.closest('[data-for-types]')?.hidden)return;
    data[key]=input.type==='checkbox'?input.checked:input.value;
  });
  if(['scale','rating'].includes(data.type))card.querySelectorAll('[data-scale-key]').forEach(select=>{data[select.dataset.scaleKey]=select.value;});
  return data;
}

export function initFormBuilder(scope = document) {
  scope.querySelectorAll('[data-form-builder]').forEach(builder => {
    let index = 1000;
    const panels = [...builder.querySelectorAll('[data-form-panel]')];
    const tabs = [...builder.querySelectorAll('[data-form-tab]')];
    const dialog = builder.querySelector('[data-form-preview-dialog]');
    const status = builder.querySelector('[data-builder-status]');
    const cards = panel => [...panel.querySelector('[data-question-list]').children];
    const activePanel = () => panels.find(panel => !panel.hidden);
    const announce = message => { status.textContent = message; };
    const standalone=builder.hasAttribute('data-form-workspace');

    function selectPanel(phase, focus = false) {
      panels.forEach(panel => { panel.hidden = panel.dataset.formPanel !== phase; });
      tabs.forEach(tab => {
        const selected = tab.dataset.formTab === phase;
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected && focus) tab.focus();
      });
    }

    function updatePanel(panel) {
      const rows = cards(panel);
      rows.forEach((card, position) => {
        card.querySelector('[data-question-number]').textContent = `Question ${position + 1}`;
        card.querySelector('[data-question-move="up"]').disabled = position === 0;
        card.querySelector('[data-question-move="down"]').disabled = position === rows.length - 1;
        card.querySelector('[data-question-duplicate]').disabled = rows.length >= 100;
        const select=card.querySelector('[data-condition-source]');
        const saved=select.value||select.dataset.savedCondition||'';
        select.replaceChildren(new Option('Always show',''));
        rows.slice(0,position).forEach(earlier=>{
          const data=questionData(earlier);
          if(!['section','description','image','video','file','grid','checkgrid'].includes(data.type))select.append(new Option(data.label||'Untitled question',data.id));
        });
        if([...select.options].some(option=>option.value===saved))select.value=saved;
        delete select.dataset.savedCondition;
      });
      panel.querySelector('[data-question-count]').textContent = `${rows.length} / 100 items`;
      panel.querySelector('[data-question-empty]').hidden = rows.length > 0;
      builder.querySelector('[data-question-add]').disabled = rows.length >= 100;
    }

    function optionRow(card, value) {
      const row = document.createElement('div');
      row.className = 'question-option-row';
      const marker = document.createElement('span');
      marker.className = 'question-option-marker';
      marker.setAttribute('aria-hidden', 'true');
      const input = document.createElement('input');
      input.type = 'text';
      input.maxLength = 120;
      input.value = value;
      input.dataset.optionValue = '';
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.dataset.optionDelete = '';
      remove.textContent = '×';
      row.append(marker, input, remove);
      card.querySelector('[data-option-list]').append(row);
      return input;
    }

    function syncOptions(card) {
      const inputs = [...card.querySelectorAll('[data-option-value]')];
      const isChoice = choiceTypes.has(card.querySelector('[data-question-type]').value);
      const values = inputs.map(input => input.value.trim());
      inputs.forEach((input, position) => {
        input.parentElement.querySelector('.question-option-marker').textContent=card.dataset.answerType==='select'?`${position+1}.`:'';
        input.setAttribute('aria-label', `Option ${position + 1}`);
        input.placeholder = `Option ${position + 1}`;
        input.required = isChoice;
        input.disabled = !isChoice;
        input.setCustomValidity(isChoice && values[position] !== '' && values.indexOf(values[position]) !== position ? 'Use a different option.' : '');
        const remove = input.parentElement.querySelector('[data-option-delete]');
        remove.disabled = inputs.length <= 2;
        remove.setAttribute('aria-label', `Remove option ${position + 1}`);
      });
      card.querySelector('[data-options-source]').value = values.join('\n');
      card.querySelector('[data-option-add]').disabled = inputs.length >= 50;
    }

    function rowInput(card,value=''){
      const row=document.createElement('div');row.className='question-option-row';
      const marker=document.createElement('span');marker.dataset.gridRowNumber='';
      const input=document.createElement('input');input.value=value;input.maxLength=120;input.dataset.gridRowValue='';
      const remove=document.createElement('button');remove.type='button';remove.dataset.gridRowDelete='';remove.textContent='×';
      row.append(marker,input,remove);card.querySelector('[data-grid-row-list]').append(row);return input;
    }
    function syncRows(card){
      const inputs=[...card.querySelectorAll('[data-grid-row-value]')];const grid=['grid','checkgrid'].includes(card.dataset.answerType);
      inputs.forEach((input,i)=>{input.disabled=!grid;input.required=grid;input.placeholder=`Row ${i+1}`;input.setAttribute('aria-label',`Row ${i+1}`);input.previousElementSibling.textContent=`${i+1}.`;input.nextElementSibling.disabled=inputs.length<=1;input.nextElementSibling.setAttribute('aria-label',`Remove row ${i+1}`);});
      card.querySelector('[data-grid-rows-source]').value=inputs.map(input=>input.value.trim()).join('\n');
    }

    function updateType(card) {
      const type = card.querySelector('[data-question-type]').value;
      const isChoice = choiceTypes.has(type);
      card.dataset.answerType = type;
      card.querySelector('[data-question-options]').hidden = !isChoice;
      if (isChoice) while (card.querySelectorAll('[data-option-value]').length < 2) optionRow(card, '');
      const hint = card.querySelector('[data-answer-hint]');
      hint.hidden = isChoice||['scale','rating','image','video'].includes(type);
      hint.textContent = ({text: 'Short answer', textarea: 'Long answer', email: 'Email address', tel: 'Phone number', number: 'Number', date: 'Day / month / year', checkbox: '□ Yes'})[type] || 'Answer';
      card.querySelectorAll('[data-for-types]').forEach(group=>{group.hidden=!group.dataset.forTypes.split(' ').includes(type);});
      const layout=['section','description','image','video'].includes(type);
      const required=card.querySelector('[data-question-required]');required.disabled=layout;
      if(layout)required.checked=false;
      card.querySelector('[data-required-label]').textContent=['grid','checkgrid'].includes(type)?'Require a response in each row':'Required';
      if(['grid','checkgrid'].includes(type)&&!card.querySelector('[data-grid-row-value]'))rowInput(card,'Row 1');syncRows(card);
      card.querySelector('[data-other-preview]').hidden=!card.querySelector('[name$="[other]"]').checked||!['radio','multiselect'].includes(type);
      card.querySelectorAll('[data-scale-key]').forEach(select=>{const value=card.querySelector(`[name$="[${select.dataset.scaleKey}]"]`).value;select.value=value|| (select.dataset.scaleKey==='min'?'1':'5');});
      if(['image','video','file','description','section'].includes(type)){card.querySelector('[data-question-more]').hidden=false;card.querySelector('[data-question-more-toggle]').setAttribute('aria-expanded','true');card.querySelector('.advanced-question-settings').open=true;}
      hint.textContent=({file:'Participant files are stored privately',section:'Starts a new page in the participant form',image:'Choose an image or upload a QR in settings below',video:'Choose or upload an MP4 in settings below',grid:'One choice per row',checkgrid:'Multiple choices per row',scale:'Numbered scale · configure start/end below',rating:'Star rating · configure maximum below',description:'Text shown between questions',time:'Hour / minute'})[type]||hint.textContent;
      syncOptions(card);
    }

    function prepareCard(card) {
      const identity=card.querySelector('[data-question-id]');if(!identity.value)identity.value=`field-${crypto.randomUUID()}`;
      parseFormChoices(card.querySelector('[data-options-source]').value).forEach(value => optionRow(card, value));
      card.querySelector('[data-options-fallback]').hidden = true;
      card.querySelector('[data-option-add]').hidden = false;
      parseFormChoices(card.querySelector('[data-grid-rows-source]').value).forEach(value=>rowInput(card,value));card.querySelector('[data-grid-rows-source]').hidden=true;
      const select=card.querySelector('[data-question-type]');
      const picker=document.createElement('div');picker.className='question-type-picker';
      const button=document.createElement('button');button.type='button';button.className='question-type-button';button.setAttribute('aria-label','Question type');button.setAttribute('aria-expanded','false');button.setAttribute('aria-haspopup','listbox');
      const menu=document.createElement('div');menu.className='question-type-menu';menu.hidden=true;menu.setAttribute('role','listbox');menu.setAttribute('aria-label','Question types');
      const symbols={text:'☰',textarea:'≡',radio:'◉',multiselect:'☑',select:'⊙',file:'♧',scale:'•••',rating:'☆',grid:'⠿',checkgrid:'▦',date:'▣',time:'◷',email:'@',tel:'♧',number:'#',checkbox:'☑',section:'▤',description:'Tᴛ',image:'▧',video:'▷'};
      const refresh=()=>{button.replaceChildren(node('span',symbols[select.value],'question-type-symbol'),node('span',select.selectedOptions[0].textContent),node('span','▾'));menu.querySelectorAll('button').forEach(item=>item.setAttribute('aria-selected',String(item.dataset.value===select.value)));};
      [...select.options].forEach(option=>{const item=document.createElement('button');item.type='button';item.dataset.value=option.value;item.setAttribute('role','option');item.append(node('span',symbols[option.value],'question-type-symbol'),node('span',option.textContent));item.addEventListener('click',()=>{select.value=option.value;select.dispatchEvent(new Event('change',{bubbles:true}));menu.hidden=true;button.setAttribute('aria-expanded','false');refresh();button.focus();});menu.append(item);});
      button.addEventListener('click',()=>{menu.hidden=!menu.hidden;button.setAttribute('aria-expanded',String(!menu.hidden));if(!menu.hidden)menu.querySelector('[aria-selected=true]')?.focus();});
      picker.addEventListener('keydown',event=>{const items=[...menu.querySelectorAll('button')];let i=items.indexOf(document.activeElement);if(event.key==='Escape'){menu.hidden=true;button.setAttribute('aria-expanded','false');button.focus();}if(!menu.hidden&&['ArrowDown','ArrowUp','Home','End'].includes(event.key)){event.preventDefault();i=event.key==='Home'?0:event.key==='End'?items.length-1:(i+(event.key==='ArrowDown'?1:-1)+items.length)%items.length;items[i].focus();}});
      picker.addEventListener('focusout',event=>{if(picker.contains(event.relatedTarget))return;setTimeout(()=>{if(!picker.contains(document.activeElement)){menu.hidden=true;button.setAttribute('aria-expanded','false');}},0);});
      select.hidden=true;select.parentElement.after(picker);select.parentElement.hidden=true;picker.append(button,menu);select.addEventListener('change',refresh);refresh();
      updateType(card);
    }

    function addCard(panel, data, focus = true) {
      if (cards(panel).length >= 100) { announce('Each form can have up to 100 questions and layout blocks.'); return; }
      const template = builder.querySelector(`#${panel.dataset.formPanel}-field-template`);
      const wrapper = document.createElement('div');
      wrapper.innerHTML = template.innerHTML.replaceAll('INDEX', String(index++));
      const card = wrapper.firstElementChild;
      if (data) {
        for (const [key, value] of Object.entries(data)) {
          const input = card.querySelector(`[name$="[${key}]"]`);
          if (!input) continue;
          if(key==='condition_field')input.dataset.savedCondition=value;
          if (input.type === 'checkbox') input.checked = Boolean(value);
          else input.value = Array.isArray(value)?value.join('\n'):value;
        }
      }
      const selected=panel.querySelector('[data-question-card].is-selected');
      if(selected)selected.after(card);else panel.querySelector('[data-question-list]').append(card);
      prepareCard(card);
      updatePanel(panel);
      if(focus)card.querySelector('[data-question-label]').focus();
      return card;
    }
    builder.formEditor={questions:()=>cards(activePanel()).map(questionData),replace:rows=>{const panel=activePanel();panel.querySelector('[data-question-list]').replaceChildren();rows.forEach(data=>addCard(panel,data,false));updatePanel(panel);}};

    function node(tag, text, className) {
      const element = document.createElement(tag);
      if (text) element.textContent = text;
      if (className) element.className = className;
      return element;
    }

    function preview() {
      const panel=activePanel(),phase=panel.dataset.formPanel;
      renderFormPreview(dialog,panel.querySelector(`[name="${phase}_title"]`).value||'Untitled form',panel.querySelector(`[name="${phase}_intro"]`).value,cards(panel).map(questionData),phase,panel.querySelector(`[name="${phase}_button"]`).value,JSON.parse(builder.dataset.ticketOptions||'[]').map(ticket=>({...ticket,price:Math.round(Number(builder.querySelector(`[data-ticket-price108="${ticket.id}"]`)?.value??ticket.price/100)*100)})));
    }

    builder.addEventListener('click', event => {
      const button = event.target.closest('button');
      if (!button || button.disabled) return;
      if (button.hasAttribute('data-form-tab')) { selectPanel(button.dataset.formTab); return; }
      if (button.hasAttribute('data-question-add')) { addCard(activePanel()); announce('Question added. Save event to keep your changes.'); return; }
      if (button.hasAttribute('data-form-preview')) { preview(); return; }
      if (button.hasAttribute('data-preview-close')) { dialog.close(); return; }
      const card = button.closest('[data-question-card]');
      if (!card) return;
      const panel = card.closest('[data-form-panel]');
      if (button.hasAttribute('data-question-duplicate')) {
        const data = questionData(card);
        data.id='';
        data.label = copiedQuestionLabel(data.label, cards(panel).map(row => questionData(row).label));
        const copy = addCard(panel, data);
        if (copy) { card.after(copy); updatePanel(panel); announce('Question duplicated.'); }
      } else if (button.hasAttribute('data-question-delete')) {
        const next = card.nextElementSibling || card.previousElementSibling;
        card.remove(); updatePanel(panel);
        (next?.querySelector('[data-question-label]') || panel.querySelector('[data-question-add]')).focus();
        announce('Question removed. Save event to keep your changes.');
      } else if (button.hasAttribute('data-question-move')) {
        const before = button.dataset.questionMove === 'up';
        const sibling = before ? card.previousElementSibling : card.nextElementSibling;
        if (sibling) { if (before) sibling.before(card); else sibling.after(card); updatePanel(panel); card.querySelector('[data-question-label]').focus(); announce('Question moved.'); }
      } else if (button.hasAttribute('data-option-add')) {
        if (card.querySelectorAll('[data-option-value]').length < 50) { optionRow(card, '').focus(); syncOptions(card); }
      } else if (button.hasAttribute('data-option-delete')) {
        const row = button.closest('.question-option-row');
        const next = row.nextElementSibling || row.previousElementSibling;
        row.remove(); syncOptions(card); next?.querySelector('input').focus();
      } else if(button.hasAttribute('data-grid-row-add')){if(card.querySelectorAll('[data-grid-row-value]').length<25){rowInput(card).focus();syncRows(card);}}
      else if(button.hasAttribute('data-grid-row-delete')){button.closest('.question-option-row').remove();syncRows(card);}
      else if(button.hasAttribute('data-add-other')||button.hasAttribute('data-remove-other')){card.querySelector('[name$="[other]"]').checked=button.hasAttribute('data-add-other');updateType(card);}
      else if(button.hasAttribute('data-question-more-toggle')){const more=card.querySelector('[data-question-more]');more.hidden=!more.hidden;button.setAttribute('aria-expanded',String(!more.hidden));
      }
    });
    builder.addEventListener('input', event => {
      if (event.target.matches('[data-option-value]')) syncOptions(event.target.closest('[data-question-card]'));
      if(event.target.matches('[data-grid-row-value]'))syncRows(event.target.closest('[data-question-card]'));
    });
    builder.addEventListener('change', event => {
      if (event.target.matches('[data-question-type]')) updateType(event.target.closest('[data-question-card]'));
      if(event.target.matches('[data-scale-key]'))event.target.closest('[data-question-card]').querySelector(`[name$="[${event.target.dataset.scaleKey}]"]`).value=event.target.value;
      const panel=event.target.closest('[data-form-panel]');if(panel)updatePanel(panel);
    });
    let invalidPanel;
    builder.addEventListener('invalid', event => {
      const panel = event.target.closest('[data-form-panel]');
      if (panel && !invalidPanel) {
        let parent=event.target.parentElement;while(parent&&parent!==builder){if(parent.tagName==='DETAILS')parent.open=true;parent=parent.parentElement;}
        invalidPanel = panel;
        selectPanel(panel.dataset.formPanel);
        queueMicrotask(() => { invalidPanel = null; });
      }
    }, true);
    builder.querySelector('[role="tablist"]').addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const current = tabs.indexOf(document.activeElement);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      if(tabs[next])selectPanel(tabs[next].dataset.formTab, true);
    });
    dialog.addEventListener('close', () => builder.querySelector('[data-form-preview]').focus());
    panels.forEach(panel => {
      if(!standalone){panel.setAttribute('role', 'tabpanel');panel.setAttribute('aria-labelledby', `form-tab-${panel.dataset.formPanel}`);}
      cards(panel).forEach(prepareCard); updatePanel(panel);
      builder.querySelector('[data-question-add]').hidden = false;
    });
    builder.querySelector('[role="tablist"]').hidden = false;
    builder.querySelector('[data-form-preview]').hidden = false;
    selectPanel(standalone?builder.dataset.phase:'interest');
    builder.addEventListener('focusin',event=>{const card=event.target.closest('[data-question-card]');if(card){builder.querySelectorAll('.is-selected').forEach(other=>other.classList.remove('is-selected'));card.classList.add('is-selected');}});
    let dragged;
    builder.addEventListener('dragstart',event=>{if(!event.target.matches('[data-question-drag]'))return;dragged=event.target.closest('[data-question-card]');event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('text/plain','question');dragged.classList.add('is-dragging');});
    builder.addEventListener('dragover',event=>{if(dragged&&event.target.closest('[data-question-list]'))event.preventDefault();});
    builder.addEventListener('drop',event=>{const target=event.target.closest('[data-question-card]');if(dragged&&target&&target!==dragged){event.preventDefault();target.before(dragged);updatePanel(activePanel());builder.dispatchEvent(new Event('builderchange'));}});
    builder.addEventListener('dragend',()=>{dragged?.classList.remove('is-dragging');dragged=null;});
    builder.addEventListener('click',()=>queueMicrotask(()=>builder.dispatchEvent(new Event('builderchange'))));
    builder.addEventListener('click',async event=>{
      const button=event.target.closest('button');if(!button)return;
      const panel=activePanel();
      if(button.hasAttribute('data-add-kind'))addCard(panel,{type:button.dataset.addKind,label:button.dataset.addKind==='section'?'New section':button.dataset.addKind==='image'?'Payment QR / image':'Instructions',required:false});
      if(button.hasAttribute('data-add-payment')){
        if(cards(panel).length>96){announce('Leave space for four payment items.');return;}
        const labels=cards(panel).map(card=>questionData(card).label);
        const unique=label=>labels.includes(label)?copiedQuestionLabel(label,labels):label;
        addCard(panel,{type:'image',label:unique('Payment QR'),payment_dynamic:true,purpose:'payment',help:'Choose your ticket, scan its QR and pay the displayed amount. Upload your screenshot below.',required:false});
        addCard(panel,{type:'text',label:unique('Transaction reference'),purpose:'payment',required:true});
        addCard(panel,{type:'date',label:unique('Payment date'),purpose:'payment',required:true});
        addCard(panel,{type:'file',label:unique('Payment screenshot'),purpose:'payment',file_types:'images',file_count:1,file_size:5,required:true});
        announce('Payment items added. Enter the receiving UPI ID and account name. Set amounts in Settings → Ticket prices, then publish.');
      }
      if(button.hasAttribute('data-form-export')){
        const payload={format:'anazori-form',version:1,questions:cards(panel).map(questionData)};
        const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));link.download=`anazori-${panel.dataset.formPanel}-template.json`;link.click();URL.revokeObjectURL(link.href);
      }
      if(button.hasAttribute('data-form-copy')){
        const other=panels.find(candidate=>candidate!==panel);if(!other)return;const taken=cards(other).map(card=>questionData(card).label);const remap=new Map();
        cards(panel).map(questionData).forEach(data=>{
          const old=data.id;data.id=`field-${crypto.randomUUID()}`;remap.set(old,data.id);data.condition_field=remap.get(data.condition_field)||'';
          if(taken.includes(data.label))data.label=copiedQuestionLabel(data.label,taken);taken.push(data.label);addCard(other,data);
        });announce('Questions copied to the other form. Save event to keep the changes.');
      }
    });
    builder.addEventListener('change',async event=>{
      const input=event.target;
      if(input.matches('[data-form-import]')){
        const file=input.files[0];if(!file)return;
        try{
          if(file.size>500000)throw Error('Use a form template smaller than 500 KB.');
          const payload=JSON.parse(await file.text());if(payload.format!=='anazori-form'||!Array.isArray(payload.questions))throw Error('Choose an Anazori form template.');
          const panel=activePanel();if(cards(panel).length+payload.questions.length>100)throw Error('This template would exceed 100 items.');
          const remap=new Map();const taken=cards(panel).map(card=>questionData(card).label);
          payload.questions.forEach(item=>{const data={...item};const old=data.id;data.id=`field-${crypto.randomUUID()}`;remap.set(old,data.id);data.condition_field=remap.get(data.condition_field)||'';if(taken.includes(data.label))data.label=copiedQuestionLabel(data.label,taken);taken.push(data.label);addCard(panel,data);});announce('Template imported. Review and save the event.');
        }catch(error){announce(error.message);}finally{input.value='';}
      }
      if(input.matches('[data-form-media-upload]')){
        const file=input.files[0];if(!file)return;const card=input.closest('[data-question-card]');
        const form=builder.closest('form');const data=new FormData();data.set('csrf_token',form.querySelector('[name="csrf_token"]').value);data.set('event_id',form.querySelector('[name="id"]').value);data.set('file',file);
        input.disabled=true;announce('Uploading media…');
        try{
          const response=await fetch('/api/studio-form-media.php',{method:'POST',body:data,credentials:'same-origin'});const result=await response.json();if(!response.ok||!result.ok)throw Error(result.error||'Upload failed.');
          builder.querySelectorAll('[data-question-media]').forEach(select=>{const option=new Option(result.media.title,result.media.path);option.dataset.mime=result.media.mime;select.append(option);});
          card.querySelector('[data-question-media]').value=result.media.path;announce('Media attached. Publish the form to make it visible.');builder.dispatchEvent(new Event('builderchange'));
        }catch(error){announce(error.message);}finally{input.disabled=false;input.value='';}
      }
    });
  });
}
