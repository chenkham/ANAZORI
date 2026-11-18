/** Enhance the real registration link; unsupported browsers keep the chooser page. */
export function initGameRegistration105(root=document){
 const dialog=root.querySelector('#joystick-registration-dialog');
 if(!dialog||typeof dialog.showModal!=='function')return;
 root.querySelectorAll('[data-game-registration105]').forEach(link=>link.addEventListener('click',event=>{
  if(event.defaultPrevented||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;
  try{if(!dialog.open)dialog.showModal();}catch{return;}
  event.preventDefault();root.body.classList.add('modal-open');
  dialog.querySelector('[data-registration-game105]')?.focus();
 }));
}
