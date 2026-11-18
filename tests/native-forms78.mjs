import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
const temp=await mkdtemp(join(tmpdir(),'anazori-forms78-'));
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_TEST_MODE:'1'};
const port=Number(process.argv.find(arg=>arg.startsWith('--port='))?.split('=')[1]||8178);
const base=`http://127.0.0.1:${port}`,password='Native-Forms-QA-2026!';
const php=code=>execFileSync('php',['-r',`require 'src/includes/commerce.php';$db=cms_db();${code}`],{env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+');'));
const token=html=>{const value=html.match(/name="csrf_token" value="([^"]+)"/);assert(value,'CSRF token');return value[1];};
function client(){let cookie='';return async(path,data,isJson=false)=>{
 const multipart=data instanceof FormData;const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data&&!multipart?{'Content-Type':isJson?'application/json':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:multipart?data:isJson?JSON.stringify(data):new URLSearchParams(data)}:{})});
 const cookies=response.headers.getSetCookie();if(cookies.length)cookie=cookies.map(value=>value.split(';')[0]).join('; ');return response;
};}
const coordinator=client(),other=client(),participant=client(),anonymous=client();
const fixture=JSON.parse(php(`
 $events=[];foreach(['treasure-hunt','goc'] as $slug){$event=az_event($slug);$fields=$event['fields'];$fields['registration_mode']='open';$fields['registration_opens']='';$fields['registration_closes']='';$fields['registration_url']='';$fields['form_workflow']='1';
 $fields['ticket_types']=json_encode([['id'=>'entry','label'=>'Event entry','price'=>20000,'capacity'=>10,'active'=>true]]);$fields['payment_methods']='[]';$fields['registration_kind']=$slug==='treasure-hunt'?'team':'individual';
 $db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event['id']]);$events[$slug]=$event['id'];}
 foreach(['qa-form-editor'=>'treasure-hunt','qa-other-editor'=>'goc'] as $name=>$slug){$db->prepare('INSERT INTO users(username,display_name,email,role,active,permissions,password_hash,must_change_password) VALUES(?,?,?,?,1,?,?,0)')->execute([$name,'Form coordinator',$name.'@example.invalid','COORDINATOR',json_encode(st_coordinator_permissions()),password_hash('${password}',PASSWORD_DEFAULT)]);$id=(int)$db->lastInsertId();$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$id,$events[$slug],gmdate('c')]);}
 $db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['forms@example.invalid','Form Participant',password_hash('${password}',PASSWORD_DEFAULT),gmdate('c')]);
 echo json_encode($events);`));
const log=[];const server=spawn('php',['-d','upload_max_filesize=64M','-d','post_max_size=70M','-S',`127.0.0.1:${port}`,'-t','src','scripts/router.php'],{env,stdio:['ignore','ignore','pipe'],windowsHide:true});server.stderr.on('data',data=>log.push(data.toString()));
const staffLogin=async(request,username)=>{const page=await(await request('/login.php')).text();assert.equal((await request('/login.php',{csrf_token:token(page),username,password})).status,303);};
let keep=false;
try{
 for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 await staffLogin(coordinator,'qa-form-editor');await staffLogin(other,'qa-other-editor');
 const eventId=fixture['treasure-hunt'];let record=json(`cms_record(${eventId})`);
 const edit=await(await coordinator('/admin.php?section=event&edit='+eventId)).text();assert.match(edit,/<summary>Form setup<\/summary>/);assert.doesNotMatch(edit,/data-question-card|Payment methods/);
 const page=await(await coordinator('/form-setup.php?event_id='+eventId)).text();assert.match(page,/data-form-workspace/);assert.match(page,/Questions<\/button>/);assert.match(page,/Responses<\/button>/);assert.match(page,/Settings<\/button>/);
 assert.equal((await other('/form-setup.php?event_id='+eventId)).status,403);
 const csrf=token(page);
 const questions=[
  {id:'team-name',label:'Team name',type:'text',required:true},
  {id:'issued-id',label:'Issued ID',type:'text',required:true,allowed_values:'0017'},
  {id:'category',label:'Category',type:'radio',required:true,options:'Student\nGuest',other:true},
  {id:'preferences',label:'Preferences',type:'multiselect',options:'Music\nGames'},
  {id:'scale',label:'Experience',type:'scale',min:'0',max:'5',required:true,low_label:'New',high_label:'Expert'},
  {id:'grid',label:'Availability',type:'grid',required:true,rows:'Morning\nEvening',options:'Yes\nNo'},
  {id:'checkgrid',label:'Interests',type:'checkgrid',rows:'Day 1\nDay 2',options:'Tech\nCulture'},
  {id:'hidden-section',label:'Guest details',type:'section',condition_field:'category',condition_value:'Guest'},
  {id:'hidden-answer',label:'Guest ID',type:'text',required:true},
  {id:'payment-section',label:'Payment details',type:'section'},
  {id:'qr',label:'Scan to pay',type:'image',media:'/assets/logo.png',help:'Pay ₹200 and upload your screenshot.'},
  {id:'proof',label:'Payment screenshot',type:'file',required:true,purpose:'payment',file_types:'images',file_size:5,file_count:1}
 ];
 const form={title:'Treasure Hunt registration',intro:'Build your team. Join the hunt.',button:'Submit for approval',questions,settings:{accepting:true,one_response:true,allow_edit:true,progress:true,shuffle:false,quiz:false,show_score:false,confirmation:'We received your application. The coordinator will verify your proof.'}};
 const save=async(action,payload=form,request=coordinator,version=record.revision,csrfToken=csrf)=>{const response=await request('/api/studio-form.php',{csrf_token:csrfToken,event_id:eventId,revision:version,phase:'registration',action,form:payload},true);return [response,await response.json()];};
 let [response,result]=await save('draft');assert.equal(response.status,200);record=json(`cms_record(${eventId})`);assert(record.fields.registration_form_draft);assert.equal(record.fields.registration_form_draft.questions[3].required,false);assert.notEqual(record.fields.registration_title,form.title);
 [response,result]=await save('publish');assert.equal(response.status,200,result.error);record=json(`cms_record(${eventId})`);assert.equal(record.fields.registration_title,form.title);assert(!record.fields.registration_form_draft);assert.equal(JSON.parse(record.fields.registration_form)[4].min,'0');
 [response,result]=await save('draft',form,coordinator,record.revision-1);assert.equal(response.status,409);
 const otherPage=await(await other('/admin.php')).text();[response,result]=await save('publish',form,other,record.revision,token(otherPage));assert.equal(response.status,400);assert.match(result.error,/access/i);
 const invalid=structuredClone(form);invalid.questions[5].rows='';[response,result]=await save('publish',invalid);assert.equal(response.status,400);assert.match(result.error,/rows/);
 console.log('PASS Compact Form setup, familiar editor structure, scoped access, draft isolation, publish validation and stale revision protection.');
 const account=await(await participant('/account.php')).text();assert.equal((await participant('/account.php',{csrf_token:token(account),email:'forms@example.invalid',password})).status,303);
 const uploadBytes=await readFile('src/assets/logo.png');
 // Drafts preserve incomplete answers and upload private files before final submission.
 const draftPage=await(await participant('/checkout.php?event=treasure-hunt')).text();assert.doesNotMatch(draftPage,/Choose your pass|Number of passes/);assert.match(draftPage,/One ticket/);
 const draftData=new FormData();for(const [key,value] of Object.entries({csrf_token:token(draftPage),event:'treasure-hunt',draft_revision:'0',team_name:'Quest team','answers[team-name]':'=HYPERLINK("bad")','answers[issued-id]':'0017','answers[category]':'Student','answers[scale]':'0'}))draftData.set(key,value);
 draftData.set('uploads[proof][]',new Blob([uploadBytes],{type:'image/png'}),'saved-before-payment.png');
 let draftReply=await participant('/api/registration-draft.php',draftData);let draftResult=await draftReply.json();assert.equal(draftReply.status,200,JSON.stringify(draftResult));assert.equal(draftResult.revision,1);assert.equal(draftResult.files.length,1);
 const draftFile=draftResult.files[0];assert.equal((await anonymous('/registration-file.php?id='+draftFile.id)).status,404);assert.equal((await other('/registration-file.php?id='+draftFile.id)).status,404);assert.equal((await participant('/registration-file.php?id='+draftFile.id)).status,200);
 const restored=await(await participant('/checkout.php?event=treasure-hunt')).text();assert.match(restored,/saved-before-payment.png/);assert.match(restored,/value="0017"/);assert.match(restored,/data-draft-revision="1"/);const draftDashboard=await(await participant('/dashboard.php')).text();assert.match(draftDashboard,/Continue registration/);assert.match(draftDashboard,/checkout.php\?event=treasure-hunt/);
 draftReply=await participant('/api/registration-draft.php',draftData);assert.equal(draftReply.status,400,'Stale draft overwrite rejected');
 console.log('PASS Account draft recovery, private pre-submission uploads and stale-tab protection.');

 async function submit({order,revision,validFile=true,includeFile=true,id='0017'}={}){
  const checkout=await(await participant('/checkout.php?event=treasure-hunt'+(order?'&order='+order:''))).text();if(!order)assert.doesNotMatch(checkout,/allowed_values|answer_key/,'Private answer lists never appear publicly');
  const data=new FormData();for(const [key,value] of Object.entries({csrf_token:token(checkout),event:'treasure-hunt',nonce:checkout.match(/name="nonce" value="([^"]+)"/)[1],type:'entry',quantity:'1',team_name:'Quest team',consent:'yes','answers[team-name]':'=HYPERLINK("bad")','answers[issued-id]':id,'answers[category]':'Student','answers[scale]':'0','answers[grid][0]':'Yes','answers[grid][1]':'No','answers[checkgrid][0][]':'Tech','answers[hidden-answer]':'malicious hidden answer',...(order?{edit_order:String(json(`$db->query("SELECT id FROM az_orders WHERE public_id='${order}'")->fetchColumn()`)),form_revision:String(revision)}:{})}))data.set(key,value);
  if(includeFile)data.set('uploads[proof][]',new Blob([validFile?uploadBytes:'<svg xmlns="http://www.w3.org/2000/svg"></svg>'],{type:'image/png'}),'payment.png');
  const reply=await participant('/api/checkout.php',data);return [reply,await reply.json()];
 }
 [response,result]=await submit({validFile:false});assert.equal(response.status,400);assert.match(result.error,/allowed format/);
 [response,result]=await submit({id:'9999'});assert.equal(response.status,400);assert.match(result.error,/organiser-issued/);
 [response,result]=await submit({includeFile:false});assert.equal(response.status,200,result.error);assert.equal(json("$db->query('SELECT COUNT(*) FROM az_checkout_drafts')->fetchColumn()"),0);let order=json("$db->query('SELECT * FROM az_orders ORDER BY id DESC LIMIT 1')->fetch()");assert.equal(order.state,'FORM_PENDING');assert.equal(json("$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()"),0);
 let formResponse=json(`az_form_response(${order.id})`);assert(!JSON.parse(order.answers)['Guest ID']);assert.equal(JSON.parse(order.answers).Experience,'0');
 const file=json("$db->query('SELECT * FROM az_registration_files ORDER BY id DESC LIMIT 1')->fetch()");assert.equal((await anonymous('/registration-file.php?id='+file.id)).status,404);assert.equal((await other('/registration-file.php?id='+file.id)).status,404);assert.equal((await coordinator('/registration-file.php?id='+file.id)).status,200);assert.equal((await participant('/registration-file.php?id='+file.id)).status,200);

 const duplicatePage=await(await participant('/checkout.php?event=treasure-hunt')).text();assert.match(duplicatePage,/You have already registered/);assert.doesNotMatch(duplicatePage,/id="checkout-form"/);
 const duplicateData=new FormData();for(const [key,value] of Object.entries({csrf_token:token(restored),event:'treasure-hunt',nonce:restored.match(/name="nonce" value="([^"]+)"/)[1],type:'entry',quantity:'1',consent:'yes',team_name:'Quest team'}))duplicateData.set(key,value);
 response=await participant('/api/checkout.php',duplicateData);result=await response.json();assert.equal(response.status,400);assert.match(result.error,/already registered/);assert.equal(json("$db->query('SELECT COUNT(*) FROM az_orders')->fetchColumn()"),1);
 console.log('PASS One registration per event per account enforced on the page and API.');
 console.log('PASS All question formats, hidden branches, zero scale value, private issued IDs, MIME validation and protected uploads. No ticket before approval.');
 async function review(decision,extra={},request=coordinator){const reviewPage=await(await request('/admin.php?section=payments')).text();const reply=await request('/admin.php',{csrf_token:token(reviewPage),action:'review_form_response',id:String(order.id),revision:String(formResponse.revision),decision,note:'Please send a clearer screenshot.',...extra});assert.equal(reply.status,303);return await(await request(reply.headers.get('location'))).text();}
 await review('approve',{reference:'UTR-2026-001',received_amount:'200.00',bank_confirmed:'yes'},other);assert.equal(json(`az_order(${order.id})`).state,'FORM_PENDING');
 await review('correct');order=json(`az_order(${order.id})`);assert.equal(order.state,'FORM_CORRECTION');formResponse=json(`az_form_response(${order.id})`);
 [response,result]=await submit({order:order.public_id,revision:formResponse.revision-1,includeFile:false});assert.equal(response.status,400);assert.match(result.error,/changed/);
 // A published schema change must not change an existing response's requirements.
 const changed=structuredClone(form);changed.questions.push({id:'later',label:'Later question',type:'text',required:true});record=json(`cms_record(${eventId})`);[response,result]=await save('publish',changed);assert.equal(response.status,200,result.error);
 [response,result]=await submit({order:order.public_id,revision:formResponse.revision,includeFile:false});assert.equal(response.status,200,result.error);formResponse=json(`az_form_response(${order.id})`);assert.equal(json(`az_order(${order.id})`).state,'FORM_PENDING');assert.equal(json("$db->query('SELECT COUNT(*) FROM az_registration_files WHERE active=1')->fetchColumn()"),1);
 let reviewHtml=await review('approve',{reference:'UTR-2026-001',received_amount:'200.00'});assert.match(reviewHtml,/receiving account/);assert.equal(json(`az_order(${order.id})`).state,'FORM_PENDING');
 reviewHtml=await review('approve',{reference:'UTR-2026-001',received_amount:'199.00',bank_confirmed:'yes'});assert.match(reviewHtml,/must match/);assert.equal(json(`az_order(${order.id})`).state,'FORM_PENDING');
 await review('approve',{reference:'UTR-2026-001',received_amount:'200.00',bank_confirmed:'yes'});order=json(`az_order(${order.id})`);assert.equal(order.state,'PAID');assert.equal(json("$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()"),1);
 await review('approve',{reference:'UTR-2026-001',received_amount:'200.00',bank_confirmed:'yes'});assert.equal(json("$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()"),1);
 const originalId=order.id;
 php(`$db->exec("INSERT INTO az_orders(public_id,participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,state,environment,provider,expires_at,created_at,updated_at) SELECT 'ORDER-CAPACITY-QA',participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,'FORM_PENDING',environment,provider,expires_at,created_at,updated_at FROM az_orders WHERE id=${originalId}");$id=(int)$db->lastInsertId();$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['capacity@example.invalid','Another team lead',password_hash('${password}',PASSWORD_DEFAULT),gmdate('c')]);$db->prepare('UPDATE az_orders SET participant_id=? WHERE id=?')->execute([$db->lastInsertId(),$id]);$db->exec("INSERT INTO az_form_responses(order_id,raw_answers,schema_json,settings_json) SELECT $id,raw_answers,schema_json,settings_json FROM az_form_responses WHERE order_id=${originalId}");`);
 order=json("$db->query(\"SELECT * FROM az_orders WHERE public_id='ORDER-CAPACITY-QA'\")->fetch()");formResponse=json(`az_form_response(${order.id})`);
 await review('approve',{reference:'UTR2026001',received_amount:'200.00',bank_confirmed:'yes'});assert.equal(json(`az_order(${order.id})`).state,'FORM_PENDING');
 php(`$event=cms_record(${eventId});$fields=$event['fields'];$types=json_decode($fields['ticket_types'],true);$types[0]['capacity']=1;$fields['ticket_types']=json_encode($types);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event['id']]);`);
 await review('approve',{reference:'UTR-2026-002',received_amount:'200.00',bank_confirmed:'yes'});assert.equal(json(`az_order(${order.id})`).state,'PAID_REVIEW');assert.equal(json("$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()"),1);
 formResponse=json(`az_form_response(${order.id})`);
 php(`$event=cms_record(${eventId});$fields=$event['fields'];$types=json_decode($fields['ticket_types'],true);$types[0]['capacity']=10;$fields['ticket_types']=json_encode($types);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event['id']]);`);
 await review('approve',{reference:'UTR-2026-002',received_amount:'200.00',bank_confirmed:'yes'});assert.equal(json(`az_order(${order.id})`).state,'PAID');assert.equal(json("$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()"),2);
 const csv=await(await coordinator('/admin.php?section=payments&event_id='+eventId+'&export=responses')).text();assert.match(csv,/Team name/);assert.match(csv,/'=HYPERLINK/);

 // Every export contains full answers, including files, and respects the event scope.
 for(const format of ['csv','xlsx','pdf']){
  const exported=await coordinator('/admin.php?section=payments&event_id='+eventId+'&export=details&format='+format);assert.equal(exported.status,200);const bytes=Buffer.from(await exported.arrayBuffer());
  if(format==='csv'){assert.match(bytes.toString(),/Answer: Team name/);assert.match(bytes.toString(),/'=HYPERLINK/);assert.match(bytes.toString(),/saved-before-payment.png/);}
  if(format==='xlsx'){assert.equal(bytes.subarray(0,2).toString(),'PK');await writeFile(join(temp,'participants.xlsx'),bytes);execFileSync('python',['-c','import zipfile,xml.etree.ElementTree as E;z=zipfile.ZipFile(r"'+join(temp,'participants.xlsx')+'");E.fromstring(z.read("xl/worksheets/sheet1.xml"));assert b"saved-before-payment.png" in z.read("xl/worksheets/sheet1.xml")']);}
  if(format==='pdf'){assert.equal(bytes.subarray(0,4).toString(),'%PDF');await writeFile(join(temp,'participants.pdf'),bytes);}
  assert.equal((await other('/admin.php?section=payments&event_id='+eventId+'&export=details&format='+format)).status,403);
 }
 console.log('PASS Full-answer PDF, valid XLSX and safe CSV exports with scoped access.');
 console.log('PASS Correction, original schema retention, bank/amount verification, duplicate transaction prevention, capacity guard, idempotent tickets and safe CSV.');
 php(`$event=az_event('goc');$fields=$event['fields'];$fields['registration_mode']='interest';$fields['interest_open']='1';$fields['interest_form']=az_validate_registration_fields([['id'=>'art','label'=>'Artwork sample','type'=>'file','required'=>1,'file_types'=>'images']]);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($fields),$event['id']]);`);
 const interestPage=await(await anonymous('/event.php?name=goc')).text();assert.match(interestPage,/data-native-form/);
 const interestData=new FormData();for(const [key,value] of Object.entries({csrf_token:token(interestPage),event:'goc',purpose:'interest',name:'Interest Participant',email:'interest@example.invalid',consent:'yes'}))interestData.set(key,value);interestData.set('uploads[art][]',new Blob([uploadBytes],{type:'image/png'}),'artwork.png');
 response=await anonymous('/api/interest.php',interestData);result=await response.json();assert.equal(response.status,201,JSON.stringify(result));
 const interestFile=json("$db->query('SELECT * FROM az_registration_files WHERE submission_id IS NOT NULL ORDER BY id DESC LIMIT 1')->fetch()");assert(interestFile);assert.equal((await anonymous('/registration-file.php?id='+interestFile.id)).status,404);assert.equal((await coordinator('/registration-file.php?id='+interestFile.id)).status,404);assert.equal((await other('/registration-file.php?id='+interestFile.id)).status,200);

 const interestSubmission=json("$db->query('SELECT * FROM submissions ORDER BY id DESC LIMIT 1')->fetch()");assert.equal(interestSubmission.status,'INTEREST');
 const interestStudio=await(await other('/admin.php?section=submissions&event_id='+fixture.goc)).text();assert.doesNotMatch(interestStudio,/name="status"/);assert.match(interestStudio,/Interest received/);
 const opening=json("az_event('inauguration')");php(`$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$db->query("SELECT id FROM users WHERE username='qa-form-editor'")->fetchColumn(),${opening.id},gmdate('c')]);`);
 const openingPage=await(await anonymous('/event.php?name=inauguration')).text();assert.match(openingPage,/Contribute/);assert.match(openingPage,/>Preview /);assert.doesNotMatch(openingPage,/Register now|Apply to perform/);
 const contributionData=new FormData();for(const [key,value] of Object.entries({csrf_token:token(openingPage),event:'inauguration',purpose:'contribution',name:'Opening Contributor',email:'contributor@example.invalid',consent:'yes','answers[phone]':'9876543210','answers[contribution]':'I would like to help with the stage.'}))contributionData.set(key,value);
 response=await anonymous('/api/interest.php',contributionData);result=await response.json();assert.equal(response.status,201,JSON.stringify(result));assert.equal(json("$db->query('SELECT status FROM submissions ORDER BY id DESC LIMIT 1')->fetchColumn()"),'RECEIVED');assert.equal(json("$db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()"),2);
 assert.equal((await coordinator('/form-setup.php?event_id='+opening.id)).status,200);
 console.log('PASS Interest records have no approval action; Inauguration contributions use the editable form without issuing tickets.');
 const culturalPage=await(await anonymous('/event.php?name=cultural-night')).text();assert.match(culturalPage,/Contribute/);assert.doesNotMatch(culturalPage,/Register now|Apply to perform/);
 const explorePage=await(await anonymous('/events.php')).text();assert.doesNotMatch(explorePage,/data-character-src/);assert.match(explorePage,/genie-inauguration77.png/);assert.match(explorePage,/phoenix-microphone77.png/);assert.doesNotMatch(explorePage,/href="\/credits.php"/);assert.match(explorePage,/https:\/\/blitz.ccsdu.in/);
 php(`$site=cms_settings();$site['privacy_content']="## Saved policy QA\\nEditable privacy text <script>";$site['terms_content']="## Saved terms QA\\nOne registration for each event.";cms_put_setting('site',json_encode($site));`);
 const privacyPage=await(await anonymous('/privacy.php')).text(),termsPage=await(await anonymous('/terms.php')).text();assert.match(privacyPage,/Saved policy QA/);assert.match(privacyPage,/&lt;script&gt;/);assert.match(termsPage,/Saved terms QA/);
 console.log('PASS Contribution-only event actions, shared artwork fallback, footer credits and editable policy pages.');
 // Simulate the automatic save before entering Form setup.
 record=json(`cms_record(${eventId})`);const eventInput={csrf_token:csrf,action:'save_content',type:'event',id:String(eventId),revision:String(record.revision),title:record.title,slug:record.slug,status:record.status,sort_order:String(record.sort_order),event_setup_editor:'1',event_editor_complete:'1',single_entry_setup:'1',registration_capacity:'10',response_format:'json'};
 const definitions=json("cms_content_schema()['event']['fields']");for(const [key,definition] of Object.entries(definitions)){const value=record.fields[key]??definition[2]??'';if(definition[1]==='checkbox'){if(value==='1')eventInput[key]='1';}else eventInput[key]=String(value);}
 eventInput.short='These event details must survive opening Form setup.';eventInput.registration_fee='200.00';
 response=await coordinator('/admin.php',eventInput);result=await response.json();assert.equal(response.status,200,JSON.stringify(result));assert.equal(json(`cms_record(${eventId})`).fields.short,eventInput.short);
 record=json(`cms_record(${eventId})`);[response,result]=await save('publish',form);assert.equal(response.status,200,result.error);assert.equal(json(`cms_record(${eventId})`).fields.short,eventInput.short);
 console.log('PASS Event save and form publish preserve both event edits and the registration schema.');
 console.log('PASS Interest forms use the same section renderer and private upload storage with assigned event access.');
 // Leave the test event with a readable demonstration form for visual checks.
 record=json(`cms_record(${eventId})`);[response,result]=await save('publish',form);assert.equal(response.status,200,result.error);
 assert(!log.join('').match(/PHP (?:Warning|Fatal|Parse|Deprecated)/),log.join(''));
 if(process.argv.includes('--preview')){keep=true;await writeFile('.local/forms78-qa.json',JSON.stringify({base,eventId,username:'qa-form-editor',password,temp,pid:server.pid,nodePid:process.pid}));console.log('QA preview ready: '+base+'/form-setup.php?event_id='+eventId);await new Promise(resolve=>{process.on('SIGINT',resolve);process.on('SIGTERM',resolve);process.stdin.resume();process.stdin.once('data',()=>{process.stdin.pause();resolve();});});}
}finally{
 if(server.exitCode===null){const done=new Promise(resolve=>server.once('exit',resolve));server.kill();await done;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+'\\')||target.startsWith(resolve(tmpdir())+'/'));await rm(target,{recursive:true,force:true});
 if(keep)await rm('.local/forms78-qa.json',{force:true});
}
