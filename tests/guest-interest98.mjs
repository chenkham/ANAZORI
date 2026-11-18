import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
const root=resolve(import.meta.dirname,'..'),temp=await mkdtemp(join(tmpdir(),'anazori-guest-interest98-'));
await mkdir(join(temp,'outbox'));
const base='http://127.0.0.1:'+Number(process.env.ANAZORI_QA_PORT||8198);
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),APP_ENV:'development',ANAZORI_PRIVATE_CONFIG:join(temp,'absent.php'),ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_SITE_URL:base,ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:join(temp,'outbox'),ANAZORI_MAIL_NOTIFICATIONS:'0'};
const php=code=>execFileSync('php',['-r',"require 'includes/commerce.php';$db=cms_db();"+code],{cwd:join(root,'src'),env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+',JSON_THROW_ON_ERROR);'));
const token=html=>{const match=html.match(/name="csrf_token" value="([^"]+)"/);assert(match,'Anonymous CSRF token');return match[1];};
function client(){let cookie='';return async(path,data)=>{
 const multipart=data instanceof FormData;
 const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data&&!multipart?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:multipart?data:new URLSearchParams(data)}:{})});
 if(response.headers.getSetCookie().length)cookie=response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
 return response;
};}
const anonymous=client(),logs=[];
const update=(slug,code)=>php("$e=az_event('"+slug+"');$f=$e['fields'];"+code+";$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$e['id']]);");
const payload={event:'tulika',purpose:'interest',name:'Guest Visitor',email:'guest98@example.invalid',consent:'yes','answers[interest]':'Please keep me informed'};
let server,checks=0;
const ok=label=>{checks++;console.log('PASS '+label);};
async function post(request,data,status){
 const response=await request('/api/interest.php',data),result=await response.json();
 assert.equal(response.status,status,JSON.stringify(result));
 assert.equal(result.success,status<400);
 return result;
}
async function reject(overrides,status=422,file=null){
 const guest=client(),csrf=token(await(await guest('/event.php?name=joystick')).text());
 let data={...payload,csrf_token:csrf,...overrides};
 if(file){const form=new FormData();for(const [key,value] of Object.entries(data))form.set(key,value);form.set('uploads[art][]',new Blob([file],{type:'image/png'}),'artwork.png');data=form;}
 return post(guest,data,status);
}
try{
 php("foreach(['tulika','joystick','goc','inauguration'] as $slug){$e=az_event($slug);$f=$e['fields'];$f['registration_mode']=$slug==='inauguration'?'open':'interest';$f['registration_opens']='';$f['registration_closes']='';$f['interest_open']='1';$f['registration_url']='';$f['interest_settings']=json_encode(['accepting'=>true,'one_response'=>true]);$f['interest_form']=az_validate_registration_fields([['id'=>'interest','label'=>'Tell us why','type'=>'text','required'=>1]]);if($slug==='joystick'){$games=[['id'=>'bgmi','label'=>'BGMI','active'=>true],['id'=>'mobile-legends','label'=>'MLBB','active'=>true],['id'=>'free-fire','label'=>'Free Fire','active'=>true]];$f['game_categories']=json_encode($games);$forms=[];foreach($games as $g)$forms[$g['id']]=['interest_form'=>az_validate_registration_fields([['id'=>'interest','label'=>$g['label'].' interest question','type'=>'text','required'=>1]]),'interest_settings'=>json_encode(['accepting'=>true,'one_response'=>true])];$f['game_forms']=json_encode($forms);}else{$f['game_categories']='[]';}if($slug==='goc')$f['interest_form']=az_validate_registration_fields([['id'=>'interest','label'=>'Tell us why','type'=>'text','required'=>1],['id'=>'art','label'=>'Artwork sample','type'=>'file','required'=>1,'file_types'=>'images']]);if($slug==='inauguration'){$f['registration_form']=az_validate_registration_fields([['id'=>'idea','label'=>'Contribution idea','type'=>'text','required'=>1]]);$f['registration_settings']=json_encode(['accepting'=>true]);}$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$e['id']]);}");
 assert.equal(json("$db->query('SELECT COUNT(*) FROM az_participants')->fetchColumn()"),0);
 server=spawn('php',['-d','upload_max_filesize=64M','-d','post_max_size=70M','-S',new URL(base).host,'-t','src','scripts/router.php'],{cwd:root,env,stdio:['ignore','ignore','pipe'],windowsHide:true});
 server.stderr.on('data',data=>logs.push(data.toString()));
 let ready=false;for(let attempt=0;attempt<50;attempt++){try{if((await anonymous('/event.php?name=tulika')).ok){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,100));}assert(ready,'QA server ready');
 const response=await anonymous('/event.php?name=tulika'),html=await response.text();
 assert.equal(response.status,200);assert.match(html,/data-interest/);assert.match(html,/id="interest-form"/);assert.match(html,/No sign-up or sign-in needed/);
 const csrf=token(html),first=await post(anonymous,{...payload,csrf_token:csrf},201);
 const saved=json("$db->query(\"SELECT * FROM submissions WHERE email='guest98@example.invalid'\")->fetch()");
 assert.equal(saved.status,'INTEREST');assert.equal(saved.name,payload.name);
 const details=JSON.parse(saved.form_data);assert.equal(details.email_verified,false);assert.equal(details.type,'INTEREST');assert(Object.values(details.answers).includes(payload['answers[interest]']));
 const again=await post(anonymous,{...payload,csrf_token:csrf},200);assert.equal(again.reference,first.reference);
 ok('A new visitor opens and submits an interest form without sign-up, sign-in or email verification; repeat submissions are deduplicated.');
 const references=new Set();
 for(const [game,label] of [['bgmi','BGMI'],['mobile-legends','MLBB'],['free-fire','Free Fire']]){
  const fragmentResponse=await anonymous('/api/event-form.php?event=joystick&phase=interest&game='+game),fragment=await fragmentResponse.json();
  assert.equal(fragmentResponse.status,200);assert(fragment.html.includes(label+' interest question'));
  const result=await post(anonymous,{...payload,csrf_token:csrf,event:'joystick',game,'answers[interest]':'Interested in '+label},201);references.add(result.reference);
 }
 assert.equal(references.size,3);
 assert.equal(json("$db->query(\"SELECT COUNT(*) FROM submissions WHERE email='guest98@example.invalid' AND status='INTEREST'\")->fetchColumn()"),4);
 ok('Guests load and submit the separate BGMI, MLBB and Free Fire interest forms without an account.');
 const fileData=new FormData();for(const [key,value] of Object.entries({...payload,csrf_token:csrf,event:'goc'}))fileData.set(key,value);
 fileData.set('uploads[art][]',new Blob([await readFile(join(root,'src/assets/logo.png'))],{type:'image/png'}),'artwork.png');
 await post(anonymous,fileData,201);
 const file=json("$db->query('SELECT * FROM az_registration_files WHERE submission_id IS NOT NULL ORDER BY id DESC LIMIT 1')->fetch()");
 assert(file);assert.equal(file.participant_id,null);assert(file.submission_id);
 assert.equal((await anonymous('/registration-file.php?id='+file.id)).status,404);
 ok('Anonymous uploads are attached to the interest response and remain private.');
 await post(anonymous,{csrf_token:csrf,event:'inauguration',purpose:'contribution',name:'Guest Contributor',email:'contributor98@example.invalid',consent:'yes','answers[idea]':'Help with the stage setup'},201);
 assert.equal(json("$db->query(\"SELECT status FROM submissions WHERE email='contributor98@example.invalid'\")->fetchColumn()"),'RECEIVED');
 for(const table of ['az_participants','az_challenges','az_orders','az_tickets'])assert.equal(json("$db->query('SELECT COUNT(*) FROM "+table+"')->fetchColumn()"),0,table);
 ok('The shared contribution flow still works; guest forms create no accounts, OTP challenges, orders or tickets.');
 await reject({csrf_token:'invalid'},403);
 await reject({email:'invalid-address'});
 await reject({consent:'no'});
 await reject({'answers[interest]':''});
 await reject({purpose:'registration'});
 await reject({event:'joystick',game:'missing'});
 await reject({event:'goc'},422,'<?php echo "not an image";');
 update('joystick',"$games=json_decode($f['game_categories'],true);$games[0]['active']=false;$f['game_categories']=json_encode($games)");
 await reject({event:'joystick',game:'bgmi'});
 update('tulika',"$f['interest_settings']=json_encode(['accepting'=>false])");
 await reject({});
 update('tulika',"$f['interest_settings']=json_encode(['accepting'=>true]);$f['registration_mode']='open'");
 await reject({});
 const checkout=await anonymous('/checkout.php?event=tulika');assert.equal(checkout.status,302);assert.match(checkout.headers.get('location'),/^\/account\.php/);
 ok('CSRF, field validation, consent, upload checks, game availability and form closing remain enforced; native checkout still requires its account.');
 const limited=client(),limitToken=token(await(await limited('/event.php?name=joystick')).text());
 for(let attempt=0;attempt<8;attempt++)await post(limited,{...payload,event:'joystick',game:'free-fire',csrf_token:limitToken,email:'invalid'},422);
 await post(limited,{...payload,event:'joystick',game:'free-fire',csrf_token:limitToken},429);
 assert(!logs.join('').match(/PHP (?:Warning|Fatal|Parse|Deprecated)/),logs.join(''));
 ok('Guest submission throttling remains active and PHP logs contain no runtime warnings.');
 console.log(checks+' guest interest check groups passed. All data was isolated and no live mail was sent.');
}finally{
 if(server&&server.exitCode===null){const stopped=new Promise(done=>server.once('exit',done));server.kill();await stopped;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+sep));await rm(target,{recursive:true,force:true});
}
