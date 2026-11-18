import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
const temp=await mkdtemp(join(tmpdir(),'anazori-options81-'));
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_TEST_MODE:'1'};
const port=Number(process.argv.find(arg=>arg.startsWith('--port='))?.split('=')[1]||8182);
const base=`http://127.0.0.1:${port}`,password='Native-Forms-QA-2026!';
const php=code=>execFileSync('php',['-r',`require 'includes/commerce.php';$db=cms_db();${code}`],{env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+');'));
const token=html=>{const value=html.match(/name="csrf_token" value="([^"]+)"/);assert(value,'CSRF token');return value[1];};
function client(){let cookie='';return async(path,data,isJson=false)=>{
 const multipart=data instanceof FormData;const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data&&!multipart?{'Content-Type':isJson?'application/json':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:multipart?data:isJson?JSON.stringify(data):new URLSearchParams(data)}:{})});
 const cookies=response.headers.getSetCookie();if(cookies.length)cookie=cookies.map(value=>value.split(';')[0]).join('; ');return response;
};}
const coordinator=client(),other=client(),participant=client(),anonymous=client();

const fixture=JSON.parse(php(`
 $events=[];foreach(['joystick','tulika'] as $slug){$event=az_event($slug);$f=$event['fields'];$f['registration_mode']='open';$f['registration_opens']='';$f['registration_closes']='';$f['registration_url']='';$f['form_workflow']='1';$f['payment_methods']='[]';
 $f['registration_form']=json_encode([['id'=>'details','label'=>'Participant details','type'=>'text','required'=>true,'options'=>[]]]);
 $f['ticket_types']=json_encode($slug==='joystick'?[
 ['id'=>'mlbb','label'=>'MLBB squad','description'=>'Five players entering together','people'=>5,'price'=>50000,'capacity'=>20,'active'=>true,'game'=>'mobile-legends'],
 ['id'=>'mlbb-alt','label'=>'MLBB invitational','description'=>'Invited squads only','people'=>5,'price'=>60000,'capacity'=>20,'active'=>true,'game'=>'mobile-legends'],
 ['id'=>'bgmi','label'=>'BGMI squad','price'=>40000,'capacity'=>20,'active'=>true,'game'=>'bgmi'],
 ['id'=>'free-fire-pass','label'=>'Free Fire squad','price'=>30000,'capacity'=>20,'active'=>true,'game'=>'free-fire']]:[
 ['id'=>'junior','label'=>'Ages 12–16','description'=>'Choose this if you are 12 to 16','price'=>10000,'capacity'=>20,'active'=>true],
 ['id'=>'senior','label'=>'Ages 17+','description'=>'Choose this if you are 17 or older','price'=>20000,'capacity'=>20,'active'=>true]]);
 $db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$event['id']]);$events[$slug]=$event['id'];}
 $db->prepare('INSERT INTO users(username,display_name,email,role,active,permissions,password_hash,must_change_password) VALUES(?,?,?,?,1,?,?,0)')->execute(['qa-options','Options coordinator','options@example.invalid','COORDINATOR',json_encode(st_coordinator_permissions()),password_hash('${password}',PASSWORD_DEFAULT)]);$id=(int)$db->lastInsertId();
 foreach($events as $event)$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$id,$event,gmdate('c')]);
 $db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['options-user@example.invalid','Options Participant',password_hash('${password}',PASSWORD_DEFAULT),gmdate('c')]);echo json_encode($events);`));
const log=[];const server=spawn('php',['-d','upload_max_filesize=64M','-d','post_max_size=70M','-S',`127.0.0.1:${port}`,'-t','src','scripts/router.php'],{env,stdio:['ignore','ignore','pipe'],windowsHide:true});server.stderr.on('data',data=>log.push(data.toString()));
const get=async(request,path)=>await(await request(path)).text();
const post=async(request,path,data,jsonBody=false)=>{const response=await request(path,data,jsonBody);return [response,await response.json()];};
try{
 for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 let html=await get(coordinator,'/login.php');assert.equal((await coordinator('/login.php',{csrf_token:token(html),username:'qa-options',password})).status,303);
 html=await get(participant,'/account.php');assert.equal((await participant('/account.php',{csrf_token:token(html),email:'options-user@example.invalid',password})).status,303);
 const gameForms={};
 for(const game of ['mobile-legends','bgmi','free-fire']){
  const editor=await get(coordinator,`/form-setup.php?event_id=${fixture.joystick}&game=${game}`);assert.match(editor,new RegExp(`data-game="${game}"`));
  const form={title:game+' registration',intro:'Your game, your squad.',button:'Send for approval',questions:[{id:'details',label:game+' player details',type:'text',required:true},{id:'proof',label:game+' payment screenshot',type:'file',file_types:'images',file_size:5,file_count:1}],settings:{accepting:true,one_response:true,allow_edit:true,progress:true}};
  gameForms[game]=form;
  const record=json(`cms_record(${fixture.joystick})`);let [response,result]=await post(coordinator,'/api/studio-form.php',{csrf_token:token(editor),event_id:fixture.joystick,revision:record.revision,phase:'registration',game,action:'publish',form},true);assert.equal(response.status,200,JSON.stringify(result));
 }
 let record=json(`cms_record(${fixture.joystick})`),stored=JSON.parse(record.fields.game_forms);
 assert.equal(Object.keys(stored).length,3);assert.equal(stored.bgmi.registration_title,'bgmi registration');assert.equal(stored['mobile-legends'].registration_title,'mobile-legends registration');
 const edit=await get(coordinator,`/admin.php?section=event&edit=${fixture.joystick}`);assert.match(edit,/Ticket categories and prices/);assert.match(edit,/People covered by one ticket/);assert.match(edit,/game=free-fire/);
 // Round-trip the event editor's new ticket category controls without changing game documents.
 assert.deepEqual(json("az_prices(['ticket_categories_enabled'=>'1','ticket_types'=>'[]','registration_fee'=>'100'])"),[]);
 const beforeForms=record.fields.game_forms;
 const eventInput={csrf_token:token(edit),action:'save_content',type:'event',id:String(fixture.joystick),revision:String(record.revision),title:record.title,slug:record.slug,status:record.status,sort_order:String(record.sort_order),event_setup_editor:'1',event_editor_complete:'1',ticket_categories81:'1',response_format:'json'};
 const definitions=json("cms_content_schema()['event']['fields']");for(const [key,definition] of Object.entries(definitions)){const value=record.fields[key]??definition[2]??'';if(definition[1]==='checkbox'){if(value==='1')eventInput[key]='1';}else eventInput[key]=String(value);}
 JSON.parse(record.fields.ticket_types).forEach((row,i)=>{for(const [key,value] of Object.entries(row))eventInput[`ticket[${i}][${key}]`]=String(key==='price'?value/100:key==='active'?(value?'1':''):value);});
 JSON.parse(record.fields.game_categories).forEach((row,i)=>{for(const [key,value] of Object.entries(row))eventInput[`games[${i}][${key}]`]=String(key==='active'?(value?'1':''):value);});
 let savedReply=await coordinator('/admin.php',eventInput);let savedResult=await savedReply.json();assert.equal(savedReply.status,200,JSON.stringify(savedResult));record=json(`cms_record(${fixture.joystick})`);assert.equal(record.fields.game_forms,beforeForms);assert.equal(JSON.parse(record.fields.ticket_types)[0].description,'Five players entering together');assert.equal(JSON.parse(record.fields.ticket_types)[0].people,5);
 console.log('PASS Independent game form publishing, editor links, category descriptions and people covered.');
 html=await get(participant,'/checkout.php?event=joystick&game=');assert.doesNotMatch(html,/id="checkout-form"/);assert.match(html,/Choose your game/);
 const upload=await readFile('src/assets/logo.png');
 async function draft(game,details,file=false){const page=await get(participant,'/checkout.php?event=joystick&game='+game);const data=new FormData();Object.entries({csrf_token:token(page),event:'joystick',game,type:game==='bgmi'?'bgmi':'mlbb',draft_revision:'0','answers[details]':details}).forEach(([k,v])=>data.set(k,v));if(file)data.set('uploads[proof][]',new Blob([upload],{type:'image/png'}),'mlbb-only.png');return post(participant,'/api/registration-draft.php',data);}
 let [response,result]=await draft('mobile-legends','MLBB saved roster',true);assert.equal(response.status,200,JSON.stringify(result));assert.equal(result.files.length,1);
 [response,result]=await draft('bgmi','BGMI saved roster');assert.equal(response.status,200,JSON.stringify(result));
 html=await get(participant,'/checkout.php?event=joystick&game=mobile-legends');assert.match(html,/MLBB saved roster/);assert.match(html,/mlbb-only.png/);assert.doesNotMatch(html,/BGMI saved roster/);assert.match(html,/Five players entering together/);assert.match(html,/One ticket covers 5 people/);
 html=await get(participant,'/checkout.php?event=joystick&game=bgmi');assert.match(html,/BGMI saved roster/);assert.doesNotMatch(html,/mlbb-only.png|MLBB saved roster/);
 console.log('PASS Game selection before forms, isolated account drafts and private uploads for each game.');
 async function submit(slug,game,type,extra={}){const page=await get(participant,'/checkout.php?event='+slug+'&game='+game);const data=new FormData();Object.entries({csrf_token:token(page),event:slug,game,type,quantity:'1',consent:'yes',nonce:page.match(/name="nonce" value="([^"]+)"/)[1],'answers[details]':game+' submitted roster',...extra}).forEach(([k,v])=>data.set(k,v));return post(participant,'/api/checkout.php',data);}
 [response,result]=await submit('joystick','mobile-legends','bgmi');assert.equal(response.status,400);assert.match(result.error,/available/);
 [response,result]=await submit('joystick','mobile-legends','mlbb',{amount:'1',price:'1'});assert.equal(response.status,200,JSON.stringify(result));
 let mlbb=json("$db->query(\"SELECT * FROM az_orders WHERE ticket_type='mlbb'\")->fetch()");assert.equal(mlbb.amount,50000);assert.equal(mlbb.quantity,1);assert.equal(JSON.parse(mlbb.snapshot).type,'MLBB squad');assert.equal(JSON.parse(mlbb.snapshot).people,5);assert.equal(JSON.parse(mlbb.snapshot).registration_kind,'single');
 assert.equal(json("$db->query('SELECT COUNT(*) FROM az_checkout_drafts')->fetchColumn()"),1);
 html=await get(participant,'/checkout.php?event=joystick&game=mobile-legends');assert.match(html,/already registered for this game/);assert.doesNotMatch(html,/id="checkout-form"/);
 [response,result]=await submit('joystick','bgmi','bgmi');assert.equal(response.status,200,JSON.stringify(result));
 [response,result]=await submit('joystick','free-fire','free-fire-pass');assert.equal(response.status,200,JSON.stringify(result));
 [response,result]=await submit('tulika','','junior');assert.equal(response.status,200,JSON.stringify(result));html=await get(participant,'/checkout.php?event=tulika');assert.match(html,/already registered for this event/);
 assert.equal(json(`(function(){try{az_validate_ticket_history81(cms_db(),${fixture.joystick},cms_record(${fixture.joystick})['fields']['ticket_types'],'[]');return false;}catch(RuntimeException $error){return str_contains($error->getMessage(),'already has registrations');}})()`),true);
 html=await get(coordinator,`/form-setup.php?event_id=${fixture.joystick}&game=bgmi`);assert.match(html,/1 responses/);assert.match(html,/bgmi submitted roster/);assert.doesNotMatch(html,/mobile-legends submitted roster|free-fire submitted roster/);
 const review=await get(coordinator,'/admin.php?section=payments');let formResponse=json(`az_form_response(${mlbb.id})`);
 await coordinator('/admin.php',{csrf_token:token(review),action:'review_form_response',id:String(mlbb.id),revision:String(formResponse.revision),decision:'approve',reference:'OPTIONS-MLBB-001',received_amount:'500.00',bank_confirmed:'yes',note:'Verified locally in isolated QA'});
 assert.equal(json(`az_order(${mlbb.id})`).state,'PAID');assert.equal(json(`$db->query('SELECT COUNT(*) FROM az_tickets WHERE order_id=${mlbb.id}')->fetchColumn()`),1);
 console.log('PASS Server-owned prices, game/category matching, one registration per game, other-event 1:1 limit and one issued ticket for a squad.');
 // The public interest flow must use the same game-specific schemas and allow one interest per game.
 php(`$e=cms_record(${fixture.joystick});$f=$e['fields'];$f['registration_mode']='interest';$f['interest_open']='1';$forms=json_decode($f['game_forms'],true);foreach($forms as $game=>&$v){$v['interest_form']=json_encode([['id'=>'interest','label'=>$game.' interest question','type'=>'text','required'=>true,'options'=>[]]]);}$f['game_forms']=json_encode($forms);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$e['id']]);`);
 html=await get(anonymous,'/event.php?name=joystick');assert.match(html,/data-game-form/);const interestToken=token(html);
 for(const game of ['mobile-legends','bgmi','free-fire']){[response,result]=await post(anonymous,'/api/interest.php',{csrf_token:interestToken,event:'joystick',purpose:'interest',game,name:'Interested player',email:'interest-options@example.invalid',consent:'yes','answers[interest]':'Interested in '+game});assert.equal(response.status,201,JSON.stringify(result));const fragment=await(await anonymous('/api/event-form.php?event=joystick&phase=interest&game='+game)).json();assert.match(fragment.html,new RegExp(game+' interest question'));}
 [response,result]=await post(anonymous,'/api/interest.php',{csrf_token:interestToken,event:'joystick',purpose:'interest',game:'bgmi',name:'Interested player',email:'interest-options@example.invalid',consent:'yes','answers[interest]':'Again'});assert.equal(response.status,200);assert.equal(json("$db->query(\"SELECT COUNT(*) FROM submissions WHERE email='interest-options@example.invalid'\")->fetchColumn()"),3);
 assert(!log.join('').match(/PHP (?:Warning|Fatal|Parse|Deprecated)/),log.join(''));
 console.log('PASS Separate game interest forms, per-game interest deduplication and clean PHP logs.');
 if(process.argv.includes('--preview')){
  php(`$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['browser-options@example.invalid','Browser QA Participant',password_hash('${password}',PASSWORD_DEFAULT),gmdate('c')]);`);
  await writeFile('.local/options81-qa.json',JSON.stringify({base,eventId:fixture.joystick,username:'qa-options',email:'browser-options@example.invalid',password,temp,db:env.ANAZORI_DB_PATH,pid:server.pid}));console.log('Isolated visual QA ready: '+base);await new Promise(resolve=>{process.stdin.resume();process.stdin.once('data',()=>{process.stdin.pause();resolve();});process.stdin.once('end',resolve);process.once('SIGINT',resolve);process.once('SIGTERM',resolve);});
 }

}finally{
 if(server.exitCode===null){const done=new Promise(resolve=>server.once('exit',resolve));server.kill();await done;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+'\\')||target.startsWith(resolve(tmpdir())+'/'));await rm(target,{recursive:true,force:true});if(process.argv.includes('--preview'))await rm('.local/options81-qa.json',{force:true});
}
