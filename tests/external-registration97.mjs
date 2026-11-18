import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
const root=resolve(import.meta.dirname,'..'),temp=await mkdtemp(join(tmpdir(),'anazori-google-forms97-'));
await mkdir(join(temp,'outbox'));
const base='http://127.0.0.1:'+Number(process.env.ANAZORI_QA_PORT||8197),password='External-Forms-QA-97!';
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),APP_ENV:'development',ANAZORI_PRIVATE_CONFIG:join(temp,'absent.php'),ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_SITE_URL:base,ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:join(temp,'outbox'),ANAZORI_MAIL_NOTIFICATIONS:'0'};
const php=code=>execFileSync('php',['-r',"require 'includes/commerce.php';$db=cms_db();"+code],{cwd:join(root,'src'),env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+',JSON_THROW_ON_ERROR);'));
const urls={bgmi:'https://forms.gle/AnazoriBGMI97',mlbb:'https://docs.google.com/forms/d/e/AnazoriMLBB97/viewform?usp=sf_link',ff:'https://forms.gle/AnazoriFreeFire97',single:'https://docs.google.com/forms/d/e/AnazoriTulika97/viewform',updated:'https://forms.gle/AnazoriUpdated97',fallback:'https://forms.gle/AnazoriFallback97'};
const token=html=>{const match=html.match(/name="csrf_token" value="([^"]+)"/);assert(match,'CSRF token');return match[1];};
function client(){let cookie='';return async(path,data)=>{
 const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:new URLSearchParams(data)}:{})});
 if(response.headers.getSetCookie().length)cookie=response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
 return response;
};}
const anonymous=client(),coordinator=client();
let server,checks=0;
const ok=text=>{checks++;console.log('PASS '+text);};
const updateFields=(slug,expression)=>php("$event=az_event('"+slug+"');$f=$event['fields'];"+expression+";$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$event['id']]);");
const path=game=>'/register.php?event=joystick'+(game?'&game='+game:'');
async function redirect(url,destination){const response=await anonymous(url);assert.equal(response.status,302,url);assert.equal(response.headers.get('location'),destination,url);}
try{
 const fixture=JSON.parse(php("$events=[];foreach(['joystick','tulika'] as $slug){$event=az_event($slug);$f=$event['fields'];$f['registration_mode']='open';$f['registration_opens']='';$f['registration_closes']='';$f['ticket_types']='[]';$f['ticket_categories_enabled']='1';$f['form_workflow']='1';$f['registration_url']=$slug==='tulika'?'"+urls.single+"':'';if($slug==='joystick')$f['game_categories']=json_encode([['id'=>'bgmi','label'=>'BGMI','active'=>true,'registration_url'=>'"+urls.bgmi+"'],['id'=>'mobile-legends','label'=>'MLBB','active'=>true,'registration_url'=>'"+urls.mlbb+"'],['id'=>'free-fire','label'=>'Free Fire','active'=>true,'registration_url'=>'"+urls.ff+"']]);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$event['id']]);$events[$slug]=$event['id'];}$db->prepare('INSERT INTO users(username,display_name,email,role,active,permissions,password_hash,must_change_password) VALUES(?,?,?,?,1,?,?,0)')->execute(['qa-external97','Forms coordinator','forms97@example.invalid','COORDINATOR',json_encode(st_coordinator_permissions()),password_hash('"+password+"',PASSWORD_DEFAULT)]);$id=(int)$db->lastInsertId();$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$id,$events['joystick'],gmdate('c')]);$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['external97@example.invalid','Forms Participant',password_hash('"+password+"',PASSWORD_DEFAULT),gmdate('c')]);echo json_encode($events);"));
 for(const url of [...Object.values(urls),'https://docs.google.com/forms/u/0/d/Another97/viewform?usp=pp_url&entry.1=test'])assert.equal(json("az_google_form_url97("+JSON.stringify(url)+")"),url);
 for(const url of ['http://forms.gle/abc','https://forms.gle.evil.example/abc','https://evil.example/forms.gle/abc','https://docs.google.com/forms/d/a/edit','https://docs.google.com/url?q=https://evil.example','https://forms.gle:8443/abc','https://user@forms.gle/abc','javascript:alert(1)','https://forms.gle/abc\r\nX-Test: bad']){
  const result=php("try{az_google_form_url97("+JSON.stringify(url)+");echo 'accepted';}catch(InvalidArgumentException){echo 'rejected';}");assert.equal(result,'rejected',url);
 }
 ok('Only HTTPS Google Forms responder URLs are accepted, including shortened and prefilled links.');
 server=spawn('php',['-d','max_input_vars=3000','-S',new URL(base).host,'-t','src','scripts/router.php'],{cwd:root,env,stdio:['ignore','ignore','ignore'],windowsHide:true});
 let ready=false;for(let attempt=0;attempt<50;attempt++){try{if((await anonymous('/register.php')).status===302){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,100));}assert(ready,'QA server ready');
 let response=await anonymous(path()),html=await response.text();assert.equal(response.status,200);for(const label of ['BGMI','MLBB','Free Fire'])assert(html.includes(label));assert.doesNotMatch(html,/id="checkout-form"/);
 await redirect(path('bgmi'),urls.bgmi);await redirect(path('mobile-legends'),urls.mlbb);await redirect(path('free-fire'),urls.ff);await redirect('/register.php?event=tulika',urls.single);
 await redirect('/checkout.php?event=joystick','/register.php?event=joystick');await redirect('/checkout.php?event=joystick&game=bgmi','/register.php?event=joystick&game=bgmi');await redirect('/checkout.php?event=tulika','/register.php?event=tulika');
 await redirect(path('bgmi')+'&url=https://evil.example',urls.bgmi);
 assert.equal((await anonymous('/register?event=joystick')).status,200);
 html=await(await anonymous('/event.php?name=joystick')).text();assert.match(html,/href="\/register\.php\?event=joystick"/);assert.match(html,/Register now/);
 const gameDialog=html.match(/<dialog id="joystick-registration-dialog"[\s\S]*?<\/dialog>/)?.[0];assert(gameDialog,'Joystick has an in-page game chooser');
 assert.match(html,/data-game-registration105 aria-haspopup="dialog" aria-controls="joystick-registration-dialog"/);
 assert.equal((gameDialog.match(/data-registration-game105/g)||[]).length,3);
 for(const [id,label] of [['bgmi','BGMI'],['mobile-legends','MLBB'],['free-fire','Free Fire']]){assert(gameDialog.includes('game='+id));assert(gameDialog.includes('Register for '+label));}
 assert.equal((gameDialog.match(/Open Google Form/g)||[]).length,3);assert.doesNotMatch(gameDialog,/account\.php|name="password"/);
 const singleHtml=await(await anonymous('/event.php?name=tulika')).text();assert.doesNotMatch(singleHtml,/joystick-registration-dialog|data-game-registration105/);
 ok('Anonymous visitors choose a game and reach its exact form; single events redirect directly, including old checkout links.');
 assert.equal((await anonymous(path('missing'))).status,400);
 updateFields('joystick',"$games=json_decode($f['game_categories'],true);$games[0]['active']=false;$f['game_categories']=json_encode($games)");
 assert.equal((await anonymous(path('bgmi'))).status,400);html=await(await anonymous(path())).text();assert.doesNotMatch(html,/Register for BGMI/);
 html=await(await anonymous('/event.php?name=joystick')).text();assert.doesNotMatch(html,/Register for BGMI/);assert.equal((html.match(/data-registration-game105/g)||[]).length,2);
 updateFields('joystick',"$f['registration_mode']='closed'");response=await anonymous(path('mobile-legends'));assert.equal(response.status,403);assert.equal(response.headers.get('location'),null);
 html=await(await anonymous('/event.php?name=joystick')).text();assert.doesNotMatch(html,/joystick-registration-dialog|data-game-registration105/);
 updateFields('joystick',"$f['registration_mode']='open';$games=json_decode($f['game_categories'],true);foreach($games as &$game)$game['active']=false;unset($game);$f['game_categories']=json_encode($games)");
 assert.equal((await anonymous(path())).status,403);
 updateFields('joystick',"$games=json_decode($f['game_categories'],true);foreach($games as &$game)$game['active']=true;unset($game);$f['game_categories']=json_encode($games)");
 assert.equal((await anonymous('/register.php?event=missing')).status,404);
 ok('Closed registrations, unavailable events and inactive or unknown games never redirect externally.');
 html=await(await coordinator('/login.php')).text();response=await coordinator('/login.php',{csrf_token:token(html),username:'qa-external97',password});assert.equal(response.status,303);
 html=await(await coordinator('/admin.php?section=event&event_id='+fixture.joystick+'&edit='+fixture.joystick)).text();assert.match(html,/Google Form registration/);assert.match(html,/name="games\[0\]\[registration_url\]"/);assert(html.includes(urls.bgmi));
 assert.match(html,/Ticket reminder timing/);assert.match(html,/name="reminder_window"/);
 const csrf=token(html);
 function savePayload(record){
  const input={csrf_token:csrf,action:'save_content',type:'event',id:String(record.id),revision:String(record.revision),title:record.title,slug:record.slug,status:'PUBLISHED',sort_order:String(record.sort_order),event_setup_editor:'1',event_editor_complete:'1',ticket_categories81:'1',response_format:'json',studio_event_id:String(record.id),studio_environment:'live'};
  const schema=json("array_diff_key(cms_content_schema()['event']['fields'],array_flip(st_fixed_form_keys()))");
  for(const [key,def] of Object.entries(schema)){if(def[1]==='checkbox'){if(record.fields[key]==='1')input[key]='1';}else input[key]=record.fields[key]??'';}
  JSON.parse(record.fields.game_categories).forEach((game,index)=>{for(const [key,value] of Object.entries(game)){if(key==='active'){if(value)input['games['+index+'][active]']='1';}else input['games['+index+']['+key+']']=String(value);}});
  return input;
 }
 let record=json('cms_record('+fixture.joystick+')'),input=savePayload(record);input['games[1][registration_url]']=urls.updated;input.reminder_window='12h';
 response=await coordinator('/admin.php',input);let result=await response.json();assert.equal(response.status,200,JSON.stringify(result));record=json('cms_record('+fixture.joystick+')');assert.equal(JSON.parse(record.fields.game_categories)[1].registration_url,urls.updated);assert.equal(JSON.parse(record.fields.game_categories)[1].id,'mobile-legends');await redirect(path('mobile-legends'),urls.updated);
 assert.equal(record.fields.reminder_window,'12h');
 html=await(await coordinator('/admin.php?section=event&event_id='+fixture.joystick+'&edit='+fixture.joystick)).text();assert.match(html,/<option value="12h" selected>12 hours before the event<\/option>/);
 const revision=record.revision;
 input=savePayload(record);input.reminder_window='18h';response=await coordinator('/admin.php',input);assert.equal(response.status,400);assert.equal(json("cms_record("+fixture.joystick+")['revision']"),revision);
 ok('Studio saves and selects the 12-hour reminder setting and rejects unsupported timing without altering the event.');
 for(const invalid of ['https://evil.example/form','https://docs.google.com/forms/d/a/edit']){
  input=savePayload(record);input['games[0][registration_url]']=invalid;response=await coordinator('/admin.php',input);result=await response.json();assert.equal(response.status,400,JSON.stringify(result));assert.equal(json("cms_record("+fixture.joystick+")['revision']"),revision);
 }
 input=savePayload(record);input.registration_url='https://evil.example/default';response=await coordinator('/admin.php',input);assert.equal(response.status,400);
 input=savePayload(record);input.csrf_token='invalid';response=await coordinator('/admin.php',input);assert.equal(response.status,400);
 input=savePayload(json('cms_record('+fixture.tulika+')'));response=await coordinator('/admin.php',input);result=await response.json();assert.equal(response.status,400);assert.match(result.error,/access/);
 ok('Assigned coordinators save per-game links; invalid destinations, CSRF failures and other event assignments are rejected.');
 updateFields('joystick',"$games=json_decode($f['game_categories'],true);unset($games[2]['registration_url']);$f['game_categories']=json_encode($games)");
 await redirect(path('free-fire'),'/checkout.php?event=joystick&game=free-fire');
 html=await(await anonymous('/event.php?name=joystick')).text();assert.equal((html.match(/Open Google Form/g)||[]).length,2);assert.match(html,/Register for Free Fire/);
 response=await anonymous('/checkout.php?event=joystick&game=free-fire');assert.equal(response.status,302);assert.match(response.headers.get('location'),/^\/account\.php/);
 updateFields('joystick',"$f['registration_url']='"+urls.fallback+"'");
 assert.equal((await anonymous(path())).status,200);await redirect(path('free-fire'),urls.fallback);await redirect(path('bgmi'),urls.bgmi);
 updateFields('tulika',"$f['registration_url']=''");await redirect('/register.php?event=tulika','/checkout.php?event=tulika');
 ok('Blank game links preserve native checkout; event defaults and per-game overrides resolve without redirect loops.');
 const denied=php("$u=$db->query(\"SELECT * FROM az_participants WHERE email='external97@example.invalid'\")->fetch();foreach(['form','manual'] as $mode){try{if($mode==='form')az_create_form_order($u,'joystick','standard-entry',1,[],[],'bgmi');else az_create_manual_order($u,'joystick','standard-entry',1,[],'','bgmi');echo 'accepted';}catch(RuntimeException $e){echo str_contains($e->getMessage(),'Google Form')?'blocked;':'unexpected:'.$e->getMessage();}}echo 'orders:'.$db->query('SELECT COUNT(*) FROM az_orders')->fetchColumn();");
 assert.equal(denied,'blocked;blocked;orders:0');
 const readiness=php("require 'includes/launch-readiness.php';$f=az_event('joystick')['fields'];$f['ticket_types']=json_encode([['id'=>'bgmi-ticket','game'=>'bgmi','label'=>'BGMI team','price'=>50000,'capacity'=>0,'active'=>true]]);echo az_launch_payment_ready90($f)?'ready':'missing';");
 assert.equal(readiness,'ready');
 ok('External registrations create no native orders or tickets and do not require an internal payment QR.');
 updateFields('tulika',"$f['registration_url']='';$f['ticket_types']=json_encode([['id'=>'test-entry','label'=>'Event entry','price'=>0,'capacity'=>0,'active'=>true]]);$f['registration_form']=json_encode([['id'=>'details','label'=>'Details','type'=>'text','required'=>true,'options'=>[]]]);$f['registration_settings']=json_encode(['accepting'=>true,'allow_edit'=>true])");
 const order=JSON.parse(php("$u=$db->query(\"SELECT * FROM az_participants WHERE email='external97@example.invalid'\")->fetch();echo json_encode(az_create_form_order($u,'tulika','test-entry',1,['details'=>'Original native response'],[]));"));
 assert.equal(order.state,'FORM_PENDING');
 updateFields('tulika',"$f['registration_url']='"+urls.single+"'");
 const edited=JSON.parse(php("$u=$db->query(\"SELECT * FROM az_participants WHERE email='external97@example.invalid'\")->fetch();$r=az_form_response("+(Number(order.id))+");echo json_encode(az_create_form_order($u,'tulika','test-entry',1,['details'=>'Updated native response'],[],'',"+Number(order.id)+",(int)$r['revision']));"));
 assert.equal(edited.id,order.id);
 const participant=client();html=await(await participant('/account.php')).text();response=await participant('/account.php',{csrf_token:token(html),email:'external97@example.invalid',password});assert.equal(response.status,303);
 response=await participant('/checkout.php?event=tulika&order='+encodeURIComponent(order.public_id));assert.equal(response.status,200);html=await response.text();assert.match(html,/id="checkout-form"/);assert.match(html,/Updated native response/);
 ok('Native submission still works, and existing responses remain editable after an event switches to Google Forms.');
 console.log(checks+' Google Form registration check groups passed. No external forms visited and no live mail sent.');
}finally{
 if(server&&server.exitCode===null){const stopped=new Promise(done=>server.once('exit',done));server.kill();await stopped;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+sep));await rm(target,{recursive:true,force:true});
}
