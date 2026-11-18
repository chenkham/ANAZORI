import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readdir,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join,sep} from 'node:path';
const root=resolve(import.meta.dirname,'..'),temp=await mkdtemp(join(tmpdir(),'anazori-mail-http107-')),base='http://127.0.0.1:8207',password='Isolated-Mail-Check-107!';
for(const folder of ['outbox','sessions'])await mkdir(join(temp,folder));
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_APP_ENV:'development',ANAZORI_PRIVATE_CONFIG:join(temp,'absent.php'),ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:join(temp,'outbox'),ANAZORI_MAIL_NOTIFICATIONS:'1',ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_SITE_URL:base};
for(const key of ['DAILY_LIMIT','PER_MINUTE','SENDER_DAILY_LIMIT','SENDER_PER_MINUTE'])env['ANAZORI_PHP_MAIL_'+key]='1000';
const php=code=>execFileSync('php',['-d','session.save_path='+join(temp,'sessions'),'-r',"require 'includes/commerce.php';$db=cms_db();"+code],{cwd:join(root,'src'),env,encoding:'utf8',windowsHide:true});
const json=code=>JSON.parse(php('echo json_encode('+code+',JSON_THROW_ON_ERROR);'));
const csrf=html=>{const match=html.match(/name="csrf_token" value="([^"]+)"/);assert(match,'CSRF token');return match[1];};
function client(){const cookies=new Map();return async(path,data)=>{
 const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:[...cookies].map(([name,value])=>name+'='+value).join('; '),...(data?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:new URLSearchParams(data)}:{})});
 for(const value of response.headers.getSetCookie()){const first=value.split(';')[0],at=first.indexOf('=');cookies.set(first.slice(0,at),first.slice(at+1));}return response;
};}
const participant=client(),staff=client(),logs=[];let server;
const messages=async()=>Promise.all((await readdir(join(temp,'outbox'))).filter(name=>name.endsWith('.json')).map(async name=>JSON.parse(await readFile(join(temp,'outbox',name),'utf8'))));
async function expectMessages(count){for(let attempt=0;attempt<50;attempt++){if((await messages()).length===count)return;await new Promise(done=>setTimeout(done,50));}assert.equal((await messages()).length,count);}
function worker(...args){return JSON.parse(execFileSync('php',['-d','session.save_path='+join(temp,'sessions'),join(root,'src/includes/mail-worker95.php'),...args],{cwd:root,env,encoding:'utf8',windowsHide:true}));}
try{
 const fixture=JSON.parse(php("$event=az_event('tulika');$f=$event['fields'];$f=array_replace($f,['registration_mode'=>'open','registration_opens'=>'','registration_closes'=>'','registration_url'=>'','game_categories'=>'[]','form_workflow'=>'1','starts_at'=>gmdate('c',time()+72*3600),'ends_at'=>'','reminder_window'=>'24h','venue'=>'QA venue','ticket_types'=>az_validate_prices([['id'=>'entry','label'=>'Entry','price'=>'0','active'=>1]]),'registration_form'=>az_validate_registration_fields([['id'=>'details','label'=>'Details','type'=>'text','required'=>1]]),'registration_settings'=>json_encode(['accepting'=>true,'allow_edit'=>true])]);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$event['id']]);$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['mail-http107@example.invalid','Mail QA',password_hash('"+password+"',PASSWORD_DEFAULT),gmdate('c')]);$db->prepare(\"UPDATE users SET password_hash=?,must_change_password=0 WHERE role='SUPERADMIN'\")->execute([password_hash('"+password+"',PASSWORD_DEFAULT)]);echo json_encode(['event'=>$event['id'],'owner'=>ANAZORI_SUPER_EMAIL]);"));
 server=spawn('php',['-d','max_input_vars=3000','-d','session.save_path='+join(temp,'sessions'),'-S',new URL(base).host,'-t','src','scripts/router.php'],{cwd:root,env,windowsHide:true,stdio:['ignore','ignore','pipe']});server.stderr.on('data',bytes=>logs.push(bytes.toString()));
 let ready=false;for(let attempt=0;attempt<60;attempt++){try{if((await participant('/account.php')).ok){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,100));}assert(ready,'Temporary PHP server ready');
 let html=await(await participant('/account.php')).text(),response=await participant('/account.php',{csrf_token:csrf(html),email:'mail-http107@example.invalid',password});assert.equal(response.status,303);
 html=await(await participant('/checkout.php?event=tulika')).text();const token=csrf(html),nonce=html.match(/name="nonce" value="([^"]+)"/)?.[1];assert(nonce);
 const input={csrf_token:token,nonce,event:'tulika',type:'entry',quantity:'1',consent:'yes','answers[details]':'Private submitted answer',response_format:'json'};
 response=await participant('/api/checkout.php',input);assert.equal(response.status,200);const result=await response.json();assert(result.ok);
 await expectMessages(1);let deliveries=await messages();assert.match(deliveries[0].subject,/registration is received/);assert.equal(deliveries[0].from,'noreply3@ccsdu.in');assert(!deliveries[0].body.includes('Private submitted answer'));
 assert.equal(json("$db->query(\"SELECT status FROM az_mail_jobs89 WHERE kind='registration_received'\")->fetchColumn()"),'sent');
 const beforeCron=worker('--status');assert(beforeCron.transport_available&&beforeCron.notifications_enabled);assert.equal(beforeCron.cron_recent,false,'Request sending must not pretend a cron is running');
 console.log('PASS Real checkout request sends one branded receipt after commit, without a cron run.');
 response=await participant('/api/checkout.php',input);assert.equal(response.status,200);await expectMessages(1);
 console.log('PASS A repeated checkout nonce does not send a duplicate receipt.');
 html=await(await staff('/login.php')).text();response=await staff('/login.php',{csrf_token:csrf(html),username:fixture.owner,password});assert.equal(response.status,303);
 html=await(await staff('/admin.php?section=payments&event_id='+fixture.event)).text();const staffToken=csrf(html),order=json("$db->query('SELECT * FROM az_orders ORDER BY id LIMIT 1')->fetch()"),revision=json('az_form_response('+(Number(order.id))+')[\'revision\']');
 response=await staff('/admin.php',{csrf_token:staffToken,action:'review_form_response',id:String(order.id),revision:String(revision),decision:'approve',studio_event_id:String(fixture.event),studio_environment:'live'});assert.equal(response.status,303);
 await expectMessages(2);deliveries=await messages();const approved=deliveries.find(message=>message.subject.includes('ticket is ready'));assert(approved);assert(approved.body.includes('/ticket.php?id='));assert.equal(approved.from,'noreply3@ccsdu.in');
 assert.equal(json('$db->query(\'SELECT state FROM az_orders ORDER BY id LIMIT 1\')->fetchColumn()'),'PAID');assert.equal(worker('--status').cron_recent,false);
 console.log('PASS Actual Studio approval sends the ticket email automatically, without a cron run.');
 php("$event=az_event('tulika');$f=$event['fields'];$f['starts_at']=gmdate('c',time()+10*3600);$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$event['id']]);");
 const reminderRun=worker();assert.equal(reminderRun.scheduled,1);assert.equal(reminderRun.sent,1);assert.equal(reminderRun.pending_total,0);await expectMessages(3);
 assert((await messages()).some(message=>message.subject.includes('event is coming up')));assert(worker('--status').cron_recent);assert.equal(worker().sent,0);await expectMessages(3);
 console.log('PASS CLI cron sends the due reminder once and reports queue counts and a fresh heartbeat.');
 assert([403,404].includes((await participant('/includes/mail-worker95.php')).status));
 assert(!logs.join('').match(/PHP (?:Warning|Notice|Fatal|Parse|Deprecated)/),logs.join(''));
 console.log('PASS Worker remains inaccessible over HTTP; PHP logs contain no runtime errors.');
 if(process.env.ANAZORI_MAIL107_REPORT)await writeFile(process.env.ANAZORI_MAIL107_REPORT,JSON.stringify({httpSubmissionReceipt:true,httpApprovalConfirmation:true,cronReminder:true,repeatedSubmissionDeduped:true,workerHeartbeatAccurate:true,httpWorkerDenied:true,mailCount:3,phpErrors:0,realEmailsSent:false},null,2)+'\n');
}finally{
 if(server&&server.exitCode===null){const stopped=new Promise(done=>server.once('exit',done));server.kill();await stopped;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+sep));await rm(target,{recursive:true,force:true});
}
