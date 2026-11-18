import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readdir,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
const root=resolve(import.meta.dirname,'..'),temp=await mkdtemp(join(tmpdir(),'anazori-auth99-'));
for(const directory of ['outbox','sessions'])await mkdir(join(temp,directory));
const base='http://127.0.0.1:'+Number(process.env.ANAZORI_QA_PORT||8199),password='Auth-Regression-99!';
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_APP_ENV:'development',ANAZORI_PRIVATE_CONFIG:join(temp,'absent.php'),ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_SITE_URL:base,ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:join(temp,'outbox'),ANAZORI_MAIL_NOTIFICATIONS:'0',ANAZORI_GOOGLE_CLIENT_ID:'dummy99.apps.googleusercontent.com',ANAZORI_GOOGLE_CLIENT_SECRET:'dummy-test-secret99'};
for(const key of ['DAILY_LIMIT','PER_MINUTE','SENDER_DAILY_LIMIT','SENDER_PER_MINUTE'])env['ANAZORI_PHP_MAIL_'+key]='1000';
const php=code=>execFileSync('php',['-d','session.save_path='+join(temp,'sessions'),'-r',"require 'includes/commerce.php';require 'includes/google-auth.php';require 'includes/participant-auth99.php';$db=cms_db();"+code],{cwd:join(root,'src'),env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+',JSON_THROW_ON_ERROR);'));
const token=html=>{const match=html.match(/name="csrf_token" value="([^"]+)"/);assert(match,'CSRF token');return match[1];};
function client(){
 let cookie='';
 const request=async(path,data)=>{
  const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:new URLSearchParams(data)}:{})});
  if(response.headers.getSetCookie().length)cookie=response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
  return response;
 };
 request.session=()=>cookie.match(/PHPSESSID=([^;]+)/)?.[1];
 return request;
}
const get=async(request,path)=>await(await request(path)).text();
const emails=async()=>Promise.all((await readdir(join(temp,'outbox'))).map(async name=>JSON.parse(await readFile(join(temp,'outbox',name),'utf8'))));
async function codeFor(email,kind='Verify your email'){
 const messages=(await emails()).filter(message=>message.to===email&&message.subject===kind);
 assert(messages.length,'Test OTP delivered');
 return messages.at(-1).body.match(/\b\d{6}\b/)[0];
}
const challenge=email=>json("$db->query(\"SELECT * FROM az_challenges WHERE email_hash='"+json("hash('sha256','"+email+"')")+"' ORDER BY rowid DESC LIMIT 1\")->fetch()");
async function signup(email,name='Auth Visitor'){
 const request=client(),page=await get(request,'/account.php?mode=signup');
 const response=await request('/account.php?mode=signup',{csrf_token:token(page),name,email,password});
 assert.equal(response.status,303);assert.equal(response.headers.get('location'),'/verify-email.php');
 return request;
}
async function send(request,action='send'){
 const page=await get(request,'/verify-email.php');
 const response=await request('/verify-email.php',{csrf_token:token(page),action});
 assert.equal(response.status,303);assert.equal(response.headers.get('location'),'/verify-email.php');
 return get(request,'/verify-email.php');
}
async function verify(request,code){
 const page=await get(request,'/verify-email.php');
 const response=await request('/verify-email.php',{csrf_token:token(page),action:'verify',code});
 assert.equal(response.status,303);
 return response;
}
const logs=[];let server,checks=0;
const ok=label=>{checks++;console.log('PASS '+label);};
try{
 php("$settings=cms_settings();$settings['sponsor_deck']='/uploads/old-sponsorship-deck.pdf';$settings['show_sponsors']='1';cms_put_setting('site',json_encode($settings));");
 server=spawn('php',['-d','session.save_path='+join(temp,'sessions'),'-S',new URL(base).host,'-t','src','scripts/router.php'],{cwd:root,env,stdio:['ignore','ignore','pipe'],windowsHide:true});
 server.stderr.on('data',data=>logs.push(data.toString()));
 let ready=false;for(let attempt=0;attempt<50;attempt++){try{if((await fetch(base+'/account.php')).ok){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,100));}assert(ready,'QA server ready');
 const guest=await signup('pending99@example.invalid');
 async function duplicate(email){
  const other=client(),page=await get(other,'/account.php?mode=signup'),before=json("$db->query('SELECT COUNT(*) FROM az_participants')->fetchColumn()"),mailBefore=(await emails()).length;
  const response=await other('/account.php?mode=signup',{csrf_token:token(page),name:'Duplicate attempt',email,password:'short'});
  assert.equal(response.status,200);assert.match(await response.text(),/An account already exists with this email\. Please sign in\./);
  assert.equal(json("$db->query('SELECT COUNT(*) FROM az_participants')->fetchColumn()"),before);assert.equal((await emails()).length,mailBefore);
 }
 await duplicate('PENDING99@EXAMPLE.INVALID');
 const google=json("az_google_participant($db,az_google_identity(['email'=>'google99@example.invalid','sub'=>'subject99','email_verified'=>true]),'signup')");
 await duplicate('GOOGLE99@example.invalid');
 php("$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['MiXeD99@Example.Invalid','Legacy account',password_hash('"+password+"',PASSWORD_DEFAULT),gmdate('c')]);");
 await duplicate('mixed99@example.invalid');
 ok('Pending, verified and Google-created accounts block duplicate email signup, including legacy mixed-case emails, without sending mail.');
 const beforeGoogle=json("$db->query('SELECT COUNT(*) FROM az_participants')->fetchColumn()");
 assert.match(php("try{az_google_participant($db,az_google_identity(['email'=>'google99@example.invalid','sub'=>'subject99','email_verified'=>true]),'signup');echo 'accepted';}catch(RuntimeException $e){echo $e->getMessage();}"),/account already exists/);
 const reused=json("az_google_participant($db,az_google_identity(['email'=>'GOOGLE99@example.invalid','sub'=>'subject99','email_verified'=>true]),'login')");
 assert.equal(reused.id,google.id);assert.equal(json("$db->query('SELECT COUNT(*) FROM az_participants')->fetchColumn()"),beforeGoogle);
 const oauth=client(),oauthResponse=await oauth('/oauth.php?target=participant&mode=signup');assert.equal(oauthResponse.status,302);
 assert.equal(new URL(oauthResponse.headers.get('location')).hostname,'accounts.google.com');
 const sessionData=await readFile(join(temp,'sessions','sess_'+oauth.session()),'utf8');assert.match(sessionData,/"mode";s:6:"signup"/);
 assert.equal((await oauth('/oauth.php?code=fake&state=invalid&mode=login')).status,400);
 ok('Google signup rejects an existing identity, Google sign-in reuses it, and OAuth retains the original mode with state validation.');
 let page=await send(guest);assert.match(page,/id="verify-code"/);assert.match(page,/data-verification-expires=/);
 const original=challenge('pending99@example.invalid'),code=await codeFor('pending99@example.invalid');
 assert.equal(Number(original.expires_at)-Number(original.created_at),600);
 const mailCount=(await emails()).length;
 for(let visit=0;visit<3;visit++){page=await get(guest,'/verify-email.php');assert.match(page,/id="verify-code"/);assert.equal(challenge('pending99@example.invalid').id,original.id);}
 await send(guest);assert.equal((await emails()).length,mailCount);assert.equal(challenge('pending99@example.invalid').id,original.id);
 const badCsrf=await guest('/verify-email.php',{csrf_token:'invalid',action:'send'});assert.equal(badCsrf.status,303);
 page=await get(guest,'/verify-email.php');assert.match(page,/session expired/i);assert.match(page,/id="verify-code"/);assert.equal((await emails()).length,mailCount);
 ok('OTP send redirects to GET; returning, refreshing and repeated send requests preserve the same 600-second code and input without additional emails.');
 const recovered=client(),loginPage=await get(recovered,'/account.php');
 assert.equal((await recovered('/account.php',{csrf_token:token(loginPage),email:'PENDING99@example.invalid',password})).status,303);
 page=await get(recovered,'/verify-email.php');assert.match(page,/id="verify-code"/);assert.equal(challenge('pending99@example.invalid').id,original.id);
 const unrelated=await signup('separate99@example.invalid');assert.doesNotMatch(await get(unrelated,'/verify-email.php'),/id="verify-code"/);
 await verify(recovered,'000000');page=await get(recovered,'/verify-email.php');assert.match(page,/invalid or expired/i);assert.match(page,/id="verify-code"/);
 assert.equal((await verify(recovered,code)).headers.get('location'),'/dashboard.php');
 assert.equal(json("$db->query(\"SELECT email_verified FROM az_participants WHERE email='pending99@example.invalid'\")->fetchColumn()"),1);
 assert.equal(Number(challenge('pending99@example.invalid').consumed),1);
 await duplicate('pending99@example.invalid');
 ok('A fresh authenticated session recovers only its own pending code; a wrong attempt keeps the input, and the original code verifies once.');
 const resend=await signup('resend99@example.invalid');await send(resend);
 const old=challenge('resend99@example.invalid'),oldCode=await codeFor('resend99@example.invalid');
 php("$db->exec('DELETE FROM az_rate_limits');");
 await send(resend,'resend');const replacement=challenge('resend99@example.invalid');assert.notEqual(replacement.id,old.id);
 assert.equal(Number(json("$db->query(\"SELECT consumed FROM az_challenges WHERE id='"+old.id+"'\")->fetchColumn()")),1);
 assert.equal(Number(replacement.expires_at)-Number(replacement.created_at),600);
 const expired=await signup('expired99@example.invalid');await send(expired);const expiredCode=await codeFor('expired99@example.invalid'),expiredId=challenge('expired99@example.invalid').id;
 php("$db->prepare('UPDATE az_challenges SET expires_at=? WHERE id=?')->execute([time()-1,'"+expiredId+"']);");
 assert.doesNotMatch(await get(expired,'/verify-email.php'),/id="verify-code"/);
 await verify(expired,expiredCode);assert.equal(json("$db->query(\"SELECT email_verified FROM az_participants WHERE email='expired99@example.invalid'\")->fetchColumn()"),0);
 const attempts=await signup('attempts99@example.invalid');await send(attempts);const validAttemptCode=await codeFor('attempts99@example.invalid');
 for(let attempt=0;attempt<5;attempt++)await verify(attempts,'000000');
 assert.equal(Number(challenge('attempts99@example.invalid').attempts),5);await verify(attempts,validAttemptCode);
 assert.equal(json("$db->query(\"SELECT email_verified FROM az_participants WHERE email='attempts99@example.invalid'\")->fetchColumn()"),0);
 ok('Explicit resend replaces the previous code; expired codes and codes after five failed attempts cannot verify.');
 const reset=client(),resetPage=await get(reset,'/forgot-password.php');
 let response=await reset('/forgot-password.php',{csrf_token:token(resetPage),action:'request',email:'pending99@example.invalid'});
 assert.equal(response.status,303);assert.equal(response.headers.get('location'),'/forgot-password.php');
 page=await get(reset,'/forgot-password.php');assert.match(page,/id="reset-code"/);
 const resetCount=(await emails()).length;assert.match(await get(reset,'/forgot-password.php'),/id="reset-code"/);assert.equal((await emails()).length,resetCount);
 const resetMail=(await emails()).filter(message=>message.to==='pending99@example.invalid'&&message.subject!=='Verify your email').at(-1);assert(resetMail);
 response=await reset('/forgot-password.php',{csrf_token:token(page),action:'reset',code:resetMail.body.match(/\b\d{6}\b/)[0],password:'Changed-Password-99!',confirm_password:'Changed-Password-99!'});
 assert.equal(response.status,303);assert.match(await get(reset,'/forgot-password.php'),/Password updated/);
 assert.equal(json("password_verify('Changed-Password-99!',$db->query(\"SELECT password_hash FROM az_participants WHERE email='pending99@example.invalid'\")->fetchColumn())"),true);
 const legacyReset=client(),legacyPage=await get(legacyReset,'/forgot-password.php'),legacyCount=(await emails()).length;
 assert.equal((await legacyReset('/forgot-password.php',{csrf_token:token(legacyPage),action:'request',email:'MIXED99@EXAMPLE.INVALID'})).status,303);
 assert.match(await get(legacyReset,'/forgot-password.php'),/id="reset-code"/);assert.equal((await emails()).length,legacyCount+1);
 assert.equal(challenge('mixed99@example.invalid').kind,'RESET');
 ok('Password reset also redirects to persistent GET code entry and completes without resubmission.');
 const home=await(await fetch(base)).text();assert.doesNotMatch(home,/Sponsorship deck|old-sponsorship-deck\.pdf/);assert.match(home,/Start a conversation/);
 assert.equal(json("(function(){foreach(cms_setting_schema() as $group)if(array_key_exists('sponsor_deck',$group))return true;return false;})()"),false);
 assert(!logs.join('').match(/PHP (?:Warning|Fatal|Parse|Deprecated)/),logs.join(''));
 ok('The public deck link and Studio upload setting are removed even when an old deck remains in saved settings; PHP logs are clean.');
 console.log(checks+' authentication and deck check groups passed. Isolated data only; no live emails or Google requests.');
}finally{
 if(server&&server.exitCode===null){const stopped=new Promise(done=>server.once('exit',done));server.kill();await stopped;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+sep));await rm(target,{recursive:true,force:true});
}
