import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readdir,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname,join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=dirname(dirname(fileURLToPath(import.meta.url))),temp=await mkdtemp(join(tmpdir(),'anazori-remember102-'));
for(const directory of ['outbox','sessions'])await mkdir(join(temp,directory));
const base='http://127.0.0.1:8202',password='Remember-Regression-102!',cookieName='anazori_remember102';
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_APP_ENV:'development',ANAZORI_PRIVATE_CONFIG:join(temp,'absent.php'),ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_SITE_URL:base,ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:join(temp,'outbox'),ANAZORI_MAIL_NOTIFICATIONS:'0'};
for(const key of ['DAILY_LIMIT','PER_MINUTE','SENDER_DAILY_LIMIT','SENDER_PER_MINUTE'])env['ANAZORI_PHP_MAIL_'+key]='1000';
const php=code=>execFileSync('php',['-d','session.save_path='+join(temp,'sessions'),'-r',"require 'includes/commerce.php';require 'includes/google-auth.php';require 'includes/participant-auth99.php';$db=cms_db();"+code],{cwd:join(root,'src'),env,encoding:'utf8',windowsHide:true});
const json=code=>JSON.parse(php('echo json_encode('+code+',JSON_THROW_ON_ERROR);'));
const token=html=>{const match=html.match(/name="csrf_token" value="([^"]+)"/);assert(match,'CSRF token');return match[1];};
function client(remember=''){
 const jar=new Map(remember?[[cookieName,remember]]:[]);
 const request=async(path,data)=>{
  const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:[...jar].map(([key,value])=>key+'='+value).join('; '),...(data?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:new URLSearchParams(data)}:{})});
  for(const set of response.headers.getSetCookie()){
   const first=set.split(';')[0],split=first.indexOf('='),key=first.slice(0,split),value=first.slice(split+1);
   if(!value||/Max-Age=0(?:;|$)/i.test(set))jar.delete(key);else jar.set(key,value);
  }
  return response;
 };
 request.jar=jar;request.close=()=>jar.delete('PHPSESSID');request.remember=()=>jar.get(cookieName);
 return request;
}
const html=async(request,path)=>await(await request(path)).text();
const messages=async()=>Promise.all((await readdir(join(temp,'outbox'))).map(async file=>JSON.parse(await readFile(join(temp,'outbox',file),'utf8'))));
async function codeFor(email,subject){const mail=(await messages()).filter(item=>item.to===email&&item.subject===subject).at(-1);assert(mail,'Test OTP');return mail.body.match(/\b\d{6}\b/)[0];}
const challenge=email=>json("$db->query(\"SELECT * FROM az_challenges WHERE kind='VERIFY' AND email_hash='\".hash('sha256','"+email+"').\"' ORDER BY created_at DESC,rowid DESC LIMIT 1\")->fetch()");
async function login(email,pass=password){const request=client(),page=await html(request,'/account.php');const response=await request('/account.php',{csrf_token:token(page),email,password:pass});assert.equal(response.status,303,await response.text());return request;}
function fixture(email){return json("(function()use($db){$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['"+email+"','Remember Visitor',password_hash('"+password+"',PASSWORD_DEFAULT),gmdate('c')]);return (int)$db->lastInsertId();})()");}
const logs=[];let server,checks=0;
const ok=label=>{checks++;console.log('PASS '+label);};
async function denied(request){const response=await request('/dashboard.php');assert.equal(response.status,302);assert.match(response.headers.get('location'),/^\/account\.php/);}
try{
 php('');
 server=spawn('php',['-d','session.save_path='+join(temp,'sessions'),'-S',new URL(base).host,'-t','src','scripts/router.php'],{cwd:root,env,windowsHide:true,stdio:['ignore','ignore','pipe']});server.stderr.on('data',data=>logs.push(data.toString()));
 let ready=false;for(let n=0;n<60;n++){try{if((await fetch(base+'/account.php')).ok){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,100));}assert(ready);
 const pending=client(),signup=await html(pending,'/account.php?mode=signup');
 let response=await pending('/account.php?mode=signup',{csrf_token:token(signup),name:'Pending Visitor',email:'pending102@example.invalid',password});assert.equal(response.status,303);
 const rememberedHeader=response.headers.getSetCookie().find(value=>value.startsWith(cookieName+'='));assert(rememberedHeader);
 assert.match(rememberedHeader,/HttpOnly/i);assert.match(rememberedHeader,/SameSite=Lax/i);assert.match(rememberedHeader,/Max-Age=2592000/);
 const issued=pending.remember();assert.match(issued,/^[a-f0-9]{32}\.[a-f0-9]{64}$/);
 let row=json("$db->query('SELECT * FROM az_remember_tokens102')->fetch()");assert.equal(row.validator_hash,json("hash('sha256','"+issued.split('.')[1]+"')"));assert(!JSON.stringify(row).includes(issued.split('.')[1]));
 assert.equal((await messages()).length,0);
 ok('Signup issues a 30-day HttpOnly, SameSite cookie; only a hash of its random secret is stored and no OTP is sent automatically.');
 let page=await html(pending,'/verify-email.php');response=await pending('/verify-email.php',{csrf_token:token(page),action:'send'});assert.equal(response.status,303);
 const original=challenge('pending102@example.invalid'),originalCode=await codeFor('pending102@example.invalid','Verify your email');assert.equal(original.expires_at-original.created_at,600);
 const oldSession=pending.jar.get('PHPSESSID');pending.close();response=await pending('/account.php');assert.equal(response.status,302);assert.equal(response.headers.get('location'),'/dashboard.php');
 assert.notEqual(pending.jar.get('PHPSESSID'),oldSession);assert.notEqual(pending.remember(),issued);
 page=await html(pending,'/dashboard.php');assert.match(page,/Verify email/);page=await html(pending,'/verify-email.php');assert.match(page,/id="verify-code"/);
 assert.equal(challenge('pending102@example.invalid').id,original.id);assert.equal(challenge('pending102@example.invalid').expires_at,original.expires_at);assert.equal((await messages()).length,1);
 assert.equal(Number(json("$db->query('SELECT COUNT(*) FROM az_participants')->fetchColumn()")),1);
 ok('Closing the browser restores the same account, rotates the token and recovers the original ten-minute code without another signup or email.');
 const sessionPath=resolve(temp,'sessions','sess_'+pending.jar.get('PHPSESSID'));assert(sessionPath.startsWith(resolve(temp,'sessions')+sep));await rm(sessionPath,{force:true});
 response=await pending('/verify-email.php');assert.equal(response.status,200);assert.match(response.headers.get('cache-control'),/private, no-store/);assert.match(await response.text(),/id="verify-code"/);
 assert.equal(challenge('pending102@example.invalid').id,original.id);assert.equal((await messages()).length,1);
 ok('Server-side PHP session expiry also recovers verification; authenticated responses are private and no-store.');
 const rapid=client(pending.remember()),rapidCookie=pending.remember();assert.equal((await rapid('/dashboard.php')).status,200);assert.equal(rapid.remember(),rapidCookie);assert.equal((await client(issued)('/dashboard.php')).status,200);
 ok('Rapid session restores keep the current token stable during the grace period so other tabs remain signed in.');
 response=await pending('/');assert.equal(response.status,200);assert.match(await response.text(),/My festival/);assert.doesNotMatch(logs.join(''),/headers already sent/i);
 ok('Public navigation restores login before output, without PHP header warnings.');
 const oldCookie=pending.remember(),oldSelector=oldCookie.split('.')[0];php("$db->prepare('UPDATE az_remember_tokens102 SET previous_until=0 WHERE selector=?')->execute(['"+oldSelector+"']);");pending.close();assert.equal((await pending('/dashboard.php')).status,200);
 const latestCookie=pending.remember();assert.notEqual(latestCookie,oldCookie);
 const simultaneous=client(oldCookie);assert.equal((await simultaneous('/dashboard.php')).status,200);
 php("$db->prepare('UPDATE az_remember_tokens102 SET previous_until=? WHERE selector=?')->execute([time()-1,'"+oldSelector+"']);");
 await denied(client(oldCookie));assert.equal((await client(latestCookie)('/dashboard.php')).status,200);
 ok('Concurrent tabs get a short rotation grace period; old tokens fail after it ends while the latest token works.');
 const live=pending.remember(),forged=live.split('.')[0]+'.'+'0'.repeat(64);
 await denied(client(forged));assert.equal(Number(json("$db->query(\"SELECT COUNT(*) FROM az_remember_tokens102 WHERE selector='"+oldSelector+"'\")->fetchColumn()")),1);
 await denied(client('malformed'));assert.equal((await client(live)('/dashboard.php')).status,200);
 ok('Forged and malformed cookies cannot authenticate or revoke the valid browser token.');
 page=await html(pending,'/verify-email.php');response=await pending('/verify-email.php',{csrf_token:token(page),action:'verify',code:originalCode});assert.equal(response.status,303);assert.equal(response.headers.get('location'),'/dashboard.php');
 assert.equal(Number(json("$db->query(\"SELECT email_verified FROM az_participants WHERE email='pending102@example.invalid'\")->fetchColumn()")),1);
 ok('The original inbox code verifies successfully after browser and server-session loss.');
 const other=client(),form=await html(other,'/account.php?mode=signup');await other('/account.php?mode=signup',{csrf_token:token(form),name:'Expired Visitor',email:'expired102@example.invalid',password});
 page=await html(other,'/verify-email.php');await other('/verify-email.php',{csrf_token:token(page),action:'send'});const expiredCode=await codeFor('expired102@example.invalid','Verify your email');
 php("$db->prepare('UPDATE az_challenges SET expires_at=? WHERE email_hash=?')->execute([time()-1,hash('sha256','expired102@example.invalid')]);");
 other.close();page=await html(other,'/verify-email.php');assert.doesNotMatch(page,/id="verify-code"/);assert.match(page,/Your account is already created/);
 await other('/verify-email.php',{csrf_token:token(page),action:'verify',code:expiredCode});assert.equal(Number(json("$db->query(\"SELECT email_verified FROM az_participants WHERE email='expired102@example.invalid'\")->fetchColumn()")),0);
 php("$db->exec('DELETE FROM az_rate_limits');");page=await html(other,'/verify-email.php');await other('/verify-email.php',{csrf_token:token(page),action:'send'});
 assert.match(await html(other,'/verify-email.php'),/id="verify-code"/);assert.equal(Number(json("$db->query(\"SELECT COUNT(*) FROM az_participants WHERE email='expired102@example.invalid'\")->fetchColumn()")),1);
 ok('Expired codes stay expired; a new code is requested for the existing account without recreating it.');
 const id=fixture('logout102@example.invalid'),first=await login('logout102@example.invalid'),second=await login('logout102@example.invalid');
 const replay=first.remember(),restored=client(replay);assert.equal((await restored('/dashboard.php')).status,200);
 page=await html(first,'/dashboard.php');response=await first('/dashboard.php',{csrf_token:token(page),action:'logout'});assert.equal(response.status,303);assert.equal(first.remember(),undefined);
 await denied(first);await denied(client(replay));await denied(restored);assert.equal((await second('/dashboard.php')).status,200);
 ok('Sign-out revokes that browser and its restored sessions; a separately signed-in browser remains signed in.');
 const reset=client();page=await html(reset,'/forgot-password.php');await reset('/forgot-password.php',{csrf_token:token(page),action:'request',email:'logout102@example.invalid'});
 const resetCode=await codeFor('logout102@example.invalid','Reset your password');page=await html(reset,'/forgot-password.php');
 await reset('/forgot-password.php',{csrf_token:token(page),action:'reset',code:resetCode,password:'Changed-Remember-102!',confirm_password:'Changed-Remember-102!'});
 assert.equal(Number(json("$db->query('SELECT COUNT(*) FROM az_remember_tokens102 WHERE participant_id="+id+"')->fetchColumn()")),0);
 await denied(second);await denied(client(second.remember()||replay));const renewed=await login('logout102@example.invalid','Changed-Remember-102!');renewed.close();assert.equal((await renewed('/dashboard.php')).status,200);
 ok('Password reset revokes all remembered browsers; signing in with the new password creates a working token.');
 for(const [label,change] of [['disabled','active=0'],['version','session_version=session_version+1'],['email',"email='changed102@example.invalid'"]]){
  const email=label+'102@example.invalid',person=fixture(email),request=await login(email),remember=request.remember();php("$db->exec(\"UPDATE az_participants SET "+change+" WHERE id="+person+"\");");request.close();await denied(request);await denied(client(remember));
 }
 ok('Disabled accounts, changed account versions and changed email ownership cannot restore access.');
 const expiryId=fixture('cookie-expiry102@example.invalid'),expired=await login('cookie-expiry102@example.invalid');php("$db->exec('UPDATE az_remember_tokens102 SET expires_at=0 WHERE participant_id="+expiryId+"');");await denied(expired);await denied(client(expired.remember()||'expired'));
 ok('The 30-day token expiry is enforced for remembered access and associated PHP sessions.');
 const capId=fixture('capacity102@example.invalid');php("for($i=0;$i<12;$i++)$db->prepare('INSERT INTO az_remember_tokens102(selector,participant_id,validator_hash,email_hash,session_version,auth_method,created_at,last_used_at,expires_at) VALUES(?,?,?,?,0,?,?,?,?)')->execute([bin2hex(random_bytes(16)),"+capId+",hash('sha256',random_bytes(32)),hash('sha256','capacity102@example.invalid'),'email_password',time(),time(),time()+86400]);");
 const cap=await login('capacity102@example.invalid');assert.equal(Number(json("$db->query('SELECT COUNT(*) FROM az_remember_tokens102 WHERE participant_id="+capId+"')->fetchColumn()")),10);cap.close();assert.equal((await cap('/dashboard.php')).status,200);
 ok('The ten-browser cap retains the newly issued token even when older tokens share its timestamp.');
 const google=client();await html(google,'/account.php');const sid=google.jar.get('PHPSESSID');
 const googleSession=php("$u=az_google_participant($db,az_google_identity(['email'=>'google102@example.invalid','sub'=>'google-subject102','email_verified'=>true]),'signup');$db->prepare('UPDATE az_participants SET name=?,profile_completed=1 WHERE id=?')->execute(['Google Visitor',$u['id']]);session_write_close();session_id('"+sid+"');session_start();az_participant_login($u,'google');echo session_id();session_write_close();");google.jar.set('PHPSESSID',googleSession);
 response=await google('/dashboard.php');assert.equal(response.status,200);assert(google.remember());assert.equal(json("$db->query(\"SELECT auth_method FROM az_remember_tokens102 WHERE participant_id=(SELECT id FROM az_participants WHERE email='google102@example.invalid')\")->fetchColumn()"),'google');
 google.close();assert.equal((await google('/dashboard.php')).status,200);response=await google('/admin.php');assert.equal(response.status,302);assert.match(response.headers.get('location'),/login\.php/);
 ok('Google-created participant sessions remember the browser without granting Studio access.');
 const googleVersion=Number(json("$db->query(\"SELECT session_version FROM az_participants WHERE email='google102@example.invalid'\")->fetchColumn()"));
 php("for($i=0;$i<2;$i++)az_google_participant($db,az_google_identity(['email'=>'google102@example.invalid','sub'=>'google-subject102','email_verified'=>true]),'login');");
 assert.equal(Number(json("$db->query(\"SELECT session_version FROM az_participants WHERE email='google102@example.invalid'\")->fetchColumn()")),googleVersion);google.close();assert.equal((await google('/dashboard.php')).status,200);
 ok('Routine Google sign-ins preserve existing remembered browsers instead of forcing another login.');
 const linkId=fixture('link102@example.invalid');php("$db->exec('UPDATE az_participants SET email_verified=0 WHERE id="+linkId+"');");const linked=await login('link102@example.invalid'),beforeLink=linked.remember();
 php("az_google_participant($db,az_google_identity(['email'=>'link102@example.invalid','sub'=>'new-linked-subject102','email_verified'=>true]),'login');");
 assert.equal(Number(json("$db->query('SELECT COUNT(*) FROM az_remember_tokens102 WHERE participant_id="+linkId+"')->fetchColumn()")),0);assert.equal(json("$db->query('SELECT password_hash FROM az_participants WHERE id="+linkId+"')->fetchColumn()"),null);await denied(linked);await denied(client(beforeLink));
 ok('First linking a verified Google identity revokes the earlier unverified-account tokens and password.');
 const production=JSON.parse(execFileSync('php',['-r',"require 'includes/commerce.php';echo json_encode(['name'=>az_remember_name102(),'secure'=>az_remember_secure102()]);"],{cwd:join(root,'src'),env:{...env,ANAZORI_APP_ENV:'production'},encoding:'utf8',windowsHide:true}));
 assert.equal(production.secure,true);assert.equal(production.name,'__Host-anazori_remember102');
 ok('Production remembers users with a Secure, host-only cookie name.');
 assert.doesNotMatch(logs.join(''),/PHP (?:Warning|Fatal|Parse|Deprecated)/,logs.join(''));
 console.log(checks+' remembered-login, OTP continuation and security check groups passed. Isolated data; no live emails or Google requests.');
}finally{
 if(server&&server.exitCode===null){const ended=new Promise(done=>server.once('exit',done));server.kill();await ended;}
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+sep));await rm(target,{recursive:true,force:true});
}
