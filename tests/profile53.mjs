import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
const temp=await mkdtemp(join(tmpdir(),'anazori-profile53-')),sessions=join(temp,'sessions');await mkdir(sessions);
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_TEST_MODE:'1'};
const server=spawn('php',['-d','session.save_path='+sessions,'-S','127.0.0.1:8157','-t','src','scripts/router.php'],{env,stdio:'ignore'}),base='http://127.0.0.1:8157';let cookie='';
const php=code=>execFileSync('php',['-d','session.save_path='+sessions,'-r',code],{env,encoding:'utf8'});
const data=code=>php("require 'includes/commerce.php';$db=cms_db();"+code);
const request=async(path,values)=>{const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(values?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(values?{method:'POST',body:new URLSearchParams(values)}:{})});if(response.headers.getSetCookie().length)cookie=response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');return response;};
const csrf=html=>html.match(/name="csrf_token" value="([^"]+)"/)[1];
try{
 for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 let res=await request('/profile.php');assert.equal(res.status,302);assert.match(res.headers.get('location'),/^\/account.php/);
 await request('/');const sid=cookie.match(/PHPSESSID=([a-zA-Z0-9,-]+)/)[1];
 const signed=JSON.parse(php(`session_id('${sid}');require 'includes/commerce.php';require 'includes/google-auth.php';$u=az_google_participant(cms_db(),az_google_identity(['sub'=>'isolated-profile53','email'=>'profile53@example.invalid','name'=>'Google imported name','email_verified'=>true]),true);az_participant_login($u,'google');$destination=az_participant_destination($u,'/checkout.php?event=joystick');echo json_encode(['session'=>session_id(),'id'=>$u['id'],'destination'=>$destination]);`));cookie='PHPSESSID='+signed.session;assert.equal(signed.destination,'/profile.php');
 res=await request('/dashboard.php');assert.equal(res.status,302);assert.equal(res.headers.get('location'),'/profile.php');
 const profile=await (await request('/profile.php')).text();assert.match(profile,/What should we call you/);assert.doesNotMatch(profile,/Google imported name/);assert.match(profile,/name="name" value=""/);assert.doesNotMatch(profile,/name="(?:email|password|avatar|college)"/);
 res=await request('/profile.php',{csrf_token:csrf(profile),name:'A',phone:'-------'});assert.equal(res.status,200);assert.match(await res.text(),/Enter your full name/);assert.equal(Number(data("echo $db->query('SELECT profile_completed FROM az_participants')->fetchColumn();")),0);
 res=await request('/profile.php',{csrf_token:csrf(profile),name:'Chosen by participant',phone:'+91 98765 43210',email:'forged@example.invalid',id:'999',role:'SUPERADMIN'});assert.equal(res.status,303);assert.equal(res.headers.get('location'),'/dashboard.php');
 let saved=JSON.parse(data("echo json_encode($db->query('SELECT name,phone,email,profile_completed FROM az_participants')->fetch());"));assert.equal(saved.name,'Chosen by participant');assert.equal(saved.phone,'+91 98765 43210');assert.equal(saved.email,'profile53@example.invalid');assert.equal(Number(saved.profile_completed),1);
 assert.match(await (await request('/dashboard.php')).text(),/Edit profile/);
 const edit=await (await request('/profile.php')).text();assert.match(edit,/name="name" value="Chosen by participant"/);assert.match(edit,/Save profile/);
 res=await request('/profile.php',{csrf_token:csrf(edit),name:'Updated participant',phone:''});assert.equal(res.status,303);assert.equal(res.headers.get('location'),'/profile.php?saved=1');
 saved=JSON.parse(data("echo json_encode($db->query('SELECT name,phone,email FROM az_participants')->fetch());"));assert.equal(saved.name,'Updated participant');assert.equal(saved.phone,'');assert.equal(saved.email,'profile53@example.invalid');
 data("$db->exec('UPDATE az_participants SET session_version=session_version+1');");res=await request('/profile.php');assert.equal(res.status,302);assert.match(res.headers.get('location'),/^\/account.php/);
 const renew=()=>{const currentSession=cookie.match(/PHPSESSID=([a-zA-Z0-9,-]+)/)[1];const next=php(`session_id('${currentSession}');require 'includes/commerce.php';$u=cms_db()->query('SELECT * FROM az_participants')->fetch();az_participant_login($u,'google');echo session_id();`);cookie='PHPSESSID='+next;};
 renew();data("$db->exec('UPDATE az_participants SET active=0');");res=await request('/dashboard.php');assert.equal(res.status,302);assert.match(res.headers.get('location'),/^\/account.php/);
 data("$db->exec('UPDATE az_participants SET active=1');");renew();data("$db->exec(\"UPDATE az_participants SET email='different@example.invalid'\");");res=await request('/dashboard.php');assert.equal(res.status,302);assert.match(res.headers.get('location'),/^\/account.php/);
 data("$db->exec(\"UPDATE az_participants SET email='profile53@example.invalid'\");");renew();data("$db->exec('DELETE FROM az_participants');");res=await request('/dashboard.php');assert.equal(res.status,302);assert.match(res.headers.get('location'),/^\/account.php/);
 console.log('PASS Google name onboarding, required completion, own name/phone edits, immutable email, persistence and denial for stale, disabled, email-mismatched or deleted accounts.');
}finally{server.kill();if(server.exitCode===null)await new Promise(resolve=>server.once('exit',resolve));await rm(temp,{recursive:true,force:true});}
