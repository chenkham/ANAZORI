import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const temp=await mkdtemp(join(tmpdir(),'anazori-homepage-photos-'));
const env={...process.env,ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_TEST_MODE:'1'};
const base='http://127.0.0.1:8163';
const php=code=>execFileSync('php',['-r',`require 'includes/cms.php';$db=cms_db();${code}`],{env,encoding:'utf8'});
const server=spawn('php',['-S','127.0.0.1:8163','-t','src','scripts/router.php'],{env,stdio:'ignore',windowsHide:true});
let cookie='';
const request=async(path,values)=>{
 const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(values?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(values?{method:'POST',body:new URLSearchParams(values)}:{})});
 if(response.headers.getSetCookie().length)cookie=response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
 return response;
};
const csrf=html=>html.match(/name="csrf_token" value="([^"]+)"/)[1];
const pane=(html,slug)=>html.split(`data-programme-pane="${slug}"`)[1]?.split('<div class="theatre-caption">')[0];
try{
 for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 const home=await (await request('/')).text();
 assert.match(home,/<\/html>\s*$/);
 assert.equal((home.match(/class="programme-photo-frame/g)||[]).length,9);
 assert.equal((home.match(/class="programme-companion"/g)||[]).length,9);
 assert.match(pane(home,'youth-parliament'),/programme-companion[\s\S]*graphics\/parliament.svg/);
 assert.match(pane(home,'treasure-hunt'),/programme-companion[\s\S]*treasure-scene/);
 assert.match(pane(home,'joystick'),/programme-photo-frame is-awaiting-photo/);
 assert.doesNotMatch(pane(home,'joystick'),/class="programme-event-photo"/);
 assert.match(home,/data-programme-step="-1"/);assert.match(home,/data-programme-step="1"/);

 php("$db->prepare(\"UPDATE users SET password_hash=?,must_change_password=0 WHERE role='SUPERADMIN'\")->execute([password_hash('Photo-Editor-QA-2026!',PASSWORD_DEFAULT)]);");
 const login=await (await request('/login.php')).text();
 assert.equal((await request('/login.php',{csrf_token:csrf(login),username:php('echo ANAZORI_SUPER_EMAIL;'),password:'Photo-Editor-QA-2026!'})).status,303);
 const record=JSON.parse(php("echo json_encode(cms_unpack($db->query(\"SELECT * FROM cms_content WHERE type='event' AND slug='goc'\")->fetch()));"));
 const schema=JSON.parse(php("echo json_encode(cms_content_schema()['event']['fields']);"));
 const editor=await (await request(`/admin.php?section=event&edit=${record.id}`)).text();
 assert.match(editor,/Event photo \/ cover/);
 assert.match(editor,/name="image"[^>]*data-image-select/);
 const save={action:'save_content',type:'event',id:record.id,revision:record.revision,title:record.title,slug:record.slug,status:record.status,sort_order:record.sort_order,csrf_token:csrf(editor)};
 for(const [key,definition] of Object.entries(schema))if(definition[1]!=='checkbox'||record.fields[key]==='1')save[key]=record.fields[key]??definition[2]??'';
 save.image='/assets/2026/culture.webp';
 const result=await request('/admin.php',save);assert.equal(result.status,303);
 const saved=JSON.parse(php(`echo json_encode(cms_record(${record.id}));`));
 assert.equal(saved.fields.image,save.image);
 assert.match(pane(await (await request('/')).text(),'goc'),/class="programme-event-photo" src="\/assets\/2026\/culture.webp"/);
 assert.match(await (await request('/event.php?name=goc')).text(),/src="\/assets\/2026\/culture.webp"/);
 assert.equal((await request(save.image)).status,200);
 save.image='';save.revision=saved.revision;
 assert.equal((await request('/admin.php',save)).status,303);
 const cleared=pane(await (await request('/')).text(),'goc');
 assert.match(cleared,/programme-photo-frame is-awaiting-photo/);
 assert.doesNotMatch(cleared,/class="programme-event-photo"/);
 console.log('PASS All nine homepage events have a photo frame and lower-right artwork; empty frames, event links, Studio photo selection and clearing work. Only an isolated database was used.');
}finally{
 if(server.exitCode===null){const ended=new Promise(resolve=>server.once('exit',resolve));server.kill();await ended;}
 await rm(temp,{recursive:true,force:true});
}
