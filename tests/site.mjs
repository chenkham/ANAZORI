import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,unlink,rmdir,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
const root=resolve('.');
const directory=await mkdtemp(join(tmpdir(),'anazori-2026-test-'));
const db=join(directory,'qa.sqlite');
const env={...process.env,ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:db};
const port=8097,base='http://127.0.0.1:'+port;
let serverErrors='';
const server=spawn('php',['-S','127.0.0.1:'+port,'-t','src','scripts/router.php'],{cwd:root,env,windowsHide:true,stdio:['ignore','ignore','pipe']});
server.stderr.on('data',chunk=>{serverErrors=(serverErrors+chunk).slice(-12000);});
let passed=0;const ok=message=>{passed++;console.log('PASS '+message);};
try{
 for(let n=0;n<50;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const paths=['/','/events.php','/event.php?name=goc','/event.php?name=youth-parliament','/event.php?name=inauguration','/event.php?name=cultural-night','/event.php?name=joystick','/event.php?name=futsal','/event.php?name=workshops','/event.php?name=paper-presentation','/event.php?name=tulika','/gallery.php','/teams.php','/login.php'];
 const assetPaths=new Set();
 let csrf='',cookie='';
 for(const path of paths){
  const response=await fetch(base+path);assert.equal(response.status,200,path+'\n'+serverErrors);
  const html=await response.text();assert.match(html,/2026/);assert.doesNotMatch(html,/cdn.tailwindcss|three.min.js|portal\/app.js|swup-init|lenis.min/);
  assert.match(html,/<\/html>\s*$/,path+' must render completely\n'+serverErrors);
  assert.equal((html.match(/<h1\b/g)||[]).length,1,path+' h1');
  if(path==='/gallery.php'){
   assert.equal((html.match(/class="gallery-item"/g)||[]).length,18,'All published archive photos render.');
   assert.equal((html.match(/<div class="gallery-photo"><img /g)||[]).length,18,'Each photo has a thumbnail.');
   assert.match(html,/id="gallery-dialog"/,'Photo viewer renders after the complete gallery.');
   assert.doesNotMatch(html.match(/<div class="gallery-grid">[\s\S]*?<section class="programme-banner/)[0],/2024|v14\.0/i);
  }
  if(path==='/event.php?name=goc'){csrf=html.match(/name="csrf_token" value="([^"]+)"/)[1];cookie=response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');}
  for(const match of html.matchAll(/(?:src|href)="(\/[^"?#]+(?:css|js|webp|png|svg|woff2))(?:\?[^"]*)?"/g))assetPaths.add(match[1]);
 }
 ok('All public pages render completely, including all 18 gallery photos and the photo viewer.');
 for(const path of assetPaths){assert.equal((await fetch(base+path)).status,200,'Missing asset '+path);}
 ok('All referenced local CSS, JavaScript, fonts, and images resolve.');
 assert.equal((await fetch(base+'/event.php?name=does-not-exist')).status,404);
 assert.equal((await fetch(base+'/event/game-of-codes',{redirect:'manual'})).status,301);
 assert.equal((await fetch(base+'/event.php?name=prativa',{redirect:'manual'})).headers.get('location'),'/event.php?name=youth-parliament');
 assert.equal((await fetch(base+'/index.html',{redirect:'manual'})).status,302);
 assert.equal((await fetch(base+'/admin.php',{redirect:'manual'})).status,302);
 for(const path of ['/.local/qa-2026.sqlite','/config/festival.php','/src/site.js','/data/anazori.sqlite','/data/.application-key','/vendor/autoload.php','/composer.json','/composer.lock','/includes/platform.php'])assert.equal((await fetch(base+path)).status,404);
 ok('Unknown events, legacy links, admin authentication, and private-file routes behave correctly.');
 const valid={csrf_token:csrf,event:'goc',name:'Automated QA',email:'automated-qa@example.com',college:'Isolated QA fixture',consent:'yes'};
 const post=async values=>{const r=await fetch(base+'/api/interest.php',{method:'POST',headers:{Cookie:cookie,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(values)});return {status:r.status,data:await r.json()};};
 assert.equal((await fetch(base+'/api/interest.php')).status,405);
 assert.equal((await post({...valid,csrf_token:'invalid'})).status,403);
 assert.equal((await post({...valid,email:'not-email'})).status,422);
 assert.equal((await post({...valid,consent:''})).status,422);
 assert.equal((await post({...valid,event:'invalid-event'})).status,422);
 ok('Interest API rejects incorrect method, CSRF, email, consent, and event.');
 const saved=await post(valid);assert.equal(saved.status,201,JSON.stringify(saved.data));assert.match(saved.data.reference,/^AZ26-[A-F0-9]{10}$/);
 const duplicate=await post(valid);assert.equal(duplicate.status,200);assert.equal(duplicate.data.reference,saved.data.reference);
 const rows=JSON.parse(execFileSync('php',['-r',"$db=new PDO('sqlite:'.getenv('ANAZORI_DB_PATH'));echo json_encode($db->query('SELECT status,form_data FROM submissions')->fetchAll(PDO::FETCH_ASSOC));"],{env,encoding:'utf8'}));
 assert.equal(rows.length,1);assert.equal(rows[0].status,'PENDING');assert.equal(JSON.parse(rows[0].form_data).edition,2026);
 ok('Interest is stored once, returns a stable reference, and never confirms entry or payment.');
 for(const file of ['index.php','events.php','event.php','gallery.php','teams.php','login.php','admin.php','router.php','includes/festival.php','includes/header.php','includes/footer.php','api/interest.php','config/festival.php'])execFileSync('php',['-l',file==='router.php'?'scripts/router.php':'src/'+file],{stdio:'pipe'});
 ok('PHP syntax checks pass for the complete redesigned flow.');
 console.log(passed+' integration checks passed. Only an isolated temporary database was used.');
}finally{
 if(server.exitCode===null){const ended=new Promise(r=>server.once('exit',r));server.kill();await ended;}
 for(const name of await readdir(directory)){await unlink(join(directory,name));}
 await rmdir(directory);
}
