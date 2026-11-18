import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readdir,writeFile,unlink,rmdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';

const directory=await mkdtemp(join(tmpdir(),'anazori-keepsake-'));
const outbox=join(directory,'outbox');await mkdir(outbox);
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(directory,'qa.sqlite'),ANAZORI_SECRET_PATH:join(directory,'key'),ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:outbox};
const mobilePreview=process.argv.includes('--mobile-preview');
const port=mobilePreview?8151:8149,base=`http://127.0.0.1:${port}`;
const previewRouter=join(directory,'preview-router.php');
if(mobilePreview){
 const route=resolve('scripts/router.php').replaceAll('\\','/').replaceAll("'","\\'");
 await writeFile(previewRouter,`<?php if(parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH)==='/mobile-preview'){header('Content-Type: text/html; charset=utf-8');echo '<!doctype html><html><head><title>Mobile QA</title><style>body{margin:0;background:#171d28}iframe{border:0;width:390px;height:660px}</style></head><body><iframe src="/" title="Festival phone preview"></iframe></body></html>';return;}return require '${route}';`);
}
const server=spawn('php',['-S',`127.0.0.1:${port}`,mobilePreview?previewRouter:'-t','src','scripts/router.php'],{env,windowsHide:true,stdio:'ignore'});
const php=code=>execFileSync('php',['-r',`require 'includes/cms.php';cms_db();${code}`],{env,encoding:'utf8'});
let groups=0;const ok=message=>{groups++;console.log('PASS '+message);};
try{
 for(let i=0;i<50;i++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 const response=await fetch(base);assert.equal(response.status,200);
 const html=await response.text(),station=html.match(/<section[^>]*id="motion-studio"[\s\S]*?<\/section>/)?.[0];assert(station);
 assert.match(station,/<label for="keepsake-name">Enter your name<\/label>/);
 assert.match(station,/<input[^>]+maxlength="60"[^>]+required[^>]+data-keepsake-name/);
 assert.match(station,/<button type="submit"[^>]+data-video-save/);
 assert.doesNotMatch(station,/account\.php|Sign up|Sign in|data-signed-in|data-keepsake-account|data-card-theme/);
 ok('Anonymous visitors receive the name form and download button without an account gate.');
 const data=JSON.parse(station.match(/data-keepsake-studio="([^"]+)"/)[1].replaceAll('&quot;','"').replaceAll('&amp;','&'));
 assert.equal(data.name,'Your name');assert.equal(data.festival,'ANAZORI');assert.match(data.notice,/Not valid for event entry/);assert(data.logo);assert(data.edition);assert.equal(data.email,undefined);assert.equal(data.id,undefined);
 assert.match(station,/A keepsake to share\. Not valid for event entry\./);
 ok('The public design contains only festival metadata and the keepsake notice.');
 assert.equal((await fetch(base+'/api/keepsake.php')).status,404);
 assert.deepEqual(JSON.parse(php("echo json_encode([cms_db()->query('SELECT COUNT(*) FROM az_participants')->fetchColumn(),cms_db()->query('SELECT COUNT(*) FROM az_orders')->fetchColumn(),cms_db()->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn()]);")),[0,0,0]);
 ok('The retired account endpoint is unavailable and previewing creates no accounts, orders or admission tickets.');
 console.log(`${groups} public-keepsake integration checks passed.`);
 if(process.argv.includes('--preview')||mobilePreview){
  console.log(`Temporary guest QA preview: ${base}/#motion-studio`);
  if(mobilePreview)console.log(`Phone viewport QA: ${base}/mobile-preview`);
  console.log('Temporary server PID: '+server.pid);
  await new Promise(resolve=>{const timer=setTimeout(resolve,600000);process.once('SIGINT',()=>{clearTimeout(timer);resolve();});});
 }
}finally{
 if(server.exitCode===null){const ended=new Promise(resolve=>server.once('exit',resolve));server.kill();await ended;}
 for(const name of await readdir(outbox))await unlink(join(outbox,name));await rmdir(outbox);
 for(const name of await readdir(directory))await unlink(join(directory,name));await rmdir(directory);
}
