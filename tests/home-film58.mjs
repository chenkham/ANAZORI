import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const temp=await mkdtemp(join(tmpdir(),'anazori-home-film58-'));
const env={...process.env,ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_TEST_MODE:'1'};
const base='http://127.0.0.1:8162';
const server=spawn('php',['-S','127.0.0.1:8162','-t','src','scripts/router.php'],{env,stdio:'ignore',windowsHide:true});
const php=code=>execFileSync('php',['-r',`require 'includes/cms.php';$db=cms_db();${code}`],{env,encoding:'utf8'});
const csrf=html=>html.match(/name="csrf_token" value="([^"]+)"/)[1];
let cookie='';
const request=async(path,values)=>{
  const res=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(values?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(values?{method:'POST',body:new URLSearchParams(values)}:{})});
  if(res.headers.getSetCookie().length)cookie=res.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
  return res;
};
try {
  for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
  const html=await (await request('/')).text();
  assert.match(html,/reference-background page-home/);
  assert.match(html,/public.css\?v=2026.65/);
  assert.doesNotMatch(html,/id="hero-film"|class="hero-media"|robot-stage/);
  const intro=html.match(/<section class="intro[\s\S]*?<\/section>/)[0];
  assert.match(intro,/video-stage has-video/);assert.match(intro,/class="arcane-frame"/);
  assert.match(intro,/id="intro-video"[^>]*controls[^>]*loop[^>]*muted data-autoplay="1"/);
  assert.match(intro,/<source src="\/assets\/2026\/hero-sound.mp4" type="video\/mp4"/);
  for(const route of ['/events.php','/gallery.php','/teams.php','/account.php'])assert.match(await (await request(route)).text(),/reference-background page-/);
  for(const path of ['/assets/2026/hero-sound.mp4','/assets/2026/hero-poster.jpg','/assets/2026/arcane-corner.svg','/assets/2026/public.css?v=2026.65'])assert.equal((await request(path)).status,200);

  php("$db->prepare(\"UPDATE users SET password_hash=?,must_change_password=0 WHERE role='SUPERADMIN'\")->execute([password_hash('Home-Film-QA-2026!',PASSWORD_DEFAULT)]);");
  const login=await (await request('/login.php')).text();
  assert.equal((await request('/login.php',{csrf_token:csrf(login),username:php('echo ANAZORI_SUPER_EMAIL;'),password:'Home-Film-QA-2026!'})).status,303);
  const settings=await (await request('/admin.php?section=settings')).text();
  for(const key of ['intro_video','intro_video_poster','intro_video_url','intro_video_autoplay','intro_video_controls','intro_video_loop'])assert(settings.includes(`name="${key}"`),key);
  assert.doesNotMatch(settings,/name="hero_video"|name="hero_poster"/);
  const group='Our spirit & festival film',schema=JSON.parse(php(`echo json_encode(cms_setting_schema()['${group}']);`));
  const save={action:'save_settings',group,csrf_token:csrf(settings)};
  for(const [key,definition] of Object.entries(schema))if(definition[1]!=='checkbox'||definition[2]==='1')save[key]=definition[2]??'';
  const publish=async changes=>{
    Object.assign(save,changes,{revision:php("echo $db->query(\"SELECT value FROM cms_settings WHERE setting_key='settings_revision'\")->fetchColumn();")});
    const response=await request('/admin.php',save);assert.equal(response.status,303);
    assert.match(await (await request(response.headers.get('location'))).text(),/updated\./);
    return (await request('/')).text();
  };
  assert.match(await publish({intro_video:'/anazori.mp4'}),/<source src="\/anazori.mp4"/);
  assert.match(await publish({intro_video:'',intro_video_url:''}),/video-stage is-blank/);
  assert.match(await (await request('/')).text(),/Official film coming soon/);
  assert.match(await publish({intro_video_url:'https://youtu.be/abcdefghijk'}),/https:\/\/www.youtube-nocookie.com\/embed\/abcdefghijk/);

  const migrate=site=>JSON.parse(php(`$site=json_decode('${JSON.stringify(site)}',true);cms_put_setting('site',json_encode($site));$db->exec("DELETE FROM cms_settings WHERE setting_key='home_film_location_58'");az_move_home_film($db);echo $db->query("SELECT value FROM cms_settings WHERE setting_key='site'")->fetchColumn();`));
  const legacy={hero_video:'/anazori.mp4',hero_poster:'/assets/2026/hero-poster.jpg',intro_video:'',intro_video_url:'',intro_video_autoplay:'0',show_intro:'0',hero_line1:'Saved custom heading'};
  const moved=migrate(legacy);
  assert.equal(moved.intro_video,legacy.hero_video);assert.equal(moved.intro_video_poster,legacy.hero_poster);
  assert.equal(moved.intro_video_autoplay,'1');assert.equal(moved.intro_video_controls,'1');assert.equal(moved.intro_video_loop,'1');
  assert.equal(moved.show_intro,'0');assert.equal(moved.hero_line1,legacy.hero_line1);
  const selected={...legacy,intro_video:'/assets/2026/hero-sound.mp4',intro_video_autoplay:'0'};
  assert.deepEqual(migrate(selected),selected);
  const embed={...legacy,intro_video_url:'https://vimeo.com/12345'};
  assert.deepEqual(migrate(embed),embed);
  console.log('PASS Public background, film relocation and border, media assets, Studio video edits/clearing/embeds, and preservation of saved settings during migration.');
} finally {
  if(server.exitCode===null){const ended=new Promise(resolve=>server.once('exit',resolve));server.kill();await ended;}
  await rm(temp,{recursive:true,force:true});
}
