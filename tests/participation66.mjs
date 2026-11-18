import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const temp=await mkdtemp(join(tmpdir(),'anazori-participation66-'));
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_TEST_MODE:'1'};
const password='Participation-QA-2026!',base='http://127.0.0.1:8166';
const php=code=>execFileSync('php',['-r',`require 'includes/commerce.php';$db=cms_db();${code}`],{env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+');'));
const token=html=>html.match(/name="csrf_token" value="([^"]+)"/)[1];
function client(){let cookie='';return async(path,data)=>{
 const r=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:new URLSearchParams(data)}:{})});
 if(r.headers.getSetCookie().length)cookie=r.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');return r;
};}
const visitor=client(),performer=client(),second=client(),coordinator=client(),other=client();
const fixture=JSON.parse(php(`
 $ids=[];foreach(['inauguration','cultural-night','goc'] as $slug)$ids[$slug]=az_event($slug)['id'];
 foreach(['performer','second'] as $name)$db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute([$name.'@example.invalid',ucfirst($name).' QA',password_hash('${password}',PASSWORD_DEFAULT),gmdate('c')]);
 foreach(['culture-review'=>$ids['cultural-night'],'code-review'=>$ids['goc']] as $name=>$event){
  $db->prepare("INSERT INTO users(username,password_hash,role,active,display_name,email,permissions,event_scope,must_change_password) VALUES(?,?,'COORDINATOR',1,?,?,?,'ASSIGNED',0)")->execute([$name,password_hash('${password}',PASSWORD_DEFAULT),$name,$name.'@example.invalid',json_encode(st_coordinator_permissions())]);$id=$db->lastInsertId();
  $db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,0,?)')->execute([$id,$event,gmdate('c')]);
 }
 echo json_encode($ids);`));
let errors='';const server=spawn('php',['-S','127.0.0.1:8166','-t','src','scripts/router.php'],{env,stdio:['ignore','ignore','pipe'],windowsHide:true});server.stderr.on('data',data=>{errors=(errors+data).slice(-12000);});
try{
 for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const home=await (await visitor('/')).text();
 assert.doesNotMatch(home,/THE ANAZORI SPIRIT|setting\('intro_label'\)/);
 const goc=home.match(/data-programme-pane="goc"[\s\S]*?class="theatre-caption"/)[0];
 assert.match(goc,/hackathon-pixel\.svg/);assert.doesNotMatch(goc,/roz-code/);
 const culture=home.match(/data-programme-pane="cultural-night"[\s\S]*?class="theatre-caption"/)[0];
 assert.match(culture,/characters\/stuart\.webp/);
 assert.equal((await visitor('/assets/2026/graphics/hackathon-pixel.svg')).status,200);
 const inauguration=await (await visitor('/event.php?name=inauguration')).text();
 assert.doesNotMatch(inauguration,/Register now|I'm interested|interest-dialog|checkout.php\?event=inauguration|ENTRY DETAILS|Registration closed/);
 assert.match(inauguration,/No registration or participant ticket is required/);
 assert.equal((await visitor('/checkout.php?event=inauguration')).headers.get('location'),'/event.php?name=inauguration');
 let interestPage=await (await visitor('/event.php?name=goc')).text();
 for(const event of ['inauguration','cultural-night']){
  const r=await visitor('/api/interest.php',{csrf_token:token(interestPage),event,name:'Visitor QA',email:'visitor@example.invalid',consent:'yes'});assert.equal(r.status,422);
 }
 console.log('PASS Home artwork and clean introduction; inauguration has no registration UI or API path.');

 for(const [request,email] of [[performer,'performer'],[second,'second']]){
  const page=await (await request('/account.php')).text();assert.equal((await request('/account.php',{csrf_token:token(page),email:email+'@example.invalid',password})).status,303);
 }
 for(const [request,username] of [[coordinator,'culture-review'],[other,'code-review']]){
  const page=await (await request('/login.php')).text();assert.equal((await request('/login.php',{csrf_token:token(page),username,password})).status,303);
 }
 const apply=async request=>{
  const page=await (await request('/checkout.php?event=cultural-night')).text();
  assert.doesNotMatch(page,/Choose your pass|How would you like to pay|Number of passes|checkout-total|screenshot|College/);
  assert.match(page,/What would you like to perform/);
  const input={csrf_token:token(page),event:'cultural-night',nonce:page.match(/name="nonce" value="([^"]+)"/)[1],type:'performer-pass',quantity:'1',consent:'yes','answers[phone]':'9876543210','answers[performance]':'Solo acoustic guitar',response_format:'json'};
  const r=await request('/api/checkout.php',input);assert.equal(r.status,200,await r.clone().text());const result=await r.json();assert.equal(result.url,'/dashboard.php');assert.equal(result.amount,0);return {input,result};
 };
 const application=await apply(performer);let order=json(`az_order_public('${application.result.order}')`);assert.equal(order.state,'PERFORMER_PENDING');
 assert.equal(Number(php('echo $db->query("SELECT COUNT(*) FROM az_tickets")->fetchColumn();')),0);
 assert.equal(Number(php('echo $db->query("SELECT COUNT(*) FROM az_manual_payments")->fetchColumn();')),0);
 const duplicate=await apply(performer);assert.equal(duplicate.result.order,application.result.order);
 const fake=await performer('/api/checkout.php',{...duplicate.input,event:'inauguration',nonce:duplicate.input.nonce+'x'});assert.equal(fake.status,400);
 php(`$u=$db->query("SELECT * FROM az_participants WHERE email='performer@example.invalid'")->fetch();try{az_create_order($u,'inauguration','standard-entry',1,[]);throw new Exception('Unexpected admission');}catch(RuntimeException $e){if(!str_contains($e->getMessage(),'closed'))throw $e;}`);
 console.log('PASS One free performer application; duplicates are stable, no payment records or early tickets.');

 const reviewPage=await (await coordinator('/admin.php?section=payments&event_id='+fixture['cultural-night'])).text();
 assert.match(reviewPage,/Confirm &amp; issue ticket|Confirm & issue ticket/);assert.match(reviewPage,/Solo acoustic guitar/);assert.match(reviewPage,/Download performer list/);
 assert.doesNotMatch(reviewPage,/Confirm the transaction|bank_confirmed/);
 const action={csrf_token:token(reviewPage),action:'review_performer',id:String(order.id),decision:'confirm'};
 const otherPage=await (await other('/admin.php?section=payments')).text();await other('/admin.php',{...action,csrf_token:token(otherPage)});assert.equal(json(`az_order(${order.id})`).state,'PERFORMER_PENDING');
 assert.equal((await coordinator('/admin.php',action)).status,303);assert.equal(json(`az_order(${order.id})`).state,'PAID');
 await coordinator('/admin.php',action);assert.equal(Number(php('echo $db->query("SELECT COUNT(*) FROM az_tickets")->fetchColumn();')),1);
 const ticket=json('$db->query("SELECT * FROM az_tickets")->fetch()');
 assert.equal((await performer('/ticket.php?id='+ticket.ticket_id)).status,200);assert.equal((await second('/ticket.php?id='+ticket.ticket_id)).status,404);
 const dashboard=await (await performer('/dashboard.php')).text();assert.match(dashboard,new RegExp(ticket.ticket_id));assert.doesNotMatch(dashboard,/Upload payment screenshot/);
 const csv=await (await coordinator('/admin.php?section=payments&event_id='+fixture['cultural-night']+'&export=csv')).text();assert.match(csv,/Performer QA/);assert.match(csv,/Solo acoustic guitar/);
 const rejected=await apply(second);order=json(`az_order_public('${rejected.result.order}')`);
 const currentPage=await (await coordinator('/admin.php?section=payments&event_id='+fixture['cultural-night'])).text();await coordinator('/admin.php',{csrf_token:token(currentPage),action:'review_performer',id:String(order.id),decision:'decline'});
 assert.equal(json(`az_order(${order.id})`).state,'PERFORMER_DECLINED');assert.equal(Number(php('echo $db->query("SELECT COUNT(*) FROM az_tickets")->fetchColumn();')),1);
 console.log('PASS Scoped performer confirmation issues exactly one private ticket; decline issues none; performer list exports.');

 for(const slug of ['inauguration','cultural-night']){
  const page=await (await coordinator('/admin.php?section=event&edit='+fixture[slug])).text();
  if(slug==='inauguration')continue; // This coordinator only has Cultural Night access.
  assert.doesNotMatch(page,/Passes, prices and capacity|Add payment method|Interest form|Add game/);
  assert.match(page,/Performer application dates/);
 }
 const normal=json("az_event('goc')");assert.equal(normal.fields.registration_mode,'interest');
 const saved=json("az_event('cultural-night')"),schema=json("cms_content_schema()['event']['fields']");
 const edit=await (await coordinator('/admin.php?section=event&edit='+saved.id)).text();
 const save={csrf_token:token(edit),action:'save_content',type:'event',id:String(saved.id),revision:String(saved.revision),title:saved.title,slug:saved.slug,status:'PUBLISHED',sort_order:String(saved.sort_order),event_setup_editor:'1',event_editor_complete:'1',registration_fee:'0'};
 for(const key of ['short','description','category','format','image','art','color','label','starts_at','ends_at','venue','prizes','eligibility','rules','rules_pdf','contact','status_label','featured','registration_mode','registration_opens','registration_closes','registration_closed_message']){
  if(schema[key][1]!=='checkbox'||saved.fields[key]==='1')save[key]=saved.fields[key];
 }
 save.registration_mode='closed';assert.equal((await coordinator('/admin.php',save)).status,303);
 assert.equal(json("az_event('cultural-night')['fields']['registration_mode']"),'closed');
 const closed=await (await performer('/checkout.php?event=cultural-night')).text();assert.doesNotMatch(closed,/id="checkout-form"/);
 for(const path of ['event.php','checkout.php','includes/event-participation.php','includes/cms.php','includes/cms-actions.php','includes/event-setup-view.php','includes/studio-operations-view.php','includes/studio-workspace.php','includes/studio-layout.php'])execFileSync('php',['-l',path],{env,stdio:'pipe'});
 assert.doesNotMatch(errors,/PHP (?:Fatal error|Warning|Parse error)/);
 console.log('PASS Coordinator setup stays simple, application closure persists, existing competition flows remain available, and PHP has no warnings.');
}finally{
 if(server.exitCode===null){const done=new Promise(r=>server.once('exit',r));server.kill();await done;}
 await rm(temp,{recursive:true,force:true});
}
