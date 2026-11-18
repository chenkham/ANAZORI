import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn, execFileSync, execFile} from 'node:child_process';
import {mkdtemp, mkdir, readFile, readdir, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';

const temp = await mkdtemp(join(tmpdir(), 'anazori-studio-scope-'));
const receiptDir = join(temp, 'private-receipts'); await mkdir(receiptDir);
const mediaDir = join(temp, 'media'); await mkdir(mediaDir);
const base = 'http://127.0.0.1:8122', gatewayBase = 'http://127.0.0.1:8123';
const env = {...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('ANAZORI_'))),
  ANAZORI_DB_PATH: join(temp, 'qa.sqlite'), ANAZORI_SECRET_PATH: join(temp, 'app-key'), ANAZORI_TEST_MODE: '1',
  ANAZORI_MEDIA_DIR: mediaDir,
  ANAZORI_STUDIO_RECEIPT_PATH: receiptDir, ANAZORI_TEST_GATEWAY: gatewayBase,
  ANAZORI_PHONEPE_SANDBOX_CLIENT_ID: 'scope-fixture', ANAZORI_PHONEPE_SANDBOX_CLIENT_VERSION: '1',
  ANAZORI_PHONEPE_SANDBOX_CLIENT_SECRET: 'scope-fixture-secret', ANAZORI_PHONEPE_SANDBOX_WEBHOOK_USERNAME: 'fixture',
  ANAZORI_PHONEPE_SANDBOX_WEBHOOK_PASSWORD: 'fixture-password'};
const php = code => JSON.parse(execFileSync('php', ['-r', `require 'includes/commerce.php';cms_db();${code}`], {env, encoding: 'utf8'}));
const asyncPhp = code => new Promise((resolve,reject)=>execFile('php',['-r',`require 'includes/commerce.php';cms_db();${code}`],{env,encoding:'utf8'},(error,output)=>error?reject(error):resolve(JSON.parse(output))));
const rows = sql => php(`echo json_encode(cms_db()->query(${JSON.stringify(sql)})->fetchAll());`);
const alter = sql => php(`cms_db()->exec(${JSON.stringify(sql)});echo 'true';`);
let passed = 0; const ok = message => {passed++; console.log('PASS ' + message);};
let revokeDuringFetch = null, gatewayState = 'COMPLETED';
const gateway = createServer(async (request, response) => {
  for await (const ignored of request) {void ignored;}
  response.setHeader('Content-Type', 'application/json');
  if (request.url === '/v1/oauth/token') {response.end(JSON.stringify({access_token:'scope-token',token_type:'O-Bearer',expires_at:Math.floor(Date.now()/1000)+3600})); return;}
  const match = request.url.match(/^\/checkout\/v2\/order\/(ORDER-[A-F0-9]{16})\/status\?details=true$/);
  if (!match) {response.statusCode=404; response.end('{}'); return;}
  if (revokeDuringFetch) {const action = revokeDuringFetch; revokeDuringFetch=null; action();}
  response.end(JSON.stringify({orderId:'OMO_SCOPE_PENDING',merchantOrderId:match[1],amount:1234,state:gatewayState,
    paymentDetails:gatewayState==='COMPLETED'?[{transactionId:'OMT_SCOPE_COMPLETED',state:'COMPLETED',amount:1234,paymentMode:'UPI_INTENT',rail:{type:'UPI'},instrument:{type:'ACCOUNT'}}]:[]}));
});
await new Promise(resolve => gateway.listen(8123, '127.0.0.1', resolve));
const server = spawn('php', ['-S','127.0.0.1:8122','-t','src','scripts/router.php'], {env,windowsHide:true,stdio:'ignore'});
let browser;
const errors=[];
const password='Scope-Test-Password-2026!';
const coordinatorPermissions=['event.view','event.edit','event.publish','event.delete','participants.view','participants.edit','payments.view','payments.verify','tickets.view','tickets.revoke','tickets.scan','submissions.view','submissions.edit','audit.view','operations.export','finance.view','finance.submit','finance.approve','finance.export','finance.allocate','finance.record','finance.close'];
try {
  for(let i=0;i<100;i++){try{if((await fetch(base)).ok)break;}catch{} await new Promise(resolve=>setTimeout(resolve,100));}
  const fixture=join(temp,'fixture.php');
  const root=process.cwd().replaceAll('\\','/');
  await writeFile(fixture,`<?php
require '${root}/includes/commerce.php'; $db=cms_db();
$master=$db->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();
$db->prepare('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?')->execute([password_hash('${password}',PASSWORD_DEFAULT),$master['id']]);
cms_put_setting('integrations_private',az_encrypt(json_encode(['site_url'=>'${base}','payment_mode'=>'test','payment_enabled'=>'1'])));
$db->exec("DELETE FROM cms_content WHERE type='event';DELETE FROM events;");
$fields=[];foreach(cms_content_schema()['event']['fields'] as $key=>$value)$fields[$key]=$value[2]??'';
$fields=array_replace($fields,['category'=>'tech','registration_mode'=>'open','short'=>'Scope fixture','description'=>'Scope fixture','venue'=>'Fixture Hall','ticket_types'=>json_encode([['id'=>'general','label'=>'General','price'=>100,'capacity'=>50,'active'=>true]])]);
$insert=$db->prepare("INSERT INTO cms_content(id,type,slug,title,data,status,sort_order,created_by,updated_at) VALUES(?,'event',?,?,?,'PUBLISHED',0,0,?)");
foreach([[101,'scope-alpha','SCOPE ALPHA EVENT'],[202,'scope-beta','SCOPE BETA EVENT']] as $event)$insert->execute([...$event,json_encode($fields),gmdate('c')]);
$insert=$db->prepare('INSERT INTO events(id,slug,title) VALUES(?,?,?)');$insert->execute([9001,'scope-alpha','SCOPE ALPHA EVENT']);$insert->execute([101,'scope-beta','SCOPE BETA EVENT']);
$insert=$db->prepare("INSERT INTO users(username,email,display_name,password_hash,role,active,must_change_password,permissions) VALUES(?,?,?,?,'COORDINATOR',1,0,?)");
$ids=[];foreach([['scope-coordinator','scope@example.com','Scope Coordinator',${JSON.stringify(JSON.stringify(coordinatorPermissions))}],['scope-unassigned','unassigned@example.com','Unassigned Coordinator',${JSON.stringify(JSON.stringify(coordinatorPermissions))}],['scope-reader','reader@example.com','Limited Reader','["payments.view"]']] as $user){$insert->execute([$user[0],$user[1],$user[2],password_hash('${password}',PASSWORD_DEFAULT),$user[3]]);$ids[$user[0]]=(int)$db->lastInsertId();}
st_set_assignments($master,$ids['scope-coordinator'],[101],false);st_set_assignments($master,$ids['scope-reader'],[101],false);
$insert=$db->prepare('INSERT INTO az_participants(id,email,name,email_verified,created_at) VALUES(?,?,?,1,?)');
foreach([[501,'alpha@example.com','ALPHA PERSON'],[502,'beta@example.com','BETA PERSON'],[503,'shared@example.com','SHARED PERSON'],[504,'unregistered@example.com','UNREGISTERED PERSON']] as $person)$insert->execute([...$person,gmdate('c')]);
$insert=$db->prepare("INSERT INTO az_orders(id,public_id,participant_id,event_id,event_slug,ticket_type,snapshot,answers,quantity,unit_price,amount,state,environment,provider,gateway_order,gateway_payment,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,'general',?,'{}',?,?,?,?,?,'phonepe',?,?,?, ?,?)");
foreach([[110,'ORDER-AAAAAAAAAAAAAAAA',501,101,'scope-alpha',2,650,1300,'PAID','live','OMO_ALPHA','OMT_ALPHA'],[111,'ORDER-AAAAAAAAAAAAAAAB',503,101,'scope-alpha',1,500,500,'PAID','live','OMO_SHARED_ALPHA','OMT_SHARED_ALPHA'],[210,'ORDER-BBBBBBBBBBBBBBBB',502,202,'scope-beta',8,700,5600,'PAID','live','OMO_BETA','OMT_BETA'],[211,'ORDER-BBBBBBBBBBBBBBBC',503,202,'scope-beta',1,1000,1000,'PAID','live','OMO_SHARED_BETA','OMT_SHARED_BETA'],[112,'ORDER-CCCCCCCCCCCCCCCC',501,101,'scope-alpha',1,1234,1234,'PENDING','test',null,null],[113,'ORDER-DDDDDDDDDDDDDDDD',501,101,'scope-alpha',1,9999,9999,'PAID','test','OMO_PRODUCTION','OMT_PRODUCTION']] as $order){$snapshot=json_encode(['title'=>$order[3]===101?'SCOPE ALPHA EVENT':'SCOPE BETA EVENT','name'=>$order[2]===502?'BETA PERSON':($order[2]===503?'SHARED PERSON':'ALPHA PERSON'),'type'=>'General','starts_at'=>'','venue'=>'Fixture Hall']);$insert->execute([$order[0],$order[1],$order[2],$order[3],$order[4],$snapshot,$order[5],$order[6],$order[7],$order[8],$order[9],$order[10],$order[11],time()+3600,gmdate('c'),gmdate('c')]);}
$insert=$db->prepare('INSERT INTO az_tickets(id,ticket_id,order_id,participant_id,event_id,token,created_at) VALUES(?,?,?,?,?,?,?)');
foreach([[1101,'AZ16-AAAAAAAAAAAAAA',110,501,101,'a'],[1102,'AZ16-AAAAAAAAAAAAAB',110,501,101,'b'],[1103,'AZ16-AAAAAAAAAAAAAC',111,503,101,'c'],[2101,'AZ16-BBBBBBBBBBBBBB',210,502,101,'d']] as $ticket)$insert->execute([$ticket[0],$ticket[1],$ticket[2],$ticket[3],$ticket[4],$ticket[1].'.'.str_repeat($ticket[5],64),gmdate('c')]);
$insert=$db->prepare("INSERT INTO submissions(id,event_id,name,email,phone,form_data,status) VALUES(?,?,?,?,?,'{}','PENDING')");$insert->execute([1111,9001,'ALPHA APPLICATION','alphaform@example.com','9876543210']);$insert->execute([2222,101,'BETA APPLICATION','betaform@example.com','9876543211']);
$insert=$db->prepare('INSERT INTO st_budgets(event_id,environment,allocated,updated_by,updated_at) VALUES(?,?,?, ?,?)');$insert->execute([101,'live',100000,$master['id'],gmdate('c')]);$insert->execute([202,'live',900000,$master['id'],gmdate('c')]);
$insert=$db->prepare('INSERT INTO st_finance_evidence(id,event_id,environment,filename,title,mime,size_bytes,sha256,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)');
foreach([[1,101,'a'],[2,202,'b']] as $proof){$filename=str_repeat($proof[2],48).'.png';$path=getenv('ANAZORI_STUDIO_RECEIPT_PATH').DIRECTORY_SEPARATOR.$filename;copy('${root}/assets/logo.png',$path);$insert->execute([$proof[0],$proof[1],'live',$filename,'Private proof','image/png',filesize($path),hash_file('sha256',$path),$master['id'],gmdate('c')]);}
st_event_audit($master,101,'event.save','ALPHA ACTIVITY');st_event_audit($master,202,'event.save','BETA ACTIVITY');
echo json_encode(['users'=>$ids,'master'=>(int)$master['id']]);
`);
  const fixtureIds=JSON.parse(execFileSync('php',[fixture],{env,encoding:'utf8'}));
  browser=await chromium.launch();
  async function session(email){const context=await browser.newContext({viewport:{width:1440,height:960}});const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));await page.goto(base+'/login.php');await page.locator('#login-user').fill(email);await page.locator('#login-pass').fill(password);await page.locator('[type=submit]').click();await page.waitForURL('**/admin.php**');return {context,page};}
  const {page}=await session('scope@example.com');
  async function token(p=page){await p.goto(base+'/admin.php?environment=live');return p.locator('[name=csrf_token]').first().inputValue();}
  async function post(values,p=page){const body=new URLSearchParams({csrf_token:await token(p)});for(const[key,value]of Object.entries(values)){if(Array.isArray(value))value.forEach(item=>body.append(key+'[]',String(item)));else body.append(key,String(value));}const response=await p.request.post(base+'/admin.php',{data:body.toString(),headers:{'Content-Type':'application/x-www-form-urlencoded'}});return response.text();}
  async function html(section,extra='',p=page){const response=await p.request.get(base+'/admin.php?section='+section+'&environment=live'+extra);const content=await response.text();assert.equal(response.status(),200,content);assert.doesNotMatch(content,/Fatal error:|Parse error:|Warning:/);return content;}
  for(const section of ['event','participants','payments','tickets','submissions','finance','budgets','reports','audit']){const content=await html(section);assert.ok(!content.includes('SCOPE BETA EVENT')&&!content.includes('BETA PERSON')&&!content.includes('BETA APPLICATION')&&!content.includes('BETA ACTIVITY'),section+' leaked another event');}
  ok('All operational, financial and activity pages exclude other event records and workspace labels.');
  await page.goto(base+'/admin.php?environment=live');
  const metrics=await page.locator('.metric-card').allTextContents();
  assert.ok(metrics.some(text=>text.includes('Registered people')),await page.textContent('body'));
  assert.match(metrics.find(text=>text.includes('Registered people')),/Registered people\s*2/);
  assert.match(metrics.find(text=>text.includes('Confirmed collections')),/₹18\.00/);
  const participants=await html('participants');assert.ok(participants.includes('ALPHA PERSON')&&participants.includes('SHARED PERSON'));assert.ok(!participants.includes('UNREGISTERED PERSON'));
  for(const section of ['payments','participants','tickets']){const content=await html(section,'&q=BETA');assert.ok(!content.includes('BETA PERSON')&&!content.includes('SCOPE BETA EVENT'),section+' search leaked scope');}
  assert.ok(!(await html('payments')).includes('ORDER-DDDDDDDDDDDDDDDD'));assert.ok(!(await html('payments','&environment=test')).includes('ORDER-DDDDDDDDDDDDDDDD'));
  ok('Overview counts, joined participant lists, search and single website accounting workflow use the same authorised order scope.');
  for(const section of ['participants','payments','tickets','submissions']){const response=await page.request.get(base+'/admin.php?section='+section+'&environment=live&export=csv');assert.equal(response.status(),200);assert.match(response.headers()['content-type'],/text\/csv/);const csv=await response.text();assert.ok(!csv.includes('BETA')&&!csv.includes('BBBBBBBBBBBBBB')&&!csv.includes('UNREGISTERED PERSON'),section+' CSV leaked scope');}
  assert.equal((await page.request.get(base+'/admin.php?section=payments&environment=live&event_id=202&export=csv')).status(),403);
  ok('Operational CSV exports retain scope and reject another event filter.');
  for(const section of ['overview','finance','budgets','expenses','reports','payments','tickets'])assert.equal((await page.request.get(base+'/admin.php?section='+section+'&event_id=202&environment=live')).status(),403,section);
  const betaTicket='AZ16-BBBBBBBBBBBBBB';for(const suffix of ['', '&download=qr','&download=pdf'])assert.equal((await page.request.get(base+'/ticket.php?id='+betaTicket+suffix)).status(),404);
  const alphaPdf=await page.request.get(base+'/ticket.php?id=AZ16-AAAAAAAAAAAAAA&download=pdf');assert.equal(alphaPdf.status(),200);assert.equal((await alphaPdf.body()).subarray(0,4).toString(),'%PDF');
  ok('Direct workspace URLs and private ticket HTML/QR/PDF enforce parent-order ownership, including wrong redundant ticket event IDs.');
  assert.match(await post({action:'revoke_ticket',id:2101}),/unavailable in your assigned events/);assert.equal(rows('SELECT status FROM az_tickets WHERE id=2101')[0].status,'VALID');
  assert.match(await post({action:'revoke_ticket',id:1102}),/Ticket revoked/);assert.equal(rows('SELECT status FROM az_tickets WHERE id=1102')[0].status,'VOID');
  assert.match(await post({action:'participant_status',id:501}),/festival-wide access/);assert.equal(rows('SELECT active FROM az_participants WHERE id=501')[0].active,1);
  assert.match(await post({action:'submission_status',id:2222,status:'CONFIRMED'}),/outside your assigned/);assert.equal(rows('SELECT status FROM submissions WHERE id=2222')[0].status,'PENDING');
  assert.match(await post({action:'submission_status',id:1111,status:'CONTACTED'}),/Submission status updated/);assert.equal(rows('SELECT status FROM submissions WHERE id=1111')[0].status,'CONTACTED');
  ok('Cross-event revocation and legacy submission status changes fail; own-event changes succeed; shared accounts require festival authority.');
  const old=rows('SELECT * FROM cms_content WHERE id=101')[0],fields=JSON.parse(old.data);
  const save={action:'save_content',type:'event',id:101,revision:old.revision,title:'SCOPE ALPHA EVENT',slug:'scope-alpha',status:'PUBLISHED',sort_order:0,...fields,'ticket[0][id]':'general','ticket[0][label]':'General','ticket[0][price]':'1.00','ticket[0][capacity]':'50','ticket[0][active]':'1'};
  for(const[key,definition]of Object.entries(php("echo json_encode(cms_content_schema()['event']['fields']);")))if(definition[1]==='checkbox'&&save[key]!=='1')delete save[key];
  assert.match(await post({...save,id:202,slug:'scope-beta',title:'BYPASS EVENT'}),/do not have access|outside your assigned/);assert.equal(rows('SELECT title FROM cms_content WHERE id=202')[0].title,'SCOPE BETA EVENT');
  assert.match(await post({...save,slug:'renamed-alpha'}),/existing event URL cannot change/);
  assert.match(await post(save),/Saved\./);assert.equal(rows('SELECT revision FROM cms_content WHERE id=101')[0].revision,old.revision+1);
  assert.match(await post({...save,id:0,slug:'scope-created'}),/do not have access|outside your assigned/);assert.equal(rows("SELECT COUNT(*) n FROM cms_content WHERE slug='scope-created'")[0].n,0);
  ok('Event edits are isolated; immutable slugs protect mappings; scoped coordinators cannot create an unassigned event.');
  let response=await page.request.post(base+'/api/checkin.php',{form:{csrf_token:await token(),token:'AZ16-BBBBBBBBBBBBBB.'+'d'.repeat(64),action:'checkin'}});assert.equal(response.status(),409);assert.equal((await response.json()).ok,false);assert.equal(rows('SELECT COUNT(*) n FROM az_checkins')[0].n,0);
  response=await page.request.post(base+'/api/checkin.php',{form:{csrf_token:await token(),token:'AZ16-AAAAAAAAAAAAAA.'+'a'.repeat(64),action:'checkin'}});assert.equal(response.status(),200);assert.equal((await response.json()).ticket.status,'USED');
  response=await page.request.post(base+'/api/checkin.php',{form:{csrf_token:await token(),token:'AZ16-AAAAAAAAAAAAAA.'+'a'.repeat(64),action:'checkin'}});assert.equal(response.status(),409);
  ok('Scanning API scopes tokens by parent order and admits a pass once.');
  const noFinance=await session('reader@example.com');for(const section of ['finance','budgets','expenses','reports'])assert.equal((await noFinance.page.request.get(base+'/admin.php?section='+section+'&environment=live')).status(),403);
  assert.equal((await page.request.get(base+'/admin.php?section=expenses&environment=live&finance_receipt=1')).status(),200);
  assert.equal((await page.request.get(base+'/admin.php?section=expenses&environment=live&finance_receipt=2')).status(),404);
  assert.equal((await noFinance.page.request.get(base+'/admin.php?finance_receipt=1')).status(),404);
  const budgetExport=await page.request.get(base+'/admin.php?section=reports&environment=live&export=budgets');assert.equal(budgetExport.status(),200);assert.match(await budgetExport.text(),/100000/);assert.ok(!(await budgetExport.text()).includes('900000'));
  assert.match(await post({action:'finance_allocate',environment:'live',event_id:101,request_key:'a'.repeat(48),revision:1,amount:'99.00',note:'Scope test'}),/requires an authorised festival finance/);assert.equal(rows("SELECT allocated FROM st_budgets WHERE event_id=101 AND environment='live'")[0].allocated,100000);
  ok('Finance view and export permissions remain separate; event-scoped users cannot allocate common festival funds.');
  const unassigned=await session('unassigned@example.com');const empty=await html('overview','',unassigned.page);assert.match(empty,/No events assigned yet/);for(const section of ['event','participants','payments','tickets','submissions','budgets']){const content=await html(section,'',unassigned.page);assert.ok(!content.includes('ALPHA PERSON')&&!content.includes('SCOPE ALPHA EVENT'),section);}
  ok('An unassigned account exposes no event data even with broad module permissions.');
  const masterSession=await session('chenkhamchowlu@gmail.com');
  const granted=await post({action:'save_user',id:fixtureIds.users['scope-reader'],username:'scope-reader',email:'reader@example.com',display_name:'Limited Reader',role:'COORDINATOR',active:1,password:'',permissions:['payments.view'],event_scope_present:1,event_scope:'assigned',event_ids:[202]},masterSession.page);
  assert.match(granted,/Staff access saved/);assert.match((await noFinance.page.request.get(base+'/admin.php',{maxRedirects:0})).headers().location,/login\.php/);
  const switched=await session('reader@example.com');const switchedHtml=await html('payments','',switched.page);assert.ok(switchedHtml.includes('BETA PERSON')&&!switchedHtml.includes('ALPHA PERSON'));
  ok('Team access HTTP assignment changes revoke existing sessions and apply only the replacement event scope on new login.');
  const existingMedia=rows('SELECT COUNT(*) n FROM cms_media')[0].n;
  alter("CREATE TRIGGER scope_upload_audit_failure BEFORE INSERT ON cms_audit WHEN NEW.action='media.upload' BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END");
  const image=await readFile('src/assets/logo.png');
  let upload=await masterSession.page.request.post(base+'/admin.php',{multipart:{action:'upload_media',csrf_token:await token(masterSession.page),file:{name:'scope-proof.png',mimeType:'image/png',buffer:image}}});
  assert.match(await upload.text(),/could not be saved/);assert.deepEqual(await readdir(mediaDir),[]);assert.equal(rows('SELECT COUNT(*) n FROM cms_media')[0].n,existingMedia);
  alter('DROP TRIGGER scope_upload_audit_failure');
  upload=await masterSession.page.request.post(base+'/admin.php',{multipart:{action:'upload_media',csrf_token:await token(masterSession.page),file:{name:'scope-proof.png',mimeType:'image/png',buffer:image}}});
  assert.match(await upload.text(),/Uploaded\./);assert.equal((await readdir(mediaDir)).length,1);assert.equal(rows('SELECT COUNT(*) n FROM cms_media')[0].n,existingMedia+1);
  ok('Media file, database row and audit commit together; an audit/database failure removes the moved file without leaving an orphan.');
  // Simulate revocation while PHP is blocked awaiting its provider response. No real gateway is contacted.
  const revoke=()=>php(`$m=cms_db()->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();st_set_assignments($m,${fixtureIds.users['scope-coordinator']},[],false);echo 'true';`);
  revokeDuringFetch=revoke;gatewayState='PENDING';
  assert.match(await post({action:'verify_payment',id:112}),/id="login-user"/);let pending=rows('SELECT * FROM az_orders WHERE id=112')[0];assert.equal(pending.state,'PENDING');assert.equal(pending.gateway_order,null);assert.equal(rows('SELECT COUNT(*) n FROM az_tickets WHERE order_id=112')[0].n,0);
  assert.match((await page.request.get(base+'/admin.php',{maxRedirects:0})).headers().location,/login\.php/);
  ok('A scope change revokes the session and blocks pending-status/reference writes after the provider fetch.');
  php(`$m=cms_db()->query("SELECT * FROM users WHERE role='SUPERADMIN'")->fetch();st_set_assignments($m,${fixtureIds.users['scope-coordinator']},[101],false);echo 'true';`);
  const resumed=await session('scope@example.com');revokeDuringFetch=revoke;gatewayState='COMPLETED';assert.match(await post({action:'verify_payment',id:112},resumed.page),/id="login-user"/);pending=rows('SELECT * FROM az_orders WHERE id=112')[0];assert.equal(pending.state,'PENDING');assert.equal(pending.gateway_order,null);assert.equal(rows('SELECT COUNT(*) n FROM az_tickets WHERE order_id=112')[0].n,0);
  ok('Revocation during completed payment lookup prevents both confirmation and ticket issuance.');
  // Gateway/participant reconciliation does not require a staff actor.
  const settled=await asyncPhp("echo json_encode(az_refresh_order(az_order(112)));");assert.equal(settled.state,'PAID');assert.equal(rows('SELECT COUNT(*) n FROM az_tickets WHERE order_id=112')[0].n,1);
  ok('Actor-free participant/webhook reconciliation still verifies the local mock payment and issues one pass.');
  assert.deepEqual(errors,[]);ok('Studio pages report no browser JavaScript errors.');
  console.log(`${passed} studio scope groups passed.`);
} finally {
  if(browser)await browser.close();
  if(server.exitCode===null&&server.signalCode===null){server.kill();await new Promise(resolve=>server.once('exit',resolve));}
  await new Promise(resolve=>gateway.close(resolve));
  await rm(temp,{recursive:true,force:true});
}
