import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const temp=await mkdtemp(join(tmpdir(),'anazori-coordinator57-'));
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),
 ANAZORI_PRIVATE_CONFIG:'/nonexistent',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),
 ANAZORI_PAYMENT_PROOF_DIR:join(temp,'proofs'),ANAZORI_TEST_MODE:'1'};
const base='http://127.0.0.1:8161',password='Workflow-QA-2026!';
const php=code=>execFileSync('php',['-r',`require 'includes/commerce.php';$db=cms_db();${code}`],{env,encoding:'utf8'});
const json=code=>JSON.parse(php('echo json_encode('+code+');'));
const token=html=>html.match(/name="csrf_token" value="([^"]+)"/)[1];
function client(){let cookie='';return async(path,data)=>{
 const multipart=data instanceof FormData;
 const response=await fetch(base+path,{redirect:'manual',headers:{Cookie:cookie,...(data&&!multipart?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:multipart?data:new URLSearchParams(data)}:{})});
 const cookies=response.headers.getSetCookie();if(cookies.length)cookie=cookies.map(value=>value.split(';')[0]).join('; ');return response;
};}
const master=client(),coordinator=client(),other=client(),participant=client(),anonymous=client();
const fixture=JSON.parse(php(`
 $db->prepare("UPDATE users SET password_hash=?,must_change_password=0 WHERE role='SUPERADMIN'")->execute([password_hash('${password}',PASSWORD_DEFAULT)]);
 $events=[];foreach(['treasure-hunt','goc'] as $slug){$e=az_event($slug);$f=$e['fields'];$f['registration_mode']='open';$f['registration_opens']='';$f['registration_closes']='';
 $f['ticket_types']=json_encode([['id'=>'entry','label'=>'Event entry','price'=>20000,'capacity'=>10,'active'=>true],['id'=>'free','label'=>'Free entry','price'=>0,'capacity'=>10,'active'=>true]]);
 $f['payment_methods']=az_validate_payment_methods([['id'=>'bank-entry','label'=>'Bank transfer','kind'=>'bank','recipient'=>'Isolated Event','bank'=>'QA Bank','account'=>'1234567890','ifsc'=>'ABCD0123456','active'=>1]]);
 $f['registration_form']=az_validate_registration_fields([['id'=>'college','label'=>'College','type'=>'text','required'=>1],['id'=>'phone','label'=>'Contact number','type'=>'tel','required'=>1],['id'=>'team-name','label'=>'Team name','type'=>'text','required'=>1],['id'=>'issued-id','label'=>'Issued team ID','type'=>'text','required'=>1,'allowed_values'=>'0017']]);
 $db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$e['id']]);$events[$slug]=$e['id'];}
 $db->prepare('INSERT INTO az_participants(email,name,password_hash,email_verified,profile_completed,created_at) VALUES(?,?,?,1,1,?)')->execute(['flow@example.invalid','Workflow Participant',password_hash('${password}',PASSWORD_DEFAULT),gmdate('c')]);
 echo json_encode($events);`));
const server=spawn('php',['-S','127.0.0.1:8161','-t','src','scripts/router.php'],{env,stdio:'ignore',windowsHide:true});
const loginStaff=async(request,username)=>{const html=await (await request('/login.php')).text();const response=await request('/login.php',{csrf_token:token(html),username,password});assert.equal(response.status,303);};
try{
 for(let n=0;n<60;n++){try{if((await fetch(base)).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 await loginStaff(master,'chenkhamchowlu@gmail.com');
 for(const [username,event] of [['flow-coordinator',fixture['treasure-hunt']],['other-coordinator',fixture.goc]]){
  const page=await (await master('/admin.php?section=users')).text();
  const response=await master('/admin.php',{csrf_token:token(page),action:'save_user',username,display_name:username,email:username+'@example.invalid',role:'COORDINATOR',password,active:'1',event_scope_present:'1','event_ids[0]':String(event)});
  assert.equal(response.status,303);
 }
 php("$db->exec(\"UPDATE users SET must_change_password=0 WHERE role='COORDINATOR'\");");
 await loginStaff(coordinator,'flow-coordinator');await loginStaff(other,'other-coordinator');
 const permissions=json("json_decode($db->query(\"SELECT permissions FROM users WHERE username='flow-coordinator'\")->fetchColumn(),true)");
 for(const key of ['payments.verify','tickets.view','tickets.revoke','tickets.scan','submissions.edit','operations.export'])assert(permissions.includes(key));
 const overview=await (await coordinator('/admin.php?event_id='+fixture['treasure-hunt'])).text();
 assert.doesNotMatch(overview,/Finance overview|Event budgets|Expenses &amp; approvals|studio-workspace-tabs|Open register|Central finance/);
 assert.match(overview,/Registrations &amp; payments/);
 const nav=overview.match(/<nav aria-label="Studio navigation">([\s\S]*?)<\/nav>/)[1];
 const links=[...nav.matchAll(/href="([^"]+)"/g)].map(match=>match[1]);assert.equal(links.length,new Set(links).size);
 assert.equal((await coordinator('/admin.php?section=payments&event_id='+fixture.goc)).status,403);
 for(const section of ['finance','budgets','expenses','reports'])assert.equal((await master('/admin.php?section='+section)).status,403);
 console.log('PASS Saved coordinator grants, event scope and a single Studio navigation; retired Finance routes are denied.');

 const record=json(`cms_record(${fixture['treasure-hunt']})`),schema=json("cms_content_schema()['event']['fields']");
 const edit=await (await coordinator('/admin.php?section=event&edit='+record.id)).text();
 assert.doesNotMatch(edit,/data-form-builder|data-question-add|name="form_fields|name="interest_fields|name="registration_intro"/);
 assert.match(edit,/Issued team ID/);assert.doesNotMatch(edit,/Add game|Game \(optional\)/);
 const save={csrf_token:token(edit),action:'save_content',type:'event',id:String(record.id),revision:String(record.revision),title:record.title,slug:record.slug,status:'PUBLISHED',sort_order:String(record.sort_order),event_setup_editor:'1',event_editor_complete:'1'};
 for(const [key,definition] of Object.entries(schema))if(definition[1]!=='checkbox'||record.fields[key]==='1')save[key]=record.fields[key]??definition[2]??'';
 for(const [i,row] of JSON.parse(record.fields.ticket_types).entries())for(const [key,value] of Object.entries(row))save[`ticket[${i}][${key}]`]=key==='price'?(value/100).toFixed(2):String(value);
 for(const [i,row] of JSON.parse(record.fields.payment_methods).entries())for(const [key,value] of Object.entries(row))save[`payment_methods[${i}][${key}]`]=String(value);
 Object.assign(save,{registration_title:'Forged heading',registration_questions:'Forged question','form_fields[0][label]':'Injected question','interest_fields[0][label]':'Injected interest'});
 const saved=await coordinator('/admin.php',save);assert.equal(saved.status,303);assert.match(await (await coordinator(saved.headers.get('location'))).text(),/Saved\./);
 const after=json(`cms_record(${record.id})`);
 for(const key of ['registration_form','interest_form','registration_questions','interest_title','registration_title','registration_intro','registration_button'])assert.equal(after.fields[key],record.fields[key]);
 const blocked=await coordinator('/admin.php',{...save,id:String(fixture.goc)});assert.equal(blocked.status,303);assert.equal((await coordinator(blocked.headers.get('location'))).status,403);
 console.log('PASS Event edits retain every fixed form, including forged question posts; other events cannot be edited.');

 const account=await (await participant('/account.php')).text();assert.equal((await participant('/account.php',{csrf_token:token(account),email:'flow@example.invalid',password})).status,303);
 const checkout=await (await participant('/checkout.php?event=treasure-hunt')).text();
 const registration={csrf_token:token(checkout),event:'treasure-hunt',nonce:checkout.match(/name="nonce" value="([^"]+)"/)[1],type:'entry',quantity:'1',payment_method:'bank-entry','answers[college]':'QA College','answers[phone]':'9876543210','answers[team-name]':'QA Team','answers[issued-id]':'0017',consent:'yes',response_format:'redirect'};
 const response=await participant('/api/checkout.php',registration);assert.equal(response.status,303);assert.match(response.headers.get('location'),/^\/payment-proof.php\?order=/);
 const proofPage=await (await participant(response.headers.get('location'))).text();assert.match(proofPage,/ABCD0123456/);assert.match(proofPage,/1234567890/);assert.match(proofPage,/Transaction reference \/ UTR/);
 let order=json("$db->query('SELECT * FROM az_orders ORDER BY id DESC LIMIT 1')->fetch()");assert.equal(order.state,'AWAITING_PROOF');assert.equal(Number(php("echo $db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn();")),0);
 const upload=new FormData();for(const [key,value] of Object.entries({csrf_token:token(proofPage),order:order.public_id,revision:proofPage.match(/name="revision" value="([^"]+)"/)[1],reference:'WORKFLOW-REF-2026',paid_on:new Date().toISOString().slice(0,10)}))upload.set(key,value);
 upload.set('proof',new Blob([await readFile('src/assets/logo.png')],{type:'image/png'}),'payment.png');
 assert.equal((await participant('/api/payment-proof.php',upload)).status,303);
 order=json(`az_order(${order.id})`);assert.equal(order.state,'PENDING_REVIEW');assert.equal(Number(php("echo $db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn();")),0);
 const proof=json("$db->query('SELECT * FROM az_payment_proofs ORDER BY id DESC LIMIT 1')->fetch()");
 assert.equal((await anonymous('/payment-proof-file.php?id='+proof.id)).status,404);assert.equal((await other('/payment-proof-file.php?id='+proof.id)).status,404);assert.equal((await coordinator('/payment-proof-file.php?id='+proof.id)).status,200);
 const payment=json(`az_manual_payment(${order.id})`);
 const reviewPage=await (await coordinator('/admin.php?section=payments&event_id='+record.id)).text();assert.match(reviewPage,/Team name/);assert.match(reviewPage,/0017/);assert.match(reviewPage,/Confirm payment &amp; release ticket/);
 const approve={csrf_token:token(reviewPage),action:'review_manual_payment',id:String(order.id),revision:String(payment.revision),decision:'approve',received_amount:'200.00',bank_confirmed:'yes',note:'Verified receiving account credit'};
 const otherPage=await (await other('/admin.php?section=payments')).text();const attempt=await other('/admin.php',{...approve,csrf_token:token(otherPage)});assert.equal(attempt.status,303);assert.equal(json(`az_order(${order.id})`).state,'PENDING_REVIEW');
 assert.equal((await coordinator('/admin.php',approve)).status,303);
 order=json(`az_order(${order.id})`);assert.equal(order.state,'PAID');
 const ticket=json("$db->query('SELECT * FROM az_tickets ORDER BY id DESC LIMIT 1')->fetch()");
 assert.equal(Number(php("echo $db->query('SELECT COUNT(*) FROM az_tickets')->fetchColumn();")),1);
 assert.equal((await anonymous('/ticket.php?id='+ticket.ticket_id)).status,404);assert.equal((await other('/ticket.php?id='+ticket.ticket_id)).status,404);
 const ticketResponse=await participant('/ticket.php?id='+ticket.ticket_id);assert.equal(ticketResponse.status,200);const ticketHtml=await ticketResponse.text();assert.match(ticketHtml,/simple-event-ticket/);assert.match(ticketHtml,/Workflow Participant/);assert.doesNotMatch(ticketHtml,/ticket-perforation|Download QR/);
 const pdf=await participant('/ticket.php?id='+ticket.ticket_id+'&download=pdf');assert.equal(pdf.status,200);assert.match(pdf.headers.get('content-type'),/application\/pdf/);const pdfBytes=Buffer.from(await pdf.arrayBuffer());assert.equal(pdfBytes.subarray(0,4).toString(),'%PDF');
 await mkdir('artifacts/revision57',{recursive:true});await writeFile('artifacts/revision57/qa-entry.pdf',pdfBytes);
 console.log('PASS Registration → bank details → private screenshot → scoped payment approval → one simple PDF entry ticket.');
 console.log('PASS Payment proofs and entry tickets stay private to the participant and the assigned event coordinator.');
}finally{
 if(server.exitCode===null){const done=new Promise(resolve=>server.once('exit',resolve));server.kill();await done;}
 await rm(temp,{recursive:true,force:true});
}
