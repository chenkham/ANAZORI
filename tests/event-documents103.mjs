import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readdir,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname,join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
const root=dirname(dirname(fileURLToPath(import.meta.url))),temp=await mkdtemp(join(tmpdir(),'anazori-pdfs103-')),base='http://127.0.0.1:8203',password='Named-PDF-Regression-103!';
const publicPdf='/uploads/media/pdf-view103-'+process.pid+'.pdf';
for(const name of ['media','sessions','outbox'])await mkdir(join(temp,name));
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_APP_ENV:'development',ANAZORI_PRIVATE_CONFIG:join(temp,'absent.php'),ANAZORI_DB_DRIVER:'sqlite',ANAZORI_DB_PATH:join(temp,'qa.sqlite'),ANAZORI_SECRET_PATH:join(temp,'key'),ANAZORI_MEDIA_DIR:join(temp,'media'),ANAZORI_TEST_MODE:'1',ANAZORI_TEST_OUTBOX:join(temp,'outbox'),ANAZORI_MAIL_NOTIFICATIONS:'0',ANAZORI_SITE_URL:base,ANAZORI_REGISTRATION_FILE_DIR:join(temp,'files')};
const php=code=>execFileSync('php',['-d','session.save_path='+join(temp,'sessions'),'-r',"require 'includes/commerce.php';$db=cms_db();"+code],{cwd:join(root,'src'),env,encoding:'utf8',windowsHide:true});
const json=code=>JSON.parse(php('echo json_encode('+code+',JSON_THROW_ON_ERROR);'));
const token=html=>{const found=html.match(/name="csrf_token" value="([^"]+)"/);assert(found,'CSRF');return found[1];};
function client(){const cookies=new Map();return async(path,data)=>{
 const multipart=data instanceof FormData,response=await fetch(base+path,{redirect:'manual',headers:{Cookie:[...cookies].map(([key,value])=>key+'='+value).join('; '),...(data&&!multipart?{'Content-Type':'application/x-www-form-urlencoded'}:{})},...(data?{method:'POST',body:multipart?data:new URLSearchParams(data)}:{})});
 for(const set of response.headers.getSetCookie()){const first=set.split(';')[0],split=first.indexOf('=');if(first.slice(split+1))cookies.set(first.slice(0,split),first.slice(split+1));else cookies.delete(first.slice(0,split));}
 return response;
};}
function pdfBytes(){
 const stream='BT /F1 12 Tf 50 750 Td (Event rules and topics fixture) Tj ET';
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>','<< /Length '+stream.length+' >>\nstream\n'+stream+'\nendstream'];
 let output='%PDF-1.4\n',offsets=[0];objects.forEach((value,index)=>{offsets.push(Buffer.byteLength(output));output+=(index+1)+' 0 obj\n'+value+'\nendobj\n';});
 const xref=Buffer.byteLength(output);output+='xref\n0 6\n0000000000 65535 f \n'+offsets.slice(1).map(offset=>String(offset).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+xref+'\n%%EOF\n';return Buffer.from(output);
}
const coordinator=client(),admin=client(),visitor=client(),logs=[];let server,checks=0;
const ok=label=>{checks++;console.log('PASS '+label);};
try{
 const fixture=json("(function()use($db){$event=az_event('tulika');$f=$event['fields'];unset($f['event_documents']);$f['rules_pdf']='/assets/2026/ANAZORI_V16_Brochure_Neon.pdf';$db->prepare('UPDATE cms_content SET data=? WHERE id=?')->execute([json_encode($f),$event['id']]);$db->prepare('INSERT INTO users(username,display_name,email,role,active,permissions,password_hash,must_change_password) VALUES(?,?,?,?,1,?,?,0)')->execute(['pdfs103','PDF coordinator','pdfs103@example.invalid','COORDINATOR',json_encode(st_coordinator_permissions()),password_hash('"+password+"',PASSWORD_DEFAULT)]);$id=(int)$db->lastInsertId();$db->prepare('INSERT INTO st_event_assignments(user_id,event_id,assigned_by,assigned_at) VALUES(?,?,1,?)')->execute([$id,$event['id'],gmdate('c')]);$db->prepare('INSERT INTO users(username,display_name,email,role,active,permissions,password_hash,must_change_password) VALUES(?,?,?,?,1,?,?,0)')->execute(['media103','Media admin','media103@example.invalid','ADMIN',json_encode(['media.view','media.edit','media.delete']),password_hash('"+password+"',PASSWORD_DEFAULT)]);return ['event'=>$event['id'],'other'=>az_event('joystick')['id']];})()");
 server=spawn('php',['-d','max_input_vars=3000','-d','session.save_path='+join(temp,'sessions'),'-S',new URL(base).host,'-t','src','scripts/router.php'],{cwd:root,env,windowsHide:true,stdio:['ignore','ignore','pipe']});server.stderr.on('data',data=>logs.push(data.toString()));
 let ready=false;for(let n=0;n<60;n++){try{if((await fetch(base+'/account.php')).ok){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,100));}assert(ready);
 await writeFile(join(root,'src',publicPdf),pdfBytes());
 const opened=await visitor(publicPdf+'?view=inline');assert.equal(opened.status,200);assert.equal(opened.headers.get('content-type'),'application/pdf');assert.equal(opened.headers.get('content-disposition'),'inline');assert.doesNotMatch(opened.headers.get('content-security-policy'),/\bsandbox\b/);assert.equal(opened.headers.get('x-content-type-options'),'nosniff');assert.deepEqual(Buffer.from(await opened.arrayBuffer()),pdfBytes());
 for(const path of ['src/uploads/.htaccess','src/uploads/media/.htaccess']){const config=await readFile(join(root,path),'utf8');assert.match(config,/AddType application\/pdf \.pdf/);assert.match(config,/Header always set Content-Disposition "inline"/);assert.doesNotMatch(config,/Header always set Content-Security-Policy "[^"]*\bsandbox\b/);assert.match(config,/Options -Indexes -ExecCGI -MultiViews/);}
 ok('Public PDFs use application/pdf and inline disposition in preview and both hosting upload folders, retaining non-executable upload protection.');
 let html=await(await visitor('/event.php?name=tulika')).text();assert.match(html,/ANAZORI_V16_Brochure_Neon\.pdf/);assert.match(html,/Rules PDF/);
 ok('An event with an existing single rules PDF continues to display it before any coordinator edit.');
 html=await(await coordinator('/login.php')).text();let response=await coordinator('/login.php',{csrf_token:token(html),username:'pdfs103',password});assert.equal(response.status,303);
 html=await(await coordinator('/admin.php?section=event&event_id='+fixture.event+'&edit='+fixture.event)).text();const csrf=token(html);
 assert.match(html,/<legend>Event PDFs<\/legend>/);assert.match(html,/name="event_documents\[0\]\[label\]" value="Rules PDF"/);assert.match(html,/data-setup-add="event-document"/);assert.match(html,/id="event-document-template"/);assert.match(html,/data-direct-media data-module="event" data-kind="pdf"/);
 ok('Studio displays named PDF rows, an Add PDF template, upload controls and reorder/remove controls.');
 async function upload(bytes,name='rules.pdf',id=fixture.event,csrfValue=csrf){const data=new FormData();for(const [key,value] of Object.entries({csrf_token:csrfValue,module:'event',kind:'pdf',id:String(id)}))data.set(key,value);data.set('file',new Blob([bytes],{type:'application/pdf'}),name);const response=await coordinator('/api/studio-media.php',data);return [response,await response.json()];}
 let [uploaded,result]=await upload(pdfBytes());assert.equal(uploaded.status,200,JSON.stringify(result));const first=result.media.path;
 [uploaded,result]=await upload(pdfBytes(),'topics.pdf');assert.equal(uploaded.status,200,JSON.stringify(result));const second=result.media.path;assert.notEqual(first,second);
 assert.deepEqual(await readFile(join(temp,'media',first.split('/').at(-1))),pdfBytes());assert.equal(json("$db->query(\"SELECT mime FROM cms_media WHERE path='"+second+"'\")->fetchColumn()"),'application/pdf');
 ok('Coordinators can upload separate valid PDFs; files are stored and registered with the PDF MIME type.');
 const record=()=>json('cms_record('+fixture.event+')');
 function payload(saved,documents,legacy=false){
  const data={csrf_token:csrf,action:'save_content',type:'event',id:String(saved.id),revision:String(saved.revision),title:saved.title,slug:saved.slug,status:'PUBLISHED',sort_order:String(saved.sort_order),event_setup_editor:'1',event_editor_complete:'1',ticket_categories81:'1',response_format:'json',studio_event_id:String(saved.id),studio_environment:'live'};
  const schema=json("array_diff_key(cms_content_schema()['event']['fields'],array_flip(st_fixed_form_keys()))");
  for(const [key,definition] of Object.entries(schema)){if(key==='event_documents')continue;if(definition[1]==='checkbox'){if(saved.fields[key]==='1')data[key]='1';}else data[key]=saved.fields[key]??'';}
  if(!legacy){data.event_documents_editor103='1';documents.forEach((document,index)=>{data['event_documents['+index+'][label]']=document.label;data['event_documents['+index+'][path]']=document.path;});}
  return data;
 }
 async function save(documents){const response=await coordinator('/admin.php',payload(record(),documents));const result=await response.json();assert.equal(response.status,200,JSON.stringify(result));return record();}
 const documents=[{label:'Topics – Round 1',path:second},{label:'Rules & Eligibility',path:first}];
 let saved=await save(documents);assert.deepEqual(JSON.parse(saved.fields.event_documents),documents);assert.equal(saved.fields.rules_pdf,second);
 html=await(await visitor('/event.php?name=tulika')).text();assert(html.indexOf('Topics – Round 1')<html.indexOf('Rules &amp; Eligibility'));assert.match(html,/target="_blank" rel="noopener noreferrer"/);assert(html.includes('href="'+first+'?view=inline"'));assert(html.includes('href="'+second+'?view=inline"'));assert.match(html,/Open PDF ↗/);assert.match(html,/href="#event-documents"/);assert.doesNotMatch(html,/<a[^>]+\bdownload(?:\s|=|>)/);
 ok('Custom labels, chosen order and both PDF links save and display publicly; legacy consumers retain the first PDF.');
 const old=payload(saved,[],true);response=await coordinator('/admin.php',old);assert.equal(response.status,200);assert.deepEqual(JSON.parse(record().fields.event_documents),documents);
 ok('An older cached event editor preserves the new PDF list instead of silently erasing it.');
 const revision=record().revision;
 const invalid=[
  [{label:'',path:first}],[{label:'Rules',path:''}],[{label:'Image',path:'/assets/logo.png'}],
  [{label:'External',path:'https://evil.example/rules.pdf'}],[{label:'Script',path:'javascript:alert(1)'}],
  [{label:'Traversal',path:'/assets/../config/secret.pdf'}],[{label:'Unregistered',path:'/uploads/media/'+'a'.repeat(36)+'.pdf'}],
  [{label:'Control\nlabel',path:first}],[{label:'Long path',path:'/uploads/media/'+'a'.repeat(600)+'.pdf'}],[{label:'x'.repeat(101),path:first}],Array.from({length:21},()=>({label:'Rules',path:first}))
 ];
 for(const rows of invalid){response=await coordinator('/admin.php',payload(record(),rows));assert.equal(response.status,400,JSON.stringify(rows));assert.equal(record().revision,revision);}
 const malformed=payload(record(),[]);malformed.event_documents='{';response=await coordinator('/admin.php',malformed);assert.equal(response.status,400);assert.equal(record().revision,revision);
 ok('Empty/oversized labels, non-PDF files, unsafe or unregistered paths, malformed lists and more than 20 rows are rejected without changing the event.');
 const badCsrf=payload(record(),documents);badCsrf.csrf_token='invalid';assert.equal((await coordinator('/admin.php',badCsrf)).status,400);
 const stale=payload(record(),documents);stale.revision=String(revision-1);assert.equal((await coordinator('/admin.php',stale)).status,400);
 const unauthorized=payload(json('cms_record('+fixture.other+')'),documents);assert.equal((await coordinator('/admin.php',unauthorized)).status,400);
 const before=(await readdir(join(temp,'media'))).length;
 [uploaded]=await upload(pdfBytes(),'not-assigned.pdf',fixture.other);assert.equal(uploaded.status,400);
 [uploaded]=await upload(pdfBytes(),'bad-csrf.pdf',fixture.event,'invalid');assert.equal(uploaded.status,400);
 [uploaded]=await upload(await readFile(join(root,'src/assets/logo.png')),'image.pdf');assert.equal(uploaded.status,400);
 [uploaded]=await upload(Buffer.from(pdfBytes().toString().replace('Event rules','/JavaScript Event rules')),'script.pdf');assert.equal(uploaded.status,400);
 assert.equal((await readdir(join(temp,'media'))).length,before);
 ok('Event assignment, CSRF, stale revisions, real MIME checks and scripted-PDF restrictions remain enforced for saves and uploads.');
 const malicious='<img src=x onerror=alert(1)>';await save([{label:malicious,path:first},{label:'Second PDF',path:second}]);
 html=await(await visitor('/event.php?name=tulika')).text();assert(!html.includes(malicious));assert.match(html,/&lt;img src=x onerror=alert\(1\)&gt;/);
 ok('Coordinator labels are escaped in public links and accessibility text.');
 html=await(await admin('/login.php')).text();response=await admin('/login.php',{csrf_token:token(html),username:'media103',password});assert.equal(response.status,303);
 html=await(await admin('/admin.php?section=media')).text();const adminCsrf=token(html),mediaId=json("$db->query(\"SELECT id FROM cms_media WHERE path='"+second+"'\")->fetchColumn()");
 response=await admin('/admin.php',{csrf_token:adminCsrf,action:'remove_media',id:String(mediaId)});assert.equal(response.status,303);html=await(await admin('/admin.php?section=media')).text();assert.match(html,/still used/);assert.equal(Number(json("$db->query('SELECT COUNT(*) FROM cms_media WHERE id="+mediaId+"')->fetchColumn()")),1);
 ok('A PDF referenced only by the new list cannot be removed from the shared library while in use.');
 await save([]);assert.equal(record().fields.event_documents,'[]');assert.equal(record().fields.rules_pdf,'');html=await(await visitor('/event.php?name=tulika')).text();assert.doesNotMatch(html,/class="event-documents103"/);
 response=await admin('/admin.php',{csrf_token:adminCsrf,action:'remove_media',id:String(mediaId)});assert.equal(response.status,303);assert.equal(Number(json("$db->query('SELECT COUNT(*) FROM cms_media WHERE id="+mediaId+"')->fetchColumn()")),0);
 ok('Removing every row hides all document links and releases old media references without restoring the default brochure.');
 assert.deepEqual(json("az_event_documents103(['event_documents'=>'','rules_pdf'=>''])"),[{label:'Festival brochure',path:'/assets/2026/ANAZORI_V16_Brochure_Neon.pdf'}]);
 assert.deepEqual(json("az_event_documents103(['event_documents'=>'[{\"label\":\"Bad\",\"path\":\"javascript:alert(1)\"}]'])"),[]);
 ok('Untouched events keep the shared brochure fallback; unsafe stored document paths are never rendered.');
 let changeHandler,selected='',uploadedPath='/uploads/media/'+'b'.repeat(36)+'.pdf',fail=false;
 const document={querySelectorAll:()=>[],addEventListener:(kind,handler)=>{if(kind==='change')changeHandler=handler;}};
 const context={document,FormData,Event,Option:function(title,value){this.title=title;this.value=value;},fetch:async(url,options)=>{assert.equal(url,'/api/studio-media.php');assert.equal(options.body.get('module'),'event');assert.equal(options.body.get('id'),String(fixture.event));return {ok:!fail,json:async()=>fail?{ok:false,error:'Upload rejected'}:{ok:true,media:{title:'New PDF',path:uploadedPath}}};}};
 runInNewContext(await readFile(join(root,'frontend/studio-editor79.js'),'utf8'),context);
 const status={textContent:''},select={append:option=>{selected=option.value;},dispatchEvent:()=>{}},form={elements:{csrf_token:{value:csrf},id:{value:String(fixture.event)}}},field={closest:()=>form,querySelector:selector=>selector==='select'?select:status};
 const input={files:[new Blob([pdfBytes()])],disabled:false,value:'chosen',dataset:{module:'event',kind:'pdf'},matches:selector=>selector==='[data-direct-media]',closest:()=>field};
 await changeHandler({target:input});assert.equal(selected,uploadedPath);assert.equal(input.disabled,false);assert.equal(input.value,'');assert.match(status.textContent,/Uploaded and selected/);
 fail=true;input.value='retry';await changeHandler({target:input});assert.equal(status.textContent,'Upload rejected');assert.equal(input.disabled,false);
 ok('Choosing a file in a newly added row uploads and selects it; failures leave the control usable for retry.');
 assert.doesNotMatch(logs.join(''),/PHP (?:Warning|Fatal|Parse|Deprecated)/,logs.join(''));
 console.log(checks+' named-PDF editor, upload, publication, compatibility and security check groups passed. All data was isolated.');
}finally{
 if(server&&server.exitCode===null){const ended=new Promise(done=>server.once('exit',done));server.kill();await ended;}
 await rm(join(root,'src',publicPdf),{force:true});
 const target=resolve(temp);assert(target.startsWith(resolve(tmpdir())+sep));await rm(target,{recursive:true,force:true});
}
