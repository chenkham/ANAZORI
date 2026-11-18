import {spawn,execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
const bin=resolve('.local/mariadb/mariadb-11.4.10-winx64/bin'),id=String(process.pid);
const env={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('ANAZORI_'))),ANAZORI_DB_DRIVER:'mysql',ANAZORI_DB_HOST:'127.0.0.1',ANAZORI_DB_PORT:'3317',ANAZORI_DB_NAME:'anazori_qa_'+id,ANAZORI_DB_USER:'root',ANAZORI_DB_PASS:'Local-Only-2026!',ANAZORI_TEST_MODE:'1',ANAZORI_SQL_QA:'1',ANAZORI_QA_ID:id,ANAZORI_SECRET_PATH:resolve('.local/mariadb-qa-key')};
const server=spawn(resolve(bin,'mariadbd.exe'),['--defaults-file='+resolve('.local/mariadb-qa-data2/my.ini'),'--datadir='+resolve('.local/mariadb-qa-data2'),'--bind-address=127.0.0.1','--port=3317','--console'],{windowsHide:true,stdio:['ignore','ignore','pipe']});
let log='';server.stderr.on('data',data=>log+=data.toString());
try{
 let ready=false;for(let attempt=0;attempt<80;attempt++){try{execFileSync(resolve(bin,'mariadb-admin.exe'),['--host=127.0.0.1','--port=3317','--user=root','--password=Local-Only-2026!','ping'],{stdio:'ignore',windowsHide:true});ready=true;break;}catch{}await new Promise(r=>setTimeout(r,200));}
 if(!ready)throw new Error('Database QA server failed: '+log.slice(-1500));
 let index=0;
 for(const test of (process.argv.includes('--import-only')?[null]:['tests/game-google.php','tests/manual-payments.php','tests/studio-access.php','tests/studio-finance.php'])){
  const runEnv={...env,ANAZORI_QA_ID:id+String(index++),ANAZORI_DB_NAME:'anazori_qa_'+id+String(index-1)};
  console.log(execFileSync('php',['tests/mariadb-import.php'],{env:runEnv,encoding:'utf8',windowsHide:true}).trim());
  if(test){const output=execFileSync('php',[test],{env:runEnv,encoding:'utf8',windowsHide:true});console.log(output.trim());}
 }
 console.log('PASS Clean SQL installation'+(process.argv.includes('--import-only')?'':' and application migrations')+' on MariaDB 11.4.10.');
}finally{
 try{execFileSync(resolve(bin,'mariadb-admin.exe'),['--host=127.0.0.1','--port=3317','--user=root','--password=Local-Only-2026!','shutdown'],{windowsHide:true,stdio:'ignore'});}catch{server.kill();}
 if(server.exitCode===null)await new Promise(r=>server.once('exit',r));
}
