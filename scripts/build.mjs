import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import {mkdirSync,readdirSync,statSync,unlinkSync,writeFileSync,readFileSync} from 'node:fs';
import {resolve,sep} from 'node:path';
import {createHash} from 'node:crypto';
mkdirSync('src/assets/2026', { recursive: true });
await build({entryPoints:['frontend/loader81.css'],outfile:'src/assets/2026/loader81.css',minify:true});
await build({entryPoints:['frontend/loader81.js'],outfile:'src/assets/2026/loader81.js',minify:true,target:['es2020']});
const workerBuild=await build({entryPoints:['frontend/keepsake-worker84.js'],bundle:true,format:'esm',minify:true,target:['es2020'],write:false});
const workerName='keepsake-worker-'+createHash('sha256').update(workerBuild.outputFiles[0].contents).digest('hex').slice(0,8).toUpperCase()+'.js';
mkdirSync('src/assets/2026/chunks',{recursive:true});writeFileSync('src/assets/2026/chunks/'+workerName,workerBuild.outputFiles[0].contents);
const jsBuild=await build({metafile:true,entryPoints:['frontend/site.js','frontend/checkout.js','frontend/form-setup.js'],outdir:'src/assets/2026',bundle:true,splitting:true,format:'esm',minify:true,target:['es2020'],legalComments:'eof',chunkNames:'chunks/[name]-[hash]',define:{__KEEPSAKE_WORKER_URL84__:JSON.stringify('/assets/2026/chunks/'+workerName)}});
jsBuild.metafile.outputs['src/assets/2026/chunks/'+workerName]={};
mkdirSync('output/performance84',{recursive:true});writeFileSync('output/performance84/build.json',JSON.stringify({worker:'/assets/2026/chunks/'+workerName},null,2));
await build({entryPoints:['frontend/public.css'],outfile:'src/assets/2026/public.css',bundle:true,external:['/assets/*'],minify:true,target:['es2020']});
await build({entryPoints:['frontend/studio-console.css'],outfile:'src/assets/2026/console.css',bundle:true,external:['/assets/*'],minify:true,target:['es2020']});
await build({entryPoints:['frontend/console.js'],outfile:'src/assets/2026/console.js',minify:true,target:['es2020']});
await build({entryPoints:['frontend/studio.js'],outfile:'src/assets/2026/studio.js',bundle:true,minify:true,target:['es2020']});
execFileSync(process.execPath,['node_modules/tailwindcss/lib/cli.js','--content','./src/admin.php,./src/login.php','-o','src/assets/2026/admin.css','--minify'],{stdio:'inherit'});
console.log('Built Anazori 2026. Public site, participant portal and organiser studio built.');

// Open tabs can still request lazy chunks from the preceding build. Retain those
// briefly instead of breaking their animations when a new build is generated.
const chunkRoot=resolve('src/assets/2026/chunks'),outputs=new Set(Object.keys(jsBuild.metafile.outputs).map(path=>resolve(path))),removed=[];
const historyPath=resolve('output/performance83/build-history.json'),builtAt=Date.now(),retention=86400000;
let previous={};try{previous=JSON.parse(readFileSync(historyPath,'utf8'));}catch{}
const history={};
for(const name of readdirSync(chunkRoot)){
 const path=resolve(chunkRoot,name);
 if(!path.startsWith(chunkRoot+sep)||!/^[-\w]+-[A-Z0-9]{8}\.js$/.test(name)||!statSync(path).isFile())continue;
 const lastUsed=outputs.has(path)?builtAt:Number(previous[name]||builtAt);
 if(outputs.has(path)||builtAt-lastUsed<retention){history[name]=lastUsed;continue;}
 removed.push({path:'src/assets/2026/chunks/'+name,bytes:statSync(path).size});unlinkSync(path);
}
mkdirSync('output/performance83',{recursive:true});writeFileSync(historyPath,JSON.stringify(history,null,2));
mkdirSync('output/maintenance81',{recursive:true});writeFileSync('output/maintenance81/obsolete-chunks.json',JSON.stringify(removed,null,2));if(removed.length)console.log('Removed '+removed.length+' obsolete generated chunks.');
