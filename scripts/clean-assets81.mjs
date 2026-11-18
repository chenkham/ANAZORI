import {readFile,stat,unlink,writeFile} from 'node:fs/promises';
import {resolve,sep} from 'node:path';
import {execFileSync} from 'node:child_process';
const root=resolve('.'),candidates=['site.css','flagship.css','festival.css','portal.css','retro.css','designer.css','cards.css','enhancements.css','animations.js','three-bg.js','vendor/three.min.js','vendor/gsap.min.js'].map(name=>'assets/2026/'+name);
const cms=JSON.parse(await readFile('output/maintenance81/cms-asset-references.json','utf8'));
const files=execFileSync('rg',['--files','-g','*.php','-g','*.css','-g','*.js','-g','*.html','-g','!node_modules/**','-g','!vendor/**','-g','!.local/**','-g','!output/**','-g','!scripts/**','-g','!tests/**'],{encoding:'utf8'}).trim().split(/\r?\n/);
const documents=await Promise.all(files.filter(file=>!candidates.includes(file.replaceAll('\\','/'))).map(async file=>({file,text:await readFile(file,'utf8')})));
const removed=[],kept=[];
for(const file of candidates){const path=resolve(file);if(!path.startsWith(resolve('assets/2026')+sep))throw Error('Cleanup target escaped the asset directory.');let info;try{info=await stat(path);}catch{continue;}if(!info.isFile())continue;
 const url='/'+file,reference=documents.find(doc=>doc.text.includes(url)||doc.text.includes(file));
 if(reference||cms.some(value=>value.split('?')[0]===url)){kept.push({path:file,reason:reference?.file||'CMS or historical registration'});continue;}
 removed.push({path:file,bytes:info.size});await unlink(path);
}
await writeFile('output/maintenance81/asset-cleanup.json',JSON.stringify({removed,kept,bytes:removed.reduce((sum,file)=>sum+file.bytes,0)},null,2));console.log(JSON.stringify({removed:removed.length,bytes:removed.reduce((sum,file)=>sum+file.bytes,0),kept}));
