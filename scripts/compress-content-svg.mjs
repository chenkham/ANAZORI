// Precompress native SVG artwork once, rather than during preview requests.
import {readFile,writeFile,readdir} from 'node:fs/promises';
import {gzipSync} from 'node:zlib';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

export async function compressContentSvg() {
 const directory='src/assets/2026/vector';
 for(const name of await readdir(directory)) {
  if(!name.endsWith('.svg'))continue;
  const svg=await readFile(directory+'/'+name);
  await writeFile(directory+'/'+name+'.gz',gzipSync(svg,{level:9}));
 }
 const manifest=JSON.parse(await readFile(directory+'/sources.json','utf8'));
 for(const item of manifest) {
  const motion=directory+'/'+item.id+'-motion.svg',still=directory+'/'+item.id+'-still.svg';
  item.bytes=(await readFile(motion)).length;
  item.gzip_bytes=(await readFile(motion+'.gz')).length;
  item.still_bytes=(await readFile(still)).length;
  item.still_gzip_bytes=(await readFile(still+'.gz')).length;
 }
 await writeFile(directory+'/sources.json',JSON.stringify(manifest,null,2)+'\n');
 return manifest;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 const manifest=await compressContentSvg();
 console.log('Precompressed SVGs; '+manifest.length+' supplied vector sources recorded.');
}
