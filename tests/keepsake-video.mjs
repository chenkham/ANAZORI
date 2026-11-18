import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {supportedMp4Type,mp4DownloadFile} from '../frontend/keepsake-video.js';
import {inspectFinalMp4104} from '../frontend/keepsake-finalize104.js';
import {Input,MP4,BlobSource,EncodedPacketSink} from 'mediabunny';
import {createHash} from 'node:crypto';

assert.equal(supportedMp4Type(undefined),null);
assert.equal(supportedMp4Type({isTypeSupported:type=>type.startsWith('video/webm')}),null);
assert.equal(supportedMp4Type({isTypeSupported:type=>type==='video/mp4'}),'video/mp4');
assert.equal(supportedMp4Type({isTypeSupported:type=>type==='video/mp4;codecs=avc1'}),'video/mp4;codecs=avc1');
assert.match(supportedMp4Type({isTypeSupported:()=>true}),/^video\/mp4;codecs=avc1\./);
console.log('PASS MP4-only capability detection with H.264 and generic MP4 fallbacks.');

const ftyp=brand=>new Blob([new Uint8Array([0,0,0,24]),'ftyp',brand,new Uint8Array(4),brand,brand],{type:'video/mp4'});
await assert.rejects(mp4DownloadFile(new Blob([],{type:'video/mp4'})),/empty/);
await assert.rejects(mp4DownloadFile(new Blob(['webm'],{type:'video/webm'})),/did not create an MP4/);
await assert.rejects(mp4DownloadFile(new Blob([new Uint8Array([0x1a,0x45,0xdf,0xa3]),'webm'],{type:'video/mp4'})),/could not be verified/);
await assert.rejects(mp4DownloadFile(ftyp('qt  ')),/could not be verified/);
await assert.rejects(mp4DownloadFile(ftyp('isom')));
console.log('PASS Empty, fake, header-only and renamed non-MP4 files cannot be downloaded.');

async function packets(blob){
 const input=new Input({source:new BlobSource(blob),formats:[MP4]});
 try{
  const track=await input.getPrimaryVideoTrack(),hash=createHash('sha256');let count=0,end=0,start=Infinity;
  for await(const packet of new EncodedPacketSink(track).packets()){hash.update(packet.data);count++;end=Math.max(end,packet.timestamp+packet.duration);start=Math.min(start,packet.timestamp);}
  return {sha256:hash.digest('hex'),count,duration:end-start,width:await track.getDisplayWidth(),height:await track.getDisplayHeight()};
 }finally{input.dispose();}
}
const bytes=await readFile(process.argv[2]||new URL('./fixtures/keepsake-fragmented104.mp4',import.meta.url)),original=new Blob([bytes],{type:'video/mp4'});
assert.throws(()=>inspectFinalMp4104(bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)),/finalized/);
const before=await packets(original),file=await mp4DownloadFile(original,{expectedDuration:before.duration}),after=await packets(file),metadata=inspectFinalMp4104(await file.arrayBuffer());
assert.equal(file.name,'anazori-keepsake.mp4');assert.equal(file.type,'video/mp4');
assert.deepEqual(after,before);assert.equal(metadata.tracks[0].samples,before.count);
assert(metadata.fastStart);assert(!metadata.fragmented);assert(Math.abs(metadata.duration-before.duration)<.05);
console.log('PASS Fragmented H.264 recording becomes a finalized fast-start MP4 with a correct duration, unchanged frames and resolution.');
const twice=await mp4DownloadFile(file,{expectedDuration:before.duration});assert.deepEqual(await packets(twice),before);
await assert.rejects(mp4DownloadFile(original,{expectedDuration:before.duration+5}),/incomplete/);
await assert.rejects(mp4DownloadFile(original.slice(0,Math.floor(original.size*.6),'video/mp4')));
console.log('PASS Repeated finalization is safe; truncated and incomplete recordings are rejected.');
