const MP4_TYPES=['video/mp4;codecs=avc1.42E028','video/mp4;codecs=avc1','video/mp4'];
const MP4_BRANDS=new Set(['isom','iso2','iso4','iso5','iso6','iso8','iso9','mp41','mp42','avc1','M4V ']);
export function supportedMp4Type(Recorder){
 return typeof Recorder?.isTypeSupported==='function'?MP4_TYPES.find(type=>Recorder.isTypeSupported(type))||null:null;
}
export async function mp4DownloadFile(blob,options){
 if(!blob.size)throw new Error('The video was empty. Please try again.');
 if(!/^video\/mp4(?:;|$)/i.test(blob.type))throw new Error('Your browser did not create an MP4 video. Please try another browser.');
 const bytes=new Uint8Array(await blob.slice(0,256).arrayBuffer());
 const tag=offset=>String.fromCharCode(...bytes.subarray(offset,offset+4));
 const size=bytes.length>=16?new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(0):0;
 const brands=size>=16&&size<=bytes.length?[tag(8),...Array.from({length:Math.floor((size-16)/4)},(_,i)=>tag(16+i*4))]:[];
 if(tag(4)!=='ftyp'||!brands.some(brand=>MP4_BRANDS.has(brand)))throw new Error('The MP4 video could not be verified. Please try another browser.');
 const {finalizeKeepsakeMp4104}=await import('./keepsake-finalize104.js');
 return finalizeKeepsakeMp4104(blob,options);
}
