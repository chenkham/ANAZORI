/*! Uses Mediabunny 1.61.4 (MPL-2.0). License: /assets/2026/licenses/mediabunny-MPL-2.0.txt
 * Unmodified library source: https://registry.npmjs.org/mediabunny/-/mediabunny-1.61.4.tgz */
import {Input,MP4,BlobSource,EncodedPacketSink,EncodedVideoPacketSource,Output,Mp4OutputFormat,BufferTarget} from 'mediabunny';

/** Inspect the finalized movie index, independently of the demuxer's duration estimate. */
export function inspectFinalMp4104(buffer) {
 const view=new DataView(buffer),bytes=new Uint8Array(buffer),tracks=[],top=[];
 const name=offset=>String.fromCharCode(...bytes.subarray(offset,offset+4));
 function boxes(start,end) {
  const result=[];let at=start;
  while(at<end){
   if(end-at<8)throw Error('Incomplete MP4 box.');
   let size=view.getUint32(at),header=8;
   if(size===1){if(end-at<16)throw Error('Incomplete MP4 size.');size=Number(view.getBigUint64(at+8));header=16;}
   else if(size===0)size=end-at;
   if(!Number.isSafeInteger(size)||size<header||at+size>end)throw Error('Invalid MP4 box.');
   result.push({type:name(at+4),start:at,data:at+header,end:at+size});at+=size;
  }
  return result;
 }
 const child=(parent,type)=>boxes(parent.data,parent.end).find(box=>box.type===type);
 const timing=box=>{
  if(!box)throw Error('The MP4 duration is missing.');
  const wide=view.getUint8(box.data)===1,scaleAt=box.data+(wide?20:12),durationAt=box.data+(wide?24:16);
  if(durationAt+(wide?8:4)>box.end)throw Error('Incomplete MP4 timing.');
  const timescale=view.getUint32(scaleAt),duration=wide?Number(view.getBigUint64(durationAt)):view.getUint32(durationAt);
  if(!(timescale>0&&duration>0&&Number.isFinite(duration)))throw Error('The MP4 duration is invalid.');
  return {timescale,duration,seconds:duration/timescale};
 };
 top.push(...boxes(0,buffer.byteLength));const movie=top.find(box=>box.type==='moov'),media=top.find(box=>box.type==='mdat');
 if(!movie||!media||movie.start>media.start||top.some(box=>box.type==='moof'))throw Error('The MP4 movie index was not finalized.');
 const movieTime=timing(child(movie,'mvhd'));
 for(const track of boxes(movie.data,movie.end).filter(box=>box.type==='trak')){
  const header=child(track,'tkhd'),mdia=child(track,'mdia'),minf=mdia&&child(mdia,'minf'),table=minf&&child(minf,'stbl'),sizes=table&&child(table,'stsz');
  if(!header||!mdia||!sizes||sizes.data+12>sizes.end)throw Error('Incomplete MP4 track.');
  const wide=view.getUint8(header.data)===1,offset=header.data+(wide?28:20);
  if(offset+(wide?8:4)>header.end)throw Error('Incomplete MP4 track timing.');
  const duration=wide?Number(view.getBigUint64(offset)):view.getUint32(offset);
  const count=view.getUint32(sizes.data+8),mediaTime=timing(child(mdia,'mdhd'));
  if(!(duration>0&&count>0)||Math.abs(duration/movieTime.timescale-movieTime.seconds)>.1)throw Error('The MP4 track has invalid playback timing.');
  tracks.push({duration,samples:count,...mediaTime});
 }
 if(tracks.length!==1||Math.abs(tracks[0].seconds-movieTime.seconds)>.1)throw Error('The MP4 track duration does not match its movie.');
 return {duration:movieTime.seconds,tracks,fastStart:true,fragmented:false};
}

/** Copy the original H.264 packets into a conventional seekable MP4; never re-encode. */
export async function finalizeKeepsakeMp4104(blob,{expectedDuration=12}={}) {
 if(blob.size>64*1024*1024)throw Error('The recording is too large. Please create it again.');
 const input=new Input({source:new BlobSource(blob),formats:[MP4]});
 let output;
 try{
  const videos=await input.getVideoTracks(),audio=await input.getAudioTracks();
  if(videos.length!==1||audio.length)throw Error('The recording does not contain the expected keepsake video.');
  const track=videos[0],codec=await track.getCodec(),config=await track.getDecoderConfig();
  if(codec!=='avc'||!config?.description)throw Error('This browser did not create an H.264 MP4. Please try Chrome or Edge.');
  const start=await track.getFirstTimestamp();
  if(!Number.isFinite(start))throw Error('The recording has no usable video timestamps.');
  const target=new BufferTarget(),source=new EncodedVideoPacketSource('avc');
  output=new Output({format:new Mp4OutputFormat({fastStart:'in-memory'}),target});
  output.addVideoTrack(source,{rotation:await track.getRotation()});
  await output.start();
  const sink=new EncodedPacketSink(track);let count=0,end=0;
  for await(const packet of sink.packets()){
   if(++count>4096||!packet.data.length||!Number.isFinite(packet.timestamp)||!Number.isFinite(packet.duration)||packet.duration<0)throw Error('The recording contains invalid video frames.');
   if(count===1&&packet.type!=='key')throw Error('The recording is missing its first video frame.');
   const timestamp=packet.timestamp-start,duration=packet.duration||1/30;
   if(timestamp<-.001||timestamp>60||duration>60)throw Error('The recording contains invalid video timing.');
   end=Math.max(end,timestamp+duration);
   await source.add(packet.clone({timestamp:Math.max(0,timestamp),duration}),count===1?{decoderConfig:config}:undefined);
   if(count%64===0)await new Promise(resolve=>setTimeout(resolve,0));
  }
  if(count<2||!(end>0)||!Number.isFinite(expectedDuration)||expectedDuration<=0||end<expectedDuration-.5||end>expectedDuration+3)throw Error('The video recording was incomplete. Keep this tab open and try again.');
  await output.finalize();
  const result=target.buffer;
  if(!result)throw Error('The MP4 video could not be finalized. Please try again.');
  const metadata=inspectFinalMp4104(result);
  if(metadata.tracks[0].samples!==count||Math.abs(metadata.duration-end)>.1)throw Error('The MP4 video timing could not be verified. Please try again.');
  return new File([result],'anazori-keepsake.mp4',{type:'video/mp4'});
 }finally{
  input.dispose();
  if(output&&output.state!=='finalized')await output.cancel().catch(()=>{});
 }
}
