"""Package faithfully rendered Lottie frames into lossless WebP atlases and CSS clocks."""
from pathlib import Path
from PIL import Image
import json,math,hashlib
root=Path(__file__).resolve().parents[1]
sources=json.loads((root/'.local/animation-source/sources.json').read_text())
output=root/'assets/2026/animations';output.mkdir(parents=True,exist_ok=True)
css=['/* Generated from supplied Lottie artwork. CSS transform clocks preserve source frame timings. */']
manifest=[]
for source in sources:
 ident=source['id'];duration_frames=round(source['end']-source['start'],4);count=math.ceil(duration_frames)
 frames=[Image.open(root/f'.local/animation-frames/{ident}/{i:03}.png').convert('RGBA') for i in range(count)]
 boxes=[frame.getbbox() for frame in frames if frame.getbbox()]
 box=(max(0,min(b[0] for b in boxes)-8),max(0,min(b[1] for b in boxes)-8),min(frames[0].width,max(b[2] for b in boxes)+8),min(frames[0].height,max(b[3] for b in boxes)+8))
 size=160;tiles=[];indices=[];unique={}
 for i,frame in enumerate(frames):
  art=frame.crop(box);art.thumbnail((size,size),Image.Resampling.LANCZOS)
  tile=Image.new('RGBA',(size,size));tile.paste(art,((size-art.width)//2,size-art.height))
  digest=hashlib.sha256(tile.tobytes()).digest()
  if digest not in unique:unique[digest]=len(tiles);tiles.append(tile)
  indices.append(unique[digest])
 columns=8 if len(tiles)<30 else 16;rows=math.ceil(len(tiles)/columns)
 atlas=Image.new('RGBA',(size*columns,size*rows))
 for i,tile in enumerate(tiles):atlas.paste(tile,((i%columns)*size,(i//columns)*size))
 # Some source animations open on a transparent entrance frame. Use a fully
 # visible original pose for loading, reduced-motion and no-JavaScript posters.
 poster_index=max(range(len(tiles)),key=lambda i:sum(alpha*n for alpha,n in enumerate(tiles[i].getchannel('A').histogram())))
 tiles[poster_index].save(output/(ident+'-poster.webp'),'WEBP',lossless=True,method=6)
 # Large event artwork gets a crisp poster independent of the small motion atlas.
 poster_art=frames[indices.index(poster_index)].crop(box)
 poster_art.thumbnail((480,480),Image.Resampling.LANCZOS)
 poster=Image.new('RGBA',(480,480));poster.paste(poster_art,((480-poster_art.width)//2,480-poster_art.height))
 poster.save(output/(ident+'-still.webp'),'WEBP',lossless=True,method=6)
 if ident=='festival-snow':
  snow=frames[indices.index(poster_index)].crop(box)
  snow.thumbnail((640,360),Image.Resampling.LANCZOS)
  snow.save(output/(ident+'-texture.webp'),'WEBP',lossless=True,method=6)
  manifest.append({**source,'frames':count,'poster':(output/(ident+'-poster.webp')).relative_to(root).as_posix(),'texture':(output/(ident+'-texture.webp')).relative_to(root).as_posix(),'static_texture':True})
  print(ident+': reusable source snow texture',flush=True)
  continue
 if ident not in ['doraemon-run','pikachu-run']:
  # Native animated WebP stores frame differences, avoiding a giant decoded
  # texture for longer performances. Every authored pose and timing is retained.
  native_size=192 if ident in ['walle-build','coco-guitar'] else 160
  native_frames=[]
  for frame in frames:
   art=frame.crop(box);art.thumbnail((native_size,native_size),Image.Resampling.LANCZOS)
   tile=Image.new('RGBA',(native_size,native_size));tile.paste(art,((native_size-art.width)//2,native_size-art.height));native_frames.append(tile)
  # Integer millisecond timings are cumulative-rounded so the complete source
  # cycle remains accurate (rather than accumulating rounding on 60fps sources).
  timings=[max(1,round(min(i+1,duration_frames)/source['fps']*1000)-round(i/source['fps']*1000)) for i in range(count)]
  native=output/(ident+'-motion.webp')
  native_frames[0].save(native,'WEBP',save_all=True,append_images=native_frames[1:],duration=timings,loop=0,quality=88,method=4,exact=True)
  source['native_animation']=native.relative_to(root).as_posix();source['native_bytes']=native.stat().st_size
  item={**source,'frames':count,'unique_frames':len(tiles),'duration':duration_frames/source['fps'],'poster':(output/(ident+'-still.webp')).relative_to(root).as_posix(),'poster_frame':indices.index(poster_index),'native_cell':native_size}
  manifest.append(item);print(json.dumps(item),flush=True)
  continue
 path=output/(ident+'.webp');atlas.save(path,'WEBP',lossless=True,method=6)
 duration=duration_frames/source['fps']
 css.append(f'.sprite-{ident}{{--sprite-columns:{columns};--sprite-rows:{rows}}}')
 css.append(f'.sprite-{ident} .sprite-sheet{{animation:sprite-{ident}-frames {duration:.6f}s steps(1,end) infinite paused}}')
 keys=[]
 for i in range(count):
  percent=i/duration_frames*100
  frame_index=indices[i]
  keys.append(f'{percent:.6f}%{{transform:translate({-(frame_index%columns)/columns*100:.6f}%,{-(frame_index//columns)/rows*100:.6f}%)}}')
 keys.append('100%{transform:translate(0,0)}')
 css.append('@keyframes sprite-'+ident+'-frames{'+''.join(keys)+'}')
 item={**source,'frames':count,'unique_frames':len(tiles),'cell':size,'columns':columns,'rows':rows,'duration':duration,'atlas':path.relative_to(root).as_posix(),'bytes':path.stat().st_size,'poster':(output/(ident+'-poster.webp')).relative_to(root).as_posix(),'poster_frame':indices.index(poster_index)}
 manifest.append(item);print(json.dumps({k:v for k,v in item.items() if k not in ['source_sha256']}),flush=True)
(output/'sources.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
(root/'src/supplied-sprites.css').write_text('\n'.join(css)+'\n',encoding='utf-8')
