"""Read supplied dotLottie archives as artwork data; embed their local raster layers."""
from pathlib import Path
from zipfile import ZipFile
import base64,json,hashlib
root=Path(__file__).resolve().parents[1]
output=root/'.local/animation-source'
output.mkdir(parents=True,exist_ok=True)
files={'doraemon-run':'Doraemon Run.lottie','pikachu-run':'Pikachu.lottie','coco-guitar':'Skeleton.lottie','walle-build':'Wall-E Loading Animation.lottie','stitch-light':'Stitch animation.lottie','totoro-visit':'Totoro Walk.lottie','baymax-help':'Baymax.lottie','among-us':'among us.lottie','mario-discovery':'Loading 52 _ Mario.lottie','deadpool-photo':'DeadPool.lottie','festival-snow':'Let it snow.lottie'}
metadata=[]
for ident,filename in files.items():
 source=root/'svg animations'/filename
 with ZipFile(source) as archive:
  name=next(n for n in archive.namelist() if n.startswith('animations/') and n.endswith('.json'))
  animation=json.loads(archive.read(name))
  for asset in animation.get('assets',[]):
   if asset.get('p'):
    image=archive.read('images/'+asset['p'])
    asset.update(p='data:image/png;base64,'+base64.b64encode(image).decode(),u='',e=1)
  (output/(ident+'.json')).write_text(json.dumps(animation,separators=(',',':')),encoding='utf-8')
  metadata.append(dict(id=ident,source='svg animations/'+filename,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),width=animation['w'],height=animation['h'],fps=animation['fr'],start=animation['ip'],end=animation['op']))
(output/'sources.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
print(json.dumps(metadata,indent=2))
