"""Fetch publisher artwork once. The public website uses only local WebP exports."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import urllib.request, hashlib, json, io
from PIL import Image
root=Path(__file__).resolve().parents[1]
out=root/'assets/2026/characters';out.mkdir(parents=True,exist_ok=True)
files={
 'kirby':'https://www.smashbros.com/assets_v2/img/fighter/kirby/main.png',
 'link':'https://www.smashbros.com/assets_v2/img/fighter/link/main.png',
 'megaman':'https://www.smashbros.com/assets_v2/img/fighter/mega_man/main.png',
 'roz-research':'https://www.dreamworks.com/storage/cms-uploads/the-wild-robot-gallery1.jpg'
}
def fetch(item):
 ident,url=item
 req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
 with urllib.request.urlopen(req,timeout=40) as response:data=response.read()
 image=Image.open(io.BytesIO(data)).convert('RGBA')
 image.thumbnail((900,700),Image.Resampling.LANCZOS)
 path=out/(ident+'.webp');image.save(path,'WEBP',quality=92,method=6)
 return {'id':ident,'source':url,'source_sha256':hashlib.sha256(data).hexdigest(),'file':path.relative_to(root).as_posix(),'width':image.width,'height':image.height,'bytes':path.stat().st_size,'credit':'DreamWorks Animation' if ident.startswith('roz') else 'Official Super Smash Bros. character artwork','usage_rights':'Publisher artwork; no independent reuse licence asserted.'}
with ThreadPoolExecutor(max_workers=4) as pool:records=list(pool.map(fetch,files.items()))
path=out/'sources.json';previous=json.loads(path.read_text()) if path.exists() else []
previous=[r for r in previous if r['id'] not in files]
path.write_text(json.dumps(previous+records,indent=2)+'\n',encoding='utf-8')
for item in records:print(item['id'],item['width'],item['height'],item['bytes'])
