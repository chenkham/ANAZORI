"""Optional backup archive. Hosting uses direct folders; this is never required."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from datetime import datetime
root=Path(__file__).resolve().parent.parent
web=root/'src'
destination=root/'.local/packages'
destination.mkdir(parents=True,exist_ok=True)
output=destination/('anazori-runtime-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.zip')
with ZipFile(output,'x',ZIP_DEFLATED,compresslevel=6) as archive:
    for file in sorted(web.rglob('*')):
        if file.is_file():archive.write(file,file.relative_to(web).as_posix())
print('Optional runtime backup saved outside the hosted src directory.')
