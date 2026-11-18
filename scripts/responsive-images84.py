"""Build lossless, correctly sized public image variants; leave originals untouched."""
from pathlib import Path
from hashlib import sha256
import json
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / 'src/assets/2026/responsive84'
WIDTHS = (320, 640, 960, 1440)

def build():
    DEST.mkdir(parents=True, exist_ok=True)
    files = list((ROOT / 'src/assets/2026').glob('*'))
    files += list((ROOT / 'src/assets/2026/graphics').glob('*.png'))
    files += list((ROOT / 'src/assets/2026/creative').glob('*.png'))
    files += list((ROOT / 'src/uploads/media').glob('*'))
    results = []
    for path in files:
        if not path.is_file() or path.suffix.lower() not in ('.png', '.jpg', '.jpeg', '.webp'):
            continue
        with Image.open(path) as original:
            if getattr(original, 'n_frames', 1) != 1 or original.width < 320:
                continue
            # EXIF-rotated originals retain their browser rendering and original file.
            if original.getexif().get(274, 1) != 1:
                continue
            stat = path.stat()
            url = '/' + path.relative_to(ROOT / 'src').as_posix()
            key = sha256(f'{url}|{stat.st_size}|{int(stat.st_mtime)}'.encode()).hexdigest()[:20]
            image = original.convert('RGBA' if 'A' in original.getbands() else 'RGB')
            variants = []
            for width in WIDTHS:
                if width >= image.width:
                    continue
                target = DEST / f'{key}-{width}.webp'
                if not target.exists():
                    height = max(1, round(image.height * width / image.width))
                    resized = image.resize((width, height), Image.Resampling.LANCZOS)
                    temporary = target.with_suffix('.tmp')
                    resized.save(temporary, format='WEBP', lossless=True, method=6,
                                 icc_profile=original.info.get('icc_profile', b''))
                    if temporary.stat().st_size < stat.st_size:
                        temporary.replace(target)
                    else:
                        temporary.unlink()
                if target.exists():
                    variants.append({'width': width, 'bytes': target.stat().st_size})
            if variants:
                results.append({'source': url, 'originalBytes': stat.st_size, 'variants': variants})
    report = ROOT / 'output/performance84/responsive-images.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f'Prepared responsive variants for {len(results)} public images; originals and animation sheets retained.')

if __name__ == '__main__':
    build()
