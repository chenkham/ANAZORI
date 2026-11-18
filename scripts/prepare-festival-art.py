"""Fetch source artwork and encode smaller web copies; no generated character redraws."""
from pathlib import Path
from urllib.request import Request, urlopen
from io import BytesIO
import json
from PIL import Image

root = Path(__file__).resolve().parents[1]
output = root / 'assets/2026/characters'
output.mkdir(parents=True, exist_ok=True)
sources = {
    'pikachu': 'https://www.pokemon.com/static-assets/content-assets/cms2/img/pokedex/full/025.png',
    'gengar': 'https://www.pokemon.com/static-assets/content-assets/cms2/img/pokedex/full/094.png',
    'charizard': 'https://www.pokemon.com/static-assets/content-assets/cms2/img/pokedex/full/006.png',
    'minion': 'https://www.illumination.com/wp-content/themes/illumination/assets/images/bumper_minion.png',
    'stuart': 'https://www.illumination.com/wp-content/uploads/2019/11/SHM_PRINTS_P1880.png',
    'doraemon': 'https://www.dora-world.com/assets/images/hd/hd_bg_s01_chara.webp',
    'sonic': 'https://sonic.sega.jp/SonicForces/character/image/sp_pic_01.png',
    'mlbb-gusion': 'https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/f/876c3469-6c49-47bc-a474-e157a30d6d40/de60tw2-42b42c2d-8790-432a-ac89-c663b9ba8967.png/v1/fill/w_1117%2Ch_715/gusion___cosmic_gleam_png__chesterkay30__by_chesterkay30_de60tw2-pre.png?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1cm46YXBwOjdlMGQxODg5ODIyNjQzNzNhNWYwZDQxNWVhMGQyNmUwIiwiaXNzIjoidXJuOmFwcDo3ZTBkMTg4OTgyMjY0MzczYTVmMGQ0MTVlYTBkMjZlMCIsIm9iaiI6W1t7ImhlaWdodCI6Ijw9ODIwIiwicGF0aCI6IlwvZlwvODc2YzM0NjktNmM0OS00N2JjLWE0NzQtZTE1N2EzMGQ2ZDQwXC9kZTYwdHcyLTQyYjQyYzJkLTg3OTAtNDMyYS1hYzg5LWM2NjNiOWJhODk2Ny5wbmciLCJ3aWR0aCI6Ijw9MTI4MCJ9XV0sImF1ZCI6WyJ1cm46c2VydmljZTppbWFnZS5vcGVyYXRpb25zIl19.c7Iwhqac39wEKBUEoGri4rghGYW_UBXSYAEVlO4Hh8Y',
    'bgmi-royal-aurum': 'https://pbs.twimg.com/media/FaiDDBSXkAcpLlA.jpg?name=large',
}
manifest = []
previous = {item['id']: item for item in json.loads((output / 'sources.json').read_text(encoding='utf-8'))} if (output / 'sources.json').exists() else {}
for name, source in sources.items():
    try:
        path = output / (name + '.webp')
        if path.exists():
            img = Image.open(path)
            manifest.append({**previous.get(name, {}), 'id': name, 'source': source, 'file': str(path.relative_to(root)).replace('\\', '/'), 'width': img.width, 'height': img.height, 'bytes': path.stat().st_size})
            continue
        request = Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        raw = urlopen(request, timeout=30).read()
        img = Image.open(BytesIO(raw)).convert('RGBA')
        img.thumbnail((720, 720) if name in {'mlbb-gusion','bgmi-royal-aurum'} else (600, 600), Image.Resampling.LANCZOS)
        path = output / (name + '.webp')
        img.save(path, 'WEBP', quality=88, method=6)
        item = {**previous.get(name, {}), 'id': name, 'source': source, 'file': str(path.relative_to(root)).replace('\\', '/'), 'width': img.width, 'height': img.height, 'bytes': path.stat().st_size}
        manifest.append(item)
        print(json.dumps(item))
    except Exception as error:
        print(name, type(error).__name__, str(error))
(output / 'sources.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
