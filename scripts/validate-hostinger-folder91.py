"""Validate the direct-upload boundary and unchanged runtime without printing secrets."""
from pathlib import Path
from hashlib import sha256
import json
root=Path(__file__).resolve().parent.parent
web=root/'src'
required=['index.php','.htaccess','.user.ini','vendor/autoload.php','includes/private-storage.php','includes/mail-notifications.php','assets/2026/public.css','assets/2026/site.js','assets/2026/console.css','api/registration-draft.php']
for name in required:
    assert (web/name).is_file(),f'Missing runtime file: {name}'
for name in ['.local','data','deploy','docs','frontend','node_modules','scripts','tests','development','legacy','output','scratch','tmp','artifacts','anazori-private']:
    assert not (web/name).exists(),f'Private/development directory inside website: {name}'
for file in web.rglob('*'):
    if not file.is_file():continue
    assert file.suffix.lower() not in {'.sql','.sqlite','.sqlite3','.bak','.zip','.log'},f'Unexpected private/archive file: {file.relative_to(web)}'
    assert file.name not in {'anazori-config.php','application-key','.application-key','.DS_Store','Thumbs.db','desktop.ini'},f'Private/junk file in hosted folder: {file.relative_to(web)}'
    assert '__MACOSX' not in file.parts
snapshot=json.loads((root/'.local/relocation91-runtime-before.json').read_text(encoding='utf-8-sig'))
checked=0
for item in snapshot:
    relative=Path(item['Path'])
    archived=relative.suffix.lower()=='.zip' or '__MACOSX' in relative.parts or relative.name in {'.DS_Store','Thumbs.db','desktop.ini'}
    file=(root/'legacy' if archived else web)/relative
    assert file.is_file(),f'Moved file missing: {relative}'
    assert sha256(file.read_bytes()).hexdigest().upper()==item['Hash'],f'Runtime changed during relocation: {relative}'
    if not archived:checked+=1
paths=json.loads((root/'.local/hostinger-public-paths90.json').read_text())
for path in paths:
    assert (web/path.lstrip('/')).is_file(),f'Missing CMS asset: {path}'
for relative in ['anazori-config.php','anazori-private/application-key','anazori-private/payment-proofs','anazori-private/registration-files','anazori-private/studio-receipts']:
    assert (root/'deploy/private'/relative).exists(),f'Missing private upload item: {relative}'
keys=[root/'data/.application-key',root/'anazori-private/application-key',root/'deploy/private/anazori-private/application-key']
assert len({sha256(file.read_bytes()).hexdigest() for file in keys})==1,'Application key changed'
config=(root/'deploy/private/anazori-config.php').read_text()
assert 'C:\\Users' not in config and 'anazori_local' not in config,'Laptop settings in production config'
assert "'ANAZORI_MAIL_NOTIFICATIONS' => '0'" in config,'OTP-only setting changed'
manifest=json.loads((root/'deploy/database-manifest90.json').read_text())
for table in ['az_participants','az_orders','az_tickets','az_checkout_drafts','az_registration_files','az_mail_jobs89','submissions']:
    assert manifest['tables'][table]==0,f'Unexpected user data in SQL: {table}'
assert manifest['staff_accounts']==2
print(f'PASS direct-folder boundary, {checked} unchanged runtime files, {len(paths)} CMS assets, private key/setup and clean SQL manifest.')
