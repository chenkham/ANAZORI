<?php
declare(strict_types=1);
require_once __DIR__.'/includes/commerce.php';
require_once __DIR__.'/includes/form-builder-view.php';
require_once __DIR__.'/includes/form-review-view.php';
$staff=cms_require_user();set_security_headers();header('Cache-Control: no-store');
$event=cms_record((int)($_GET['event_id']??0));$phase=($_GET['phase']??'registration')==='interest'?'interest':'registration';
if($staff['must_change_password']){header('Location: /admin.php?section=profile',true,303);exit;}
if(!$event||$event['type']!=='event'||!cms_can($staff,'event','edit',$event)){http_response_code(403);exit('This form is outside your assigned editing access.');}
if($phase==='interest'&&az_participation_mode($event)==='contribution'){http_response_code(404);exit('Use the contribution form for this event.');}
$gameId=is_string($_GET['game']??null)?$_GET['game']:'';
try{$fields=az_game_fields81($event['fields'],$gameId,$phase);}catch(Throwable $error){http_response_code(404);exit('Game form unavailable.');}
$draft=$fields[$phase.'_form_draft']??null;
if(is_array($draft)){
    if($phase==='registration')$fields=az_form_prices108($fields,$draft['prices']??[],$gameId);
    $fields[$phase.'_form']=json_encode($draft['questions']);$fields[$phase.'_settings']=json_encode($draft['settings']);
    foreach(['title','intro','button'] as $key)$fields[$phase.'_'.$key]=$draft[$key];
}
?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Form setup · <?= e($event['title']) ?></title><link rel="icon" href="<?= e(setting('logo')) ?>"><link rel="stylesheet" href="/assets/2026/console.css?v=<?= (int)filemtime(__DIR__.'/assets/2026/console.css') ?>"><script type="module" src="/assets/2026/form-setup.js?v=<?= (int)filemtime(__DIR__.'/assets/2026/form-setup.js') ?>"></script></head><body class="console form-workspace">
<?php st_form_workspace($event,$fields,cms_media($staff),$phase,$staff,is_array($draft)); ?>
</body></html>
