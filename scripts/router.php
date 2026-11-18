<?php
declare(strict_types=1);
$siteRoot=dirname(__DIR__).'/src';
// PHP development router. The allowlist prevents source, backup, and database disclosure.
$settings = require $siteRoot . '/config.php';
$base = rtrim($settings['base_path'], '/');
$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/');
if ($base !== '') {
    if ($path !== $base && !str_starts_with($path, $base . '/')) { http_response_code(404); exit('Not found'); }
    $path = substr($path, strlen($base)) ?: '/';
}
if (str_contains($path, "\0") || str_contains($path, '\\') || preg_match('#(^|/)(\.|data|config|deploy|docs|includes|vendor|node_modules|src|scripts|tests)(/|$)#i', $path) || preg_match('#(^|/)\.#', $path)) { http_response_code(404); exit('Not found'); }
if ($path === '/' || $path === '/index.php') { require $siteRoot . '/index.php'; return; }
if (in_array($path, ['/index.html','/default.php'],true)) { header('Location: ' . ($base ?: '') . '/',true,302); return; }
if (preg_match('#^/event/([a-zA-Z0-9_-]+)/?$#',$path,$match)) { $_GET['name']=$match[1];require $siteRoot.'/event.php';return; }
$legacy = ['events','event','teams','gallery','exhibitions','competitions','accommodation','register','admin','login','logout','account','verify-email','forgot-password','oauth','dashboard','profile','checkout','ticket','payment-return','payment-qr','payment-proof','payment-proof-file','registration-file','form-setup','festival-poster','privacy','terms','credits'];
$slug = preg_replace('/\.php$/','',trim($path,'/'));
if (in_array($slug,$legacy,true) && is_file($siteRoot.'/'.$slug.'.php')) { require $siteRoot . '/' . $slug . '.php'; return; }
if (in_array($path,['/api/event-form.php','/api/interest.php','/api/register.php','/api/feedback.php','/api/submit.php','/api/visitor.php','/api/checkout.php','/api/payment.php','/api/webhook.php','/api/checkin.php','/api/payment-proof.php','/api/studio-form-media.php','/api/studio-form.php','/api/registration-draft.php','/api/studio-media.php'],true)) { require $siteRoot . $path; return; }
$upload=str_starts_with(strtolower($path),'/uploads/');
if($upload&&!preg_match('#^/uploads/(?:[a-z0-9_-]+/)*[a-z0-9][a-z0-9_.-]*\.(?:jpg|jpeg|png|webp|gif|pdf|mp4|webm|mp3|m4a|wav|ogg)$#iD',$path)){http_response_code(404);exit('Not found');}
$file = realpath($siteRoot . $path);
$root = str_replace('\\','/',realpath($siteRoot)) . '/';
$extension = strtolower(pathinfo($path,PATHINFO_EXTENSION));
$mime = ['css'=>'text/css','js'=>'text/javascript','svg'=>'image/svg+xml','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','webp'=>'image/webp','gif'=>'image/gif','ico'=>'image/x-icon','woff'=>'font/woff','woff2'=>'font/woff2','ttf'=>'font/ttf','otf'=>'font/otf','mp4'=>'video/mp4','webm'=>'video/webm','mp3'=>'audio/mpeg','m4a'=>'audio/mp4','wav'=>'audio/wav','ogg'=>'audio/ogg','pdf'=>'application/pdf'];
if ($file && is_file($file) && str_starts_with(strtolower(str_replace('\\','/',$file)),strtolower($root)) && isset($mime[$extension])) {
    // Match production SVG compression in the local preview. These prebuilt
    // files never require rendering or compression work on an HTTP request.
    if ($extension==='svg' && str_starts_with($path,'/assets/2026/vector/') && is_file($file.'.gz')) {
        $gzip=false;
        foreach (explode(',',$_SERVER['HTTP_ACCEPT_ENCODING']??'') as $encoding) {
            if (preg_match('/^\s*gzip\s*(?:;\s*q\s*=\s*(0(?:\.\d+)?|1(?:\.0+)?))?\s*$/i',$encoding,$accepted)) {
                $gzip=!isset($accepted[1])||(float)$accepted[1]>0;
            }
        }
        $served=$gzip?$file.'.gz':$file;$etag='"'.hash_file('sha256',$served).'"';
        header('Content-Type: image/svg+xml');header('X-Content-Type-Options: nosniff');header('Vary: Accept-Encoding');header('Cache-Control: public, max-age=2592000');header('ETag: '.$etag);
        if (($_SERVER['HTTP_IF_NONE_MATCH']??'')===$etag) {http_response_code(304);return;}
        if ($gzip) header('Content-Encoding: gzip');
        header('Content-Length: '.filesize($served));readfile($served);return;
    }
    if($upload){header('Content-Type: '.$mime[$extension]);header('X-Content-Type-Options: nosniff');header('Cross-Origin-Resource-Policy: same-origin');if($extension==='pdf'){header('Content-Disposition: inline');header("Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'");}readfile($file);return;}
    if ($base==='') return false;
    header('Content-Type: ' . $mime[$extension]);header('X-Content-Type-Options: nosniff');readfile($file);return;
}
http_response_code(404);header('Content-Type: text/plain; charset=utf-8');echo 'Not found';
