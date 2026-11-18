<?php
declare(strict_types=1);
require __DIR__.'/../src/includes/responsive-images84.php';
$checks=0;
function image_check84(bool $condition,string $message): void {
    global $checks;
    if(!$condition)throw new RuntimeException($message);
    $checks++;
}
foreach(['https://example.invalid/art.png','/uploads/registration/private.png','/uploads/payment-proof/private.png','/assets/../src/config/private.png','/assets/art.png?token=private','/assets/..\\config\\private.png'] as $url){
    image_check84(az_image_source84($url)===null,'Only public local artwork can receive variants.');
}
$url='/assets/2026/anazori-main-font.png';
$source=az_image_source84($url);
$attributes=az_image_attributes84($url,'(max-width:700px) 80vw, 600px');
image_check84($source!==null&&str_contains($attributes,'srcset='),'Existing public artwork has responsive candidates.');
image_check84(str_contains($attributes,$url.' '.$source['width'].'w'),'The full resolution original remains available.');
preg_match_all('#(/assets/2026/responsive84/[a-f0-9]+-(\d+)\.(?:webp|png)) (\d+)w#',$attributes,$matches,PREG_SET_ORDER);
foreach($matches as $match){
    $size=getimagesize(__DIR__.'/../src'.$match[1]);
    image_check84($size[0]===(int)$match[2]&&$match[2]===$match[3],'Candidate descriptors match actual image pixels.');
    image_check84(abs($size[1]-$source['height']*$size[0]/$source['width'])<=1,'Artwork retains its aspect ratio.');
}
image_check84(!str_contains(az_image_attributes84($url,'"><script>'),'<script>'),'Responsive attributes escape supplied sizes.');
echo "PASS $checks public responsive image checks.\n";
