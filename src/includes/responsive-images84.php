<?php
declare(strict_types=1);

/** Public artwork only. Private registration/payment uploads never enter this pipeline. */
function az_image_source84(string $url): ?array {
    static $cache=[];
    if(array_key_exists($url,$cache))return $cache[$url];
    if(!preg_match('#^/(?:assets/|uploads/media/)[^?\\\\]+\.(?:png|jpe?g|webp)$#iD',$url)||str_contains($url,'..'))return $cache[$url]=null;
    $root=realpath(__DIR__.'/..');$file=realpath($root.$url);
    if(!$file||!str_starts_with(str_replace('\\','/',$file),str_replace('\\','/',$root).'/'))return $cache[$url]=null;
    $size=@getimagesize($file);if(!$size||$size[0]<320)return $cache[$url]=null;
    $key=substr(hash('sha256',$url.'|'.filesize($file).'|'.filemtime($file)),0,20);
    return $cache[$url]=['file'=>$file,'width'=>$size[0],'height'=>$size[1],'key'=>$key];
}
function az_image_attributes84(string $url,string $sizes): string {
    $source=az_image_source84($url);if(!$source)return '';
    $candidates=[];
    foreach([320,640,960,1440] as $width){
        if($width>=$source['width'])continue;
        foreach(['webp','png'] as $format){
            $path='/assets/2026/responsive84/'.$source['key'].'-'.$width.'.'.$format;
            if(is_file(__DIR__.'/..'.$path)){$candidates[]=$path.' '.$width.'w';break;}
        }
    }
    if(!$candidates)return '';
    $candidates[]=$url.' '.$source['width'].'w';
    return ' srcset="'.htmlspecialchars(implode(', ',$candidates),ENT_QUOTES,'UTF-8').'" sizes="'.htmlspecialchars($sizes,ENT_QUOTES,'UTF-8').'"';
}
/** New Studio uploads receive variants when GD is available, without altering originals. */
function az_generate_image_variants84(string $url): void {
    if(!function_exists('imagecreatefromstring')||!function_exists('imagepng'))return;
    $source=az_image_source84($url);if(!$source||$source['width']*$source['height']>4000000)return;
    $bytes=@file_get_contents($source['file']);if(!$bytes)return;
    // GD does not preserve orientation or embedded colour profiles. Keep such
    // originals (and animation) rather than generate a visibly different image.
    foreach(['ANIM','acTL',"Exif\0\0",'ICC_PROFILE','iCCP','ICCP'] as $metadata)if(str_contains($bytes,$metadata))return;
    $image=@imagecreatefromstring($bytes);unset($bytes);if(!$image)return;
    $directory=__DIR__.'/../assets/2026/responsive84';
    if(!is_dir($directory)&&!@mkdir($directory,0755,true))return;
    foreach([320,640,960,1440] as $width){
        if($width>=$source['width'])continue;
        $path=$directory.'/'.$source['key'].'-'.$width.'.png';if(is_file($path))continue;
        $height=max(1,(int)round($source['height']*$width/$source['width']));
        $variant=imagecreatetruecolor($width,$height);imagealphablending($variant,false);imagesavealpha($variant,true);
        imagecopyresampled($variant,$image,0,0,0,0,$width,$height,$source['width'],$source['height']);
        $temporary=$path.'.'.bin2hex(random_bytes(4)).'.tmp';
        if(imagepng($variant,$temporary,6)&&filesize($temporary)<filesize($source['file']))@rename($temporary,$path);
        if(is_file($temporary))@unlink($temporary);
        unset($variant);
    }
}
