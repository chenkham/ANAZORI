<?php
declare(strict_types=1);

/** The festival film lives in the bordered introduction player. */
function intro_video_config(): array {
    $video=trim(setting('intro_video'));
    $url=trim(setting('intro_video_url'));
    $autoplay=setting('intro_video_autoplay')==='1';
    $config=['has_video'=>false,'is_embed'=>false,'embed_url'=>'','src'=>'','poster'=>trim(setting('intro_video_poster')),'autoplay'=>$autoplay,'controls'=>setting('intro_video_controls')!=='0','loop'=>setting('intro_video_loop')==='1'];
    if($video!=='')$config['src']=$video;
    elseif($url!==''){
        $host=strtolower(parse_url($url,PHP_URL_HOST)??'');
        $path=parse_url($url,PHP_URL_PATH)??'';
        $id='';
        if(in_array($host,['youtube.com','www.youtube.com','m.youtube.com','youtube-nocookie.com','www.youtube-nocookie.com','youtu.be'],true)){
            if($host==='youtu.be')$id=trim($path,'/');
            elseif(preg_match('~^/(?:embed|shorts)/([a-zA-Z0-9_-]{11})/?$~D',$path,$match))$id=$match[1];
            elseif($path==='/watch'){parse_str(parse_url($url,PHP_URL_QUERY)??'',$query);$id=is_string($query['v']??null)?$query['v']:'';}
            if(preg_match('/^[a-zA-Z0-9_-]{11}$/D',$id))$config['embed_url']='https://www.youtube-nocookie.com/embed/'.$id.'?rel=0'.($autoplay?'&autoplay=1&mute=1':'');
        }elseif(in_array($host,['vimeo.com','www.vimeo.com','player.vimeo.com'],true)&&preg_match('~/(?:video/)?([0-9]+)/*$~D',$path,$match)){
            $config['embed_url']='https://player.vimeo.com/video/'.$match[1].($autoplay?'?autoplay=1&muted=1':'');
        }elseif(filter_var($url,FILTER_VALIDATE_URL)&&in_array(strtolower(parse_url($url,PHP_URL_SCHEME)??''),['https','http'],true))$config['src']=$url;
    }
    $config['is_embed']=$config['embed_url']!=='';
    $config['has_video']=$config['src']!==''||$config['is_embed'];
    return $config;
}
