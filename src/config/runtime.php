<?php
declare(strict_types=1);

// An explicit SQLite path is an environment choice, including isolated CLI checks.
// It takes priority over a private file's default MySQL driver.
if(getenv('ANAZORI_DB_DRIVER')===false&&getenv('ANAZORI_DB_PATH')!==false)putenv('ANAZORI_DB_DRIVER=sqlite');

// Shared hosting can load private settings without putting passwords in public_html.
$privateConfig=getenv('ANAZORI_PRIVATE_CONFIG')?:dirname(__DIR__,2).'/anazori-config.php';
if(is_file($privateConfig)){
    $settings=require $privateConfig;
    if(!is_array($settings))throw new RuntimeException('Check the private website configuration.');
    foreach($settings as $name=>$value){
        if(preg_match('/^ANAZORI_[A-Z0-9_]+$/D',(string)$name)&&is_scalar($value)&&(string)$value!==''&&getenv($name)===false)putenv($name.'='.(string)$value);
    }
}
// Fix the public origin on the deployed domain; keep local previews on their local origin.
$requestHost=strtolower(explode(':',$_SERVER['HTTP_HOST']??'')[0]);
if($requestHost==='anazori.ccsdu.in'){
    foreach(['ANAZORI_APP_ENV'=>'production','ANAZORI_SITE_URL'=>'https://anazori.ccsdu.in','ANAZORI_URL'=>'https://anazori.ccsdu.in','ANAZORI_DB_DRIVER'=>'mysql'] as $name=>$value)if(getenv($name)===false)putenv($name.'='.$value);
}
unset($privateConfig,$settings,$name,$value,$requestHost);
