<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require_once __DIR__.'/../src/includes/commerce.php';
$config=az_config();
$directory=dirname(__DIR__).'/deploy/private';
if(!is_dir($directory))mkdir($directory,0700,true);
// Carry working Google credentials and the encryption key outside the public upload.
// Hosting database credentials and sender authorisation require the owner's real values.
$settings=require dirname(__DIR__).'/deploy/anazori-config.example.php';
$existing=is_file($directory.'/anazori-config.php')?require $directory.'/anazori-config.php':[];
// Keep owner-supplied hosting credentials when rebuilding the private package.
foreach(['ANAZORI_DB_NAME','ANAZORI_DB_USER','ANAZORI_DB_PASS'] as $name)if(!empty($existing[$name]))$settings[$name]=$existing[$name];
$settings['ANAZORI_GOOGLE_CLIENT_ID']=$config['google_client_id'];
$settings['ANAZORI_GOOGLE_CLIENT_SECRET']=$config['google_client_secret'];
foreach($existing as $name=>$value)if(str_starts_with($name,'ANAZORI_PHP_MAIL_'))$settings[$name]=$value;
$settings['ANAZORI_BOOTSTRAP_PASSWORD']=bin2hex(random_bytes(24));
unset($settings['ANAZORI_SECRET_PATH'],$settings['ANAZORI_PAYMENT_PROOF_DIR'],$settings['ANAZORI_REGISTRATION_FILE_DIR'],$settings['ANAZORI_STUDIO_RECEIPT_PATH']);
$source="<?php\n// PRIVATE: upload beside src, never inside it or a public repository.\nreturn ".var_export($settings,true);
$source=substr($source,0,-1)."  'ANAZORI_SECRET_PATH'=>__DIR__.'/anazori-private/application-key',\n  'ANAZORI_PAYMENT_PROOF_DIR'=>__DIR__.'/anazori-private/payment-proofs',\n  'ANAZORI_REGISTRATION_FILE_DIR'=>__DIR__.'/anazori-private/registration-files',\n  'ANAZORI_STUDIO_RECEIPT_PATH'=>__DIR__.'/anazori-private/studio-receipts',\n);\n";
file_put_contents($directory.'/anazori-config.php',$source);chmod($directory.'/anazori-config.php',0600);
if(!is_dir($directory.'/anazori-private'))mkdir($directory.'/anazori-private',0700);
file_put_contents($directory.'/anazori-private/application-key',base64_encode(az_key()));chmod($directory.'/anazori-private/application-key',0600);
echo "Private setup files prepared for direct folder upload. Hosting credentials retained; Google settings and application key carried over. PHP mail uses the configured four senders and one shared hosting quota.\n";
