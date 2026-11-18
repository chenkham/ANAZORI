<?php
declare(strict_types=1);

/** Persistent uploads live beside public_html and are served through access-checked PHP. */
function az_private_directory90(string $directory): string {
    $public=realpath(dirname(__DIR__));
    $normalize=static fn(string $path): string=>strtolower(str_replace('\\','/',rtrim($path,'/\\'))).'/';
    // Check the nearest existing ancestor before mkdir, including symlink destinations.
    $ancestor=$directory;
    while(!file_exists($ancestor)&&dirname($ancestor)!==$ancestor)$ancestor=dirname($ancestor);
    $existing=realpath($ancestor);
    if(!$public||!$existing||str_starts_with($normalize($existing),$normalize($public)))throw new RuntimeException('Private storage must stay outside public_html.');
    if(!is_dir($directory)&&!@mkdir($directory,0700,true)&&!is_dir($directory))throw new RuntimeException('Private storage is unavailable. Check hosting directory permissions.');
    $resolved=realpath($directory);
    if(!$resolved||str_starts_with($normalize($resolved),$normalize($public))||!is_writable($resolved))throw new RuntimeException('Private storage is unavailable or inside public_html.');
    return $resolved;
}

function az_application_key_path90(): string {
    if(getenv('ANAZORI_SECRET_PATH'))return getenv('ANAZORI_SECRET_PATH');
    // Existing installations keep their key; new hosts create it outside the website.
    $legacy=dirname(__DIR__).'/data/.application-key';
    return is_file($legacy)?$legacy:dirname(__DIR__,2).'/anazori-private/application-key';
}

function az_storage_checks90(): array {
    $checks=[];
    foreach(['Payment screenshots'=>'ANAZORI_PAYMENT_PROOF_DIR','Registration uploads'=>'ANAZORI_REGISTRATION_FILE_DIR','Studio receipts'=>'ANAZORI_STUDIO_RECEIPT_PATH'] as $label=>$variable){
        $suffix=match($variable){'ANAZORI_PAYMENT_PROOF_DIR'=>'payment-proofs','ANAZORI_REGISTRATION_FILE_DIR'=>'registration-files',default=>'studio-receipts'};
        try{az_private_directory90(getenv($variable)?:dirname(__DIR__,2).'/anazori-private/'.$suffix);$checks[]=[$label,true,'Private storage created automatically and writable.'];}
        catch(Throwable){$checks[]=[$label,false,'Allow PHP to create the private anazori-private directory beside public_html, or set a writable private path.'];}
    }
    return $checks;
}
