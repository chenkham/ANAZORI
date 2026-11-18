<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit('CLI only');
putenv('ANAZORI_PRIVATE_CONFIG=/nonexistent');putenv('ANAZORI_DB_PATH=:memory:');
require __DIR__.'/../src/config/security.php';$checks=0;$temp=sys_get_temp_dir().'/anazori-upload95-'.bin2hex(random_bytes(8));mkdir($temp,0700);
function upload_check95(bool $ok,string $label): void {global $checks;if(!$ok)throw new RuntimeException($label);$checks++;}
function upload_denied95(callable $fn,string $label): void {try{$fn();}catch(InvalidArgumentException){upload_check95(true,$label);return;}throw new RuntimeException('Expected rejection: '.$label);}
$types=['image/png'=>'png','application/pdf'=>'pdf','text/plain'=>'txt'];
try{
    $image=$temp.'/image.png';copy(__DIR__.'/../src/assets/logo.png',$image);$info=az_inspect_upload95($image,'photo.png',$types,5*1024*1024);upload_check95($info['mime']==='image/png'&&$info['size']===filesize($image),'Valid raster passes with measured size.');
    upload_denied95(fn()=>az_inspect_upload95($image,'photo.php',$types,5*1024*1024),'Executable extension cannot masquerade as image.');upload_denied95(fn()=>az_inspect_upload95($image,'photo.jpg',$types,5*1024*1024),'MIME and extension mismatch rejected.');upload_denied95(fn()=>az_inspect_upload95($image,'photo.png',$types,1),'Actual bytes enforce size limit.');upload_denied95(fn()=>az_inspect_upload95($image,'photo.png',$types,5*1024*1024,1),'Decoded dimensions enforce pixel cap.');
    $polyglot=$temp.'/polyglot.png';file_put_contents($polyglot,file_get_contents($image)."<?php echo 'execute';");upload_denied95(fn()=>az_inspect_upload95($polyglot,'photo.png',$types,5*1024*1024),'Appended executable PHP rejected.');
    $svg=$temp.'/vector.svg';file_put_contents($svg,'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');upload_denied95(fn()=>az_inspect_upload95($svg,'vector.svg',$types,10000),'Active SVG excluded.');
    $pdf=$temp.'/document.pdf';file_put_contents($pdf,"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n");upload_check95(az_inspect_upload95($pdf,'receipt.pdf',$types,10000)['mime']==='application/pdf','PDF signature and trailer accepted.');
    foreach(['/JavaScript (alert(1))','/Launch /F (cmd.exe)','/EmbeddedFile <<>>','/J#61vaScript (alert(1))'] as $payload){file_put_contents($pdf,"%PDF-1.4\n".$payload."\n%%EOF\n");upload_denied95(fn()=>az_inspect_upload95($pdf,'receipt.pdf',$types,10000),'Active PDF feature rejected.');}
    file_put_contents($pdf,"%PDF-1.4\nincomplete");upload_denied95(fn()=>az_inspect_upload95($pdf,'receipt.pdf',$types,10000),'Incomplete PDF rejected.');
    upload_denied95(fn()=>az_validate_upload95(['error'=>UPLOAD_ERR_OK,'tmp_name'=>$image,'name'=>'image.png'],$types,1000000),'Local filesystem file cannot be submitted as an HTTP upload.');upload_denied95(fn()=>az_validate_upload95(['error'=>[],'tmp_name'=>[],'name'=>[]],$types,1000000),'Malformed multipart parameters rejected.');upload_denied95(fn()=>az_inspect_upload95($image,"x\r\n.png",$types,1000000),'Header injection filename rejected.');
    $_SESSION['csrf_token']=str_repeat('a',64);$_POST['csrf_token']=[];upload_check95(!csrf_verify(),'Array CSRF token returns false.');upload_check95(csrf_verify(str_repeat('a',64)),'Valid CSRF token accepted.');$_SERVER['HTTP_SEC_FETCH_SITE']='cross-site';upload_check95(!csrf_verify(str_repeat('a',64)),'Cross-site POST rejected.');unset($_SERVER['HTTP_SEC_FETCH_SITE']);
    upload_check95(az_private_file_safe95($image,$temp),'Private file containment accepts its own root.');upload_check95(!az_private_file_safe95(__DIR__.'/../src/assets/logo.png',$temp),'Private file containment rejects external files.');
    if(class_exists('ZipArchive')){
        $doc=$temp.'/document.docx';$office=['application/vnd.openxmlformats-officedocument.wordprocessingml.document'=>'docx'];
        $make=function(array $extra)use($doc){$zip=new ZipArchive();$zip->open($doc,ZipArchive::CREATE|ZipArchive::OVERWRITE);$zip->addFromString('[Content_Types].xml','<Types></Types>');$zip->addFromString('word/document.xml','<document/>');foreach($extra as $name=>$value)$zip->addFromString($name,$value);$zip->close();};
        $make([]);upload_check95(az_inspect_upload95($doc,'document.docx',$office,1000000)['extension']==='docx','OOXML structure accepted.');$make(['../escape'=>'bad']);upload_denied95(fn()=>az_inspect_upload95($doc,'document.docx',$office,1000000),'ZIP traversal rejected.');$make(['word/vbaProject.bin'=>'macro']);upload_denied95(fn()=>az_inspect_upload95($doc,'document.docx',$office,1000000),'Office macros rejected.');$make(['word/huge.xml'=>str_repeat('a',2*1024*1024)]);upload_denied95(fn()=>az_inspect_upload95($doc,'document.docx',$office,1000000),'ZIP expansion bomb rejected.');
    }
    echo 'PASS '.$checks.' upload validation, size, content, containment and CSRF checks.'.PHP_EOL;
}finally{foreach(glob($temp.'/*')?:[] as $path)unlink($path);rmdir($temp);}
