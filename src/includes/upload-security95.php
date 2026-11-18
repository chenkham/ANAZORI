<?php
declare(strict_types=1);

/** Content inspection is separate from the HTTP upload check so it is testable without a bypass. */
function az_inspect_upload95(string $path,string $name,array $types,int $limit,int $pixels=40000000): array {
    if(str_contains($name,"\0")||preg_match('/[\r\n]/',$name)||is_link($path)||!is_file($path))throw new InvalidArgumentException('Invalid upload.');
    $size=filesize($path);if(!$size||$size>$limit)throw new InvalidArgumentException('The file exceeds the allowed size.');
    $extension=strtolower(pathinfo($name,PATHINFO_EXTENSION));$mime=(new finfo(FILEINFO_MIME_TYPE))->file($path);
    $aliases=['jpg'=>['jpg','jpeg'],'wav'=>['wav'],'mp3'=>['mp3'],'m4a'=>['m4a'],'ogg'=>['ogg','oga'],'webm'=>['webm']];
    if($extension==='csv'&&$mime==='text/plain'&&isset($types['text/csv']))$mime='text/csv';
    $office=['docx'=>['word/document.xml','application/vnd.openxmlformats-officedocument.wordprocessingml.document'],'xlsx'=>['xl/workbook.xml','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],'pptx'=>['ppt/presentation.xml','application/vnd.openxmlformats-officedocument.presentationml.presentation']];
    if(isset($office[$extension])&&in_array($mime,['application/zip',$office[$extension][1]],true)){
        if(!class_exists('ZipArchive'))throw new InvalidArgumentException('Office uploads are unavailable on this server. Please use PDF.');
        $zip=new ZipArchive();if($zip->open($path)!==true)throw new InvalidArgumentException('Invalid office document.');
        try{
            if($zip->numFiles>2000||$zip->locateName('[Content_Types].xml')===false||$zip->locateName($office[$extension][0])===false)throw new InvalidArgumentException('Invalid office document structure.');
            $expanded=0;for($i=0;$i<$zip->numFiles;$i++){
                $entry=$zip->statIndex($i);$entryName=str_replace('\\','/',$entry['name']);$expanded+=$entry['size'];
                if(preg_match('#(^/|^[a-z]:|(^|/)\.\.(/|$)|vbaProject|/embeddings/|/activeX/)#i',$entryName)||str_contains($entryName,"\0")||($entry['encryption_method']??0)!==0||$expanded>100*1024*1024||$entry['size']>max(1024*1024,100*$entry['comp_size']))throw new InvalidArgumentException('Unsafe or oversized office document.');
            }
            $contentInfo=$zip->statName('[Content_Types].xml');if($contentInfo['size']>1024*1024)throw new InvalidArgumentException('Oversized office document manifest.');
            $content=$zip->getFromName('[Content_Types].xml');if(!$content||preg_match('/<!DOCTYPE|<!ENTITY|macroEnabled/i',$content))throw new InvalidArgumentException('Macro-enabled documents are not accepted.');
        }finally{$zip->close();}
        $mime=$office[$extension][1];
    }
    if(!isset($types[$mime])||!in_array($extension,$aliases[$types[$mime]]??[$types[$mime]],true))throw new InvalidArgumentException('The filename and detected file type must match an allowed format.');
    if(str_starts_with($mime,'image/')){
        $image=@getimagesize($path);
        if(!$image||($image['mime']??'')!==$mime||$image[0]<1||$image[1]<1||$image[0]>10000||$image[1]>10000||$image[0]*$image[1]>$pixels)throw new InvalidArgumentException('Use a valid image within the supported dimensions.');
    }
    // Scan bounded chunks without loading a 64 MB video into PHP memory.
    $stream=fopen($path,'rb');if(!$stream)throw new InvalidArgumentException('The file could not be checked.');$tail='';$pdf=$mime==='application/pdf';
    try{while(!feof($stream)){
        $chunk=$tail.fread($stream,65536);
        if(preg_match('/<\?(?:php|=)/i',$chunk))throw new InvalidArgumentException('Executable content is not accepted.');
        $pdfNames=$pdf?preg_replace_callback('/#([0-9a-f]{2})/i',fn($m)=>chr(hexdec($m[1])),$chunk):'';
        if($pdf&&preg_match('#/(?:JavaScript|JS|Launch|EmbeddedFile|RichMedia|XFA)(?=[\s/<\[\(])#i',$pdfNames))throw new InvalidArgumentException('Use a PDF without scripts or embedded attachments.');
        $tail=substr($chunk,-256);
    }}finally{fclose($stream);}
    if($pdf){$stream=fopen($path,'rb');try{$head=fread($stream,8);fseek($stream,max(0,$size-4096));$end=stream_get_contents($stream);}finally{fclose($stream);}if(!str_starts_with($head,'%PDF-')||!str_contains($end,'%%EOF'))throw new InvalidArgumentException('The PDF is incomplete or corrupt.');}
    return ['mime'=>$mime,'extension'=>$types[$mime],'size'=>$size];
}
function az_validate_upload95(array $file,array $types,int $limit,int $pixels=40000000): array {
    if(!is_int($file['error']??null)||$file['error']!==UPLOAD_ERR_OK||!is_string($file['tmp_name']??null)||!is_string($file['name']??null)||!is_uploaded_file($file['tmp_name']))throw new InvalidArgumentException('Choose a file that uploaded successfully.');
    return az_inspect_upload95($file['tmp_name'],$file['name'],$types,$limit,$pixels);
}
function az_private_file_safe95(string $path,string $directory): bool {
    $file=realpath($path);$root=realpath($directory);
    $normal=fn(string $value)=>PHP_OS_FAMILY==='Windows'?strtolower(str_replace('\\','/',$value)):str_replace('\\','/',$value);
    return $file!==false&&$root!==false&&!is_link($path)&&is_file($file)&&str_starts_with($normal($file),rtrim($normal($root),'/').'/');
}
