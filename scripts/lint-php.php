<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit;
$root=dirname(__DIR__);$count=0;
$directories=new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),fn($entry)=>!$entry->isDir()||!in_array($entry->getFilename(),['.local','node_modules','archive'],true));
$files=new RecursiveIteratorIterator($directories);
foreach($files as $file){
 $relative=str_replace('\\','/',substr($file->getPathname(),strlen($root)+1));
 if(!$file->isFile()||$file->getExtension()!=='php'||preg_match('#^(?:\.local|node_modules|tests/archive)/#',$relative))continue;
 $process=proc_open(['php','-l',$file->getPathname()],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
 fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
 if(proc_close($process)!==0)throw new RuntimeException($relative."\n".$output.$errors);$count++;
}
echo "PASS PHP syntax across $count application, dependency and check files.\n";
