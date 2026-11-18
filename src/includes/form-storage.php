<?php
declare(strict_types=1);

function az_install_form_storage(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='native_forms78'")->fetchColumn())return;
    $sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';$id=$sqlite?'INTEGER PRIMARY KEY AUTOINCREMENT':'INT AUTO_INCREMENT PRIMARY KEY';$text=$sqlite?'TEXT':'MEDIUMTEXT';
    $db->exec("CREATE TABLE IF NOT EXISTS az_form_responses (order_id INT PRIMARY KEY,revision INT NOT NULL DEFAULT 1,raw_answers $text NOT NULL,schema_json $text NOT NULL,settings_json $text NOT NULL,score INT NOT NULL DEFAULT 0,max_score INT NOT NULL DEFAULT 0,review_note $text,reviewed_by INT,reviewed_at VARCHAR(40))");
    $db->exec("CREATE TABLE IF NOT EXISTS az_registration_files (id $id,order_id INT,submission_id INT,participant_id INT,event_id INT NOT NULL,field_id VARCHAR(60) NOT NULL,label VARCHAR(120) NOT NULL,original_name VARCHAR(200) NOT NULL,filename VARCHAR(100) NOT NULL UNIQUE,mime VARCHAR(100) NOT NULL,size_bytes INT NOT NULL,sha256 VARCHAR(64) NOT NULL,active INT NOT NULL DEFAULT 1,created_at VARCHAR(40) NOT NULL)");
    $db->exec("CREATE TABLE IF NOT EXISTS az_form_reviews (id $id,order_id INT NOT NULL,staff_id INT NOT NULL,action VARCHAR(30) NOT NULL,note $text NOT NULL,revision INT NOT NULL,created_at VARCHAR(40) NOT NULL)");
    $db->exec("CREATE TABLE IF NOT EXISTS az_form_payment_refs (reference_hash VARCHAR(64) PRIMARY KEY,order_id INT NOT NULL,reference VARCHAR(100) NOT NULL)");
    $db->beginTransaction();
    try{
        az_lock($db);
        foreach($db->query("SELECT * FROM cms_content WHERE type='event'")->fetchAll() as $record){
            $fields=json_decode($record['data'],true)?:[];
            if($record['slug']==='inauguration')continue;
            $fields['form_workflow']='1';
            $questions=az_registration_fields($fields);
            // Retain current receiving details as editable form content during the transition.
            $methods=az_payment_methods($fields);
            if($methods&&!array_filter($questions,fn($item)=>($item['purpose']??'')==='payment')){
                foreach($methods as $i=>$method){
                    $text=trim(($method['recipient']??'')."\n".($method['upi']??'')."\n".($method['bank']??'').' '.($method['account']??'').' '.($method['ifsc']??'')."\n".($method['instructions']??''));
                    $questions[]=['id'=>'payment-info-'.$i,'label'=>$method['label'],'type'=>empty($method['qr'])?'description':'image','required'=>false,'options'=>[],'help'=>$text,'media'=>$method['qr']??''];
                }
                $questions[]=['id'=>'payment-reference','label'=>'Payment transaction reference','type'=>'text','required'=>true,'options'=>[]];
                $questions[]=['id'=>'payment-screenshot','label'=>'Payment screenshot','type'=>'file','required'=>true,'options'=>[],'file_types'=>'images','file_count'=>1,'file_size'=>5,'purpose'=>'payment'];
                $fields['registration_form']=json_encode($questions,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
            }
            $db->prepare('UPDATE cms_content SET data=?,revision=revision+1 WHERE id=?')->execute([json_encode($fields,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE),$record['id']]);
        }
        az_schema_marker($db,'native_forms78');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
function az_form_response(int $orderId): ?array {
    $q=cms_db()->prepare('SELECT * FROM az_form_responses WHERE order_id=?');$q->execute([$orderId]);return $q->fetch()?:null;
}
function az_registration_files(int $orderId,bool $activeOnly=true): array {
    $q=cms_db()->prepare('SELECT * FROM az_registration_files WHERE order_id=?'.($activeOnly?' AND active=1':'').' ORDER BY id');$q->execute([$orderId]);return $q->fetchAll();
}
function az_form_file_mimes(): array {
    return ['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp','image/gif'=>'gif','application/pdf'=>'pdf','text/plain'=>'txt','text/csv'=>'csv',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'=>'docx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'=>'xlsx','application/vnd.openxmlformats-officedocument.presentationml.presentation'=>'pptx',
        'audio/mpeg'=>'mp3','audio/wav'=>'wav','audio/x-wav'=>'wav','audio/ogg'=>'ogg','video/mp4'=>'mp4','video/webm'=>'webm'];
}
function az_form_file_allowed(string $mime,string $group): bool {
    if(!isset(az_form_file_mimes()[$mime]))return false;
    return match($group){'images'=>str_starts_with($mime,'image/'),'pdf'=>$mime==='application/pdf','images-pdf'=>str_starts_with($mime,'image/')||$mime==='application/pdf',
        'audio'=>str_starts_with($mime,'audio/'),'video'=>str_starts_with($mime,'video/'),'documents'=>!str_starts_with($mime,'image/')&&!str_starts_with($mime,'audio/')&&!str_starts_with($mime,'video/'),default=>true};
}
function az_form_file_accept(string $group): string {
    return implode(',',array_keys(array_filter(az_form_file_mimes(),fn($extension,$mime)=>az_form_file_allowed($mime,$group),ARRAY_FILTER_USE_BOTH)));
}
function az_form_file_directory(): string {
    $directory=getenv('ANAZORI_REGISTRATION_FILE_DIR')?:dirname(__DIR__,2).'/anazori-private/registration-files';
    return az_private_directory90($directory);
}
/** Validate all uploads before writing any, and never accept client-supplied file IDs. */
function az_collect_form_uploads(array $event,array $answers,array $files,string $phase,string $gameId,array $existing=[]): array {
    $result=[];$total=0;$count=0;
    foreach(az_visible_form_fields($event,$answers,$phase,$gameId) as $field){
        if($field['type']!=='file')continue;$id=$field['id'];$uploads=[];
        $errors=$files['error'][$id]??[];if(!is_array($errors))throw new InvalidArgumentException('Check the upload for '.$field['label'].'.');
        foreach($errors as $i=>$error){
            if($error===UPLOAD_ERR_NO_FILE)continue;
            $tmp=$files['tmp_name'][$id][$i]??'';$name=$files['name'][$id][$i]??'';
            if($error!==UPLOAD_ERR_OK||!is_string($tmp)||!is_uploaded_file($tmp))throw new InvalidArgumentException('The upload for '.$field['label'].' did not complete.');
            $allowed=array_filter(az_form_file_mimes(),fn($extension,$type)=>az_form_file_allowed($type,$field['file_types']??'images-pdf'),ARRAY_FILTER_USE_BOTH);
            $info=az_validate_upload95(['error'=>$error,'tmp_name'=>$tmp,'name'=>$name],$allowed,(int)($field['file_size']??5)*1024*1024);$size=$info['size'];$mime=$info['mime'];
            $original=preg_replace('/[^\pL\pN ._()-]/u','_',basename(str_replace('\\','/',is_string($name)?$name:'upload')));
            $uploads[]=['tmp_name'=>$tmp,'original_name'=>mb_substr($original?:'upload',0,190),'mime'=>$mime,'size_bytes'=>$size,'sha256'=>hash_file('sha256',$tmp),'filename'=>bin2hex(random_bytes(24)).'.'.az_form_file_mimes()[$mime]];
            $total+=$size;$count++;
        }
        $retained=array_values(array_filter($existing,fn($file)=>$file['field_id']===$id));
        if(!$uploads){$count+=count($retained);$total+=array_sum(array_column($retained,'size_bytes'));}
        if(count($uploads?:$retained)>(int)($field['file_count']??1)||$count>20||$total>60*1024*1024)throw new InvalidArgumentException('Upload fewer files. A response supports up to 20 files and 60 MB total.');
        if(!empty($field['required'])&&!$uploads&&!$retained)throw new InvalidArgumentException('Upload '.$field['label'].'.');
        $result[$id]=['field'=>$field,'new'=>$uploads,'retained'=>$uploads?[]:$retained];
    }
    return $result;
}
function az_save_form_uploads(PDO $db,array $groups,int $eventId,?int $participantId,?int $orderId,?int $submissionId,array &$written): array {
    $answers=[];
    if($orderId)$db->prepare('UPDATE az_registration_files SET active=0 WHERE order_id=?')->execute([$orderId]);
    foreach($groups as $id=>$group){
        $names=[];$field=$group['field'];
        foreach($group['retained'] as $file){$db->prepare('UPDATE az_registration_files SET active=1 WHERE id=?')->execute([$file['id']]);$names[]=$file['original_name'];}
        foreach($group['new'] as $file){
            $destination=az_form_file_directory().DIRECTORY_SEPARATOR.$file['filename'];
            if(!move_uploaded_file($file['tmp_name'],$destination))throw new RuntimeException('The file could not be stored. Try again.');
            @chmod($destination,0600);$written[]=$destination;
            $db->prepare('INSERT INTO az_registration_files(order_id,submission_id,participant_id,event_id,field_id,label,original_name,filename,mime,size_bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')->execute([$orderId,$submissionId,$participantId,$eventId,$id,$field['label'],$file['original_name'],$file['filename'],$file['mime'],$file['size_bytes'],$file['sha256'],gmdate('c')]);
            $names[]=$file['original_name'];
        }
        $answers[$field['label']]=implode("\n",$names);
    }
    return $answers;
}
function az_serve_registration_file(int $id): never {
    $q=cms_db()->prepare('SELECT * FROM az_registration_files WHERE id=?');$q->execute([$id]);$file=$q->fetch();
    $participant=az_participant();$staff=cms_user();
    $owner=$file&&$participant&&!empty($file['participant_id'])&&(int)$file['participant_id']===(int)$participant['id'];
    $reviewer=$file&&$staff&&!$staff['must_change_password']&&(cms_can($staff,'submissions','view')||cms_can($staff,'payments','view'))&&st_can_event($staff,(int)$file['event_id']);
    if(!$file||!($owner||$reviewer)||!preg_match('/^[a-f0-9]{48}\.[a-z0-9]{2,5}$/D',$file['filename'])){http_response_code(404);exit('File unavailable.');}
    $path=az_form_file_directory().DIRECTORY_SEPARATOR.$file['filename'];
    if(!az_private_file_safe95($path,az_form_file_directory())||!hash_equals($file['sha256'],hash_file('sha256',$path))){http_response_code(404);exit('File unavailable.');}
    header('Cross-Origin-Resource-Policy: same-origin');header('Content-Type: '.$file['mime']);header('X-Content-Type-Options: nosniff');header('Cache-Control: private, no-store');header("Content-Security-Policy: default-src 'none'; sandbox");
    $inline=str_starts_with($file['mime'],'image/')||$file['mime']==='application/pdf';
    header('Content-Disposition: '.($inline?'inline':'attachment').'; filename="registration-file.'.pathinfo($file['filename'],PATHINFO_EXTENSION).'"');
    header('Content-Length: '.filesize($path));readfile($path);exit;
}
