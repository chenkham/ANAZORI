<?php
declare(strict_types=1);

function az_form_types(): array {
    return ['text'=>'Short answer','textarea'=>'Paragraph','radio'=>'Multiple choice','multiselect'=>'Checkboxes','select'=>'Dropdown',
        'file'=>'File upload','scale'=>'Linear scale','rating'=>'Rating','grid'=>'Multiple choice grid','checkgrid'=>'Checkbox grid',
        'date'=>'Date','time'=>'Time','email'=>'Email address','tel'=>'Phone number','number'=>'Number','checkbox'=>'Consent checkbox',
        'section'=>'Section break','description'=>'Title and description','image'=>'Image / payment QR','video'=>'Video'];
}
function az_form_layout(string $type): bool { return in_array($type,['section','description','image','video'],true); }
function az_form_lines(mixed $value,int $limit=50): array {
    if(is_array($value)){foreach($value as $item)if(!is_string($item))throw new InvalidArgumentException('Check the list of choices.');$value=implode("\n",$value);}
    if(!is_string($value)||strlen($value)>30000)throw new InvalidArgumentException('Check the list of choices.');
    $lines=array_values(array_unique(array_filter(array_map('trim',preg_split('/\R/',$value)),fn($v)=>$v!=='')));
    if(count($lines)>$limit)throw new InvalidArgumentException('Use up to '.$limit.' items in this list.');
    foreach($lines as $line)if(mb_strlen($line)>120||str_contains($line,"\0"))throw new InvalidArgumentException('Keep each list item under 120 characters.');
    return $lines;
}
function az_registration_fields(array $event,string $phase='registration'): array {
    $stored=json_decode($event[$phase==='interest'?'interest_form':'registration_form']??'',true);
    if(is_array($stored))return $stored;
    $fields=[['id'=>'college','label'=>'College / organisation','type'=>'text','required'=>true,'options'=>[]],['id'=>'phone','label'=>'Contact number','type'=>'tel','required'=>true,'options'=>[]]];
    if($phase==='interest')return [$fields[0]];
    foreach(cms_questions($event) as $i=>$label)$fields[]=['id'=>'extra-'.$i,'label'=>$label,'type'=>'textarea','required'=>true,'options'=>[]];
    return $fields;
}
function az_validate_registration_fields(mixed $rows,array $games=[]): string {
    if(!is_array($rows)||count($rows)>100)throw new InvalidArgumentException('Use up to 100 questions and layout blocks per form.');
    $fields=[];$ids=[];$labels=[];
    foreach($rows as $row){
        if(!is_array($row))throw new InvalidArgumentException('Invalid form item.');
        $label=az_setup_text($row,'label',120);if($label==='')continue;
        $id=az_setup_text($row,'id',60)?:'field-'.bin2hex(random_bytes(6));
        if(!preg_match('/^[a-z0-9-]{2,60}$/D',$id)||isset($ids[$id]))throw new InvalidArgumentException('Each form item needs a unique identity. Reload the editor.');
        $type=az_setup_text($row,'type',20);if(!isset(az_form_types()[$type]))throw new InvalidArgumentException('Choose a supported answer type.');
        if(!az_form_layout($type)&&isset($labels[mb_strtolower($label)]))throw new InvalidArgumentException('Use a different label for each answer field.');
        $options=az_form_lines($row['options']??'');
        if(in_array($type,['radio','multiselect','select','grid','checkgrid'],true)&&count($options)<2)throw new InvalidArgumentException($label.' needs at least two choices / columns.');
        $gridRows=az_form_lines($row['rows']??'',25);
        if(in_array($type,['grid','checkgrid'],true)&&!$gridRows)throw new InvalidArgumentException('Add rows for '.$label.'.');
        $game=az_setup_text($row,'game',60);if($game!==''&&!in_array($game,array_column($games,'id'),true))throw new InvalidArgumentException('Choose an existing game for '.$label.'.');
        $condition=az_setup_text($row,'condition_field',60);$conditionValue=az_setup_text($row,'condition_value',120);
        if($condition!==''&&(!isset($ids[$condition])||az_form_layout($ids[$condition]['type'])||in_array($ids[$condition]['type'],['file','grid','checkgrid'],true)))throw new InvalidArgumentException('Conditions must use an earlier answer field.');
        $min=az_setup_text($row,'min',20);$max=az_setup_text($row,'max',20);
        if($min!==''&&!is_numeric($min)||$max!==''&&!is_numeric($max)||$min!==''&&$max!==''&&(float)$min>(float)$max)throw new InvalidArgumentException('Check the minimum and maximum for '.$label.'.');
        if(in_array($type,['scale','rating'],true)){
            $min=$type==='rating'?'1':($min===''?'1':$min);$max=$max===''?'5':$max;
            if(!ctype_digit($min)||!ctype_digit($max)||(int)$min>1||(int)$max<2||(int)$max>10)throw new InvalidArgumentException('Use a scale starting at 0 or 1 and ending from 2 to 10.');
        }
        $media=az_setup_text($row,'media',500);
        $paymentUpi=az_setup_text($row,'payment_upi',120);
        $paymentTicket=az_setup_text($row,'payment_ticket',60);
        $dynamic=!empty($row['payment_dynamic']);$paymentName=az_setup_text($row,'payment_name',80);
        if($dynamic&&($type!=='image'||$paymentUpi===''))throw new InvalidArgumentException('An automatic payment QR needs an image block and a receiving UPI ID.');
        if($paymentTicket!==''&&($type!=='image'||!preg_match('/^[a-z0-9-]{3,60}$/D',$paymentTicket)))throw new InvalidArgumentException('Link a payment QR to a valid ticket category.');
        if($paymentUpi!==''&&($type!=='image'||!preg_match('/^[a-zA-Z0-9._-]{2,80}@[a-zA-Z0-9.-]{2,30}$/D',$paymentUpi)))throw new InvalidArgumentException('Enter a valid UPI ID for the payment QR.');
        if($media!==''&&!cms_valid_media($media,$type==='video'?'video':'image'))throw new InvalidArgumentException('Choose an uploaded '.($type==='video'?'video':'image').' from Media library.');
        if(in_array($type,['image','video'],true)&&$media===''&&!$dynamic)throw new InvalidArgumentException('Choose media for '.$label.'.');
        $validation=az_setup_text($row,'validation',20);
        if(!in_array($validation,['','email','url','contains','not_contains','length','number'],true))throw new InvalidArgumentException('Choose a validation rule.');
        $fileTypes=az_setup_text($row,'file_types',20)?:'images-pdf';
        if(!in_array($fileTypes,['images','pdf','images-pdf','documents','audio','video','all'],true))throw new InvalidArgumentException('Choose supported upload types.');
        $fileCount=filter_var($row['file_count']??1,FILTER_VALIDATE_INT);$fileSize=filter_var($row['file_size']??5,FILTER_VALIDATE_INT);
        if(!$fileCount||$fileCount>10||!$fileSize||$fileSize>20)throw new InvalidArgumentException('Allow 1–10 files, up to 20 MB each.');
        $purpose=az_setup_text($row,'purpose',20);if(!in_array($purpose,['','payment','identity'],true))throw new InvalidArgumentException('Choose a file purpose.');
        if($paymentTicket!==''||$dynamic)$purpose='payment';
        $points=filter_var($row['points']??0,FILTER_VALIDATE_INT);if($points===false||$points<0||$points>1000)throw new InvalidArgumentException('Use 0–1000 points.');
        $field=['id'=>$id,'label'=>$label,'type'=>$type,'required'=>!az_form_layout($type)&&isset($row['required']),'options'=>$options,'rows'=>$gridRows,
            'help'=>az_setup_text($row,'help',2000),'placeholder'=>az_setup_text($row,'placeholder',120),'game'=>$game,
            'allowed_values'=>az_form_lines($row['allowed_values']??'',500),'condition_field'=>$condition,'condition_value'=>$conditionValue,
            'min'=>$min,'max'=>$max,'validation'=>$validation,'validation_value'=>az_setup_text($row,'validation_value',120),
            'validation_message'=>az_setup_text($row,'validation_message',200),'other'=>in_array($type,['radio','multiselect'],true)&&isset($row['other']),'shuffle'=>isset($row['shuffle']),
            'media'=>$media,'payment_dynamic'=>$dynamic,'payment_name'=>$paymentName,'payment_upi'=>$paymentUpi,'payment_ticket'=>$paymentTicket,'file_types'=>$fileTypes,'file_count'=>$fileCount,'file_size'=>$fileSize,'purpose'=>$purpose,
            'low_label'=>az_setup_text($row,'low_label',60),'high_label'=>az_setup_text($row,'high_label',60),
            'points'=>$points,'answer_key'=>az_form_lines($row['answer_key']??'',50),'feedback'=>az_setup_text($row,'feedback',500)];
        $ids[$id]=$field;if(!az_form_layout($type))$labels[mb_strtolower($label)]=true;$fields[]=$field;
    }
    return json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}
function az_form_settings(array $event,string $phase='registration'): array {
    $stored=json_decode($event[$phase.'_settings']??'{}',true);
    $settings=array_replace(['accepting'=>true,'one_response'=>true,'allow_edit'=>true,'progress'=>true,'shuffle'=>false,'quiz'=>false,'show_score'=>false,
        'confirmation'=>$phase==='interest'?'Thank you for sharing your interest.':'Your application is with the event coordinators. Your ticket will appear after approval.'],is_array($stored)?$stored:[]);
    if($phase==='registration')$settings['one_response']=true;
    if($phase==='interest'){$settings['confirmation']='Thank you for sharing your interest.';$settings['quiz']=false;$settings['show_score']=false;}
    if(az_participation_mode($event)==='contribution'){$settings['confirmation']='Thank you. Your contribution has been sent to the event team.';$settings['allow_edit']=false;$settings['quiz']=false;$settings['show_score']=false;}
    return $settings;
}
function az_validate_form_settings(mixed $input): string {
    if(!is_array($input))throw new InvalidArgumentException('Check the form settings.');$settings=[];
    foreach(['accepting','one_response','allow_edit','progress','shuffle','quiz','show_score'] as $key)$settings[$key]=isset($input[$key]);
    $settings['confirmation']=az_setup_text($input,'confirmation',1000)?:'Your response has been received.';
    return json_encode($settings,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}
function az_visible_form_fields(array $event,array $answers,string $phase='registration',string $gameId=''): array {
    $result=[];$visible=[];$section=true;
    foreach(az_registration_fields($event,$phase) as $field){
        $show=empty($field['game'])||$field['game']===$gameId;
        if($phase==='registration'&&isset($event['_ticket_price'])&&(int)$event['_ticket_price']===0&&($field['purpose']??'')==='payment')$show=false;
        if($phase==='registration'&&!empty($field['payment_ticket'])&&isset($event['_ticket_id']))$show=$show&&$field['payment_ticket']===$event['_ticket_id'];
        if(!empty($field['condition_field'])){
            $controller=$field['condition_field'];$value=$answers[$controller]??'';
            $show=$show&&isset($visible[$controller])&&(is_array($value)?in_array($field['condition_value'],$value,true):$value===$field['condition_value']);
        }
        if($field['type']==='section')$section=$show;
        elseif(!$section)$show=false;
        if($show){$result[]=$field;$visible[$field['id']]=true;}
    }
    return $result;
}
function az_registration_answers(array $event,array $answers,string $phase='registration',string $gameId=''): array {
    $validated=[];
    foreach(az_visible_form_fields($event,$answers,$phase,$gameId) as $field){
        $type=$field['type'];if(az_form_layout($type)||$type==='file')continue;
        $label=$field['label'];$value=$answers[$field['id']]??'';$required=!empty($field['required']);
        if(in_array($type,['grid','checkgrid'],true)){
            if($value==='')$value=[];
            if(!is_array($value)||count($value)>25||array_diff(array_keys($value),array_map('strval',array_keys($field['rows']))))throw new InvalidArgumentException('Check '.$label.'.');
            $result=[];
            foreach($field['rows'] as $index=>$row){
                $choice=$value[$index]??($type==='checkgrid'?[]:'');
                if($type==='checkgrid'){
                    if(!is_array($choice)||count($choice)>50)throw new InvalidArgumentException('Choose listed columns for '.$label.'.');
                    foreach($choice as $item)if(!is_string($item)||!in_array($item,$field['options'],true))throw new InvalidArgumentException('Choose listed columns for '.$label.'.');
                    $choice=implode(', ',array_values(array_filter($field['options'],fn($v)=>in_array($v,$choice,true))));
                }elseif(!is_string($choice)||$choice!==''&&!in_array($choice,$field['options'],true))throw new InvalidArgumentException('Choose a listed column for '.$label.'.');
                if($required&&$choice==='')throw new InvalidArgumentException('Answer every row of '.$label.'.');
                $result[]=$row.': '.$choice;
            }
            $validated[$label]=implode("\n",$result);continue;
        }
        if($type==='multiselect'){
            if($value==='')$value=[];
            if(!is_array($value)||count($value)>50)throw new InvalidArgumentException('Check '.$label.'.');
            foreach($value as $choice)if(!is_string($choice)||!in_array($choice,$field['options'],true))throw new InvalidArgumentException('Choose listed options for '.$label.'.');
            $choices=array_values(array_filter($field['options'],fn($v)=>in_array($v,$value,true)));
            $other=$answers[$field['id'].'-other']??'';
            if(!empty($field['other'])&&is_string($other)&&trim($other)!==''){if(mb_strlen($other)>120||str_contains($other,"\0"))throw new InvalidArgumentException('Check the other answer.');$choices[]='Other: '.trim($other);}
            if($required&&!$choices)throw new InvalidArgumentException('Choose at least one option for '.$label.'.');
            $count=count($choices);if(($field['min']??'')!==''&&$count<(int)$field['min']||($field['max']??'')!==''&&$count>(int)$field['max'])throw new InvalidArgumentException('Check how many options you chose for '.$label.'.');
            foreach($choices as $choice)if(!empty($field['allowed_values'])&&!in_array($choice,$field['allowed_values'],true))throw new InvalidArgumentException('Choose an organiser-approved value for '.$label.'.');
            $validated[$label]=implode("\n",$choices);continue;
        }
        if(!is_string($value)||mb_strlen($value)>10000||str_contains($value,"\0"))throw new InvalidArgumentException('Check '.$label.'.');
        $value=trim($value);if($required&&$value==='')throw new InvalidArgumentException('Enter '.$label.'.');
        if($value!==''){
            $valid=match($type){
                'email'=>filter_var($value,FILTER_VALIDATE_EMAIL)!==false,'tel'=>preg_match('/^\+?[0-9 ()-]{7,25}$/D',$value)===1,
                'number'=>preg_match('/^-?[0-9]{1,12}(?:\.[0-9]{1,6})?$/D',$value)===1,'date'=>az_calendar_date($value)!==null,
                'time'=>preg_match('/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/D',$value)===1,
                'scale','rating'=>ctype_digit($value)&&(int)$value>=(int)($field['min']??1)&&(int)$value<=(int)($field['max']??5),
                'select','radio'=>in_array($value,$field['options'],true)||(!empty($field['other'])&&$value==='__other__'),
                'checkbox'=>$value==='yes',default=>true};
            if(!$valid)throw new InvalidArgumentException('Enter a valid answer for '.$label.'.');
            if(!empty($field['other'])&&$value==='__other__'){$other=$answers[$field['id'].'-other']??'';if(!is_string($other)||trim($other)===''||mb_strlen($other)>120||str_contains($other,"\0"))throw new InvalidArgumentException('Enter your other answer for '.$label.'.');$value='Other: '.trim($other);}
            if(!empty($field['allowed_values'])&&!in_array($value,$field['allowed_values'],true))throw new InvalidArgumentException('Enter an organiser-issued value for '.$label.'.');
            $rule=$field['validation']??'';$needle=$field['validation_value']??'';
            $valid=match($rule){'email'=>filter_var($value,FILTER_VALIDATE_EMAIL)!==false,'url'=>filter_var($value,FILTER_VALIDATE_URL)!==false&&in_array(strtolower(parse_url($value,PHP_URL_SCHEME)??''),['http','https'],true),
                'contains'=>str_contains($value,$needle),'not_contains'=>!str_contains($value,$needle),default=>true};
            $measure=$rule==='length'?mb_strlen($value):($type==='number'||$rule==='number'?(is_numeric($value)?(float)$value:null):null);
            if($rule==='number'&&!is_numeric($value))$valid=false;
            if($measure!==null&&(($field['min']??'')!==''&&$measure<(float)$field['min']||($field['max']??'')!==''&&$measure>(float)$field['max']))$valid=false;
            if(!$valid)throw new InvalidArgumentException(($field['validation_message']??'')?:'Check the response rule for '.$label.'.');
        }
        $validated[$label]=$type==='checkbox'?($value==='yes'?'Yes':'No'):$value;
    }
    return $validated;
}
function az_public_registration_schema(array $event,string $phase='registration'): array {
    return array_map(function($field){unset($field['allowed_values'],$field['answer_key'],$field['feedback']);return $field;},az_registration_fields($event,$phase));
}
function az_setup_text(array $row,string $key,int $maximum): string {
    $value=$row[$key]??'';if(!is_string($value)||mb_strlen($value)>$maximum||str_contains($value,"\0"))throw new InvalidArgumentException('Check the '.str_replace('_',' ',$key).' field.');return trim($value);
}
function az_calendar_date(string $value): ?DateTimeImmutable {
    $date=DateTimeImmutable::createFromFormat('!Y-m-d',$value,new DateTimeZone('Asia/Kolkata'));return $date&&$date->format('Y-m-d')===$value?$date:null;
}
