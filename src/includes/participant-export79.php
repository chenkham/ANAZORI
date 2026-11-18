<?php
declare(strict_types=1);

function st_export_buttons79(string $section,?int $eventId,string $environment): void {
    global $u;if(!cms_can($u,'operations','export'))return;
    echo '<div class="export-actions" aria-label="Export participant details"><span>Export all details</span>';
    $filters=[];foreach(['q','status','game'] as $key)if(is_string($_GET[$key]??null)&&$_GET[$key]!=='')$filters[$key]=$_GET[$key];
    foreach(['pdf'=>'PDF','xlsx'=>'Excel','csv'=>'CSV'] as $format=>$label)echo '<a class="quiet-button" href="'.e(st_workspace_url($section,$eventId,$environment,['export'=>'details','format'=>$format,...$filters])).'">'.$label.' ↓</a>';
    echo '</div>';
}
function st_export_details79(array $user,string $section,?int $eventId,string $environment,string $format): never {
    if($user['must_change_password']||!cms_can($user,'operations','export')||!in_array($format,['pdf','xlsx','csv'],true))throw new RuntimeException('Export access denied.');
    $source=$section==='participants'&&$eventId&&cms_can($user,'payments')?'payments':$section;
    $filters=[];foreach(['q','status','game'] as $key)$filters[$key]=is_string($_GET[$key]??null)?mb_substr($_GET[$key],0,100):'';
    $query=st_operation_query($user,$source,$eventId,$environment,$filters['q'],$filters['status'],$filters['game']);$q=cms_db()->prepare($query['sql']);$q->execute($query['params']);$records=$q->fetchAll();$labels=[];$rows=[];
    foreach($records as $record){
        $snapshot=json_decode($record['snapshot']??'{}',true)?:[];$data=json_decode($record['form_data']??'{}',true)?:[];
        $answers=$source==='submissions'?($data['answers']??[]):(json_decode($record['answers']??'{}',true)?:[]);
        $row=['Reference'=>$record['public_id']??$record['ticket_id']??$data['reference']??(string)$record['id'],'Event'=>$snapshot['title']??$record['event_title']??'','Name'=>$record['name'],'Email'=>$record['email']];
        if($source==='payments')$row+=['Registration type'=>$snapshot['registration_kind']??'individual','Team name'=>$snapshot['team_name']??'','Game'=>$snapshot['game']??'','Status'=>az_payment_state_label($record['state']),'Amount (INR)'=>number_format($record['amount']/100,2,'.',''),'Transaction reference'=>$record['payment_reference']??'','Review note'=>$record['review_note']??'','Registered at'=>$record['created_at']];
        elseif($source==='submissions')$row+=['Response type'=>$data['type']??'','Phone'=>$record['phone'],'Status'=>($data['type']??'')==='INTEREST'?'Interest received':$record['status'],'Submitted at'=>$record['created_at']];
        elseif($source==='tickets')$row+=['Ticket status'=>$record['status'],'Checked in'=>$record['checked_at']??'','Game'=>$snapshot['game']??''];
        else $row+=['Registrations'=>(string)$record['orders'],'Approved entries'=>(string)$record['entries'],'Created at'=>$record['created_at']];
        foreach($answers as $label=>$value)$row['Answer: '.$label]=is_array($value)?json_encode($value,JSON_UNESCAPED_UNICODE):(string)$value;
        if($source==='payments'||$source==='submissions'){
            $fileQ=cms_db()->prepare('SELECT id,label,original_name FROM az_registration_files WHERE '.($source==='payments'?'order_id':'submission_id').'=? AND active=1 ORDER BY id');$fileQ->execute([$record['id']]);
            foreach($fileQ as $file){$column='Attachment: '.$file['label'];$row[$column]=trim(($row[$column]??'')."\n".$file['original_name'].' · '.az_origin().'/registration-file.php?id='.$file['id']);}
        }
        foreach(array_keys($row) as $label)$labels[$label]=true;$rows[]=$row;
    }
    $headers=array_keys($labels);if(!$headers)$headers=['Reference','Event','Name','Email'];
    $name='Anazori-'.$section.'-'.($eventId??'all').'-'.date('Y-m-d');
    header('Cache-Control: private, no-store');header('X-Content-Type-Options: nosniff');
    if($eventId)st_event_audit($user,$eventId,'participants.export',strtoupper($format).' · '.count($rows).' records');
    if($format==='csv'){
        header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename="'.$name.'.csv"');$out=fopen('php://output','w');fwrite($out,"\xEF\xBB\xBF");fputcsv($out,array_map('st_csv_cell',$headers),',','"','');
        foreach($rows as $row)fputcsv($out,array_map(fn($label)=>st_csv_cell($row[$label]??''),$headers),',','"','');exit;
    }
    if($format==='xlsx'){
        $xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>';
        foreach([array_combine($headers,$headers),...$rows] as $index=>$row){$xml.='<row r="'.($index+1).'">';foreach($headers as $label){$value=preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u','',(string)($row[$label]??''));$xml.='<c t="inlineStr"><is><t xml:space="preserve">'.htmlspecialchars($value,ENT_XML1|ENT_QUOTES,'UTF-8').'</t></is></c>';}$xml.='</row>';}
        $xml.='</sheetData></worksheet>';
        $files=['[Content_Types].xml'=>'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
            '_rels/.rels'=>'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            'xl/workbook.xml'=>'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Participant details" sheetId="1" r:id="rId1"/></sheets></workbook>',
            'xl/_rels/workbook.xml.rels'=>'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            'xl/worksheets/sheet1.xml'=>$xml];
        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');header('Content-Disposition: attachment; filename="'.$name.'.xlsx"');echo st_xlsx_zip79($files);exit;
    }
    $options=new Dompdf\Options();$options->set('isRemoteEnabled',false);$options->set('isPhpEnabled',false);$options->set('isJavascriptEnabled',false);$options->set('chroot',dirname(__DIR__).'/assets');$pdf=new Dompdf\Dompdf($options);
    $html='<html><meta charset="utf-8"><style>@page{margin:30px}body{font-family:DejaVu Sans;font-size:10px;color:#251635}h1{font-size:20px}h2{font-size:15px;color:#7134a3}p{line-height:1.5}table{width:100%;border-collapse:collapse;table-layout:fixed}tr{page-break-inside:avoid}td,th{text-align:left;vertical-align:top;padding:7px;border-bottom:1px solid #ddd;overflow-wrap:break-word}th{width:30%;color:#694b7a}h3{font-size:10px;margin:13px 0 3px;color:#694b7a;page-break-after:avoid}p{margin:3px 0 10px;word-wrap:break-word}.record{page-break-before:always}.record:first-of-type{page-break-before:auto}</style><h1>ANAZORI · Participant details</h1><p>'.count($rows).' records · '.e(date('d M Y')).'<br>Private event preparation records. Attachment links require authorised sign-in.</p>';
    foreach($rows as $row){$html.='<section class="record"><h2>'.e($row['Name'].' · '.$row['Reference']).'</h2>';foreach($row as $label=>$value)if($value!=='')$html.='<h3>'.e($label).'</h3><p>'.nl2br(e($value)).'</p>';$html.='</section>';}
    $pdf->loadHtml($html.'</html>');$pdf->setPaper('A4');$pdf->render();$pdf->stream($name.'.pdf',['Attachment'=>true]);exit;
}
/** Minimal ZIP with stored entries: real XLSX, no optional PHP zip extension required. */
function st_xlsx_zip79(array $files): string {
    $body='';$directory='';$count=0;
    foreach($files as $name=>$data){$offset=strlen($body);$size=strlen($data);$crc=crc32($data);$length=strlen($name);
        $body.=pack('VvvvvvVVVvv',0x04034b50,20,0,0,0,33,$crc,$size,$size,$length,0).$name.$data;
        $directory.=pack('VvvvvvvVVVvvvvvVV',0x02014b50,20,20,0,0,0,33,$crc,$size,$size,$length,0,0,0,0,0,$offset).$name;$count++;
    }
    return $body.$directory.pack('VvvvvVVv',0x06054b50,0,0,$count,$count,strlen($directory),strlen($body),0);
}
