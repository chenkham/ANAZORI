<?php
declare(strict_types=1);

/** Event documents are public PDFs selected from the existing media library. */
function az_event_pdf_path103(string $path): bool {
    if(strlen($path)>500)return false;
    return (bool)preg_match('#^/(?:assets|uploads)/(?:[a-z0-9_-]+/)*[a-z0-9][a-z0-9_.-]*\.pdf$#iD',$path)||$path==='/ANAZORI_V15.0_Brochure.pdf';
}

/** Empty legacy data retains its rules PDF/brochure; an explicit [] removes all links. */
function az_event_documents103(array $fields): array {
    $raw=$fields['event_documents']??'';
    if(is_string($raw)&&$raw!==''){
        $rows=json_decode($raw,true);$documents=[];
        if(!is_array($rows))return [];
        foreach(array_slice($rows,0,20) as $row){
            if(!is_array($row)||!is_string($row['label']??null)||!is_string($row['path']??null))continue;
            $label=trim($row['label']);
            if($label!==''&&mb_strlen($label)<=100&&az_event_pdf_path103($row['path']))$documents[]=['label'=>$label,'path'=>$row['path']];
        }
        return $documents;
    }
    $rules=(string)($fields['rules_pdf']??'');
    if($rules!==''&&az_event_pdf_path103($rules))return [['label'=>'Rules PDF','path'=>$rules]];
    $brochure=setting('brochure_pdf');
    return $brochure!==''&&az_event_pdf_path103($brochure)?[['label'=>'Festival brochure','path'=>$brochure]]:[];
}

function az_validate_event_documents103(mixed $rows): string {
    if(is_string($rows)){
        if(strlen($rows)>20000)throw new InvalidArgumentException('The event PDF list is too large.');
        try{$rows=json_decode($rows,true,32,JSON_THROW_ON_ERROR);}
        catch(JsonException){throw new InvalidArgumentException('Check the event PDF list.');}
    }
    if(!is_array($rows)||count($rows)>20)throw new InvalidArgumentException('Add up to 20 named event PDFs.');
    $documents=[];
    foreach($rows as $row){
        if(!is_array($row)||!is_string($row['label']??null)||!is_string($row['path']??null))throw new InvalidArgumentException('Each event PDF needs a label and a PDF file.');
        $label=trim($row['label']);$path=trim($row['path']);
        if($label===''||mb_strlen($label)>100||preg_match('/[\x00-\x1F\x7F]/u',$label))throw new InvalidArgumentException('Give each PDF a label of 1–100 characters.');
        if(!az_event_pdf_path103($path)||!cms_valid_media($path,'pdf'))throw new InvalidArgumentException('Choose an available PDF from the media library for '.$label.'.');
        $documents[]=['label'=>$label,'path'=>$path];
    }
    return json_encode($documents,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
}

function st_event_documents103(array $fields,array $media): void {
    echo '<fieldset class="wide"><legend>Event PDFs</legend><p class="help">Add up to 20 PDFs with your own labels, such as Rules PDF, Topics or Schedule. Upload a PDF here or choose one from Media library. Move rows to change the order; remove a row to hide its link. Save the event to publish changes.</p><input type="hidden" name="event_documents_editor103" value="1"><div id="event-document-rows" class="setup-list">';
    foreach(az_event_documents103($fields) as $index=>$document)st_event_document_row103((string)$index,$document,$media);
    echo '</div><button type="button" class="quiet-button" data-setup-add="event-document">Add PDF</button><template id="event-document-template">';
    st_event_document_row103('INDEX',[],$media);
    echo '</template></fieldset>';
}

function st_event_document_row103(string $index,array $document,array $media): void {
    $name='event_documents['.$index.']';$id='event-document-'.$index;
    ?>
    <details class="setup-row" <?= !$document?'open':'' ?>><summary><?= e($document['label']??'New PDF') ?></summary><div class="disclosure-content form-grid">
     <label class="field" for="<?= e($id.'-label') ?>"><span>Link label</span><input id="<?= e($id.'-label') ?>" name="<?= e($name.'[label]') ?>" value="<?= e($document['label']??'') ?>" placeholder="e.g. Rules PDF or Topics" maxlength="100" required data-setup-label></label>
     <label class="field" for="<?= e($id.'-path') ?>"><span>PDF file</span><select id="<?= e($id.'-path') ?>" name="<?= e($name.'[path]') ?>" required><option value="">Choose a PDF</option><?php foreach($media as $item):if($item['mime']!=='application/pdf'||!az_event_pdf_path103($item['path']))continue; ?><option value="<?= e($item['path']) ?>" <?= ($document['path']??'')===$item['path']?'selected':'' ?>><?= e($item['title']) ?></option><?php endforeach; ?></select>
      <span class="direct-media-upload"><span>Upload PDF here</span><input type="file" form="studio-upload-only" data-direct-media data-module="event" data-kind="pdf" accept="application/pdf"></span><small data-upload-status role="status">PDFs must be under 12 MB. Save the event after uploading.</small>
     </label>
     <?php st_setup_row_actions(); ?>
    </div></details>
    <?php
}
