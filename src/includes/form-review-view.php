<?php
declare(strict_types=1);

function st_form_upload_previews(array $files): void {
    if(!$files)return;
    echo '<div class="native-uploads">';
    foreach($files as $file){
        $url='/registration-file.php?id='.(int)$file['id'];
        echo '<a class="native-upload-review" href="'.$url.'" target="_blank" rel="noopener">';
        if(str_starts_with($file['mime'],'image/'))echo '<img src="'.$url.'" alt="'.e($file['label']).'" loading="lazy">';
        echo '<span><strong>'.e($file['label']).'</strong><span>'.e($file['original_name']).' · '.number_format($file['size_bytes']/1024).' KB ↗</span>'.(!$file['active']?'<small>Previous response version</small>':'').'</span></a>';
    }
    echo '</div>';
}
function st_form_response_review(array $order,array $staff): void {
    $response=az_form_response((int)$order['id']);if(!$response)return;
    $schema=json_decode($response['schema_json'],true);$hasPayment=(int)$order['amount']>0;
    foreach(az_visible_form_fields(['registration_form'=>$response['schema_json'],'_ticket_id'=>$order['ticket_type'],'_ticket_price'=>(int)$order['amount']],json_decode($response['raw_answers'],true)?:[],'registration',(json_decode($order['snapshot'],true)['game_id']??'')) as $field)if(($field['purpose']??'')==='payment')$hasPayment=true;
    st_form_upload_previews(az_registration_files((int)$order['id']));
    $ticketPayment=json_decode($order['snapshot'],true)['ticket_payment']??null;
    if(!empty($ticketPayment['payment_dynamic']))$ticketPayment['media']=az_payment_qr_url108($order['event_slug'],$order['ticket_type'],'',$order['public_id']);
    if($ticketPayment)echo '<details class="studio-disclosure"><summary>Payment setup for this ticket · '.e(az_money((int)$order['amount'])).'</summary><div class="disclosure-content"><p>'.e($ticketPayment['label']).'</p><img class="native-form-media" src="'.e($ticketPayment['media']).'" alt="Payment QR shown for this registration" loading="lazy"><p class="help">'.nl2br(e($ticketPayment['help'])).'</p>'.(!empty($ticketPayment['payment_upi'])?'<p>UPI: '.e($ticketPayment['payment_upi']).'</p>':'').'</div></details>';
    if($response['review_note'])echo '<p class="native-review-note">'.nl2br(e($response['review_note'])).'</p>';
    if($response['max_score'])echo '<p class="help">Automatic quiz score: '.(int)$response['score'].' / '.(int)$response['max_score'].'</p>';
    if(cms_can($staff,'submissions','edit')&&cms_can($staff,'tickets','view')&&in_array($order['state'],['FORM_PENDING','PAID_REVIEW'],true)){
        echo '<form method="post" class="form-grid native-response-review">';cms_hidden('review_form_response');
        echo '<input type="hidden" name="id" value="'.(int)$order['id'].'"><input type="hidden" name="revision" value="'.(int)$response['revision'].'">';
        if($hasPayment){
            echo '<p class="help wide">Match the screenshot with the actual payment in your receiving account before approval.</p><label class="field"><span>Verified transaction reference</span><input name="reference" minlength="6" maxlength="100"></label><label class="field"><span>Amount received (₹)</span><input name="received_amount" type="number" min="0" step="0.01" value="'.number_format($order['amount']/100,2,'.','').'"></label><label class="check-field wide"><input type="checkbox" name="bank_confirmed" value="yes"><span>I checked the payment reference and amount in the receiving account.</span></label>';
        }
        echo '<label class="field wide"><span>Review note (required for correction or decline)</span><textarea name="note" maxlength="1000" rows="3"></textarea></label><div class="form-actions wide"><button class="primary-button" name="decision" value="approve">Approve & issue ticket</button>';
        if($order['state']!=='PAID_REVIEW')echo '<button class="quiet-button" name="decision" value="correct">Request correction</button><button class="danger-button" name="decision" value="decline">Decline application</button>';
        echo '</div></form>';
    }
    echo '<details class="studio-disclosure"><summary>Response and review history</summary>';
    $q=cms_db()->prepare('SELECT r.*,u.display_name FROM az_form_reviews r LEFT JOIN users u ON u.id=r.staff_id WHERE r.order_id=? ORDER BY r.id DESC');$q->execute([$order['id']]);
    foreach($q as $review)echo '<p><strong>'.e(ucfirst($review['action'])).'</strong> · '.e($review['display_name']??'Coordinator').' · '.e(az_record_date_label($review['created_at'])).'<br>'.e($review['note']).'</p>';
    st_form_upload_previews(array_values(array_filter(az_registration_files((int)$order['id'],false),fn($file)=>!$file['active'])));echo '</details>';
}
function st_form_response_table(array $rows): void {
    $labels=[];foreach(array_slice($rows,0,50) as $row)foreach(json_decode($row['answers'],true)?:[] as $label=>$value)$labels[$label]=true;
    echo '<div class="table-wrap" tabindex="0" role="region" aria-label="Form response spreadsheet"><table><thead><tr><th>Name / reference</th><th>Status</th><th>Ticket holder</th>';
    foreach(array_keys($labels) as $label)echo '<th>'.e($label).'</th>';echo '</tr></thead><tbody>';
    foreach(array_slice($rows,0,50) as $row){$answers=json_decode($row['answers'],true)?:[];$snapshot=json_decode($row['snapshot'],true)?:[];
        echo '<tr><th scope="row">'.e($row['name']).'<br><small>'.e($row['email']).'<br>'.e($row['public_id']).'</small></th><td>'.e(az_payment_state_label($row['state'])).'</td><td>'.e(($snapshot['registration_kind']??'individual')==='team'?($snapshot['team_name']??'Team ticket'):$row['name']).'</td>';
        foreach(array_keys($labels) as $label)echo '<td style="white-space:pre-line">'.e(is_string($answers[$label]??null)?$answers[$label]:'—').'</td>';echo '</tr>';
    }
    echo '</tbody></table></div><p class="help">Columns come from the submitted questions. Use the individual view to open private files and approve responses.</p>';
}
function az_export_form_responses(array $user,?int $eventId,string $environment): never {
    if($user['must_change_password']||!cms_can($user,'operations','export')){http_response_code(403);exit('Export access denied.');}
    $query=st_operation_query($user,'payments',$eventId,$environment);$db=cms_db();$q=$db->prepare($query['sql']);$q->execute($query['params']);$labels=[];
    foreach($q as $row)foreach(json_decode($row['answers'],true)?:[] as $label=>$value)$labels[$label]=true;
    header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename="Anazori-form-responses-'.date('Y-m-d').'.csv"');header('X-Content-Type-Options: nosniff');
    $out=fopen('php://output','w');fputcsv($out,array_map('st_csv_cell',['Reference','Event','Name','Email','Status','Created at',...array_keys($labels)]),',','"','');
    $q->execute($query['params']);foreach($q as $row){$snapshot=json_decode($row['snapshot'],true)?:[];$answers=json_decode($row['answers'],true)?:[];$cells=[$row['public_id'],$snapshot['title']??$row['event_slug'],$row['name'],$row['email'],az_payment_state_label($row['state']),$row['created_at']];foreach(array_keys($labels) as $label)$cells[]=is_string($answers[$label]??null)?$answers[$label]:'';fputcsv($out,array_map('st_csv_cell',$cells),',','"','');}
    if($eventId)st_event_audit($user,$eventId,'form.export','CSV response spreadsheet');exit;
}
