<?php
declare(strict_types=1);
require_once __DIR__.'/dynamic-payment108.php';
function az_ticket_qrs85(array $fields): array {
    $links=[];$tickets=az_ticket_options81($fields,$fields['_form_game']??'');
    foreach(az_registration_fields($fields) as $field)if($field['type']==='image')foreach(az_payment_targets108($field,$tickets) as $id)$links[$id]=$field;
    return $links;
}
function az_validate_ticket_qrs85(array $fields,string $phase='registration'): void {
    $links=[];$tickets=az_ticket_options81($fields,$fields['_form_game']??'');$conditionalSection=false;
    foreach(az_registration_fields($fields,$phase) as $field){
        if($field['type']==='section')$conditionalSection=!empty($field['condition_field']);
        $targets=az_payment_targets108($field,$tickets);if(!$targets)continue;
        if($phase!=='registration'||az_participation_mode($fields)!=='registration')throw new InvalidArgumentException('Payment QR codes belong in a registration form.');
        if(!empty($field['condition_field'])||$conditionalSection)throw new InvalidArgumentException('Place payment QR codes in an unconditional section.');
        foreach($targets as $id){
            $ticket=null;foreach($tickets as $option)if($option['id']===$id)$ticket=$option;
            if(!$ticket||(int)$ticket['price']===0)throw new InvalidArgumentException('Link '.$field['label'].' to an available paid ticket.');
            if(isset($links[$id]))throw new InvalidArgumentException('Use one payment QR configuration per ticket category.');$links[$id]=true;
        }
    }
    if(!$links)return;
    foreach($tickets as $ticket)if((int)$ticket['price']>0&&!isset($links[$ticket['id']]))throw new InvalidArgumentException('Add a payment QR for '.$ticket['label'].' before publishing.');
    foreach(az_registration_fields($fields,$phase) as $field)if($field['type']==='image'&&(!empty($field['payment_upi'])||($field['purpose']??'')==='payment')&&empty($field['payment_ticket'])&&empty($field['payment_dynamic']))throw new InvalidArgumentException('Choose a linked ticket or enable an automatic QR for every payment image.');
}
function az_checkout_ticket_picker85(array $options,string $typeId,?array $editOrder=null,array $snapshot=[]): void {
    echo '<fieldset class="ticket-categories81" data-ticket-picker><legend>Choose your ticket</legend>';
    if($editOrder){echo '<input type="hidden" name="type" value="'.e($typeId).'"><p class="account-help">'.e($snapshot['type']).' · '.e(az_money((int)$editOrder['amount'])).'. Your ticket category and fee stay the same while editing.</p>';}
    else foreach($options as $option){
        echo '<label class="ticket-option"><input type="radio" name="type" value="'.e($option['id']).'"'.($typeId===$option['id']?' checked':'').' required><span><strong>'.e($option['label']).'</strong><b>'.e(az_money((int)$option['price'])).'</b>';
        if(!empty($option['description']))echo '<small>'.e($option['description']).'</small>';
        echo '<small>One ticket'.((int)($option['people']??1)>1?' covers '.(int)$option['people'].' people':'').'</small></span></label>';
    }
    echo '<p class="account-help" data-category-prompt'.($typeId!==''?' hidden':'').'>Select a ticket to see its QR code and exact payment amount.</p><p class="account-notice" data-ticket-payment-status role="status" hidden></p></fieldset>';
}
