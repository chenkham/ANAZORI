<?php
declare(strict_types=1);

function az_registration_form(array $event,string $phase='registration',array $values=[],array $uploads=[],?callable $ticketPicker=null): void {
    $settings=az_form_settings($event,$phase);$items=az_registration_fields($event,$phase);
    $paymentAnchor=null;
    if($ticketPicker){foreach($items as $field)if($field['type']==='image'&&(!empty($field['payment_ticket'])||!empty($field['payment_upi'])||($field['purpose']??'')==='payment')){$paymentAnchor=$field['id'];break;}}
    echo '<div class="native-form-sections" data-native-form data-progress="'.(!empty($settings['progress'])?'1':'0').'" data-shuffle="'.(!empty($settings['shuffle'])?'1':'0').'">';
    $sectionOpen=false;
    foreach($items as $field){
        if(!$sectionOpen||$field['type']==='section'){
            if($sectionOpen)echo '</section>';
            echo '<section class="native-form-section" data-form-section>'; $sectionOpen=true;
        }
        if($ticketPicker&&$field['id']===$paymentAnchor){$ticketPicker();$ticketPicker=null;}
        az_registration_field($field,$values,$uploads);
    }
    if($ticketPicker)$ticketPicker();
    if($sectionOpen)echo '</section>';
    echo '<div class="native-form-navigation" hidden><span data-form-progress role="status"></span><button class="text-link" type="button" data-form-back>← Back</button><button class="button button-orange" type="button" data-form-next>Next section ›</button></div></div>';
}
function az_registration_field(array $field,array $values=[],array $uploads=[]): void {
    $id='registration-'.$field['id'];$name='answers['.$field['id'].']';$type=$field['type'];$value=$values[$field['id']]??'';
    $required=!empty($field['required'])?' required':'';
    $attributes=' data-field-id="'.e($field['id']).'" data-field-game="'.e($field['game']??'').'" data-field-ticket="'.e($field['payment_ticket']??'').'" data-field-purpose="'.e($field['purpose']??'').'" data-condition-field="'.e($field['condition_field']??'').'" data-condition-value="'.e($field['condition_value']??'').'" data-item-type="'.e($type).'"';
    if(!empty($field['payment_ticket']))$attributes.=' hidden';
    if(!empty($field['payment_dynamic']))$attributes.=' data-dynamic-payment108';
    echo '<div class="registration-question native-form-item native-form-item--'.e($type).'"'.$attributes.'>';
    $label=e($field['label']).(!empty($field['required'])?' <span class="required-mark" aria-label="required">*</span>':(!az_form_layout($type)?' <small>(optional)</small>':''));
    if(az_form_layout($type)){
        echo '<h3>'.$label.'</h3>';
        if(!empty($field['help']))echo '<p class="account-help">'.nl2br(e($field['help'])).'</p>';
        if($type==='image'&&!empty($field['payment_dynamic'])){
            echo '<p class="account-help" data-linked-ticket-amount></p><p class="account-help" data-payment-reference108></p><a data-dynamic-qr-link108 target="_blank" rel="noopener"><img class="native-form-media" data-dynamic-qr108 alt="Payment QR for the selected ticket" width="260" height="260" hidden></a><div class="native-payment-actions"><a class="button button-orange" data-payment-action data-upi-pay="'.e($field['payment_upi']).'" data-pay-name="'.e($field['payment_name']??'Anazori').'">Pay with UPI ↗</a><a class="text-link" data-payment-action data-save-dynamic108 download="anazori-payment.png">Save QR ↓</a><small>Pay the displayed amount and keep the form reference in the note. Return here to submit the payment screenshot for coordinator review.</small></div>';
        }
        elseif($type==='image'){
            if(!empty($field['payment_ticket']))echo '<p class="account-help" data-linked-ticket-amount></p>';
            echo '<a href="'.e($field['media']).'" target="_blank" rel="noopener"><img class="native-form-media" src="'.e($field['media']).'" alt="'.e($field['label']).'" loading="lazy"></a>';
            if(!empty($field['payment_upi']))echo '<div class="native-payment-actions"><a class="button button-orange" href="upi://pay?'.e(http_build_query(['pa'=>$field['payment_upi'],'pn'=>'Anazori','cu'=>'INR'])).'" data-payment-action data-upi-pay="'.e($field['payment_upi']).'">Pay with UPI ↗</a><a class="text-link" href="'.e($field['media']).'" download data-payment-action>Save QR ↓</a><small>Your progress saves before opening your payment app. Return here to attach the screenshot.</small></div>';
            elseif(!empty($field['payment_ticket']))echo '<a class="text-link" href="'.e($field['media']).'" download data-payment-action>Save QR ↓</a>';
        }
        if($type==='video')echo '<video class="native-form-media" src="'.e($field['media']).'" controls preload="metadata" aria-label="'.e($field['label']).'"></video>';
        echo '</div>';return;
    }
    if(in_array($type,['radio','multiselect','scale','rating','grid','checkgrid'],true)){
        $multiple=$type==='multiselect';$grid=in_array($type,['grid','checkgrid'],true);
        echo '<fieldset class="registration-choices"'.($multiple&&$required?' data-required-choices':'').'><legend>'.$label.'</legend>';
        $options=$field['options']??[];
        if(in_array($type,['scale','rating'],true))$options=array_map('strval',range((int)($field['min']??1),(int)($field['max']??5)));
        if(!empty($field['shuffle'])&&!$grid)shuffle($options);
        if($grid){
            echo '<div class="native-grid-wrap" tabindex="0" role="region" aria-label="'.e($field['label']).'"><table class="native-form-grid"><thead><tr><th scope="col">'.e($field['label']).'</th>';
            foreach($options as $option)echo '<th scope="col">'.e($option).'</th>';
            echo '</tr></thead><tbody>';
            foreach($field['rows'] as $index=>$row){
                $selected=is_array($value)?($value[$index]??''):'';$multi=$type==='checkgrid';
                echo '<tr'.($multi&&$required?' data-required-choices':'').'><th scope="row">'.e($row).'</th>';
                foreach($options as $option){$checked=$multi?is_array($selected)&&in_array($option,$selected,true):$selected===$option;
                    echo '<td><input type="'.($multi?'checkbox':'radio').'" name="'.e($name.'['.$index.']'.($multi?'[]':'')).'" value="'.e($option).'" aria-label="'.e($row.' — '.$option).'"'.($checked?' checked':'').(!$multi?$required:'').'></td>';}
                echo '</tr>';
            }
            echo '</tbody></table></div>';
        }else{
            if(in_array($type,['scale','rating'],true))echo '<div class="native-form-scale">';
            foreach($options as $option){$checked=$multiple?is_array($value)&&in_array($option,$value,true):$value===$option;
                echo '<label class="registration-choice"><input type="'.($multiple?'checkbox':'radio').'" name="'.e($name.($multiple?'[]':'')).'" value="'.e($option).'"'.($checked?' checked':'').(!$multiple?$required:'').'><span>'.($type==='rating'?'★ '.e($option):e($option)).'</span></label>';}
            if(in_array($type,['scale','rating'],true))echo '</div><div class="native-scale-labels"><span>'.e($field['low_label']??'').'</span><span>'.e($field['high_label']??'').'</span></div>';
            if(!empty($field['other'])){
                if(!$multiple)echo '<label class="registration-choice"><input type="radio" name="'.e($name).'" value="__other__"'.($value==='__other__'?' checked':'').$required.'><span>Other</span></label>';
                echo '<label class="native-other-label">Other answer<input type="text" name="answers['.e($field['id']).'-other]" value="'.e($values[$field['id'].'-other']??'').'" maxlength="120" placeholder="Your own answer"></label>';
            }
        }
        echo '</fieldset>';
    }elseif($type==='file'){
        $existing=array_values(array_filter($uploads,fn($upload)=>$upload['field_id']===$field['id']));
        $accept=az_form_file_accept($field['file_types']??'images-pdf');
        echo '<label for="'.e($id).'">'.$label.'<input id="'.e($id).'" type="file" name="uploads['.e($field['id']).'][]" accept="'.e($accept).'"'.(($field['file_count']??1)>1?' multiple':'').(!$existing?$required:'').' data-max-files="'.(int)($field['file_count']??1).'" data-max-mb="'.(int)($field['file_size']??5).'"></label>';
        echo '<small class="account-help">Up to '.(int)($field['file_count']??1).' file(s), '.(int)($field['file_size']??5).' MB each. Files are visible to you and the event review team.</small>';
        foreach($existing as $upload)echo '<p class="native-upload-existing"><a href="/registration-file.php?id='.(int)$upload['id'].'" target="_blank" rel="noopener">'.e($upload['original_name']).' ↗</a></p>';
        if($existing)echo '<small class="account-help">Choose new files to replace these in your current response. Previous files stay in the review history.</small>';
    }elseif($type==='checkbox'){
        echo '<label class="account-consent"><input type="checkbox" name="'.e($name).'" value="yes"'.($value==='yes'?' checked':'').$required.'><span>'.$label.'</span></label>';
    }else{
        $placeholder=!empty($field['placeholder'])?' placeholder="'.e($field['placeholder']).'"':'';
        echo '<label for="'.e($id).'">'.$label;
        if($type==='textarea')echo '<textarea id="'.e($id).'" name="'.e($name).'" maxlength="10000" rows="4"'.$placeholder.$required.'>'.e(is_string($value)?$value:'').'</textarea>';
        elseif($type==='select'){
            echo '<select id="'.e($id).'" name="'.e($name).'"'.$required.'><option value="">Choose</option>';
            $options=$field['options'];if(!empty($field['shuffle']))shuffle($options);
            foreach($options as $option)echo '<option value="'.e($option).'"'.($value===$option?' selected':'').'>'.e($option).'</option>';
            echo '</select>';
        }else{
            $limits='';if($type==='number')foreach(['min','max'] as $key)if(($field[$key]??'')!=='')$limits.=' '.$key.'="'.e($field[$key]).'"';
            if(($field['validation']??'')==='length')foreach(['min'=>'minlength','max'=>'maxlength'] as $key=>$attribute)if(($field[$key]??'')!=='')$limits.=' '.$attribute.'="'.(int)$field[$key].'"';
            echo '<input id="'.e($id).'" name="'.e($name).'" type="'.e($type).'" value="'.e(is_string($value)?$value:'').'"'.($type==='number'?' step="any"':'').$limits.$placeholder.$required.'>';
        }
        echo '</label>';
    }
    if(!empty($field['help']))echo '<small class="account-help">'.nl2br(e($field['help'])).'</small>';
    echo '</div>';
}
