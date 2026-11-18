<?php
declare(strict_types=1);
require_once __DIR__.'/form-builder-view.php';

function st_event_setup_fields(array $schema,array $fields,array $media,string $slug='',int $eventId=0): void {
    $joystick=$slug==='joystick';$games=$joystick?az_event_games($fields,false):[];
    $participation=az_participation_mode(['slug'=>$slug]);
    if($participation!=='registration'){
        $fields=az_participation_fields($slug,$fields);
        echo '<p class="help wide">Collect contributions and performance ideas in your own form. This event does not issue registration tickets.</p><input type="hidden" name="registration_fee" value="0">';
    }
    $groups=[
        'Event details'=>['short','description','category','format','image','art','color','label','starts_at','ends_at','reminder_window','venue','fees','prizes','eligibility','rules','event_documents','contact','status_label','featured'],
        'Registration dates and instructions'=>['registration_mode','registration_opens','registration_closes','registration_note','interest_open','registration_closed_message'],
    ];
    if($participation!=='registration')$groups['Event details']=array_values(array_diff($groups['Event details'],['fees','reminder_window']));
    if($participation==='contribution'){
        unset($groups['Registration dates and instructions']);
        $groups['Contribution dates and instructions']=['registration_mode','registration_opens','registration_closes','registration_note','registration_closed_message'];
        $schema['registration_mode'][0]='Contributions';$schema['registration_mode'][3]=['open'=>'Contributions open','closed'=>'Contributions closed','completed'=>'Event completed','scheduled'=>'Automatic — use contribution dates'];
    }
    if($participation==='ceremony')unset($groups['Registration dates and instructions']);
    if($participation==='performers'){
        $groups['Performer application dates']=['registration_mode','registration_opens','registration_closes','registration_closed_message'];
        unset($groups['Registration dates and instructions']);
        $schema['registration_mode'][0]='Performer applications';
        $schema['registration_mode'][3]=['open'=>'Applications open','closed'=>'Applications closed','completed'=>'Event completed','scheduled'=>'Automatic — use application dates'];
    }
    echo '<input type="hidden" name="event_setup_editor" value="1">';
    foreach($groups as $title=>$keys){
        echo '<details class="studio-disclosure event-setup-group wide"'.($title==='Event details'?' open':'').'><summary>'.e($title).'</summary><div class="disclosure-content form-grid">';
        foreach($keys as $key)if(isset($schema[$key])){if($key==='event_documents'){st_event_documents103($fields,$media);continue;}cms_field($key,$schema[$key],(string)($fields[$key]??''),'content',$media);if($key==='reminder_window')echo '<p class="help wide">A single reminder follows the published event start time above, in India time. Only approved, unused tickets receive it. The email cron must run every minute.</p>';}
        echo '</div></details>';
    }
    if($participation==='registration'){
        echo '<details class="studio-disclosure event-setup-group wide"><summary>Google Form registration (optional)</summary><div class="disclosure-content form-grid"><p class="help wide">Paste a Google Forms responder link to send the Register button to that form. Leave it blank to use the Anazori registration form. For Joystick, participants choose a game first; each game can have its own link in Games and competitions below.</p>';
        cms_field('registration_url',$schema['registration_url'],(string)($fields['registration_url']??''),'content',$media);
        echo '<p class="help wide">For games, this is the default link; a game’s own link overrides it. Responses are collected in Google Forms and are not imported into Studio or issued Anazori tickets automatically. Publish the Google Form and copy its responder link, not the editor URL.</p></div></details>';
    }
    if($participation==='contribution'){st_form_setup_entry($eventId,false);return;}
    if($participation==='performers'){
        st_form_setup_entry($eventId,false);return;
    }
    echo '<input type="hidden" name="ticket_categories81" value="1"><input type="hidden" name="registration_fee" value="'.e($fields['registration_fee']??'0').'"><details class="studio-disclosure event-setup-group wide"><summary>Ticket categories and prices</summary><div class="disclosure-content"><p class="help">Offer one ticket or several categories, each with its own price and guidance. Every registration issues exactly one ticket, including a ticket covering several people.</p><div id="ticket-category-rows" class="setup-list">';
    foreach(az_prices($fields) as $i=>$ticket)st_ticket_category81((string)$i,$ticket,$games);
    echo '</div><button type="button" class="quiet-button" data-setup-add="ticket-category">Add ticket category</button><template id="ticket-category-template">';st_ticket_category81('INDEX',[],$games);echo '</template></div></details>';
    if($joystick){
    echo '<details class="studio-disclosure event-setup-group wide"><summary>Games and competitions</summary><div class="disclosure-content"><p class="help">Add the games offered in Joystick, such as MLBB or BGMI. Participants must select an active game. Existing registrations retain their selected game.</p><div class="setup-list" id="game-category-rows">';
    foreach($games as $i=>$game)st_game_category_row((string)$i,$game);
    echo '</div><button class="quiet-button" type="button" data-setup-add="game-category">Add game</button><template id="game-category-template">';st_game_category_row('INDEX',[]);echo '</template></div></details>';
    }
    st_form_setup_entry($eventId,true,$fields);
}

function st_form_setup_entry(int $eventId,bool $interest,array $fields=[]): void {
    echo '<details class="studio-disclosure event-setup-group wide"><summary>Form setup</summary><div class="disclosure-content"><p class="help">Build questions, upload your payment QR and choose what participants must submit. Forms open in a dedicated editor.</p>';
    if(!$eventId)echo '<p>Save this event first to set up its forms.</p>';
    elseif(az_event_games($fields,false)){echo '<p class="help" data-event-save-status role="status">Your event changes save before opening a game form.</p>';st_game_form_links81($eventId,$fields,true);}
    else{echo '<p class="help" data-event-save-status role="status">Your event changes will be saved before opening Form setup.</p><div class="form-actions"><a class="primary-button" data-open-form-setup href="/form-setup.php?event_id='.$eventId.'&amp;phase=registration">Open '.($interest?'registration':'contribution').' form ↗</a>';if($interest)echo '<a class="quiet-button" data-open-form-setup href="/form-setup.php?event_id='.$eventId.'&amp;phase=interest">Open interest form ↗</a>';echo '</div>';}
    echo '</div></details>';
}

function st_setup_row_actions(): void {
    echo '<div class="row-actions"><button class="quiet-button" type="button" data-setup-move="up" aria-label="Move this row up">Move up</button><button class="quiet-button" type="button" data-setup-move="down" aria-label="Move this row down">Move down</button><button class="danger-button" type="button" data-setup-remove>Remove</button></div>';
}

function st_payment_method_row(string $index,array $method,array $media): void {
    $name='payment_methods['.$index.']';$prefix='payment-method-'.$index;
    ?>
    <details class="setup-row" <?= !$method?'open':'' ?>><summary><?= e($method['label']??'New payment method') ?></summary><div class="disclosure-content form-grid">
     <input type="hidden" name="<?= e($name) ?>[id]" value="<?= e($method['id']??'') ?>">
     <label class="field" for="<?= e($prefix) ?>-kind"><span>Payment type</span><select id="<?= e($prefix) ?>-kind" name="<?= e($name) ?>[kind]"><?php foreach(['upi'=>'UPI','bank'=>'Bank transfer','other'=>'Other payment method'] as $key=>$label): ?><option value="<?= $key ?>" <?= ($method['kind']??'upi')===$key?'selected':'' ?>><?= $label ?></option><?php endforeach; ?></select></label>
     <?php foreach(['label'=>'Display name','recipient'=>'Account holder','upi'=>'UPI ID (UPI only)','bank'=>'Bank name (bank transfer only)','account'=>'Account number (bank transfer only)','ifsc'=>'IFSC (bank transfer only)'] as $key=>$label): ?>
      <label class="field" for="<?= e($prefix.'-'.$key) ?>"><span><?= $label ?></span><input id="<?= e($prefix.'-'.$key) ?>" name="<?= e($name.'['.$key.']') ?>" value="<?= e($method[$key]??'') ?>" maxlength="<?= $key==='label'?80:($key==='recipient'?120:($key==='account'?40:($key==='ifsc'?20:100))) ?>" <?= $key==='label'?'data-setup-label':'' ?>></label>
     <?php endforeach; ?>
     <label class="field" for="<?= e($prefix) ?>-qr"><span>Payment QR (optional)</span><select id="<?= e($prefix) ?>-qr" name="<?= e($name) ?>[qr]"><option value="">No QR image</option><?php foreach($media as $item):if(!str_starts_with($item['mime'],'image/'))continue; ?><option value="<?= e($item['path']) ?>" <?= ($method['qr']??'')===$item['path']?'selected':'' ?>><?= e($item['title']) ?></option><?php endforeach; ?></select><small>Upload a QR image in Media library first.</small></label>
     <label class="field wide" for="<?= e($prefix) ?>-instructions"><span>Payment instructions</span><textarea id="<?= e($prefix) ?>-instructions" name="<?= e($name) ?>[instructions]" rows="3" maxlength="2000"><?= e($method['instructions']??'') ?></textarea></label>
     <label class="check-field"><input type="checkbox" name="<?= e($name) ?>[active]" value="1" <?= ($method['active']??true)?'checked':'' ?>>Available to participants</label>
     <?php st_setup_row_actions(); ?>
    </div></details>
    <?php
}
