<?php
function st_event_work_links79(array $user,?int $eventId,string $environment,string $current): void {
    if(!$eventId)return;$event=cms_record($eventId);$contribution=az_participation_mode($event)==='contribution';
    $items=['overview'=>['Overview','overview'],'event'=>['Event details','event'],'forms'=>['Forms','event']];
    if(!$contribution)$items+=['payments'=>['Payment review','payments'],'details'=>['Participant details','payments'],'tickets'=>['Tickets & check-in','tickets']];
    $items['submissions']=[$contribution?'Contributions':'Interest responses','submissions'];
    echo '<nav class="event-work-tabs" aria-label="Event work">';
    foreach($items as $key=>[$label,$permission])if(cms_can($user,$permission))echo '<a href="'.e(st_workspace_url($key,$eventId,$environment,$key==='event'?['edit'=>$eventId]:[])).'"'.($current===$key?' aria-current="page"':'').'>'.e($label).'</a>';
    echo '</nav>';
}
function st_event_forms79(array $user,?int $eventId,array $events): void {
    foreach($events as $event){if($eventId&&(int)$event['id']!==$eventId)continue;
        $contribution=az_participation_mode($event)==='contribution';
        echo '<section class="panel"><h2>'.e($event['title']).'</h2><p class="help">'.($contribution?'Collect contribution and performance proposals.':'Build the registration form, collect interest and review responses.').'</p><div class="form-actions">';
        if(cms_can($user,'event','edit',$event)&&az_event_games($event['fields'],false))st_game_form_links81((int)$event['id'],$event['fields']);
        elseif(cms_can($user,'event','edit',$event))foreach($contribution?['registration'=>'Contribution form']:['registration'=>'Registration form','interest'=>'Interest form'] as $phase=>$title)echo '<a class="primary-button" href="/form-setup.php?event_id='.(int)$event['id'].'&amp;phase='.$phase.'">'.$title.' ↗</a>';
        if(cms_can($user,$contribution?'submissions':'payments'))echo '<a class="quiet-button" href="'.e(st_workspace_url($contribution?'submissions':'details',(int)$event['id'])).'">All submitted details ↗</a>';
        echo '</div></section>';
    }
}
