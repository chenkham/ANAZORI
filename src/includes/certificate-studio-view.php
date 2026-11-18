<?php
declare(strict_types=1);

function az_certificate_studio_view(array $staff, ?int $eventId): void {
    if (!$eventId) {
        $events = st_scoped_events($staff);
        echo '<section class="panel"><h2>Choose an event to manage its results and certificates</h2><p class="help">Podium results, participant certificates, and their verification links are kept with the selected event.</p><div class="certificate-actions">';
        foreach ($events as $event) echo '<a class="quiet-button" href="/admin.php?section=certificates&amp;event_id='.(int)$event['id'].'">'.e($event['title']).' ›</a>';
        if (!$events) echo '<p class="help">No event is assigned to this account.</p>';
        echo '</div></section>';
        return;
    }
    $event = cms_record($eventId);
    if (!$event || $event['type'] !== 'event') { echo '<div class="notice error">Event unavailable.</div>'; return; }

    $awards = az_certificate_awards($eventId);
    $certificates = az_certificate_rows($staff,$eventId);
    $orders = az_certificate_event_orders($staff,$eventId);
    $isGocEvent = in_array($event['slug'],['goc','game-of-codes'],true) || stripos((string)$event['title'],'Game of Codes')!==false;
    $staffCertificates = $isGocEvent ? az_certificate_staff_certificates($eventId) : [];
    $certificatesById = [];
    $certificatesByOrder = [];
    $certificatesByTeam = [];
    foreach ($certificates as $certificate) {
        $certificatesById[(int)$certificate['id']] = $certificate;
        $certificatesByOrder[(int)$certificate['order_id']][] = $certificate;
        if (trim((string)$certificate['team_name']) !== '') $certificatesByTeam[az_certificate_team_key((string)$certificate['team_name'])][] = $certificate;
    }
    $registeredTeams=[];
    foreach($orders as $registeredOrder){$registeredTeam=az_certificate_order_team_name($registeredOrder);if($registeredTeam!=='')$registeredTeams[az_certificate_team_key($registeredTeam)]=$registeredTeam;}
    $rows = max(6,min(12,count($awards)+2));
    ?>
    <div class="certificate-studio">
      <section class="panel">
        <div class="panel-heading"><h2>Podium results</h2><span class="badge"><?= count($awards) ?> team<?= count($awards)===1?'':'s' ?></span></div>
        <p class="help">Choose the exact registered team name from the suggestions, then set its place. That result appears on every issued certificate for the team and updates existing certificates too. Teams without a podium result receive a Participant certificate; ties are allowed.</p>
        <form method="post">
          <?php cms_hidden('save_certificate_awards'); ?><input type="hidden" name="event_id" value="<?= $eventId ?>">
          <datalist id="certificate-registered-team-names"><?php foreach($registeredTeams as $registeredTeam): ?><option value="<?= e($registeredTeam) ?>"><?php endforeach; ?></datalist>
          <div class="certificate-award-grid">
            <?php for($i=0;$i<$rows;$i++): $award=$awards[$i]??[]; ?>
              <div class="certificate-award-row">
                <label class="field"><span>Place</span><select name="awards[<?= $i ?>][place]"><?php foreach([1=>'1st place',2=>'2nd place',3=>'3rd place'] as $place=>$label): ?><option value="<?= $place ?>" <?= (int)($award['place']??($i===0?1:($i===1||$i===2?2:3)))===$place?'selected':'' ?>><?= $label ?></option><?php endforeach; ?></select></label>
                <label class="field"><span>Team name</span><input name="awards[<?= $i ?>][team_name]" value="<?= e($award['team_name']??'') ?>" maxlength="120" list="certificate-registered-team-names" placeholder="Leave blank for an unused row"></label>
              </div>
            <?php endfor; ?>
          </div>
          <div class="form-actions"><button class="primary-button" type="submit">Save podium ›</button></div>
        </form>
      </section>

      <?php if($isGocEvent): ?>
      <section class="panel">
        <div class="panel-heading"><h2>Teacher coordinator certificates</h2><span class="badge">2 certificates</span></div>
        <p class="help">These GOC certificates use the supplied teacher certificate design and wording style. Each has a verification QR and only the Chairperson and President signatures. Preview and PDF downloads are restricted to authorized Organizing Studio accounts.</p>
        <div class="certificate-registration-list">
          <?php foreach(az_certificate_staff_people() as $personKey=>$person): $staffCertificate=$staffCertificates[$personKey]??null; ?>
            <article class="certificate-registration">
              <div class="certificate-registration-head"><div><h3><?= e($person['name']) ?></h3><p><?= e($person['role']) ?> · Game of Codes</p></div><span class="badge"><?= $staffCertificate?e($staffCertificate['status']):'Not issued' ?></span></div>
              <div class="certificate-actions">
                <form method="post" action="/certificate-staff.php"><?= csrf_field() ?><input type="hidden" name="event_id" value="<?= $eventId ?>"><input type="hidden" name="person" value="<?= e($personKey) ?>"><button class="quiet-button" type="submit"><?= $staffCertificate?'Issue / refresh certificate':'Issue certificate' ?> ›</button></form>
                <?php if($staffCertificate && $staffCertificate['status']==='ISSUED'): ?><a class="quiet-button" href="/certificate-preview.php?certificate_row_id=<?= (int)$staffCertificate['id'] ?>">Preview certificate ›</a><a class="quiet-button" href="/certificate-preview.php?certificate_row_id=<?= (int)$staffCertificate['id'] ?>&amp;download=pdf">Download PDF ↓</a><?php endif; ?>
              </div>
            </article>
          <?php endforeach; ?>
        </div>
      </section>
      <?php endif; ?>

      <section class="panel">
        <div class="panel-heading"><h2>Registered participants</h2><span class="badge"><?= count($orders) ?> confirmed</span></div>
        <p class="help">Only confirmed live registrations with an active ticket appear here. The whole-team action reads teammate names and the team name from the saved registration, then issues the lead and teammate certificates to the leader’s dashboard. They can preview them or download one combined PDF.</p>
        <?php if (!$orders): ?><p class="help">No confirmed registrations are available for this event yet.</p><?php else: ?>
          <div class="certificate-registration-list">
            <?php foreach($orders as $order):
              $snapshot=json_decode($order['snapshot'],true)?:[];
              $team=az_certificate_order_team_name($order);
              $isTeam=$team!==''||($snapshot['registration_kind']??'')==='team';
              $person=(string)($order['account_name']?:($snapshot['name']??''));
              $email=(string)($order['account_email']??$snapshot['email']??'');
              $award=az_certificate_award($eventId,$team);
              $orderCertificates=$certificatesByOrder[(int)$order['id']]??[];
              $teamCertificates=$team!==''?($certificatesByTeam[az_certificate_team_key($team)]??[]):[];
              $issuedTeamCertificates=array_values(array_filter($teamCertificates,static fn($certificate)=>$certificate['status']==='ISSUED'));
              $saved=null;
              foreach($orderCertificates as $candidate) if((int)$candidate['participant_id']===(int)$order['participant_id']&&mb_strtolower(trim($candidate['recipient_name']))===mb_strtolower(trim($person))){$saved=$candidate;break;}
              $registrationAnswers=json_decode($order['answers'],true)?:[];
              $teamMemberNames=$isTeam?az_certificate_team_member_names($order):[];
              $teamCertificateCount=1+count($teamMemberNames);
            ?>
              <article class="certificate-registration">
                <div class="certificate-registration-head"><div><h3><?= e($isTeam?($team?:'Team registration'):$person) ?></h3><p><?= e($isTeam?'Team lead: '.$person:$email) ?><?= $isTeam?' · '.e($email):'' ?> · <?= e($order['public_id']) ?></p></div><span class="badge"><?= e($award['status'].($award['status']==='Winner'?' · '.$award['label']:'')) ?></span></div>
                <div class="certificate-actions">
                  <form method="post"><?php cms_hidden('issue_certificate'); ?><input type="hidden" name="event_id" value="<?= $eventId ?>"><input type="hidden" name="order_id" value="<?= (int)$order['id'] ?>"><button class="quiet-button" type="submit"><?= $saved?($isTeam?'Refresh team lead certificate':'Refresh registration certificate'):($isTeam?'Issue team lead certificate':'Issue to registration account') ?> ›</button></form>
                  <a class="quiet-button" href="/certificate-preview.php?event_id=<?= $eventId ?>&amp;order_id=<?= (int)$order['id'] ?>">Preview certificate ›</a>
                  <?php if($saved): ?><span class="help">Issued · <?= e($saved['certificate_id']) ?></span><?php endif; ?>
                </div>
                <?php if($isTeam): ?>
                  <?php if($teamCertificates): ?><p class="help">Certificates for <?= e($team) ?> across its registrations: <?php foreach($teamCertificates as $index=>$issued): ?><?= $index?', ':'' ?><?= e($issued['recipient_name']) ?> (<?= e($issued['status']) ?>)<?php endforeach; ?></p><?php endif; ?>
                  <?php if($issuedTeamCertificates): ?><div class="certificate-actions"><a class="quiet-button" href="/certificate-preview.php?event_id=<?= $eventId ?>&amp;order_id=<?= (int)$order['id'] ?>&amp;team_certificates=1">Preview all <?= count($issuedTeamCertificates) ?> issued certificates ›</a><a class="quiet-button" href="/certificate-preview.php?event_id=<?= $eventId ?>&amp;order_id=<?= (int)$order['id'] ?>&amp;team_certificates=1&amp;download=pdf">Download team PDF ↓</a></div><?php endif; ?>
                  <details><summary>Registration details and member names</summary>
                    <?php if($registrationAnswers): ?><div class="certificate-registration-details"><?php foreach($registrationAnswers as $label=>$value): if(is_array($value))$value=implode(', ',array_map(static fn($item)=>is_scalar($item)?trim((string)$item):json_encode($item,JSON_UNESCAPED_UNICODE),(array)$value)); if(!is_scalar($value)||trim((string)$value)==='')continue; ?><p><strong><?= e((string)$label) ?>:</strong> <?= nl2br(e((string)$value)) ?></p><?php endforeach; ?></div><?php else: ?><p class="help">No additional form answers were saved with this registration.</p><?php endif; ?>
                  </details>
                  <details><summary>Issue certificates for the whole team</summary>
                    <?php if($teamMemberNames): ?><p class="help">Lead: <?= e($person) ?>. Teammates found in the saved registration: <?= e(implode(', ',$teamMemberNames)) ?>. This will issue or refresh <?= $teamCertificateCount ?> certificates, one per registered member. <?= $award['status']==='Winner'?'Every member will receive a winner certificate showing '.e($award['label']).'.':'Every member will receive a participant certificate without a winning place.' ?></p><form class="certificate-member-form" method="post"><?php cms_hidden('issue_team_certificates'); ?><input type="hidden" name="event_id" value="<?= $eventId ?>"><input type="hidden" name="order_id" value="<?= (int)$order['id'] ?>"><button class="primary-button" type="submit">Issue or refresh <?= $teamCertificateCount ?> certificates ›</button></form>
                    <?php else: ?><p class="help">No teammate names were found in the saved registration fields. Check the registration details above; this registration may only have the team lead’s name saved.</p><?php endif; ?>
                  </details>
                <?php endif; ?>
              </article>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </section>

      <section class="panel">
        <div class="panel-heading"><h2>Issued certificates</h2><span class="badge"><?= count($certificates) ?> total</span></div>
        <?php if (!$certificates): ?><p class="help">Certificates you issue will appear here. Participants can open and download them from their festival dashboard.</p><?php else: ?>
          <div class="certificate-admin-list">
            <?php foreach($certificates as $certificate): $award=az_certificate_award($eventId,$certificate['team_name']); $isTeacherCertificate=az_certificate_is_staff_certificate($certificate); ?>
              <article class="certificate-admin-row"><div><strong><?= e($certificate['recipient_name']) ?></strong><p><?= e($isTeacherCertificate?'Teacher Coordinator':($certificate['team_name']?:'Individual participant')) ?> · <?= e($certificate['recipient_email']?:($isTeacherCertificate?'Organizing Studio only':'Stored in team lead dashboard')) ?> · <?= e($certificate['certificate_id']) ?></p></div><span class="badge certificate-award-pill"><?= e($certificate['status']==='ISSUED'?($isTeacherCertificate?'Teacher Coordinator':$award['status'].($award['status']==='Winner'?' · '.$award['label']:'')):'REVOKED') ?></span><a class="quiet-button" href="/certificate-preview.php?certificate_row_id=<?= (int)$certificate['id'] ?>">View certificate ›</a><form method="post"><?php cms_hidden($certificate['status']==='ISSUED'?'revoke_certificate':'restore_certificate'); ?><input type="hidden" name="event_id" value="<?= $eventId ?>"><input type="hidden" name="certificate_row_id" value="<?= (int)$certificate['id'] ?>"><button class="<?= $certificate['status']==='ISSUED'?'danger-button':'quiet-button' ?>" type="submit"><?= $certificate['status']==='ISSUED'?'Revoke':'Restore' ?></button></form></article>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </section>
    </div>
    <?php
}
