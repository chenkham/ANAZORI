<?php
declare(strict_types=1);

/** Core event work is granted through saved staff permissions, always within event assignments. */
function st_coordinator_permissions(): array {
    return ['event.view','event.edit','event.publish','media.view','media.edit','participants.view','payments.view','payments.verify',
        'tickets.view','tickets.revoke','tickets.scan','submissions.view','submissions.edit','operations.export','audit.view'];
}

function st_install_coordinator_workflow(PDO $db): void {
    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='coordinator_workflow_schema'")->fetchColumn() === '2') return;
    $db->beginTransaction();
    try {
        az_lock($db);
        if ($db->query("SELECT value FROM cms_settings WHERE setting_key='coordinator_workflow_schema'")->fetchColumn() === '2') {
            $db->commit(); return;
        }
        $rows = $db->query("SELECT id,permissions FROM users WHERE role='COORDINATOR'")->fetchAll();
        $save = $db->prepare('UPDATE users SET permissions=?,session_version=session_version+1 WHERE id=?');
        foreach ($rows as $row) {
            $stored = json_decode($row['permissions'] ?? '[]', true);
            $permissions = is_array($stored) ? array_values(array_filter($stored, 'is_string')) : [];
            $permissions = array_values(array_unique(array_merge($permissions, st_coordinator_permissions())));
            $save->execute([json_encode($permissions), $row['id']]);
        }
        cms_put_setting('coordinator_workflow_schema', '2');
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

/** Preserve form data during partial legacy edits; the dedicated builder validates replacements. */
function st_fixed_form_keys(): array {
    return ['game_forms','registration_form','interest_form','registration_questions','interest_title','interest_intro',
        'interest_button','registration_title','registration_intro','registration_button','registration_settings','interest_settings','form_workflow','registration_form_draft','interest_form_draft'];
}

function st_preserve_event_forms(array $fields, ?array $previous): array {
    $defaults = cms_content_schema()['event']['fields'];
    foreach (st_fixed_form_keys() as $key) {
        $fields[$key] = $previous[$key] ?? ($defaults[$key][2] ?? '');
    }
    return $fields;
}
