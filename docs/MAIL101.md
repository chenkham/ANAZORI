# Anazori mail update 107

There are now three event notification emails:

1. **Registration received** after a registration form is successfully saved, or after payment proof is submitted in the older manual-payment flow. It is an acknowledgement pending review, not a ticket. Edits and repeated submissions do not send duplicate receipts.
2. **Ticket approved** when an actual ticket is issued. It contains the event/game, ticket ID, published date, venue and a sign-in-protected ticket link.
3. **Event reminder** once per approved, unused ticket and published start time, using the event's selected 24-hour or 12-hour lead time.

This replaces the previous three-email policy that included rejection notices. Rejection, correction, welcome, anonymous interest and contribution emails are not sent. Verification and password-reset OTPs continue separately.

The existing violet, pearl, pink and cyan email layout and Anazori wordmark are used for all three notifications. Messages include a plain-text alternative and omit private form answers, uploaded files and private check-in tokens.

## Why an OTP can arrive while ticket mail does not

OTPs send directly. Previously, ticket approval only created a queued job; its delivery depended entirely on the CLI mail worker. If that cron was absent or failing, a ticket could be approved without an email arriving. Separately, `ANAZORI_MAIL_NOTIFICATIONS=0` disables event messages while allowing OTPs.

This update adds a bounded automatic worker attempt at the end of the submission/approval request. It runs outside the business transaction and releases the session lock. Where supported, PHP finishes the HTTP response before sending. The same existing leases, sender quotas, fallbacks and retries protect delivery. Sending failures leave the registration/ticket intact and the email queued.

The automatic attempt does not replace the scheduled worker. Cron handles retries, backlogs and reminders even when nobody visits the site. A request attempt does not falsely refresh the cron heartbeat.

## Hostinger setup: required after uploading

1. In your **existing private Anazori PHP configuration** (outside the public website), ensure this entry is enabled:

   ```php
   'ANAZORI_MAIL_NOTIFICATIONS' => '1',
   ```

   Keep the other configuration values, credentials and application key. The production environment should remain `ANAZORI_APP_ENV=production`. Do not upload or expose the private configuration file in the domain document root.

2. Open **hPanel → Websites → the site dashboard → Cron Jobs**. Select the **PHP** type, and set its file to the real absolute hosting path ending with:

   ```text
   /includes/mail-worker95.php
   ```

   Use the actual folder containing the domain's `index.php`, not a guessed domain path. For example, if File Manager shows the site at `/home/u123456/domains/ccsdu.in/public_html/anazori`, the worker path would be `/home/u123456/domains/ccsdu.in/public_html/anazori/includes/mail-worker95.php`. This is an example, not your verified account path. Use the path/prefix shown by your own hPanel.

3. Schedule it **every minute**: minute, hour, day, month and weekday all set to `*`. PHP-type jobs take the PHP file path; do not paste a website URL or a shell command into that field. Do not add `--retry-failed` to the recurring job.

4. Open **View output** for the saved cron. A successful run prints JSON such as:

   ```json
   {"scheduled":0,"sent":0,"skipped":0,"retried":0,"failed":0,"notifications_enabled":true,"pending_total":0,"failed_total":0,"transport":"php_mail"}
   ```

   Zero sent is normal when nothing is due. `notifications_enabled:false` means the private flag is disabled. `retried` means delivery was deferred or failed temporarily; `failed_total` counts exhausted jobs. A missing output, wrong-path error or worker failure requires fixing the cron path/configuration before reminders can work.

5. In **Organising Studio → the event → Event details**, enter its actual start date/time and select **24 hours** or **12 hours** before the event. Unqualified times are interpreted as India time. The worker compares absolute timestamps, so an every-minute cron needs no separate IST clock conversion.

Hostinger's current official setup guide: https://www.hostinger.com/support/1583465-how-to-set-up-a-cron-job-at-hostinger/

## Sender routing and capacity

| Purpose | Primary | Fallback |
| --- | --- | --- |
| Verification/password-reset OTP | noreply1@ccsdu.in | noreply2@ccsdu.in |
| Submission, approval, reminder and owner alerts | noreply3@ccsdu.in | noreply4@ccsdu.in |

No SMTP conversion or password change is part of this update. The existing PHPMailer `isMail()` transport uses the host's PHP mail service. A failure from noreply3 triggers a try through noreply4; failures on both remain queued for retry. Owner quota/sender alerts remain enabled.

Keep the existing conservative application budgets unless Hostinger confirms a higher allowance. Hostinger currently documents a shared PHP/sendmail allowance of 10 messages per minute and 100 in a rolling 24 hours. Sender switching does not multiply that hosting quota. Three event emails per registration consume capacity in addition to OTPs and owner alerts.

Official limit reference: https://www.hostinger.com/support/6976044-parameters-and-limits-of-hosting-plans-in-hostinger/

## Check on hosting after upload

1. Submit a new native Anazori registration using your own verified account. Check Inbox and Spam for one acknowledgement.
2. Approve that registration in Studio. Check for its approved ticket email; opening the ticket link must still require the correct account.
3. Check Studio's Launch checks and the cron output for a recent worker run. The code's 12-/24-hour timing, rescheduling, duplicate prevention, used/blocked ticket exclusions and expired-event exclusions were tested with isolated data; do not change a real event's date just to test reminders.
4. If nothing arrives despite `sent` increasing, check Hostinger mail logs, Spam and sender/domain authentication. PHP mail acceptance does not prove inbox delivery. The fact that OTP arrives proves basic sending for the OTP pair, not successful delivery from noreply3/noreply4.

With SSH/terminal access, these optional commands use your real absolute worker path:

```text
php /YOUR/ACTUAL/DOCUMENT/ROOT/includes/mail-worker95.php --status
php /YOUR/ACTUAL/DOCUMENT/ROOT/includes/mail-worker95.php --retry-failed
```

`--status` reports only operational settings and queue counts, not recipient addresses, message contents or credentials. Use `--retry-failed` once after fixing a real transport/configuration problem; it requeues failed jobs, and current ownership/ticket/schedule checks still apply. Both commands are CLI-only; do not expose a public cron URL.

External Google Forms responses stay in Google Forms. They do not automatically produce Anazori registration receipts, tickets or reminders; no integration importing those responses exists.

## Upload files

Replace these seven files. All local files are under `src/includes/`; the destination is the corresponding `includes/` file in the anazori.ccsdu.in document root:

- `mail-notifications.php`
- `mail-policy101.php`
- `mail-templates.php`
- `form-workflow.php`
- `manual-payments.php`
- `mail-worker95.php`
- `launch-readiness.php`

No database import/reset, frontend rebuild, SMTP setup or new public endpoint is required. Keep the existing `assets/2026/email-wordmark101.png` from the earlier email update. Back up the seven files before replacement. The provided ZIP includes only the public PHP updates; it does not contain private configuration, credentials, database files or uploads.

Local validation passed: 40 lifecycle/timing/privacy/retry checks, 37 sender/OTP/quota checks, receipt scope checks and actual HTTP submission/Studio approval/CLI reminder checks. All messages were captured in temporary test outboxes. No live emails were sent and hosting was not changed by these checks.
