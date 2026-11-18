# Hostinger email setup

The email configuration has moved to [MAIL101.md](MAIL101.md). The current release uses native PHP mail with separate OTP and notification sender pairs, ticket approval/rejection notices, and scheduled event reminders. Form submission receipts are disabled.

See [hosting setup](../deploy/HOSTINGER-SETUP.md) for private configuration and the required every-minute worker cron. No SMTP password is required for the selected PHP-mail transport.
