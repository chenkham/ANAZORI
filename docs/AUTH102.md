# Participant browser login and verification

Email/password signup, email/password sign-in and Google sign-in remember this browser for up to 30 days. This includes unverified accounts. Existing valid participant sessions receive a remembered-browser token on their next page visit.

Returning to My festival shows Verify email for an unverified account. The verification page recovers its current code from the database without sending a new email. Its original ten-minute expiry, five-attempt limit and one-use rule are unchanged. After expiry, request a new verification code for the same account; do not create another account.

The host-only cookie is HttpOnly and SameSite=Lax, with Secure and the __Host- prefix on HTTPS/production. It contains random selector/validator material. The database stores only validator hashes and account-version/email bindings. Successful session restoration rotates the validator with a 60-second grace period for simultaneous tabs.

Sign out revokes this browser token and its associated restored sessions. Password reset revokes all remembered browsers. Disabled accounts, email changes, account-version changes and expired tokens cannot restore access. Organiser/administrator sessions are not restored by participant cookies.

Private account responses and authenticated page headers are no-store. The OTP itself, passwords and Google credentials are never stored in a browser-readable cookie or localStorage. Cookies deleted by the user, private browsing and a different browser require another sign-in.

Deploy the changed PHP files together. The normal schema setup creates the token table and indexes automatically; do not re-import the clean SQL or reset existing participant data.

Routine sign-ins with the same linked Google identity preserve other remembered browsers. First linking Google or verifying a previously unverified identity changes the account security version and revokes earlier browser tokens.
