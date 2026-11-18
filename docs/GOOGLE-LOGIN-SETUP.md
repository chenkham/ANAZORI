# Continue with Google — Anazori V16.0

The login code is already implemented in `oauth.php`. It uses Google's server-side authorization-code flow with state, PKCE and verified email. You only need to connect your Google project to the website. Google credentials must come from your own Google Cloud account; they are not included in this folder.

## 1. Choose your real website address

Use the exact HTTPS address visitors will use, for example `https://your-domain.com`. Replace this example everywhere below with your actual address. Decide whether your site uses `www` and keep that choice consistent.

Sign in to the organiser studio at `/login.php` with your Super Admin account. Open **Website & connections → Integrations**. Set **Public website URL** to your website origin without a trailing slash, such as `https://your-domain.com`. Save integrations. The Google section shows the callback address you need.

## 2. Create your Google project and consent configuration

1. Open [Google Cloud Console](https://console.cloud.google.com/), sign in and create/select a project named **Anazori**.
2. Open **Google Auth Platform → Overview → Get started** if the project has not been configured.
3. Enter **ANAZORI V16.0**, your support email and developer contact email.
4. Choose **External** for participants using personal Google accounts. **Internal** limits access to the project's Google Workspace organisation.
5. In **Branding**, enter your real homepage, privacy policy and terms URLs where requested. Use published pages that accurately describe the festival's account data and policies; do not enter example URLs. Add the root domain (for example `your-domain.com`, without `https://` or a path) under authorised domains. If Google requests domain ownership verification, use Google Search Console.
6. In **Data access**, select only the basic sign-in scopes: `openid`, `https://www.googleapis.com/auth/userinfo.email`, and `https://www.googleapis.com/auth/userinfo.profile`. The website requests their short equivalents `openid email profile`. You do not need Gmail, Drive or Calendar permissions for this login.

Google's current configuration guide: [Google Auth Platform setup](https://support.google.com/cloud/answer/15544987?hl=en) and [Branding](https://support.google.com/cloud/answer/15549049?hl=en).

## 3. Create a web OAuth client

1. Open **Google Auth Platform → Clients → Create client**.
2. Select **Web application**. Name it **Anazori website**.
3. Under **Authorised redirect URIs**, add exactly:

   ```text
   https://your-domain.com/oauth.php
   ```

   Use the exact callback shown by your studio, including protocol, domain, optional port and `/oauth.php`. Do not add `?target=participant` or `?target=staff`. Both login types use this same callback.
4. Authorised JavaScript origins can remain empty for this existing server-side flow. They are needed when Google APIs are called directly from browser JavaScript.
5. Create the client and securely copy the **Client ID** and **Client secret** immediately. Google's current console shows the full secret at creation; if you lose it, create/rotate a secret in the client's settings.

Google's reference: [Manage OAuth clients](https://support.google.com/cloud/answer/15549257?hl=en).

## 4. Connect it in your organiser studio

1. Return to **Integrations**.
2. Confirm **Public website URL** is your real HTTPS origin.
3. Paste the Client ID into **OAuth client ID** and the secret into **Client secret**.
4. Click **Save integrations**.
5. Confirm the Google section shows **CONFIGURED**.

The website encrypts this secret in its integration storage. An empty secret field after saving is expected. Leave it blank on later edits to keep the stored secret. Do not paste the secret into public JavaScript or share it in chat.

The **Continue with Google** button appears automatically on participant login/signup when the URL, client ID and secret are all saved. It also appears on organiser login.

## 5. Test before opening the festival

Open `/account.php` in a private window on the live domain, click **Continue with Google**, choose your Google account and complete consent. You should return to `/dashboard.php` with an automatically created, verified participant account. For an existing participant email, Google sign-in connects that account.

For organiser login, open `/login.php` and select **Continue with Google**. The Google email must already belong to an active staff account in **Team access**. Participant signup never grants organiser access. Test a staff account with its assigned permissions and verify that an unassigned email cannot enter the studio.

Under **Audience**, use **Publish app / In production** when the site is ready. Follow any requirements shown in **Verification centre**. Basic `openid email profile` sign-in has an exception to Google's usual testing allowlist and seven-day authorisation rules; adding other scopes changes that. Branding/name/logo verification is separate from sensitive-scope verification. [Google's audience rules](https://support.google.com/cloud/answer/15549945?hl=en).

The local automated tests verify OAuth redirects, state, PKCE, account permissions and forged-callback rejection. A successful real Google login still needs your credentials and must be tested on your domain.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| Button is missing | Save all three required fields: public website URL, Google client ID and Google client secret. |
| `redirect_uri_mismatch` | The URI in Google Clients must exactly equal the studio's callback: HTTPS, `www` choice, port and `/oauth.php`. Google says configuration changes can take five minutes to a few hours to apply. |
| `invalid_client` | Verify you copied credentials from the same **Web application** client. If rotating a secret, save the new one in the studio before disabling the old one. |
| `org_internal` | Choose **External** if people outside your Google Workspace organisation must sign in. |
| Sign-in cancelled or expired | Start again from the login page in the same browser. The callback state expires after ten minutes and is used once. |
| Google account does not have organiser access | Add that exact Google email to an active staff account through **Team access**. |
| Server fails after Google redirects back | Ensure PHP cURL/OpenSSL are enabled and the host can reach `oauth2.googleapis.com` and `openidconnect.googleapis.com`. Check hosting logs without logging secrets. |

For local-only testing, create a separate development Google project/client and use `http://127.0.0.1:8088` as the saved site URL with `http://127.0.0.1:8088/oauth.php` as its redirect URI. Localhost HTTP is allowed by Google. Use production credentials only on your HTTPS production site.

## Volunteer scanning app

The website camera/scanner interface has been removed. `api/checkin.php`, ticket QR generation, `tickets.scan` permissions and atomic check-in remain. The endpoint currently uses an authenticated staff session plus CSRF, not a public API key. Give scanning volunteers only **Check in tickets** permission through **Team access**. Your future native app will need to integrate that authentication contract or add a dedicated token-based app authentication flow before distribution.
