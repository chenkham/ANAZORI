# Connect “Continue with Google” for Anazori

The participant login and signup pages use the same Google OAuth flow. The button appears when the website URL, client ID and client secret are configured. Google supplies the verified email address. If it matches an active participant, sign-in opens `/dashboard.php`. Otherwise the website creates one participant account and asks for the person's own full name on `/profile.php` before opening the dashboard. The website does not import Google's display name or derive a name from the email. Phone is optional. Later sign-ins preserve the chosen name and phone. Both can be edited through My festival → Edit profile. Disabled accounts and conflicting Google identities remain unavailable. Organising Studio uses team email/username and password; Google sign-in is only for participants. The home-page keepsake download remains public.

The supplied credentials are now installed in the private local file `the private local configuration file`. The local website is running at port 8000 and its data is in MariaDB. You still need to configure the supplied client's authorised callback in Google Console and complete a real sign-in. A private production file has also been prepared above `public_html`; use a production client there as described in step 6. Nonempty private Google settings override Studio settings, so edit that private file when replacing these credentials.

## 1. Create your Google project

Open [Google Cloud Console](https://console.cloud.google.com/), select or create the project for your local Anazori setup, then open **Google Auth Platform → Get started**. Use `ANAZORI` as the app name, choose a support email you monitor, select **External** for the audience, and enter your developer contact email. External allows Google accounts outside your institution. [Google's audience settings](https://support.google.com/cloud/answer/15549945?hl=en).

## 2. Set the sign-in scopes

Open **Data Access → Add or remove scopes**. Select only these basic identity scopes:

| Scope | Google Console may display |
| --- | --- |
| `openid` | `openid` |
| `email` | `https://www.googleapis.com/auth/userinfo.email` |

The website requests `openid email` automatically. These scopes supply the identity information needed for sign-in. [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

You can use Testing during local setup. Google exempts basic identity-only requests from its usual test-user listing and seven-day authorization expiration rules. Select **Audience → Publish app** when preparing the public festival launch. [Testing and production rules](https://support.google.com/cloud/answer/15549945?hl=en).

## 3. Create the local OAuth client

Open **Clients → Create client**. Choose **Web application** and name it `Anazori Local`. Enter:

| Google field | Exact local value |
| --- | --- |
| Authorized JavaScript origins | `http://localhost:8000` |
| Authorized redirect URIs | `http://localhost:8000/oauth.php` |

Click **Create**, then copy the **Client ID** and **Client secret** from the creation dialog. Save the secret securely when it is shown. [Google's client creation and secret visibility instructions](https://support.google.com/cloud/answer/15549257?hl=en). Google requires an exact callback match, including the scheme, host, port and path. Do not add a trailing slash after `oauth.php`. [Configure callbacks](https://developers.google.com/identity/protocols/oauth2/web-server).

## 4. Connect the client to your local website

Sign in to the organiser Studio at `http://localhost:8000/login.php`. Open **Integrations** (`http://localhost:8000/admin.php?section=integrations`) and set:

| Studio field | Value |
| --- | --- |
| Public website URL | `http://localhost:8000` |
| Google sign-in → OAuth client ID | The local Client ID from Google |
| Google sign-in → Client secret | The local Client secret from Google |

Click **Save integrations**. The Google section should show **CONFIGURED**. This badge confirms that the three settings are present; the next step confirms that Google accepts them. Google sign-in uses the existing server flow, so no extra frontend SDK installation is needed for this implementation.

## 5. Test the complete sign-in

Open `http://localhost:8000/account.php` in a normal Chrome, Edge or Safari window and click **Continue with Google**. Select your Google account and finish the Google consent flow. On first sign-in, enter your own full name and optionally your phone number, then continue to **My festival** at `/dashboard.php` or the event you started from. Existing Google users whose old name was imported are asked to enter their own name once.

Sign out, then test the signup page at `http://localhost:8000/account.php?mode=signup`. It uses the Google signup flow to create an account and does not ask a Google user to create a password or complete the site's email-code verification. Also test an existing participant email to confirm that its account is reused.

Use `localhost:8000` consistently during this test. Google may reject authorization started inside an embedded app browser; use a regular browser window if it reports `disallowed_useragent`. [Google's authorization errors](https://developers.google.com/identity/protocols/oauth2/web-server#errors).

## 6. Configure the live festival website

For the public deployment, use a separate production Google Cloud project and Web application client. Configure production branding and the client with these values:

| Setting | Production value |
| --- | --- |
| Homepage | `https://anazori.ccsdu.in/` |
| Privacy policy | `https://anazori.ccsdu.in/privacy.php` |
| Terms of service | `https://anazori.ccsdu.in/terms.php` |
| Authorized domain | `ccsdu.in` |
| Authorized JavaScript origin | `https://anazori.ccsdu.in` |
| Authorized redirect URI | `https://anazori.ccsdu.in/oauth.php` |

Use an External audience and the same two identity scopes. The production homepage and policy pages must be live over HTTPS. Domain verification may require the university's domain administrator to help verify `ccsdu.in` in Google Search Console. Complete **Verify Branding**, then **Publish branding**, to show the Anazori name/logo on Google's consent screen; publishing the audience and publishing verified branding are separate controls. [Google's branding requirements](https://support.google.com/cloud/answer/15549049?hl=en).

In the live Studio, save **Public website URL = `https://anazori.ccsdu.in`** and the **production** client ID/secret. Select **Audience → Publish app** and repeat the complete sign-in test on the live domain. Google requires separate projects for development and production deployments. [Production OAuth policies](https://developers.google.com/identity/protocols/oauth2/policies).

## If something does not work

| Symptom | Check |
| --- | --- |
| Continue with Google is missing | All three Studio settings must be filled and saved: website URL, client ID and secret. |
| `redirect_uri_mismatch` | The callback in Google must equal the Studio website URL plus `/oauth.php`. Check `http` vs `https`, hostname, port and trailing slash. |
| `invalid_client` | The client ID and secret must belong to the same Web application client. Re-copy the values if one came from a different local/production project. |
| `org_internal` | Change the project's audience to External if students outside that Google Workspace organisation need access. |
| `disallowed_useragent` | Start sign-in in a normal external browser window. |
| Sign-in expired or cancelled | Start the sign-in again from the account page and complete it in the same browser. The site's request expires after ten minutes. |
| A saved Studio setting appears unchanged | Nonempty `ANAZORI_SITE_URL`, `ANAZORI_GOOGLE_CLIENT_ID` or `ANAZORI_GOOGLE_CLIENT_SECRET` values in the private hosting configuration override Studio settings. Update the active private configuration if you use it. |

Google credentials are saved through Studio's server-side integration settings, not in public JavaScript. The live Google consent and callback need your real Google project; an unconfigured local preview cannot validate that external setup.

Successful signup and login records appear in Studio → Sign-in history and phpMyAdmin → `az_auth_events`. Participant identities are in `az_participants`, including `google_sub` and `email_verified`. Email/password verification uses the same participant table and produces separate `email_otp` activity. See [the launch handover](LAUNCH-CHECKLIST.md) for local database access and SQL examples.
