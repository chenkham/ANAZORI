# Google Form registration

In Studio, open the event editor and expand **Google Form registration (optional)**.
Paste the published Google Forms responder link and save the event. Leave the link
blank to use the existing Anazori form. Keep the event's registration phase open,
or configure its normal registration dates.

For Joystick, expand **Games and competitions**, open each game, and paste its
own **Google Form link (optional)**. The public Register button opens a game
selection page. Choosing BGMI, MLBB, Free Fire or another enabled game redirects
to that game's form. A game link overrides the event's default link; when both
are blank, that game uses the existing Anazori checkout.

Use Google Forms **Publish**, then **Copy responder link**. Configure responder
access as appropriate for your event. Supported links are HTTPS forms.gle short
links and docs.google.com/forms responder links ending in /viewform, including
prefilled query parameters. Editor links and other domains are rejected.
See https://support.google.com/docs/answer/2839588.

Google Forms responses remain in Google Forms. They are not imported into Studio
and do not automatically generate Anazori tickets, payment confirmations or
reminders. Existing Anazori orders and response edits remain accessible.

The chooser is public and does not require an Anazori account. Native registration
continues to require its existing account checks. Closed, inactive and unpublished
events or games cannot redirect through the public route. Destinations come only
from validated saved event data; query parameters cannot supply a redirect URL.
Coordinator assignments, CSRF checks, publication permissions and revision
conflict protection apply when saving links.

Verification: run node tests/external-registration97.mjs from the project root.
It uses an isolated SQLite database, dummy form URLs and a local HTTP server.
It never follows redirects to Google or sends live email.
