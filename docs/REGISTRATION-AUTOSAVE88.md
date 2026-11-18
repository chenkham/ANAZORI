# Registration draft saving

Participant registration saves in the background with no save banner or manual
save button. Text changes use a short debounce with a maximum wait while typing;
choice changes, file selections, leaving a field and switching to payment flush
the draft sooner. Payment actions and final submission await draft saving.

The authenticated draft endpoint retains answers, ticket selection, payment
account, consent and private upload ownership per account/event/game/edit
context. Draft-only branch data stays available when switching answers. Final
submission continues to validate and include only the visible branch.

Unsent text is recorded immediately in an account-scoped device copy. Selected
files use an IndexedDB outbox until uploaded. Reloads restore compatible pending
data; reconnecting retries it. Requests that can fit the browser's keepalive
budget may finish during navigation. Large pending uploads rely on the outbox
when navigation interrupts them. Browser storage availability and capacity
still apply; storage failures that could lose offline work show an error.

Draft request IDs make a retry safe when the database committed but the reply
was interrupted. Revision checks continue to protect against another tab
overwriting a newer draft. A small idempotent migration adds state_json and
request_id to az_checkout_drafts through the normal CMS initialization path.

The Studio question-type dropdown has its own opaque violet surfaces and white
labels for normal, selected, hovered, focused and pressed options. This avoids
the generic question-button hover rules replacing the menu's colours.

Assets were rebuilt. Automated tests and browser/device checks were not run;
the user requested to test the result themselves.
