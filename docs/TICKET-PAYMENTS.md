# Ticket-linked payment QR codes

The existing ticket category editor remains the source of category names, descriptions, prices and people covered. Each registration still issues one ticket after coordinator approval.

## Coordinator setup

1. Configure the existing ticket categories in the event workspace.
2. Open **Form setup**. For Joystick, open the relevant game's form.
3. Add an **Image / payment QR** block and upload the correct fixed-amount QR directly there.
4. In **More question settings**, select **Linked ticket for this payment QR**. The choices show existing category names and prices. Optionally add the receiving UPI ID for fast payment.
5. Add one QR block for each paid category. Keep them together after the participant questions. Use **Payment / receipt** as the purpose of related transaction-reference and screenshot fields; the payment template sets this automatically.
6. Publish. Missing category links, duplicate links and links to unavailable/free tickets are rejected. Linked QRs must be in an unconditional section.

The participant ticket selector appears immediately before the first payment QR block. Only the selected category's QR appears, along with its fixed price. UPI app links use the same server-configured fee. Free tickets hide payment fields. Answers and the selected category use the existing account draft system.

Uploaded QR artwork is supplied by the coordinator; it is not decoded or rewritten by the site. When changing a category's price, update its fixed-amount QR as well. No production QR, bank account or category link was invented by this implementation. Existing unlinked forms remain compatible until coordinators configure their links.

The submitted order retains its category, price, form schema, QR and receiving UPI ID while it is edited or reviewed. Approval still requires the coordinator to check the actual receiving account, exact amount and unique transaction reference. A screenshot alone never issues a ticket.

## Verification

- `php tests/ticket-payment85.php`: isolated in-memory database; ticket links, game scope, conditions, amount integrity, draft restoration, frozen payment setup and approval.
- `php tests/form54.php`: form editor and validation regression coverage.
- Browser checks used an isolated loopback-only fixture with demonstrational non-payment QR codes. Single/Duo switching, UPI amounts, free-ticket visibility, restored selection, publication and shuffle ordering passed. Mobile document width equalled its viewport width.
- Screenshots are in `output/payment85/`. No real registration or transfer was made.

An older `tests/manual-payments.php` fixture currently selects Inauguration as a ticketed event. It stops because Inauguration now takes contributions. That legacy fixture is unchanged; the new targeted test covers the current form payment approval workflow.
