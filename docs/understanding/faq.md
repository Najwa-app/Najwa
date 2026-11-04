# Frequently asked questions

## Getting started

### Do I need a phone number, email address or account?

No. Najwa creates your identity on your computer. Nobody else registers you or
holds a copy of it.

### Where do I get a mailbox?

From a mailbox operator: a person or group you trust who runs a Najwa mailbox
server. You can also [run your own](../server/deployment.md). Najwa does not
come with a list of public mailboxes. The operator gives you an address that
ends in `.onion`.

### Do I need Docker, Node.js or Rust?

No. The Najwa package contains the app, its interface and Tor. Those tools are
only for developers who build Najwa from source.

### Why does Najwa open in my browser? Is it a website?

It is not a website. Najwa runs on your computer and shows its interface in
your browser at `http://127.0.0.1:1421`, an address that only your own computer
can reach. Your passphrase, identity and messages never go to a web server.

### Why does my browser say "Connect this browser"?

Najwa only talks to browsers it has connected to. Open Najwa again from its
folder; it opens your browser with a one-time link that connects it. After that,
the same browser can return for up to 30 days. You still need your passphrase.

### Can I use more than one browser or tab?

Yes. Every browser and tab connects to the same Najwa app on your computer and
shows the same identity and conversations. Using a different browser does not
create a different identity. Closing any Najwa tab locks the app for all of
them.

## Contacts and messages

### Do both people need to be online at the same time?

No. Your app needs to stay open and unlocked until your message is deposited in
the mailbox (one tick). After that you can close Najwa. The other person
receives it the next time they open and unlock Najwa. The same applies to
contact setup: each person's app does its part when it is next open and
unlocked. There is no fixed delivery time. It depends on Tor, on when each
person opens Najwa, and on how long the mailbox keeps messages.

### What do the marks next to my messages mean?

| Mark | Meaning |
| --- | --- |
| Clock | Saved on your computer and waiting to be sent, or retrying. |
| One tick | Deposited in the mailbox. You can close Najwa. |
| Two ticks | Your contact's app received it. |
| Two blue ticks | Your contact read it. |
| Warning sign | Not sent. |

For a file, the clock stays until every part is deposited. **Message info** in
a message's menu shows the full status.

### How long does an invitation last? Can I use one for several people?

An invitation lasts up to 48 hours. Najwa shows its end time under the QR code.
The link and the QR code are the same invitation with the same end time.

An invitation connects one person. To invite several people, create a separate
invitation for each of them. They can all answer at the same time. Contacts you
already have keep working after an invitation expires.

### Why does Najwa warn me when I add another contact?

Someone who sends you many invitations could learn which ones you accept. Once
10 contacts were added in the last 24 hours, Najwa warns you and asks you to
confirm before it accepts another invitation. The count includes people who
answered your own invitations. Nothing is blocked: tick the box and accept
again.

### Why compare safety numbers?

Anyone can create a valid invitation. If someone swapped the invitation on its
way to you, you would connect to them instead. Comparing the safety number with
your contact, in person or through another channel you trust, shows that no one
did. Display names are chosen by each person and prove nothing.

### Can I turn off read receipts?

No. Najwa tells your contact you read a message when it is on screen in the open
conversation while the Najwa window has focus. Messages in a background tab, or
in the **Contacts** list, do not count as read.

### Can I use more than one mailbox?

Yes, up to eight. Add them in **Settings** and choose a primary. New invitations
list the primary first and include every registered mailbox. Najwa sends
mailbox changes to your existing contacts automatically. Mailboxes run by
different operators help if one stops working.

### What if a mailbox goes offline?

While Najwa is unlocked, it retries temporary connection failures by itself and
keeps your queued messages. **Settings** lists the mailboxes it is retrying. If a
mailbox is gone for good, contacts can still reach you through your other
registered mailboxes. Messages that were waiting in the lost mailbox are lost.

### What happens when I block, delete or erase?

- **Block contact** ignores the person's new messages and holds back messages
  you have queued for them. Your history stays. Messages they send while you
  block them are lost.
- **Delete contact…** removes the person, your conversation and queued messages
  from your computer. Najwa also sends them an encrypted notice. When their app
  receives it, their Najwa removes you and the conversation too. To talk again,
  you exchange a new invitation.
- **Erase local profile…** removes your identity, contacts, messages and
  settings from your computer. If you are unlocked, it first asks your
  mailboxes, for up to 20 seconds, to stop accepting messages for you, and then
  tells you which mailboxes it reached. Erasing while locked, or a mailbox it
  cannot reach, leaves that mailbox accepting messages for you until 30 days
  pass with no messages.

Block changes only your computer, and erase reaches only your computer and your
own mailboxes. None of these recall messages already deposited. The delete notice waits in your queue until it reaches their
mailbox, for up to 90 days, even if you go offline or restart. It is not sent if
the contact was never fully set up, and it does nothing if they have blocked
you. It cannot remove copies they made themselves, such as screenshots or
exports. The same applies to you: a contact who deletes you also removes the
conversation from your Najwa. On SSDs and in backups made by your operating
system, deleted data can sometimes still be recovered.

## Files

### Which files can I send?

JPEG, PNG, GIF, BMP, TIFF and WebP pictures; MP4 and MOV video; PDF, DOCX and
ODT documents; and MP3, OGG, FLAC and WAV audio. Najwa cleans each file before
sending: pictures become WebP, and hidden details such as location and author
names are removed. Najwa refuses other files and HEIC photos. Cleaning does not
change what the file visibly shows.

### Why are large files slow?

A file is split into many encrypted parts, and each part travels over Tor to the
mailbox. Tor is slow compared with a direct connection, and mailboxes limit how
fast and how much you can store. The limit is 256 MB, but 10 MB or less is
recommended. Keep Najwa unlocked until all parts are deposited; **Keep
unlocked** helps for long transfers. Uploads and sending resume after a restart.

### Can I send files in a conversation with disappearing messages?

No. Turn the timer off first.

## Privacy and security

### Can the mailbox operator read my messages?

No. Messages are encrypted on your computer, and the mailbox stores only
encrypted data. The operator does not learn your name or identity. It can see
when encrypted data arrives and is collected, roughly how big it is, and when
your app is online. A dishonest operator can also delay, drop or keep copies of
encrypted messages. The [threat model](threat-model.md) lists what each party
can learn.

### What is the difference between Responsive and Timing privacy?

Both use Tor and encryption. **Responsive** (the default) sends a message as soon
as you write it. **Timing privacy** waits for slots in Najwa's steady
background cover traffic, so someone watching your connection has a harder time
telling when you send. Messages take longer in this mode. Neither mode hides
your activity from someone who can watch large parts of the internet at once.

### What are bridges?

Some networks block Tor. Bridges are unlisted Tor entry points that help you
connect anyway. Get bridge lines from the Tor Project or someone you trust and
paste them under **Use bridges** in **Settings**. Najwa keeps using them after a
restart and never switches back to direct Tor without you.

### What if my computer has no TPM?

Najwa asks before it uses your operating system's key storage instead. You can
say no. If you agree, your approval applies to this identity, and Najwa shows
that system key storage is in use. System key storage is weaker: the key is not
locked inside a security chip, so someone who copies your files and gets into
your computer account has an easier time attacking your passphrase.

### Do disappearing messages really disappear?

They are deleted from both apps when the timer runs out. Messages you send
start counting down after delivery, and messages you receive start when you view
them. A timer cannot stop the other person from copying or photographing a
message first.

### Has Najwa been audited? Is it safe for high-risk situations?

Najwa has not had an independent security audit, and it has known limitations.
Read the [threat model](threat-model.md),
[security properties](../security/properties.md) and
[release status](../../RELEASE-READINESS.md) before relying on it.

## Passphrase and recovery

### Why was my new passphrase refused?

Najwa refuses a new passphrase that is easy to guess, even if it has 12 or more
characters: a common password, a repeated character, a sequence or a keyboard
pattern. It estimates how many guesses an attacker would need and asks for at
least about a trillion (2^40). Four or more unrelated words usually pass. This
applies when you create an identity, change your passphrase or recover; it never
stops you from unlocking with a passphrase you already have.

### I forgot my passphrase.

On the unlock screen, select **Forgot your passphrase?** and enter your 24
recovery words. Then choose a new passphrase. Your identity and conversations
stay.

### I typed a wrong passphrase several times.

Najwa makes you wait longer after each wrong attempt. After 10 wrong attempts
the profile is locked out. Use your recovery kit, or wait: the count resets 24
hours after the last attempt.

### My computer broke. How do I get my identity back?

Install Najwa on the new computer, select **I already have a recovery kit**,
choose your recovery file and enter your 24 words. This brings back your
identity, not your contacts or conversations; Najwa has no conversation backup.
Add your mailbox again and exchange new invitations. A contact who still has you
in their list has to delete you first: otherwise Najwa tells them that this
identity is already a contact.

### Someone may have seen my recovery kit.

On the **Identity** page, confirm your passphrase and select **Create
replacement recovery kit**, then save the new kit. After that, the old words do
not work on this computer. A complete old kit, both the words and the file, still
works on another computer, and nothing can cancel it. If someone may have both
old parts, erase this profile, create a new identity and connect with your
contacts again.

### Can I use one identity on two computers?

No. An identity belongs to one profile on one computer. Najwa has no linked
devices.

### Where is my data stored?

In your profile folder: `%LOCALAPPDATA%\Najwa\Najwa Web\data\profile` on Windows
and `~/.local/share/najwaweb/profile` on Linux. Everything in it is encrypted.
Updating the app does not touch it. Quit Najwa before you update, and never copy
the folder while Najwa is running.

### What happens if I just close the browser?

Closing the Najwa page locks your identity. The app keeps running in the
background until you select **Quit Najwa** or sign out of your computer. If the
browser crashes before it can lock Najwa, Najwa still locks itself after the
inactivity time set in **Settings**.

### Does locking my computer lock Najwa?

Yes. Locking the computer, switching to another user or putting the computer to
sleep locks Najwa, even with **Keep unlocked** ticked. You need your passphrase
to unlock it again.
