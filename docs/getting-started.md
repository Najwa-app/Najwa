# Getting started

Najwa is a private messenger that runs on your own computer. It opens in your
usual web browser, but it is not a website: the app, your identity and your
messages stay on your computer. Messages travel over Tor to mailboxes, so you
and the people you talk to do not need to be online at the same time.

This guide walks you through first use. For the background, read
[How Najwa works](understanding/how-it-works.md). Najwa has not had an
independent security audit. Read the [threat model](understanding/threat-model.md)
and the [release status](../RELEASE-READINESS.md) before you rely on it.

## What you need

- A Windows or Linux computer (64-bit x86), or a Mac (Apple silicon or Intel,
  macOS 13 or later). The Mac packages are an untested preview.
- The Najwa package for your system, from the
  [releases page](https://github.com/Najwa-app/Najwa/releases). It contains
  everything Najwa needs, including Tor. You do not need Docker, Node.js or
  Rust.
- A mailbox address from a mailbox operator. It is a long address that ends in
  `.onion`. Najwa does not come with one; the [public mailbox list](../MAILBOXES.md)
  has addresses that operators offer to anyone. You can also
  [run your own mailbox](server/deployment.md).
- A passphrase of at least 12 characters that is hard to guess and that you will
  remember. Four or more unrelated words work well.

On Linux, hardware protection uses the TPM through `/dev/tpmrm0` and the TPM 2.0
libraries listed in the package's `README.txt`. Najwa also needs a desktop
keyring (Secret Service) and `xdg-open`.

## 1. Start Najwa

1. [Check the download](security/supply-chain.md#6-verifying-a-download)
   against its `.sha256` file.
2. Extract the whole package into a folder. Keep its files together.
3. Open `Najwa.exe` on Windows, `Najwa` on Linux, or `Najwa.app` on a Mac. The
   packages are not signed, so the first start brings a warning:
   - **Windows:** select **More info**, then **Run anyway**.
   - **Mac:** macOS refuses to open it. Open **System Settings → Privacy &
     Security**, select **Open Anyway** next to the message about Najwa, and
     confirm. Najwa shows no Dock icon; it opens your browser instead.
4. Your browser opens Najwa at `http://127.0.0.1:1421`. This address works only
   on your own computer.

Najwa keeps running in the background while you use it. If you open Najwa again
while it is running, it takes you back to the same app.

If the browser shows **Connect this browser**, open Najwa again from its folder.
A browser that has connected once can return to Najwa for up to 30 days. You
still need your passphrase each time.

## 2. Create your identity

Your identity is what your contacts know you by. It is created on your computer.
There is no account, phone number or email address.

1. Enter a new passphrase of at least 12 characters and confirm it. Four or more
   unrelated words work well. Najwa refuses a passphrase that is easy to guess:
   a common password, a repeated character or a keyboard pattern such as
   `qwertyuiop`. The same rule applies when you change your passphrase or choose
   a new one during recovery.
2. Select **Create my identity**. This takes a few seconds.

Najwa protects your identity with your passphrase together with a key held by
your computer's security chip (TPM 2.0). If the chip is not available, Najwa
shows an error and offers **Use system key storage instead…**. This keeps the
key in the operating system's key storage instead (Windows Credential Manager,
or the keyring on Linux), which is weaker than the security chip. Najwa uses it
only if you tick the approval box and select **Use system key storage**.
**Keep hardware protection** closes the dialog without changing anything. While
system key storage is in use, Najwa says so at the top of the window.

## 3. Save your recovery kit

The recovery kit lets you back in if you forget your passphrase or move to
another computer. It has two parts:

- 24 recovery words, and
- an encrypted recovery file named `najwa-….recovery`.

Najwa shows the kit right after you create your identity:

1. Select **Reveal recovery words** and write the 24 words on paper.
2. Select **Download recovery file** and keep the file somewhere safe.
3. Tick **I saved the words somewhere safe.**
4. Select **Check my recovery words** and type the three words Najwa asks for,
   from your written copy.
5. Select **I’ve saved both — continue**.

Keep the words and the file in different places. Anyone who has both parts can
take over your identity. The kit restores your identity only. It does not
contain your contacts or your messages.

## 4. Add your mailbox

A mailbox holds encrypted messages for you while you are away.

1. Wait until Tor is connected. Najwa shows **Waiting for Tor to connect…**
   until then. The first connection can take a minute or more.
2. Paste the `.onion` address from your operator into **Tor v3 mailbox**.
3. Select **Add mailbox**.

Registration happens over Tor and can take a while. The mailbox is ready when
**Settings** shows it as **Registered**. If it shows **Setup incomplete**,
select **Retry registration**. You can add up to eight mailboxes (see
[Settings](#settings)).

## 5. Connect with someone

You connect with someone by giving them an invitation yourself, in person or
through a channel you trust. Najwa has no directory of users.

To invite someone:

1. Select **Create invitation** in **Chats** or **Contacts**.
2. Enter the display name you want to share and select **Generate invitation**.
3. Share the link with **Copy invitation**, or let them scan the QR code.
   **Save QR image** saves the code as a picture.

An invitation is valid for up to 48 hours. Najwa shows the exact end time under
the QR code. An invitation connects one person. To invite several people,
create a separate invitation for each of them. They can all answer at the same
time.

To accept an invitation someone gave you:

1. Select **Add contact**.
2. Enter the display name you want to share.
3. Paste the invitation into **Signed invitation**, or use **Scan with camera**
   or **Upload QR image**.
4. Select **Accept invitation**.

Once 10 contacts were added in the last 24 hours, counting people who answered
your own invitations, Najwa warns that adding many contacts in a short time can
make you easier to identify. To accept another invitation anyway, tick **I
understand. Add this contact anyway.** and select **Accept invitation** again.

The other person does not need to be online. Each person's app does its part of
the setup the next time it is open and unlocked. Until setup finishes, the
conversation shows one of these:

| Status | Meaning |
| --- | --- |
| Contact request queued | Saved on this computer. Keep Najwa open and unlocked until it reaches the mailbox. |
| Contact request deposited | Waiting in the other person's mailbox. You can close Najwa. |
| No reply yet | The invitation's time limit passed and setup has not finished. |
| Contact request expired | The invitation expired before your request reached the mailbox. |
| Contact setup failed | The request could not be sent. |

When setup finishes, you can write messages.

### Compare safety numbers

A valid invitation proves only that it came from whoever created it. To be sure
you are talking to the right person, select **Safety number** in the
conversation. Compare the number with the other person in person, by phone or
through another channel you trust. If the numbers match, select **I compared
the numbers**. The conversation then shows **Identity verified**.

## 6. Send messages

Type in the message box and press Enter. Shift + Enter starts a new line.

The mark next to each message you send shows how far it got:

| Mark | Meaning |
| --- | --- |
| Clock | Saved on this computer, or retrying. Keep Najwa unlocked. |
| One tick | Deposited in the mailbox. You can close Najwa now. |
| Two ticks | Received by your contact's app. |
| Two blue ticks | Read by your contact. |
| Warning sign | Not sent. |

The small arrow beside a message opens **Reply**, **Copy text** and **Message
info**. The magnifier at the top of a conversation searches it. Search does not
include disappearing messages.

Najwa tells your contact you have read a message when the message is on screen,
in the open conversation, while the Najwa window has focus. You cannot turn
read receipts off.

## 7. Send files

Select **Attach file** in a conversation. Najwa cleans every file before it
sends it. Pictures are converted to WebP, which removes hidden details such as
location. Documents, audio and video lose their metadata. Najwa refuses files it
cannot clean safely.

| Kind | Formats |
| --- | --- |
| Pictures | JPEG, PNG, GIF, BMP, TIFF, WebP |
| Video | MP4, MOV |
| Documents | PDF, DOCX, ODT |
| Audio | MP3, OGG, FLAC, WAV |

HEIC photos are refused. Convert them to JPEG first. Cleaning removes hidden
details only: faces, text and anything else visible in the file are sent as they
are.

The largest file you can send is 256 MB. Files of 10 MB or less are
recommended, because larger files travel very slowly over Tor. Keep Najwa
unlocked until every part of the file is deposited. For a long transfer, tick
**Keep unlocked** at the top of the window. If an upload stops, choose the same
file again to resume it. To send a file, the conversation's disappearing-message
timer must be off.

When someone sends you a file, its download button becomes available once all
parts have arrived and Najwa has checked them.

## 8. Disappearing messages

Select **Disappearing messages** in a conversation to set a timer: 30 seconds,
5 minutes, 1 hour, 1 day, 7 days, 30 days, or a custom number of seconds (at
least 30). The timer applies to new messages. Messages you send start counting
down once they are delivered. Messages you receive start counting down when you
view them. After you change the timer, sending pauses until your contact's app
confirms the change.

Timers delete messages from both apps. They cannot stop someone from copying or
photographing a message before it disappears.

## 9. Manage contacts

**Chats** lists your conversations with previews and unread counts. **Contacts**
lists everyone in alphabetical order, with **Open chat** and a menu for each
person. Looking through **Contacts** does not mark messages as read.

From a contact's menu you can:

- change the name you see for them (the name stays on your computer);
- **Block contact**: Najwa ignores their new messages and holds back messages
  you have queued for them. Your history stays. Messages they send while
  blocked are lost;
- **Unblock contact**: messages flow again;
- **Delete contact…**: removes the contact, the conversation and any queued
  messages from this computer. Najwa also sends the other person a notice; when
  their app receives it, the conversation is removed from their Najwa too. To
  talk again, you exchange a new invitation.

Renaming, blocking and unblocking change only your computer. None of these
actions call back messages already deposited, and Delete cannot remove copies
the other person made themselves.

## 10. Lock, quit and come back

- **Lock** hides your messages until you enter your passphrase again. Najwa does
  not send or receive messages while it is locked.
- Najwa locks itself after 5 minutes without activity and when you close the
  page. You can change the time in **Settings**, from 1 minute to 1 hour.
- Najwa also locks when you lock your computer, switch to another user, or put
  the computer to sleep.
- **Keep unlocked** stops the inactivity lock while the page stays open, for
  example during a long file transfer. It switches off when you lock or restart
  Najwa. Locking or sleeping the computer still locks Najwa.
- **Quit Najwa** locks your identity and stops the app.

To come back, open Najwa and enter your passphrase.

If you forget your passphrase, select **Forgot your passphrase?** on the unlock
screen and enter your 24 recovery words. Your conversations stay.

On a new computer, select **I already have a recovery kit**, choose your
recovery file and enter the words. This brings back your identity, but not your
contacts or conversations. You then add your mailbox and exchange new
invitations.

## Settings

- **Mailboxes.** Add up to eight. The primary mailbox is listed first in new
  invitations; **Make primary** changes it. Najwa tells your existing contacts
  about your mailboxes automatically. Invitations you already shared do not
  change.
- **Message delivery.** **Responsive** (the default) sends right away. **Timing
  privacy** waits for slots in Najwa's background cover traffic. This hides when
  you send, but delivery takes longer.
- **Connection.** Shows whether Tor is connected, with **Reconnect** and
  **Synchronize now**.
- **Privacy & connection.** **Lock after inactivity** sets the automatic lock
  time. **Use bridges** helps on networks that block Tor: paste up to 8 bridge
  lines (plain, obfs4 or Snowflake). Changing bridges locks Najwa.

## Update Najwa

Your profile is stored outside the app folder:

- Windows: `%LOCALAPPDATA%\Najwa\Najwa Web\data\profile`
- Linux: `~/.local/share/najwaweb/profile`

To update, select **Quit Najwa**, replace the app folder with the new package,
and open Najwa again. Your identity and conversations stay. Do not copy the
profile folder while Najwa is running, and never share it with anyone.

## Erase your profile

On the **Identity** page, **Erase local profile…** deletes your identity,
contacts, messages and settings from this computer. The unlock screen offers the
same under **Remove this profile from this computer**. You tick the confirmation
box and type `ERASE`. This cannot be undone.

If your profile is unlocked, Najwa first spends up to 20 seconds asking your
mailboxes to stop accepting messages for it, then erases. Afterwards it lists
the mailboxes it reached and the ones it could not. A mailbox it could not
reach, or every mailbox if you erase while locked, keeps accepting your
contacts' messages for the erased profile until 30 days pass with no messages.
To have them stopped, unlock before you erase.

Erasing does not delete copies of your recovery kit, files you downloaded,
messages still waiting in mailboxes it could not reach, or anything on other
people's computers.

## Learn more

- [Frequently asked questions](understanding/faq.md)
- [How Najwa works](understanding/how-it-works.md)
- [Threat model](understanding/threat-model.md)
- [Run a mailbox](server/deployment.md)
- [Build Najwa from source](development/building.md)
