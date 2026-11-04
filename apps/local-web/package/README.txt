Najwa

Najwa is a private messenger. It runs on this computer and opens in your web
browser. Messages travel over Tor to mailboxes, so you and the people you talk
to do not need to be online at the same time.


START

Extract the whole folder, then open Najwa:

    Windows:  double-click Najwa.exe
    Linux:    run Najwa
    macOS:    open Najwa.app

Najwa opens in your default browser at http://127.0.0.1:1421. This address
works only on this computer. Everything Najwa needs, including Tor, is in this
folder. You do not need Docker, Node.js, Rust or any script.

This is an unsigned preview, so your system may warn before it starts the
program. On Windows, select More info, then Run anyway. On a Mac, open System
Settings > Privacy & Security and select Open Anyway next to the message about
Najwa.

Linux also needs: a desktop keyring (Secret Service), xdg-open, and the TPM 2.0
libraries. On Ubuntu or Debian install libtss2-esys-3.0.2-0, libtss2-mu0,
libtss2-tctildr0 and libtss2-tcti-device0. The TPM is used through /dev/tpmrm0.


FIRST USE

1. Create your identity with a passphrase of at least 12 characters.
2. Save your recovery kit: write down the 24 recovery words and download the
   recovery file. Keep them in different safe places. Anyone who has both can
   take over your identity. The kit does not contain your contacts or messages.
3. Paste the mailbox address (it ends in .onion) that your mailbox operator
   gave you, and select Add mailbox. Wait until Settings shows it as
   Registered. You can add up to eight mailboxes.
4. Create an invitation, or accept one, to connect with someone. Then compare
   safety numbers with them in person or through another channel you trust.


KEY PROTECTION

Najwa protects your identity with your passphrase and with the computer's
security hardware: the TPM 2.0 chip on Windows and Linux, the Secure Enclave on
macOS. If that hardware is not available, Najwa asks before it uses the system
key storage instead (Windows key storage, the Linux keyring, or the macOS
Keychain). You can say no. If you agree, the choice applies to this identity
and Najwa shows it on screen. System key storage is weaker than the hardware.
If the hardware key of an existing identity is lost, only the recovery kit can
restore that identity.


LOCKING AND CLOSING

Najwa locks your identity when you close the page, and after 5 minutes without
activity. You can change that time in Settings, from 1 minute to 1 hour.
For a long file transfer, tick Keep unlocked at the top of the page.
Locking the computer, switching user or sleeping also locks Najwa, even with
Keep unlocked ticked.

Najwa keeps running in the background after you close the page. Quit Najwa
locks your identity and stops the app. Signing out or restarting the computer
also stops it. To come back, open Najwa again and enter your passphrase.

If you forget your passphrase, select "Forgot your passphrase?" on the unlock
screen and enter your 24 recovery words.


YOUR PROFILE

Your identity and encrypted conversations are stored outside this folder:

    Windows:  %LOCALAPPDATA%\Najwa\Najwa Web\data\profile
    Linux:    ~/.local/share/najwaweb/profile
    macOS:    ~/Library/Application Support/org.Najwa.Najwa-Web/profile

Never share the profile folder, and never copy it while Najwa is running.


UPDATING

Select Quit Najwa first. Replace this folder with the new version, then open
Najwa again. Your identity and conversations stay where they are.


FILES

Najwa removes hidden details from files before it sends them, and pictures are
converted to WebP. The largest file is 256 MB. Files of 10 MB or less are
recommended, because larger files travel very slowly over Tor.


BEFORE YOU RELY ON NAJWA

Najwa has not had an independent security audit. Read the getting-started
guide, the threat model and RELEASE-READINESS.md in the Najwa source
repository.

Najwa is licensed under GPL-3.0-or-later. See LICENSE.txt.
