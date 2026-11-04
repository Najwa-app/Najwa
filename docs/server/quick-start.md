# Run a mailbox in 15 minutes

A Najwa mailbox holds encrypted messages for people while their app is closed.
It cannot read them. This page sets one up on a rented server with one command.
To understand every step, or for a system other than Ubuntu 26.04, use the full
[Deployment](deployment.md) guide.

## What you need

- A server running **Ubuntu 26.04** with at least 2 GB of memory and 20 GB of
  disk. Any hosting provider works; a small cloud server costs a few euros a
  month.
- A way to log in to it over SSH: the password your provider gives you, or
  better, an SSH key you add when you create the server.

Use a server that runs nothing else. The installer locks it down for the
mailbox: it changes the firewall and turns off root login.

## 1. Log in

```sh
ssh root@<server IP address>
```

On a new server you may first be asked to choose a new password.

## 2. Run the installer

```sh
curl -fsSL https://raw.githubusercontent.com/Najwa-app/Najwa/main/scripts/deployment/install-mailbox.sh -o install-mailbox.sh
sudo bash install-mailbox.sh
```

It takes about 15 minutes, most of it building the mailbox. It:

1. installs all updates and locks the server down: a firewall that lets only
   SSH in, no root login, protection against password guessing;
2. installs Tor and builds the mailbox from source;
3. creates the mailbox's address and its signing key;
4. starts the mailbox and checks that it answers.

If your connection drops, the install keeps going. Log in again and run
`tail -f /var/lib/najwa-install/install.log` to watch it. Running the
installer again is safe: it never replaces the keys or settings it made.

## 3. Note your address

At the end the installer prints the mailbox's **address**, a long name ending
in `.onion`, and its **operator ID**. The address is also shown whenever you log
in.

## 4. Back up the two keys

Do this now. If you lose the onion key, the address is gone for good and
everyone who uses your mailbox has to switch to a new one. Show the keys with:

```sh
sudo base64 -w0 /var/lib/tor/najwa-mailbox/hs_ed25519_secret_key; echo
sudo cat /etc/najwa-mailbox/operator-seed
```

Copy each one into a password manager, as separate entries, and keep them
private. Anyone who has both can pretend to be your mailbox. Restoring them is
described in [Operations §2](operations.md#2-backup-and-restore).

## 5. Log in as the new admin user from now on

Root can no longer log in over SSH. The installer prints the user to use,
normally `najwa-deploy`, with the same password or key you used for root:

```sh
ssh najwa-deploy@<server IP address>
```

## 6. Share it

- Give the address to the people who will use it. They paste it into Najwa's
  settings ([Getting started §4](../getting-started.md#4-add-your-mailbox)).
- To offer it to anyone, add it to the
  [public mailbox list](../../MAILBOXES.md#adding-a-mailbox).

## Keeping it running

- **Updates** to Ubuntu install by themselves. When the login message says a
  restart is required, run `sudo reboot`; the mailbox starts again on its own.
- **Updating the mailbox** itself: back up first, then run both lines of step 2
  again. The installer rebuilds from the latest source and keeps your keys and
  settings. If the new version does not start, it puts the old one back.
- **Settings** are in `/etc/najwa-mailbox/mailbox.toml`: storage limits,
  proof-of-work cost and release timing. The defaults suit most mailboxes; what
  each setting means is in [Deployment §7](deployment.md#7-configure-the-server).
  Restart after a change: `sudo systemctl restart najwa-mailbox`.
- **Everything else**, such as monitoring, database backups and shutting the
  mailbox down cleanly, is in [Operations](operations.md).
