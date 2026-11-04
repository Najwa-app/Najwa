#!/usr/bin/env bash
# Najwa Mailbox Server — Linux Server Hardening Script
#
# Run this BEFORE deploying the mailbox server. It prepares a fresh Linux
# server (Ubuntu 22.04+, Debian 12+, or RHEL/Fedora) for secure operation.
#
# Usage:
#   sudo ./harden-server.sh              # Full hardening (interactive)
#   sudo ./harden-server.sh --yes        # Skip confirmations
#   sudo ./harden-server.sh --check      # Audit only (no changes)
#
# What this script does (in safe order — SSH is LAST):
#   1. System updates + unattended-upgrades
#   2. Firewall (inbound: SSH only; outbound: any TCP, NTP and DNS; localhost)
#   3. Dedicated najwa-mailbox service user
#   4. Kernel hardening (sysctl)
#   5. Core dump prevention
#   6. Disable unnecessary services
#   7. fail2ban for SSH brute-force protection
#   8. AppArmor enforcement (if available)
#   9. File permission lockdown
#  10. Shared memory hardening
#  11. Deploy user + SSH hardening (LAST — ensures you don't get locked out)
#  12. Audit summary
#
# Reference: docs/server/deployment.md §2, S16 §12
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

AUTO_YES=false
CHECK_ONLY=false
LOG_FILE="/var/log/najwa-harden-$(date +%Y%m%d-%H%M%S).log"
ISSUES=0
APPLIED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; ISSUES=$((ISSUES+1)); }
fix()   { echo -e "${GREEN}[FIX]${NC}   $*" | tee -a "$LOG_FILE"; APPLIED=$((APPLIED+1)); }
skip()  { echo -e "${YELLOW}[SKIP]${NC}  $*" | tee -a "$LOG_FILE"; }
header(){ echo -e "\n${BOLD}━━━ $* ━━━${NC}" | tee -a "$LOG_FILE"; }

usage() {
    echo "Usage: $0 [--yes] [--check]"
    echo ""
    echo "  --yes, -y     Skip confirmation prompts"
    echo "  --check, -c   Audit only — report issues without making changes"
    echo "  --help, -h    Show this help"
}

# Parse args
for arg in "$@"; do
    case "$arg" in
        --yes|-y)   AUTO_YES=true ;;
        --check|-c) CHECK_ONLY=true ;;
        --help|-h)  usage; exit 0 ;;
    esac
done

confirm() {
    if $AUTO_YES || $CHECK_ONLY; then return 0; fi
    read -rp "  Apply? [y/N] " ans
    [[ "$ans" =~ ^[Yy] ]]
}

# Detect package manager
detect_pkg() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG="yum"
    elif command -v pacman >/dev/null 2>&1; then
        PKG="pacman"
    else
        PKG="unknown"
    fi
}

pkg_install() {
    case "$PKG" in
        apt)    apt-get install -y -qq "$@" ;;
        dnf)    dnf install -y -q "$@" ;;
        yum)    yum install -y -q "$@" ;;
        pacman) pacman -S --noconfirm "$@" ;;
        *)      warn "Unknown package manager — install manually: $*"; return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

preflight() {
    header "Pre-flight Checks"

    [[ "$(uname -s)" == "Linux" ]] || { echo "This script requires Linux."; exit 1; }
    [[ "$(id -u)" -eq 0 ]] || { echo "This script requires root. Run with sudo."; exit 1; }

    detect_pkg
    ok "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    ok "Package manager: $PKG"
    ok "Kernel: $(uname -r)"
    ok "Log: $LOG_FILE"

    if $CHECK_ONLY; then
        info "AUDIT MODE — no changes will be made"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# 1. System Updates
# ---------------------------------------------------------------------------

harden_updates() {
    header "1. System Updates"

    if $CHECK_ONLY; then
        info "Checking for pending updates..."
        case "$PKG" in
            apt) apt-get update -qq 2>/dev/null; PENDING=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true) ;;
            dnf|yum) PENDING=$(${PKG} check-update --quiet 2>/dev/null | wc -l || true) ;;
            *) PENDING=0 ;;
        esac
        if [[ "$PENDING" -gt 0 ]]; then
            warn "$PENDING packages have pending updates"
        else
            ok "System up to date"
        fi
        return
    fi

    info "Updating package lists and installing security updates..."
    case "$PKG" in
        apt)
            apt-get update -qq
            # Plain upgrade holds back packages that need new dependencies,
            # which includes every kernel update.
            DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq --with-new-pkgs
            fix "System packages updated"
            ;;
        dnf) dnf upgrade -y -q; fix "System packages updated" ;;
        yum) yum update -y -q; fix "System packages updated" ;;
        pacman) pacman -Syu --noconfirm; fix "System packages updated" ;;
    esac

    # Unattended upgrades (Debian/Ubuntu)
    if [[ "$PKG" == "apt" ]]; then
        if ! dpkg -l unattended-upgrades >/dev/null 2>&1; then
            info "Installing unattended-upgrades..."
            apt-get install -y -qq unattended-upgrades
            cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
            fix "Unattended security upgrades enabled"
        else
            ok "Unattended upgrades already installed"
        fi
    fi

    # dnf-automatic (RHEL/Fedora)
    if [[ "$PKG" == "dnf" ]]; then
        if ! systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
            pkg_install dnf-automatic
            sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
            systemctl enable --now dnf-automatic.timer
            fix "dnf-automatic security updates enabled"
        else
            ok "dnf-automatic already enabled"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 2. SSH Hardening
# ---------------------------------------------------------------------------

harden_ssh() {
    header "11. Deploy User + SSH Hardening (safe order)"

    SSHD_CONFIG="/etc/ssh/sshd_config"
    [[ -f "$SSHD_CONFIG" ]] || { ok "No SSH server installed — skipping"; return; }

    CHANGED=false
    CURRENT_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-root}")

    # -----------------------------------------------------------------------
    # Step A: Ensure a non-root sudo user exists BEFORE touching SSH config
    # -----------------------------------------------------------------------

    # Find existing non-root users with sudo/wheel membership
    SUDO_USERS=$(getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort -u || true)
    NON_ROOT_SUDO=$(echo "$SUDO_USERS" | grep -v '^root$' || true)

    if [[ -z "$NON_ROOT_SUDO" ]]; then
        warn "No non-root sudo user exists — root is the only admin"

        if $CHECK_ONLY; then
            warn "Create a deploy user before disabling root SSH login"
        else
            info "Creating deploy user 'najwa-deploy' with sudo access..."
            if ! id najwa-deploy >/dev/null 2>&1; then
                useradd -m -s /bin/bash -G sudo,systemd-journal,adm najwa-deploy 2>/dev/null || \
                useradd -m -s /bin/bash -G wheel,systemd-journal,adm najwa-deploy 2>/dev/null || \
                { warn "Could not create deploy user — skipping SSH hardening"; return; }

                # Copy root's SSH authorized_keys to the new user
                if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
                    mkdir -p /home/najwa-deploy/.ssh
                    cp /root/.ssh/authorized_keys /home/najwa-deploy/.ssh/
                    chown -R najwa-deploy:najwa-deploy /home/najwa-deploy/.ssh
                    chmod 700 /home/najwa-deploy/.ssh
                    chmod 600 /home/najwa-deploy/.ssh/authorized_keys
                    # The user has no password, so sudo is only usable without one.
                    echo "najwa-deploy ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/najwa-deploy
                    chmod 0440 /etc/sudoers.d/najwa-deploy
                    visudo -cf /etc/sudoers.d/najwa-deploy >/dev/null
                    fix "Created user 'najwa-deploy' with passwordless sudo + copied SSH keys from root"
                    warn "These SSH keys now give root. To make sudo ask for a password:"
                    warn "  passwd najwa-deploy && rm /etc/sudoers.d/najwa-deploy"
                else
                    # No SSH keys — copy root's password hash so the user can login
                    ROOT_HASH=$(getent shadow root | cut -d: -f2)
                    if [[ -n "$ROOT_HASH" ]] && [[ "$ROOT_HASH" != "!" ]] && [[ "$ROOT_HASH" != "*" ]]; then
                        usermod -p "$ROOT_HASH" najwa-deploy
                        fix "Created user 'najwa-deploy' with sudo + same password as root"
                    else
                        fix "Created user 'najwa-deploy' with sudo access"
                        warn "No password or SSH keys available — set a password:"
                        warn "  Run: passwd najwa-deploy"
                    fi
                    warn "Set up SSH keys when possible: ssh-copy-id najwa-deploy@$(hostname -I 2>/dev/null | awk '{print $1}')"
                fi
            else
                ok "User najwa-deploy already exists"
            fi
            NON_ROOT_SUDO="najwa-deploy"
        fi
    else
        ok "Non-root sudo user(s) found: $NON_ROOT_SUDO"
    fi

    # -----------------------------------------------------------------------
    # Step B: Decide the SSH settings
    # -----------------------------------------------------------------------

    # sshd keeps the first value it reads for each keyword, and the
    # distribution config includes sshd_config.d/*.conf before its own
    # settings. A drop-in that sorts first therefore wins over both, including
    # a cloud image's 50-cloud-init.conf (which sets PasswordAuthentication yes).
    SSHD_DROPIN="/etc/ssh/sshd_config.d/00-najwa-hardening.conf"
    SETTINGS=("PermitEmptyPasswords no" "MaxAuthTries 5" "ClientAliveInterval 300" "ClientAliveCountMax 2")

    # Root login — only disable if a non-root sudo user exists
    if [[ -n "$NON_ROOT_SUDO" ]]; then
        SETTINGS+=("PermitRootLogin no")
    else
        warn "Skipping root login disable — no non-root sudo user available"
    fi

    # Password auth — only disable if SSH keys are set up
    HAS_KEYS=false
    for home_dir in /root /home/*; do
        if [[ -s "$home_dir/.ssh/authorized_keys" ]]; then
            HAS_KEYS=true
            break
        fi
    done
    if $HAS_KEYS; then
        SETTINGS+=("PasswordAuthentication no" "KbdInteractiveAuthentication no")
    else
        warn "No SSH authorized_keys found for any user — keeping password auth enabled"
        warn "  Set up SSH keys first: ssh-copy-id user@server"
    fi

    # -----------------------------------------------------------------------
    # Step C: Compare with what sshd actually uses, then apply
    # -----------------------------------------------------------------------

    effective() { sshd -T 2>/dev/null | awk -v k="${1,,}" '$1 == k { print $2 }'; }
    for setting in "${SETTINGS[@]}"; do
        read -r key value <<<"$setting"
        current=$(effective "$key")
        if [[ "$current" == "$value" ]]; then
            ok "SSH $key $value"
        else
            warn "SSH $key is '$current' (want $value)"
            CHANGED=true
        fi
    done

    if $CHANGED && ! $CHECK_ONLY; then
        grep -qE '^Include /etc/ssh/sshd_config\.d/' "$SSHD_CONFIG" || \
            sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
        mkdir -p /etc/ssh/sshd_config.d
        { echo "# Written by harden-server.sh; see docs/server/deployment.md §2"
          printf '%s\n' "${SETTINGS[@]}"; } > "$SSHD_DROPIN"
        if ! sshd -t; then
            rm -f "$SSHD_DROPIN"
            warn "sshd rejected $SSHD_DROPIN — removed it; SSH left unchanged"
            return
        fi
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        for setting in "${SETTINGS[@]}"; do
            read -r key value <<<"$setting"
            [[ "$(effective "$key")" == "$value" ]] || warn "SSH $key is still not $value — check $SSHD_CONFIG"
        done
        fix "SSH settings written to $SSHD_DROPIN and reloaded"
        echo ""
        info "IMPORTANT: Test SSH access in a NEW terminal before closing this session!"
        if [[ -n "$NON_ROOT_SUDO" ]] && [[ "$CURRENT_USER" == "root" ]]; then
            info "  ssh ${NON_ROOT_SUDO}@$(hostname -I 2>/dev/null | awk '{print $1}')"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 3. Firewall
# ---------------------------------------------------------------------------

harden_firewall() {
    header "2. Firewall"

    if command -v ufw >/dev/null 2>&1; then
        harden_firewall_ufw
    elif command -v firewall-cmd >/dev/null 2>&1; then
        harden_firewall_firewalld
    elif command -v iptables >/dev/null 2>&1; then
        harden_firewall_iptables
    else
        warn "No firewall tool found — install ufw or firewalld"
        if ! $CHECK_ONLY; then
            pkg_install ufw && harden_firewall_ufw
        fi
    fi
}

harden_firewall_ufw() {
    if $CHECK_ONLY; then
        if ufw status | grep -q "Status: active"; then
            ok "UFW firewall is active"
            ufw status verbose | head -20
        else
            warn "UFW firewall is not active"
        fi
        return
    fi

    info "Configuring UFW firewall..."
    ufw --force reset >/dev/null 2>&1

    # Policy for a Tor onion-service host (same in the iptables branch):
    # - Inbound: deny everything except SSH. The mailbox needs no opening;
    #   clients arrive through Tor, which reaches the server over loopback.
    # - Outbound TCP to any port: Tor connects to guard and directory relays
    #   on whatever ORPort each relay advertises, not only 443/9001.
    #   Package updates use the same rule.
    # - Outbound NTP (123/udp): Tor, challenge expiry and proof-of-work
    #   timestamps need a correct clock.
    # - Outbound DNS (53): package mirrors and NTP pool names.
    # All other outbound UDP stays blocked.
    ufw default deny incoming
    ufw default deny outgoing

    # Allow SSH (essential — don't lock yourself out)
    ufw allow in 22/tcp comment "SSH"

    ufw allow out 1:65535/tcp comment "Tor relays (any ORPort), updates"
    ufw allow out 123/udp comment "NTP"
    ufw allow out 53 comment "DNS"

    # Allow loopback (Tor ↔ mailbox server communication)
    ufw allow in on lo
    ufw allow out on lo

    # UFW applies its own sysctl.conf whenever it starts, after sysctl.d, and
    # its default turns martian logging back off (§4 wants it on).
    sed -i 's|^\(net/ipv4/conf/[a-z]*/log_martians\)=0|\1=1|' /etc/ufw/sysctl.conf

    ufw --force enable
    fix "UFW firewall configured and enabled"
    ufw status verbose
}

harden_firewall_firewalld() {
    if $CHECK_ONLY; then
        if systemctl is-active --quiet firewalld; then
            ok "firewalld is active"
        else
            warn "firewalld is not active"
        fi
        return
    fi

    info "Configuring firewalld..."
    systemctl enable --now firewalld
    # Inbound SSH only. The health port is bound to 127.0.0.1 and needs no
    # opening. firewalld zones filter inbound only, so outbound stays open.
    firewall-cmd --set-default-zone=drop
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
    fix "firewalld configured (drop zone, SSH only; outbound unrestricted)"
}

harden_firewall_iptables() {
    if $CHECK_ONLY; then
        RULES=$(iptables -L -n 2>/dev/null | wc -l)
        if [[ "$RULES" -gt 10 ]]; then
            ok "iptables has $RULES rules"
        else
            warn "iptables has minimal rules — consider configuring"
        fi
        return
    fi

    info "Configuring iptables..."
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Same policy as the UFW branch: SSH in; any TCP, NTP and DNS out.
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp -j ACCEPT
    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    fix "iptables configured"
}

# ---------------------------------------------------------------------------
# 4. Service User
# ---------------------------------------------------------------------------

harden_user() {
    header "3. Service User"

    if id najwa-mailbox >/dev/null 2>&1; then
        ok "User najwa-mailbox exists"
    else
        if $CHECK_ONLY; then
            warn "User najwa-mailbox does not exist"
            return
        fi
        # -M: no skeleton dotfiles in the data directory (created below).
        useradd -r -s /sbin/nologin -d /var/lib/najwa-mailbox -M najwa-mailbox
        fix "Created system user: najwa-mailbox"
    fi

    # Directories
    for dir in /var/lib/najwa-mailbox /var/log/najwa-mailbox /etc/najwa-mailbox; do
        if [[ -d "$dir" ]]; then
            ok "Directory exists: $dir"
        else
            if ! $CHECK_ONLY; then
                mkdir -p "$dir"
                fix "Created: $dir"
            else
                warn "Missing: $dir"
            fi
        fi
    done

    if ! $CHECK_ONLY; then
        chown najwa-mailbox:najwa-mailbox /var/lib/najwa-mailbox /var/log/najwa-mailbox
        chmod 700 /var/lib/najwa-mailbox
        chmod 750 /var/log/najwa-mailbox
        chown root:najwa-mailbox /etc/najwa-mailbox
        chmod 750 /etc/najwa-mailbox
    fi
}

# ---------------------------------------------------------------------------
# 5. Kernel Hardening (sysctl)
# ---------------------------------------------------------------------------

harden_kernel() {
    header "4. Kernel Hardening (sysctl)"

    SYSCTL_FILE="/etc/sysctl.d/99-najwa-hardening.conf"

    declare -A PARAMS=(
        # Network
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        # IPv6 — disable if not needed
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        # ASLR
        ["kernel.randomize_va_space"]="2"
        # Restrict dmesg
        ["kernel.dmesg_restrict"]="1"
        # Restrict kernel pointer exposure
        ["kernel.kptr_restrict"]="2"
        # Restrict ptrace
        ["kernel.yama.ptrace_scope"]="2"
        # Restrict unprivileged BPF
        ["kernel.unprivileged_bpf_disabled"]="1"
    )

    MISMATCHES=0
    for param in "${!PARAMS[@]}"; do
        expected="${PARAMS[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$current" != "$expected" ]]; then
            warn "$param = $current (expected $expected)"
            MISMATCHES=$((MISMATCHES+1))
        fi
    done

    if [[ "$MISMATCHES" -eq 0 ]]; then
        ok "All kernel parameters already hardened"
        return
    fi

    if $CHECK_ONLY; then
        warn "$MISMATCHES kernel parameters need hardening"
        return
    fi

    info "Writing $SYSCTL_FILE..."
    cat > "$SYSCTL_FILE" <<'EOF'
# Najwa mailbox server — kernel hardening
# Applied by harden-server.sh — see docs/server/deployment.md

# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ICMP hardening
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Full ASLR
kernel.randomize_va_space = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Hide kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace (prevent process snooping)
kernel.yama.ptrace_scope = 2

# Restrict unprivileged BPF
kernel.unprivileged_bpf_disabled = 1
EOF

    sysctl --system >/dev/null 2>&1
    fix "Kernel parameters hardened ($MISMATCHES changes applied)"
}

# ---------------------------------------------------------------------------
# 6. Core Dump Prevention
# ---------------------------------------------------------------------------

harden_coredumps() {
    header "5. Core Dump Prevention"

    # /etc/security/limits.conf
    if grep -q "hard.*core.*0" /etc/security/limits.conf 2>/dev/null; then
        ok "Core dumps disabled in limits.conf"
    else
        if $CHECK_ONLY; then
            warn "Core dumps not disabled in limits.conf"
        else
            echo "* hard core 0" >> /etc/security/limits.conf
            fix "Core dumps disabled in limits.conf"
        fi
    fi

    # sysctl
    CURRENT=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")
    if [[ "$CURRENT" == "|/bin/false" ]]; then
        ok "kernel.core_pattern set to /bin/false"
    else
        if $CHECK_ONLY; then
            warn "kernel.core_pattern = '$CURRENT' (should be '|/bin/false')"
        else
            echo 'kernel.core_pattern=|/bin/false' >> /etc/sysctl.d/99-najwa-hardening.conf
            sysctl -w kernel.core_pattern='|/bin/false' >/dev/null
            fix "kernel.core_pattern set to |/bin/false"
        fi
    fi

    # systemd coredump
    if [[ -d /etc/systemd/coredump.d ]]; then
        if [[ -f /etc/systemd/coredump.d/najwa.conf ]]; then
            ok "systemd coredump disabled"
        else
            if ! $CHECK_ONLY; then
                mkdir -p /etc/systemd/coredump.d
                cat > /etc/systemd/coredump.d/najwa.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
                fix "systemd coredump disabled"
            else
                warn "systemd coredump not configured"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# 7. Disable Unnecessary Services
# ---------------------------------------------------------------------------

harden_services() {
    header "6. Unnecessary Services"

    SERVICES_TO_DISABLE=(
        avahi-daemon        # mDNS — not needed on a server
        cups                # Printing — not needed
        bluetooth           # Bluetooth — not needed
        ModemManager        # Modem — not needed
        snapd               # Snap — not needed on a hardened server
        apport              # Ubuntu crash reporter — resets kernel.core_pattern at boot
    )

    # Mask the service and its socket; a socket left enabled (snapd, cups,
    # avahi) starts the service again on the next boot.
    disable_unit() {
        systemctl stop "$1" "$1.socket" 2>/dev/null || true
        systemctl disable "$1" "$1.socket" 2>/dev/null || true
        systemctl mask "$1" 2>/dev/null || true
        if systemctl cat "$1.socket" >/dev/null 2>&1; then
            systemctl mask "$1.socket" 2>/dev/null || true
        fi
    }

    for svc in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            warn "Service running: $svc"
            if ! $CHECK_ONLY && confirm; then
                disable_unit "$svc"
                fix "Disabled: $svc"
            fi
        elif systemctl is-enabled --quiet "$svc" 2>/dev/null || \
             systemctl is-enabled --quiet "$svc.socket" 2>/dev/null; then
            warn "Service enabled (not running): $svc"
            if ! $CHECK_ONLY && confirm; then
                disable_unit "$svc"
                fix "Disabled: $svc"
            fi
        else
            ok "Not present/disabled: $svc"
        fi
    done
}

# ---------------------------------------------------------------------------
# 8. fail2ban
# ---------------------------------------------------------------------------

harden_fail2ban() {
    header "7. fail2ban (SSH brute-force protection)"

    if command -v fail2ban-server >/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban; then
            ok "fail2ban is active"
        else
            if ! $CHECK_ONLY; then
                systemctl enable --now fail2ban
                fix "fail2ban started"
            else
                warn "fail2ban installed but not running"
            fi
        fi
        return
    fi

    if $CHECK_ONLY; then
        warn "fail2ban not installed"
        return
    fi

    info "Installing fail2ban..."
    pkg_install fail2ban || { warn "Could not install fail2ban"; return; }

    # SSH jail config
    mkdir -p /etc/fail2ban
    cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

    systemctl enable --now fail2ban
    fix "fail2ban installed and configured for SSH"
}

# ---------------------------------------------------------------------------
# 9. AppArmor
# ---------------------------------------------------------------------------

harden_apparmor() {
    header "8. AppArmor / SELinux"

    # Check AppArmor
    if command -v aa-status >/dev/null 2>&1; then
        if aa-status --enabled 2>/dev/null; then
            ok "AppArmor is enabled"
            PROFILES=$(aa-status 2>/dev/null | grep "profiles are loaded" | head -1 || echo "")
            [[ -n "$PROFILES" ]] && info "$PROFILES"
        else
            warn "AppArmor is installed but not enabled"
            if ! $CHECK_ONLY && confirm; then
                systemctl enable --now apparmor 2>/dev/null || true
                fix "AppArmor enabled"
            fi
        fi
        return
    fi

    # Check SELinux
    if command -v getenforce >/dev/null 2>&1; then
        MODE=$(getenforce 2>/dev/null || echo "Unknown")
        if [[ "$MODE" == "Enforcing" ]]; then
            ok "SELinux is enforcing"
        elif [[ "$MODE" == "Permissive" ]]; then
            warn "SELinux is permissive (should be enforcing)"
            if ! $CHECK_ONLY && confirm; then
                setenforce 1
                sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config 2>/dev/null
                fix "SELinux set to enforcing"
            fi
        else
            warn "SELinux: $MODE"
        fi
        return
    fi

    # Neither installed
    if [[ "$PKG" == "apt" ]]; then
        warn "No MAC system (AppArmor/SELinux) found"
        if ! $CHECK_ONLY && confirm; then
            pkg_install apparmor apparmor-utils
            systemctl enable --now apparmor
            fix "AppArmor installed and enabled"
        fi
    else
        warn "No MAC system found — consider installing SELinux or AppArmor"
    fi
}

# ---------------------------------------------------------------------------
# 10. File Permission Lockdown
# ---------------------------------------------------------------------------

harden_permissions() {
    header "9. File Permissions"

    # World-writable files in critical paths
    WW=$(find /etc /usr /var -xdev -type f -perm -0002 2>/dev/null | head -5)
    if [[ -n "$WW" ]]; then
        warn "World-writable files found in system paths:"
        echo "$WW" | while read -r f; do echo "    $f"; done
    else
        ok "No world-writable files in /etc, /usr, /var"
    fi

    # /tmp sticky bit
    if [[ "$(stat -c %a /tmp)" == "1777" ]]; then
        ok "/tmp has sticky bit (1777)"
    else
        warn "/tmp does not have sticky bit"
        if ! $CHECK_ONLY; then
            chmod 1777 /tmp
            fix "/tmp sticky bit set"
        fi
    fi

    # crontab permissions
    for f in /etc/crontab /etc/cron.d; do
        if [[ -e "$f" ]]; then
            PERM=$(stat -c %a "$f")
            if [[ "$PERM" == "600" ]] || [[ "$PERM" == "700" ]]; then
                ok "$f permissions: $PERM"
            else
                if ! $CHECK_ONLY; then
                    chmod 600 "$f" 2>/dev/null || chmod 700 "$f"
                fi
            fi
        fi
    done
}

# ---------------------------------------------------------------------------
# 11. Shared Memory Hardening
# ---------------------------------------------------------------------------

harden_shm() {
    header "10. Shared Memory"

    if grep -q "tmpfs.*/run/shm.*noexec" /etc/fstab 2>/dev/null || \
       grep -q "tmpfs.*/dev/shm.*noexec" /etc/fstab 2>/dev/null; then
        ok "/dev/shm mounted with noexec"
    else
        warn "/dev/shm may allow exec — consider adding noexec mount option"
        if ! $CHECK_ONLY && confirm; then
            if ! grep -q "/dev/shm" /etc/fstab 2>/dev/null; then
                echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
                mount -o remount /dev/shm 2>/dev/null || true
                fix "/dev/shm remounted with noexec,nosuid,nodev"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# 12. Summary
# ---------------------------------------------------------------------------

summary() {
    header "12. Audit Summary"
    echo ""

    if $CHECK_ONLY; then
        if [[ "$ISSUES" -eq 0 ]]; then
            ok "Server passed all hardening checks ✅"
        else
            warn "$ISSUES issue(s) found — run without --check to apply fixes"
        fi
    else
        ok "$APPLIED hardening measure(s) applied"
        if [[ "$ISSUES" -gt 0 ]]; then
            warn "$ISSUES issue(s) flagged (some may require manual review)"
        fi
    fi

    echo ""
    info "Full log: $LOG_FILE"
    echo ""

    if ! $CHECK_ONLY; then
        echo -e "${BOLD}Next steps:${NC}"
        echo "  1. Review changes and reboot if kernel parameters changed"
        echo "  2. Verify SSH access still works (don't close this session yet!)"
        echo "  3. Install the mailbox server: docs/server/deployment.md §3 onward"
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  Najwa Mailbox Server — System Hardening Script ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    preflight
    harden_updates
    harden_firewall
    harden_user
    harden_kernel
    harden_coredumps
    harden_services
    harden_fail2ban
    harden_apparmor
    harden_permissions
    harden_shm
    harden_ssh       # LAST — after everything else is safe
    summary
}

main
