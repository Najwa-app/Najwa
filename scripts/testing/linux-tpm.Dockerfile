# Synthetic TPM + isolated Secret Service. No host TPM or keychain is mounted.
FROM rust:bookworm
RUN rustup component add clippy
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dbus gnome-keyring swtpm libtss2-dev libtss2-tcti-swtpm0 pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENV CARGO_TARGET_DIR=/work/target-linux
CMD ["dbus-run-session", "--", "sh", "scripts/testing/linux-tpm-tests.sh"]
