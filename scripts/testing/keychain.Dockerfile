# Build from the repository root: docker build -f scripts/testing/keychain.Dockerfile -t najwa-keychain-test .
# Run with the workspace mounted at /work and the cargo registry cache mounted as usual.
# Do not mount a host D-Bus socket or keychain into this test container.
FROM rust:bookworm
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dbus gnome-keyring
WORKDIR /work
ENV CARGO_TARGET_DIR=/work/target-linux
CMD ["dbus-run-session", "--", "sh", "scripts/testing/keychain-tests.sh"]
