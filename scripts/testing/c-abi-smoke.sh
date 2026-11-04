#!/bin/sh
set -eu
cargo build --locked --offline -p najwa-ffi
output_dir="${CARGO_TARGET_DIR:-target}/debug"
cc -Wall -Wextra -Werror -Icrates/najwa-ffi/include \
  crates/najwa-ffi/tests/c_abi_smoke.c -L"$output_dir" -lnajwa_ffi \
  -Wl,-rpath,"$(realpath "$output_dir")" -o "$output_dir/c-abi-smoke"
"$output_dir/c-abi-smoke"
