#!/bin/sh -e

# The amalgamation lives in the sqlite3mc-src crate, so upgrading SQLite3MC means bumping that
# dependency in Cargo.toml and regenerating the bindings from its header here.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
echo "$SCRIPT_DIR"
cd "$SCRIPT_DIR" || { echo "fatal error" >&2; exit 1; }
cargo clean -p libsqlite3-sys
TARGET_DIR="$SCRIPT_DIR/../target"
BINDINGS_DIR="$SCRIPT_DIR/sqlite3mc"
mkdir -p "$TARGET_DIR" "$BINDINGS_DIR"

rm -f "$BINDINGS_DIR/bindgen_bundled_version.rs"
find "$TARGET_DIR" -type f -name bindgen.rs -exec rm {} \;
env LIBSQLITE3_SYS_BUNDLING=1 cargo build --features "bundled-sqlite3mc buildtime_bindgen session"
find "$TARGET_DIR" -type f -name bindgen.rs -exec mv {} "$BINDINGS_DIR/bindgen_bundled_version.rs" \;

# Sanity checks
cd "$SCRIPT_DIR/.." || { echo "fatal error" >&2; exit 1; }
cargo test -p libsqlite3-sys --features "bundled-sqlite3mc session"
cargo test --features "backup blob chrono functions limits serde_json trace vtab bundled-sqlite3mc"
printf '    \e[35;1mFinished\e[0m bundled-sqlite3mc tests\n'
