#!/usr/bin/env bash
# Fails if a SymCrypt-only build depends on another crypto implementation or on
# rand/getrandom: everything cryptographic, randomness included, must come from
# SymCrypt.
#
# Usage: ci/symcrypt-ban-check.sh [cargo tree options]
#
# The options select what to check and default to
#   -p russh --no-default-features --features symcrypt
# Pass e.g. `--manifest-path path/to/Cargo.toml -p my-crate` to check a crate
# that depends on russh with only the symcrypt feature, or `--target <triple>`
# to check another target than the host. The script adds `-e normal,build`:
# dev-dependencies are not part of what gets shipped.
set -euo pipefail

cargo="${CARGO:-cargo}"
if [ "$#" -eq 0 ]; then
    set -- -p russh --no-default-features --features symcrypt
fi

# Crypto implementations and RNGs. Trait and format crates (cipher, digest,
# signature, rand_core, subtle, zeroize, der, pkcs1, pkcs8, sec1, spki, ...)
# are allowed.
banned=(
    # Other backends.
    ring aws-lc-rs aws-lc-sys aws-lc-fips-sys openssl openssl-sys boring boring-sys
    # Randomness.
    rand rand_chacha getrandom
    # Hashes and MACs.
    sha1 sha-1 sha2 sha3 keccak md5 md-5 md4 blake2 blake3 ripemd
    hmac cmac pmac ghash polyval poly1305 universal-hash
    # Ciphers, modes and AEADs.
    aes des blowfish chacha20 salsa20 cbc ctr cfb-mode ofb
    aes-gcm aes-gcm-siv aes-siv ccm chacha20poly1305 xsalsa20poly1305
    # Public-key algorithms and their arithmetic.
    rsa dsa ecdsa ed25519 ed25519-dalek x25519-dalek curve25519-dalek
    curve25519-dalek-derive elliptic-curve primeorder p256 p384 p521 k256 rfc6979
    ml-kem ml-dsa module-lattice crypto-bigint num-bigint num-bigint-dig
    # Key derivation and private key encryption.
    pbkdf2 scrypt bcrypt-pbkdf argon2 hkdf pkcs5
)

# A banned crate is allowed if all its direct dependents are listed here.
#   sha2: ssh-key computes key fingerprints with it, whatever its features.
allowed_dependents() {
    case "$1" in
    sha2) echo "ssh-key ssh-encoding" ;;
    *) ;;
    esac
}

tree() {
    "$cargo" tree "$@" -e normal,build </dev/null
}

echo "symcrypt-ban-check: cargo tree $* -e normal,build"

# "name version" for each package, e.g. "sha2 v0.11.0".
packages="$(tree "$@" --prefix none --format '{p}' | tr -d '\r' | awk 'NF { print $1, $2 }' | LC_ALL=C sort -u)"

if ! grep -q '^symcrypt ' <<<"$packages"; then
    echo "symcrypt-ban-check: symcrypt is not in the dependency graph; check the options" >&2
    exit 2
fi

failed=0
offenders=()
for crate in "${banned[@]}"; do
    while read -r name version; do
        [ -n "$name" ] || continue
        spec="$name@${version#v}"
        allowed="$(allowed_dependents "$name")"
        if [ -z "$allowed" ]; then
            echo "symcrypt-ban-check: banned crate: $name $version" >&2
            failed=1
            offenders+=("$spec")
            continue
        fi
        dependents="$(tree "$@" -i "$spec" --depth 1 --prefix depth --format '{p}' |
            tr -d '\r' | sed -n 's/^1//p' | awk '{ print $1, $2 }' | LC_ALL=C sort -u)"
        unexpected="$(awk -v allowed=" $allowed " 'index(allowed, " " $1 " ") == 0' <<<"$dependents")"
        if [ -n "$unexpected" ]; then
            echo "symcrypt-ban-check: $name $version is only allowed as a dependency of: $allowed; also used by:" >&2
            sed 's/^/    /' <<<"$unexpected" >&2
            failed=1
            offenders+=("$spec")
        else
            echo "symcrypt-ban-check: allowed: $name $version, used by: $(paste -sd, - <<<"$dependents" | sed 's/,/, /g')"
        fi
    done < <(awk -v crate="$crate" '$1 == crate' <<<"$packages")
done

if [ "$failed" -ne 0 ]; then
    for spec in "${offenders[@]}"; do
        echo
        echo "\$ cargo tree $* -e normal,build -i $spec"
        tree "$@" -i "$spec" || true
    done
    echo >&2
    echo "symcrypt-ban-check: FAILED: banned crates in the dependency graph (see above)" >&2
    exit 1
fi

echo "symcrypt-ban-check: OK: $(wc -l <<<"$packages" | tr -d ' ') packages, none banned:"
awk '{ sub(/^v/, "", $2); print $1 "@" $2 }' <<<"$packages" | paste -sd' ' - | fold -s -w 100 | sed 's/^/    /'
