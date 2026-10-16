#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![allow(clippy::single_match, clippy::upper_case_acronyms)]
#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]
// length checked
// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Server and client SSH asynchronous library, based on tokio/futures.
//!
//! The normal way to use this library, both for clients and for
//! servers, is by creating *handlers*, i.e. types that implement
//! `client::Handler` for clients and `server::Handler` for
//! servers.
//!
//! * [Writing SSH clients - the `russh::client` module](client)
//! * [Writing SSH servers - the `russh::server` module](server)
//!
//! # Crypto backends
//!
//! Russh needs a crypto backend, selected with a crate feature:
//!
//! - `aws-lc-rs` (default): AES-GCM and ChaCha20-Poly1305 from aws-lc-rs.
//!   Everything else comes from pure-Rust crates (RustCrypto,
//!   `curve25519-dalek`, `ssh-key`), with randomness from `rand`.
//! - `ring`: the same, with ring instead of aws-lc-rs.
//! - `symcrypt`: all of the SSH protocol's cryptography and randomness from
//!   Microsoft's [SymCrypt](https://github.com/microsoft/SymCrypt) library,
//!   which must be installed both to build and to run. It offers fewer
//!   algorithms (no Ed25519, finite-field Diffie-Hellman or security keys,
//!   and none of the legacy SHA-1, CBC, 3DES or DSA ones) and loads only
//!   unencrypted private keys.
//!
//! If several backend features are enabled, the first of `aws-lc-rs`, `ring`
//! and `symcrypt` is used, so selecting `ring` or `symcrypt` needs
//! `default-features = false` (keep `secure-algorithms`, see below).
//! `symcrypt` is not in a crates.io release:
//!
//! ```toml
//! [dependencies]
//! russh = { git = "https://github.com/cataggar/russh", default-features = false, features = ["symcrypt", "secure-algorithms", "flate2"] }
//! ```
//!
//! [`CRYPTO_BACKEND`] (a [`CryptoBackend`]) reports which backend this build of
//! russh uses. Because Cargo unifies features across the dependency graph, any
//! dependency that enables russh's default features (or `aws-lc-rs` or `ring`)
//! switches russh to that backend. An application can require a specific
//! backend at build time either with a compile-time assertion:
//!
//! ```
//! # #[cfg(all(feature = "symcrypt", not(feature = "aws-lc-rs"), not(feature = "ring")))]
//! const _: () = assert!(
//!     matches!(russh::CRYPTO_BACKEND, russh::CryptoBackend::SymCrypt),
//!     "russh must use the symcrypt backend; `cargo tree -e features -i russh` shows what enables another one",
//! );
//! ```
//!
//! or by setting `RUSSH_REQUIRE_BACKEND=symcrypt` (or `aws-lc-rs` or `ring`) in
//! `.cargo/config.toml` (`[env]`) or in CI, which makes russh's build script
//! fail the build if another backend is selected.
//!
//! The [README](https://github.com/cataggar/russh/blob/main/README.md#crypto-backends)
//! lists the algorithms of each backend, and how to install SymCrypt on Linux
//! and Windows.
//!
//! # Algorithm features
//!
//! Each key exchange method, cipher and MAC has a crate feature of the same
//! name (without `@openssh.com`, and `curve25519-sha256` for both names of
//! that method), and russh negotiates only the ones whose features are
//! enabled, even if [`Preferred`] lists others. `secure-algorithms`, a default
//! feature, enables all but the legacy ones (SHA-1, CBC, 3DES and `none`);
//! `all-algorithms` enables them all. [`Preferred::default()`] offers the
//! enabled ones but the legacy ones, which russh negotiates only when you list
//! them. A build needs at least one key exchange method and one cipher, and a
//! MAC unless one of its ciphers is an AEAD. Host key and signature algorithms
//! don't depend on these features.
//!
//! Any dependency can enable algorithm features through Cargo's feature
//! unification, so an application that must not negotiate an algorithm can
//! assert at compile time that it is disabled, with
//! [`kex::Name::is_enabled`], [`cipher::Name::is_enabled`] or
//! [`mac::Name::is_enabled`].
//!
//! # Using non-socket IO / writing tunnels
//!
//! The easy way to implement SSH tunnels, like `ProxyCommand` for
//! OpenSSH, is to use the `russh-config` crate, and use the
//! `Stream::tcp_connect` or `Stream::proxy_command` methods of that
//! crate. That crate is a very lightweight layer above Russh, only
//! implementing for external commands the traits used for sockets.
//!
//! # The SSH protocol
//!
//! If we exclude the key exchange and authentication phases, handled
//! by Russh behind the scenes, the rest of the SSH protocol is
//! relatively simple: clients and servers open *channels*, which are
//! just integers used to handle multiple requests in parallel in a
//! single connection. Once a client has obtained a `ChannelId` by
//! calling one of the many `channel_open_…` methods of
//! `client::Connection`, the client may send exec requests and data
//! to the server.
//!
//! A simple client just asking the server to run one command will
//! usually start by calling
//! `client::Connection::channel_open_session`, then
//! `client::Connection::exec`, then possibly
//! `client::Connection::data` a number of times to send data to the
//! command's standard input, and finally `Connection::channel_eof`
//! and `Connection::channel_close`.
//!
//! # Design principles
//!
//! The main goal of this library is conciseness, and reduced size and
//! readability of the library's code.
//!
//! One non-goal is to implement all possible cryptographic algorithms
//! published since the initial release of SSH. Technical debt is
//! easily acquired, and we would need a very strong reason to go
//! against this principle. If you are designing a system from
//! scratch, we urge you to consider recent cryptographic primitives
//! such as Ed25519 for public key cryptography, and Chacha20-Poly1305
//! for symmetric cryptography and MAC.
//!
//! # Internal details of the event loop
//!
//! It might seem a little odd that the read/write methods for server
//! or client sessions often return neither `Result` nor
//! `Future`. This is because the data sent to the remote side is
//! buffered, because it needs to be encrypted first, and encryption
//! works on buffers, and for many algorithms, not in place.
//!
//! Hence, the event loop keeps waiting for incoming packets, reacts
//! to them by calling the provided `Handler`, which fills some
//! buffers. If the buffers are non-empty, the event loop then sends
//! them to the socket, flushes the socket, empties the buffers and
//! starts again. In the special case of the server, unsolicited
//! messages sent through a `server::Handle` are processed when there
//! is no incoming packet to read.

// `russh_backend` is set by build.rs from the backend features.
#[cfg(not(any(
    russh_backend = "aws_lc",
    russh_backend = "ring",
    russh_backend = "symcrypt"
)))]
compile_error!(
    "`russh` requires enabling one of the `aws-lc-rs`, `ring` or `symcrypt` features as a crypto backend."
);

// The algorithm features (see Cargo.toml): a build needs a key exchange
// method and a cipher, and a MAC unless it has an AEAD cipher.
#[cfg(not(any(
    feature = "mlkem1024nistp384-sha384",
    feature = "mlkem768nistp256-sha256",
    feature = "mlkem768x25519-sha256",
    feature = "curve25519-sha256",
    feature = "ecdh-sha2-nistp256",
    feature = "ecdh-sha2-nistp384",
    feature = "ecdh-sha2-nistp521",
    feature = "diffie-hellman-group-exchange-sha256",
    feature = "diffie-hellman-group14-sha256",
    feature = "diffie-hellman-group15-sha512",
    feature = "diffie-hellman-group16-sha512",
    feature = "diffie-hellman-group17-sha512",
    feature = "diffie-hellman-group18-sha512",
    feature = "diffie-hellman-group-exchange-sha1",
    feature = "diffie-hellman-group14-sha1",
    feature = "diffie-hellman-group1-sha1",
)))]
compile_error!(
    "`russh` requires enabling the feature of at least one key exchange method, or `secure-algorithms` (a default feature) for all but the legacy ones."
);

#[cfg(not(any(
    feature = "aes256-gcm",
    feature = "aes128-gcm",
    feature = "chacha20-poly1305",
    feature = "aes256-ctr",
    feature = "aes192-ctr",
    feature = "aes128-ctr",
    feature = "aes256-cbc",
    feature = "aes192-cbc",
    feature = "aes128-cbc",
    feature = "3des-cbc",
)))]
compile_error!(
    "`russh` requires enabling the feature of at least one cipher, or `secure-algorithms` (a default feature) for all but the legacy ones."
);

#[cfg(not(any(
    feature = "aes256-gcm",
    feature = "aes128-gcm",
    feature = "chacha20-poly1305",
    feature = "hmac-sha2-512-etm",
    feature = "hmac-sha2-256-etm",
    feature = "hmac-sha2-512",
    feature = "hmac-sha2-256",
    feature = "hmac-sha1-etm",
    feature = "hmac-sha1",
)))]
compile_error!(
    "`russh` requires enabling the feature of at least one MAC, for the ciphers that need one, or of an AEAD cipher (`aes256-gcm`, `aes128-gcm` or `chacha20-poly1305`)."
);

#[cfg(any(
    russh_backend = "aws_lc",
    russh_backend = "ring",
    russh_backend = "symcrypt"
))]
include!("lib_inner.rs");
