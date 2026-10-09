//! Helpers shared by russh's integration tests.
//!
//! Each file in `russh/tests/` is compiled as its own crate; pull these
//! helpers in with `mod common;`. A test usually needs only part of them,
//! hence the blanket `dead_code` allowance.
#![allow(dead_code)]

pub mod openssh;
