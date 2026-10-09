use std::ffi::CStr;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use base16ct::lower;
use delegate::delegate;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use windows::Win32::Foundation::ERROR_PIPE_BUSY;
use windows::Win32::Security::Authentication::Identity::{GetUserNameExA, NameUserPrincipal};
use windows::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALG_HANDLE, BCryptHash, CRYPTPROTECTMEMORY_BLOCK_SIZE,
    CRYPTPROTECTMEMORY_CROSS_PROCESS, CryptProtectMemory,
};
use windows::Win32::System::WindowsProgramming::GetUserNameA;
use windows_strings::PSTR;

use crate::Error;

/// Pageant transport stream. Implements [AsyncRead] and [AsyncWrite].
pub struct PageantStream {
    stream: NamedPipeClient,
}

impl PageantStream {
    pub async fn new() -> Result<Self, Error> {
        let pipe_name = Self::determine_pipe_name()?;
        debug!("Opening pipe '{}'", pipe_name);
        let mut timeout_counter = 0;
        let stream = loop {
            match ClientOptions::new().open(&pipe_name) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => (),
                Err(e) => return Err(e.into()),
            }
            timeout_counter += 1;
            if timeout_counter > 40 {
                return Err(Error::PipeBusy);
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        Ok(Self { stream })
    }

    fn determine_pipe_name() -> Result<String, Error> {
        let username = Self::get_username()?;
        let suffix = Self::capi_obfuscate_string("Pageant")?;
        Ok(format!("\\\\.\\pipe\\pageant.{username}.{suffix}"))
    }

    fn get_username() -> Result<String, Error> {
        unsafe {
            let mut name_length = 0;

            // don't check result on this, always returns ERROR_MORE_DATA
            GetUserNameExA(NameUserPrincipal, None, &mut name_length);

            let mut name_buf = vec![0u8; name_length as usize];

            if !GetUserNameExA(
                NameUserPrincipal,
                Some(PSTR(name_buf.as_mut_ptr())),
                &mut name_length,
            ) {
                // GetUserNameExA fails on non-domain-joined machines, where no UPN
                // (NameUserPrincipal) is configured. Fall back to GetUserNameA
                // (the SAM account name), like the original PuTTY Pageant.
                debug!(
                    "GetUserNameExA failed ({}), falling back to GetUserNameA",
                    Error::from_win32()
                );

                let mut name_length = 0;
                // don't check result on this, always returns ERROR_INSUFFICIENT_BUFFER
                let _ = GetUserNameA(None, &mut name_length);

                name_buf = vec![0u8; name_length as usize];
                GetUserNameA(Some(PSTR(name_buf.as_mut_ptr())), &mut name_length)?;
            }

            // match putty behavior: parse as C string (trim at first NULL) and split UPNs at @
            let name = CStr::from_bytes_until_nul(&name_buf)
                .ok()
                .and_then(|name| name.to_str().ok())
                .ok_or(Error::InvalidUsername)?;
            Ok(name
                .split_once('@')
                .map_or(name, |(name, _)| name)
                .to_owned())
        }
    }

    fn capi_obfuscate_string(input: &str) -> Result<String, Error> {
        let mut cryptlen = input.len() + 1;
        cryptlen = cryptlen.next_multiple_of(CRYPTPROTECTMEMORY_BLOCK_SIZE as usize);
        let mut cryptdata = vec![0u8; cryptlen];

        // copy cleartext into crypt buffer:
        cryptdata
            .iter_mut()
            .zip(input.as_bytes())
            .for_each(|(c, i)| *c = *i);
        // (since the buffer is initialized to 0 and always at least 1 longer than the input,
        // we don't need to worry about terminating the string)

        unsafe {
            // Errors are explicitly ignored:
            let _ = CryptProtectMemory(
                cryptdata.as_mut_ptr() as *mut _,
                cryptlen as u32,
                CRYPTPROTECTMEMORY_CROSS_PROCESS,
            );
        }

        let mut hashed = Vec::with_capacity(4 + cryptdata.len());
        hashed.extend_from_slice(&(cryptdata.len() as u32).to_be_bytes());
        hashed.extend_from_slice(&cryptdata);
        Ok(lower::encode_string(&sha256(&hashed)?))
    }
}

/// SHA-256 with Windows CNG.
fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    let mut digest = [0; 32];
    unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, data, &mut digest) }.ok()?;
    Ok(digest)
}

impl AsyncRead for PageantStream {
    delegate! {
        to Pin::new(&mut self.stream) {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<Result<(), std::io::Error>>;

        }
    }
}

impl AsyncWrite for PageantStream {
    delegate! {
        to Pin::new(&mut self.stream) {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, std::io::Error>>;

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bufs: &[IoSlice<'_>],
            ) -> Poll<Result<usize, std::io::Error>>;

            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;
        }

        to Pin::new(&self.stream) {
            fn is_write_vectored(&self) -> bool;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use base16ct::lower;

    /// FIPS 180-2 test vectors.
    #[test]
    fn sha256_matches_known_answers() {
        for (data, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            assert_eq!(
                lower::encode_string(&super::sha256(data).unwrap()),
                expected
            );
        }
    }
}
