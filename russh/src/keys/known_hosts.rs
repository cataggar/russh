use std::borrow::Cow;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use data_encoding::BASE64_MIME;
use log::debug;
use subtle::ConstantTimeEq;

use crate::keys::Error;

/// Check whether the host is known, from its standard location.
pub fn check_known_hosts(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
) -> Result<bool, Error> {
    check_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Check that a server key matches the one recorded in file `path`.
pub fn check_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
    path: P,
) -> Result<bool, Error> {
    let entries = matching_entries(host, port, path)?;
    if let Some(revoked) = entries
        .iter()
        .find(|e| e.marker == Marker::Revoked && e.key.key_data() == pubkey.key_data())
    {
        return Err(Error::KeyChanged { line: revoked.line });
    }
    let check = entries
        .iter()
        .filter(|e| {
            e.marker == Marker::None
                && !entries
                    .iter()
                    .any(|r| r.marker == Marker::Revoked && r.key.key_data() == e.key.key_data())
        })
        .map(|entry| {
            match (
                pubkey.algorithm() == entry.key.algorithm(),
                pubkey.key_data() == entry.key.key_data(),
            ) {
                (true, true) => Ok(true),
                (true, false) => Err(Error::KeyChanged { line: entry.line }),
                _ => Ok(false),
            }
        })
        // If any Err was returned, we stop here
        .collect::<Result<Vec<bool>, Error>>()?
        .into_iter()
        // Now we check the results for a match
        .any(|x| x);

    Ok(check)
}

fn known_hosts_path() -> Result<PathBuf, Error> {
    env::home_dir()
        .map(|home_dir| home_dir.join(".ssh").join("known_hosts"))
        .ok_or(Error::NoHomeDir)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Marker {
    None,
    CertAuthority,
    Revoked,
}

struct KnownHostEntry {
    line: usize,
    marker: Marker,
    key: ssh_key::PublicKey,
}

/// Get the server key that matches the one recorded in the user's known_hosts file.
pub fn known_host_keys(host: &str, port: u16) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    known_host_keys_path(host, port, known_hosts_path()?)
}

/// Get the server key that matches the one recorded in `path`.
pub fn known_host_keys_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    let entries = matching_entries(host, port, path)?;
    Ok(entries
        .iter()
        .filter(|e| {
            e.marker == Marker::None
                && !entries
                    .iter()
                    .any(|r| r.marker == Marker::Revoked && r.key.key_data() == e.key.key_data())
        })
        .map(|e| (e.line, e.key.clone()))
        .collect())
}

/// Get the `@cert-authority` keys for `host` and `port` from the user's
/// `known_hosts` file.
pub fn known_host_ca_keys(
    host: &str,
    port: u16,
) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    known_host_ca_keys_path(host, port, known_hosts_path()?)
}

/// Get the `@cert-authority` keys for `host` and `port` recorded in `path`.
pub fn known_host_ca_keys_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    let entries = matching_entries(host, port, path)?;
    Ok(entries
        .iter()
        .filter(|e| {
            e.marker == Marker::CertAuthority
                && !entries
                    .iter()
                    .any(|r| r.marker == Marker::Revoked && r.key.key_data() == e.key.key_data())
        })
        .map(|e| (e.line, e.key.clone()))
        .collect())
}

fn matching_entries<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<KnownHostEntry>, Error> {
    use crate::keys::parse_public_key_base64;

    let mut f = if let Ok(f) = File::open(path) {
        BufReader::new(f)
    } else {
        return Ok(vec![]);
    };
    let mut buffer = String::new();

    debug!("host = {host:?}, port = {port}");
    let mut line = 0;
    let mut matches = vec![];
    while {
        buffer.clear();
        f.read_line(&mut buffer)? > 0
    } {
        line += 1;
        let trimmed = buffer.trim_start_matches([' ', '\t']);
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('\n')
            || trimmed.starts_with('\r')
        {
            continue;
        }
        debug!("line = {buffer:?}");
        let mut s = trimmed.split([' ', '\t']).filter(|p| !p.is_empty());
        let Some(first) = s.next() else {
            continue;
        };
        let (marker, hosts) = if first.starts_with('@') {
            let marker = match first {
                "@cert-authority" => Marker::CertAuthority,
                "@revoked" => Marker::Revoked,
                _ => continue,
            };
            let Some(hosts) = s.next() else {
                continue;
            };
            (marker, hosts)
        } else {
            (Marker::None, first)
        };
        let _ = s.next();
        let Some(key) = s.next() else {
            continue;
        };
        debug!("{hosts:?} {key:?}");
        if match_hostname(host, port, hosts) {
            matches.push(KnownHostEntry {
                line,
                marker,
                key: parse_public_key_base64(key.trim_end())?,
            });
        }
    }
    Ok(matches)
}

fn match_hostname(host: &str, port: u16, pattern: &str) -> bool {
    let host_lower = host.to_ascii_lowercase();
    let bracketed = format!("[{host_lower}]:{port}");
    let host_port: Cow<'_, str> = if port == 22 {
        Cow::Borrowed(host_lower.as_str())
    } else {
        Cow::Borrowed(bracketed.as_str())
    };
    let mut matched = false;
    for entry in pattern.split(',') {
        if entry.starts_with("|1|") {
            let mut parts = entry.split('|').skip(2);
            let Some(Ok(salt)) = parts.next().map(|p| BASE64_MIME.decode(p.as_bytes())) else {
                continue;
            };
            let Some(Ok(hash)) = parts.next().map(|p| BASE64_MIME.decode(p.as_bytes())) else {
                continue;
            };
            // HMAC-SHA1 of the host name, keyed with the salt.
            if let Ok(hmac) = crate::crypto::hmac_sha1(&salt, host_port.as_bytes())
                && bool::from(hmac.ct_eq(&hash[..]))
            {
                matched = true;
            }
        } else {
            let (negated, pat) = match entry.strip_prefix('!') {
                Some(pat) => (true, pat),
                None => (false, entry),
            };
            if pat.is_empty() {
                continue;
            }
            let pat = pat.to_ascii_lowercase();
            let target = if pat.starts_with('[') {
                bracketed.as_str()
            } else {
                host_port.as_ref()
            };
            if crate::keys::certificate::matches_pattern(pat.as_bytes(), target.as_bytes()) {
                if negated {
                    return false;
                }
                matched = true;
            }
        }
    }
    matched
}

/// Record a host's public key into the user's known_hosts file.
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &ssh_key::PublicKey) -> Result<(), Error> {
    learn_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
    path: P,
) -> Result<(), Error> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // Test whether the known_hosts file ends with a \n
    let mut buf = [0; 1];
    let mut ends_in_newline = false;
    if file.seek(SeekFrom::End(-1)).is_ok() {
        file.read_exact(&mut buf)?;
        ends_in_newline = buf[0] == b'\n';
    }

    // Write the key.
    file.seek(SeekFrom::End(0))?;
    let mut file = std::io::BufWriter::new(file);
    if !ends_in_newline {
        file.write_all(b"\n")?;
    }
    if port != 22 {
        write!(file, "[{host}]:{port} ")?
    } else {
        write!(file, "{host} ")?
    }
    file.write_all(pubkey.to_openssh()?.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::fs::File;

    use super::*;
    use crate::keys::parse_public_key_base64;

    #[test]
    fn test_check_known_hosts() {
        env_logger::try_init().unwrap_or(());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"[localhost]:13265 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n").unwrap();
            f.write_all(b"#pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
            f.write_all(b"pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
            f.write_all(b"|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n").unwrap();
        }

        // Valid key, non-standard port.
        let host = "localhost";
        let port = 13265;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, hashed.
        let host = "example.com";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, several hosts, port 22
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Now with the key in a comment above, check that it's not recognized
        // and reports line 3 (counting the comment on line 2).
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        assert!(matches!(
            check_known_hosts_path(host, port, &hostkey, &path),
            Err(Error::KeyChanged { line: 3 })
        ));
    }

    #[test]
    fn host_patterns_and_negation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let k1 = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
        let k2 = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";
        let key1 = parse_public_key_base64(k1).unwrap();
        let key2 = parse_public_key_base64(k2).unwrap();

        std::fs::write(
            &path,
            format!(
                "# comment line 1\n\
                 \n\
                 *.example.com,!bad.example.com,host?.example.net ssh-ed25519 {k1}\n\
                 [*.example.org]:2222,![denied.example.org]:2222 ssh-ed25519 {k2}\n"
            ),
        )
        .unwrap();

        assert_eq!(
            known_host_keys_path("www.example.com", 22, &path).unwrap(),
            vec![(3, key1.clone())]
        );
        assert_eq!(
            known_host_keys_path("WWW.Example.COM", 22, &path).unwrap(),
            vec![(3, key1.clone())]
        );
        assert_eq!(
            known_host_keys_path("host1.example.net", 22, &path).unwrap(),
            vec![(3, key1)]
        );
        assert!(
            known_host_keys_path("bad.example.com", 22, &path)
                .unwrap()
                .is_empty()
        );
        assert!(
            known_host_keys_path("host12.example.net", 22, &path)
                .unwrap()
                .is_empty()
        );

        assert_eq!(
            known_host_keys_path("app.example.org", 2222, &path).unwrap(),
            vec![(4, key2)]
        );
        assert!(
            known_host_keys_path("denied.example.org", 2222, &path)
                .unwrap()
                .is_empty()
        );
        assert!(
            known_host_keys_path("app.example.org", 22, &path)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cert_authority_and_revoked_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let k_host = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
        let k_revoked = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";
        let k_ca = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";
        let k_ca_revoked = "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";

        let host_key = parse_public_key_base64(k_host).unwrap();
        let revoked_key = parse_public_key_base64(k_revoked).unwrap();
        let ca_key = parse_public_key_base64(k_ca).unwrap();
        let revoked_ca_key = parse_public_key_base64(k_ca_revoked).unwrap();

        std::fs::write(
            &path,
            format!(
                "example.com ssh-ed25519 {k_revoked}\n\
                 example.com ssh-ed25519 {k_host}\n\
                 @revoked *.example.com,example.com ssh-ed25519 {k_revoked}\n\
                 @cert-authority *.example.com,example.com ssh-ed25519 {k_ca}\n\
                 @cert-authority *.example.com,example.com ssh-ed25519 {k_ca_revoked}\n\
                 @revoked * ssh-ed25519 {k_ca_revoked}\n"
            ),
        )
        .unwrap();

        // The revoked key is rejected with the line of the @revoked entry even
        // though it also appears on line 1.
        assert!(matches!(
            check_known_hosts_path("example.com", 22, &revoked_key, &path),
            Err(Error::KeyChanged { line: 3 })
        ));
        // The valid host key is accepted; the revoked line 1 and @cert-authority
        // lines do not interfere.
        assert!(check_known_hosts_path("example.com", 22, &host_key, &path).unwrap());
        assert_eq!(
            known_host_keys_path("example.com", 22, &path).unwrap(),
            vec![(2, host_key)]
        );
        // Only the non-revoked @cert-authority key is returned.
        assert_eq!(
            known_host_ca_keys_path("sub.example.com", 22, &path).unwrap(),
            vec![(4, ca_key)]
        );
        assert!(matches!(
            check_known_hosts_path("sub.example.com", 22, &revoked_ca_key, &path),
            Err(Error::KeyChanged { line: 6 })
        ));
    }
}
