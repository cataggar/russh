pub mod groups;
use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use log::{error, trace};
use ssh_encoding::{Decode, Encode, Reader, Writer};

use self::groups::{
    DhGroup, DH_GROUP1, DH_GROUP14, DH_GROUP15, DH_GROUP16, DH_GROUP17, DH_GROUP18,
};
use super::{compute_keys, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret};
use crate::client::GexParams;
use crate::crypto::provider::hash::{Sha1, Sha256, Sha512};
use crate::crypto::provider::kex::Dh;
use crate::crypto::{mpint_body, FfDh, Hash};
use crate::session::Exchange;
use crate::{cipher, mac, msg, CryptoVec, Error};

pub(crate) struct DhGroup15Sha512KexType {}

impl KexType for DhGroup15Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP15)).into()
    }
}

pub(crate) struct DhGroup17Sha512KexType {}

impl KexType for DhGroup17Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP17)).into()
    }
}

pub(crate) struct DhGroup18Sha512KexType {}

impl KexType for DhGroup18Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP18)).into()
    }
}

pub(crate) struct DhGexSha1KexType {}

impl KexType for DhGexSha1KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha1>::new(None).into()
    }
}

pub(crate) struct DhGexSha256KexType {}

impl KexType for DhGexSha256KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha256>::new(None).into()
    }
}

pub(crate) struct DhGroup1Sha1KexType {}

impl KexType for DhGroup1Sha1KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha1>::new(Some(&DH_GROUP1)).into()
    }
}

pub(crate) struct DhGroup14Sha1KexType {}

impl KexType for DhGroup14Sha1KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha1>::new(Some(&DH_GROUP14)).into()
    }
}

pub(crate) struct DhGroup14Sha256KexType {}

impl KexType for DhGroup14Sha256KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha256>::new(Some(&DH_GROUP14)).into()
    }
}

pub(crate) struct DhGroup16Sha512KexType {}

impl KexType for DhGroup16Sha512KexType {
    fn make(&self) -> KexAlgorithm {
        DhGroupKex::<Sha512>::new(Some(&DH_GROUP16)).into()
    }
}

#[doc(hidden)]
pub(crate) struct DhGroupKex<H> {
    group: Option<DhGroup>,
    /// The client's key pair, between `client_dh` and `compute_shared_secret`.
    dh: Option<Dh>,
    /// The shared secret as an mpint body.
    shared_secret: Option<Vec<u8>>,
    is_dh_gex: bool,
    _digest: PhantomData<fn() -> H>,
}

impl<H> DhGroupKex<H> {
    pub(crate) fn new(group: Option<&DhGroup>) -> DhGroupKex<H> {
        DhGroupKex {
            group: group.cloned(),
            dh: None,
            shared_secret: None,
            is_dh_gex: group.is_none(),
            _digest: PhantomData,
        }
    }
}

impl<H> std::fmt::Debug for DhGroupKex<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

impl<H: Hash> KexAlgorithmImplementor for DhGroupKex<H> {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn is_dh_gex(&self) -> bool {
        self.is_dh_gex
    }

    fn client_dh_gex_init(
        &mut self,
        gex: &GexParams,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        msg::KEX_DH_GEX_REQUEST.encode(writer)?;
        (gex.min_group_size() as u32).encode(writer)?;
        (gex.preferred_group_size() as u32).encode(writer)?;
        (gex.max_group_size() as u32).encode(writer)?;
        Ok(())
    }

    #[allow(dead_code)]
    fn dh_gex_set_group(&mut self, group: DhGroup) -> Result<(), crate::Error> {
        self.group = Some(group);
        Ok(())
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        let Some(group) = self.group.as_ref() else {
            error!("DH kex sequence error, dh is None in server_dh");
            return Err(Error::Inconsistent);
        };

        let client_pubkey = {
            if payload.first() != Some(&msg::KEX_ECDH_INIT)
                && payload.first() != Some(&msg::KEX_DH_GEX_INIT)
            {
                return Err(Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if payload.len() < 5 + pubkey_len {
                return Err(Error::Inconsistent);
            }

            &payload
                .get(5..(5 + pubkey_len))
                .ok_or(Error::Inconsistent)?
        };

        trace!("client_pubkey: {client_pubkey:?}");

        let (dh, server_pubkey) = Dh::generate(group, true).map_err(|_| Error::Inconsistent)?;

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange
            .server_ephemeral
            .extend_from_slice(&mpint_body(&server_pubkey));

        let shared = dh.agree(client_pubkey).map_err(|_| Error::Inconsistent)?;
        self.shared_secret = Some(mpint_body(&shared));
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let Some(group) = self.group.as_ref() else {
            error!("DH kex sequence error, dh is None in client_dh");
            return Err(Error::Inconsistent);
        };

        let (dh, client_pubkey) = Dh::generate(group, false).map_err(|_| Error::Inconsistent)?;
        self.dh = Some(dh);

        // fill exchange.
        let encoded_pubkey = mpint_body(&client_pubkey);
        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(&encoded_pubkey);

        if self.is_dh_gex {
            msg::KEX_DH_GEX_INIT.encode(writer)?;
        } else {
            msg::KEX_ECDH_INIT.encode(writer)?;
        }

        encoded_pubkey.encode(writer)?;

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        let Some(dh) = self.dh.as_ref() else {
            error!("DH kex sequence error, dh is None in compute_shared_secret");
            return Err(Error::Inconsistent);
        };

        let shared = dh.agree(remote_pubkey_).map_err(|_| Error::Inconsistent)?;
        self.shared_secret = Some(mpint_body(&shared));
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret.as_deref()
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);

        if let Some((gex_params, dh_group)) = &exchange.gex {
            gex_params.encode(buffer)?;
            mpint_body(&dh_group.prime).encode(buffer)?;
            mpint_body(&dh_group.generator).encode(buffer)?;
        }

        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            shared.encode(buffer)?;
        }

        Ok(H::digest_to_vec(&buffer[..]))
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error> {
        let shared_secret = self
            .shared_secret
            .as_deref()
            .map(SharedSecret::from_mpint)
            .transpose()?;

        compute_keys::<H>(
            shared_secret.as_ref(),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

impl Encode for GexParams {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        Ok(0u32.encoded_len()? * 3)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), ssh_encoding::Error> {
        (self.min_group_size() as u32).encode(writer)?;
        (self.preferred_group_size() as u32).encode(writer)?;
        (self.max_group_size() as u32).encode(writer)?;
        Ok(())
    }
}

impl Decode for GexParams {
    fn decode(reader: &mut impl Reader) -> Result<Self, Error> {
        let min_group_size = u32::decode(reader)? as usize;
        let preferred_group_size = u32::decode(reader)? as usize;
        let max_group_size = u32::decode(reader)? as usize;
        GexParams::from_peer_request(min_group_size, preferred_group_size, max_group_size)
    }

    type Error = Error;
}
