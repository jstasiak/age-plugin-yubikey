use age_core::{
    format::{FileKey, Stanza},
    primitives::{aead_encrypt, hkdf},
};
use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256},
    rand::SystemRandom,
};
use secrecy::ExposeSecret;
use std::convert::TryInto;

use crate::{p256::Recipient, STANZA_TAG};

pub(crate) const STANZA_KEY_LABEL: &[u8] = b"age-encryption.org/v1/piv-p256";

const TAG_BYTES: usize = 4;
const EPK_BYTES: usize = 33;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) tag: [u8; TAG_BYTES],
    pub(crate) epk: Recipient,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![
                base64::encode_config(&r.tag, base64::STANDARD_NO_PAD),
                base64::encode_config(r.epk.as_bytes(), base64::STANDARD_NO_PAD),
            ],
            body: r.encrypted_file_key.to_vec(),
        }
    }
}

impl RecipientLine {
    pub(super) fn from_stanza(s: &Stanza) -> Option<Result<Self, ()>> {
        if s.tag != STANZA_TAG {
            return None;
        }

        fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
            if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
                return None;
            }

            match base64::decode_config_slice(arg, base64::STANDARD_NO_PAD, buf.as_mut()) {
                Ok(_) => Some(buf),
                Err(_) => None,
            }
        }

        let tag = s
            .args
            .get(0)
            .and_then(|arg| base64_arg(arg, [0; TAG_BYTES]));
        let epk = s
            .args
            .get(1)
            .and_then(|arg| base64_arg(arg, vec![0; EPK_BYTES]))
            .and_then(|bytes| Recipient::from_bytes(&bytes));

        Some(match (tag, epk) {
            (Some(tag), Some(epk)) => Ok(RecipientLine {
                tag,
                epk,
                encrypted_file_key: s.body[..].try_into().ok()?,
            }),
            _ => Err(()),
        })
    }

    pub(crate) fn wrap_file_key(file_key: &FileKey, pk: &Recipient) -> Self {
        let rng = SystemRandom::new();

        let esk = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("TODO handle failing RNG");
        let epk = Recipient::from_bytes(esk.compute_public_key().expect("TODO").as_ref())
            .expect("epk is valid");

        let pk_uncompressed = pk.decompress();
        let pk_ring = UnparsedPublicKey::new(&ECDH_P256, pk_uncompressed.as_bytes());

        let enc_key = agree_ephemeral(esk, &pk_ring, (), |shared_secret| {
            let mut salt = vec![];
            salt.extend_from_slice(epk.as_bytes());
            salt.extend_from_slice(pk.as_bytes());

            Ok(hkdf(&salt, STANZA_KEY_LABEL, shared_secret))
        })
        .expect("keys are correct");

        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.expose_secret()));
            key
        };

        RecipientLine {
            tag: pk.tag(),
            epk,
            encrypted_file_key,
        }
    }
}
