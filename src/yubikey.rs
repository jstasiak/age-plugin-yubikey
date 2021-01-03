//! Structs for handling YubiKeys.

use bech32::ToBase32;
use dialoguer::Password;
use std::convert::TryFrom;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use yubikey_piv::{key::RetiredSlotId, yubikey::Serial, MgmKey, Readers, YubiKey};

use crate::{
    error::Error,
    p256::{Recipient, TAG_BYTES},
    IDENTITY_PREFIX,
};

const ONE_SECOND: Duration = Duration::from_secs(1);
const FIFTEEN_SECONDS: Duration = Duration::from_secs(15);

pub(crate) fn wait_for_readers() -> Result<Readers, Error> {
    // Start a 15-second timer waiting for a YubiKey to be inserted (if necessary).
    let start = SystemTime::now();
    loop {
        let mut readers = Readers::open()?;
        if readers.iter()?.len() > 0 {
            break Ok(readers);
        }

        match SystemTime::now().duration_since(start) {
            Ok(end) if end >= FIFTEEN_SECONDS => return Err(Error::TimedOut),
            _ => sleep(ONE_SECOND),
        }
    }
}

pub(crate) fn open(serial: Option<Serial>) -> Result<YubiKey, Error> {
    if Readers::open()?.iter()?.len() == 0 {
        if let Some(serial) = serial {
            eprintln!("⏳ Please insert the YubiKey with serial {}.", serial);
        } else {
            eprintln!("⏳ Please insert the YubiKey.");
        }
    }
    let mut readers = wait_for_readers()?;
    let mut readers_iter = readers.iter()?;

    // --serial selects the YubiKey to use. If not provided, and more than one YubiKey is
    // connected, an error is returned.
    let yubikey = match (readers_iter.len(), serial) {
        (0, _) => unreachable!(),
        (1, None) => readers_iter.next().unwrap().open()?,
        (1, Some(serial)) => {
            let yubikey = readers_iter.next().unwrap().open()?;
            if yubikey.serial() != serial.into() {
                Err(Error::NoMatchingSerial(serial))?;
            }
            yubikey
        }
        (_, Some(serial)) => {
            let reader = readers_iter
                .into_iter()
                .find(|reader| match reader.open() {
                    Ok(yk) => yk.serial() == serial.into(),
                    _ => false,
                })
                .ok_or(Error::NoMatchingSerial(serial))?;
            reader.open()?
        }
        (_, None) => Err(Error::MultipleYubiKeys)?,
    };

    Ok(yubikey)
}

pub(crate) fn manage(yubikey: &mut YubiKey) -> Result<(), Error> {
    let pin = Password::new()
        .with_prompt(&format!(
            "🔤 Enter PIN for YubiKey with serial {} (default is 123456)",
            yubikey.serial(),
        ))
        .interact()?;
    yubikey.verify_pin(pin.as_bytes())?;

    // TODO: If the user is using the default PIN, change it.

    // Try to authenticate with the default management key.
    // TODO: If the YubiKey is using the default management key, migrate it to a
    // PIN-protected management key.
    if yubikey.authenticate(MgmKey::default()).is_err() {
        // Management key has been changed; ask the user to provide it.
        let mgm_input = Password::new()
            .with_prompt("🔐 Enter the management key as a hex string")
            .interact()?;

        let mgm_key = match hex::decode(mgm_input) {
            Ok(mgm_bytes) => match MgmKey::try_from(&mgm_bytes[..]) {
                Ok(mgm_key) => mgm_key,
                Err(_) => {
                    eprintln!("Incorrect management key size");
                    return Ok(());
                }
            },
            Err(_) => {
                eprintln!("Management key must be a hex string");
                return Ok(());
            }
        };

        yubikey.authenticate(mgm_key)?;
    }

    Ok(())
}

/// A reference to an age key stored in a YubiKey.
#[derive(Debug)]
pub struct Stub {
    pub(crate) serial: Serial,
    pub(crate) slot: RetiredSlotId,
    pub(crate) tag: [u8; TAG_BYTES],
    identity_index: usize,
}

impl Stub {
    /// Returns a key stub and recipient for this `(Serial, SlotId, PublicKey)` tuple.
    ///
    /// Does not check that the `PublicKey` matches the given `(Serial, SlotId)` tuple;
    /// this is checked at decryption time.
    pub(crate) fn new(serial: Serial, slot: RetiredSlotId, recipient: &Recipient) -> Self {
        Stub {
            serial,
            slot,
            tag: recipient.tag(),
            identity_index: 0,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Serializes this YubiKey stub as a string.
    pub fn to_string(&self) -> String {
        bech32::encode(IDENTITY_PREFIX, self.to_bytes().to_base32())
            .expect("HRP is valid")
            .to_uppercase()
    }
}
