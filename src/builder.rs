use rand::{rngs::OsRng, RngCore};
use yubikey_piv::{
    certificate::{Certificate, PublicKeyInfo},
    key::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    policy::{PinPolicy, TouchPolicy},
    Key, YubiKey,
};

use crate::{
    error::Error,
    p256::Recipient,
    yubikey::{self, Stub},
    USABLE_SLOTS,
};

const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

pub(crate) struct IdentityBuilder {
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub(crate) fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub(crate) fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub(crate) fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, String), Error> {
        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty.
                    if Key::list(yubikey)?
                        .into_iter()
                        .any(|key| key.slot() == SlotId::Retired(slot))
                    {
                        return Err(Error::SlotIsNotEmpty(slot));
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot.
                let keys = Key::list(yubikey)?;
                USABLE_SLOTS
                    .iter()
                    .find(|&&slot| {
                        keys.iter()
                            .find(|key| key.slot() == SlotId::Retired(slot))
                            .is_none()
                    })
                    .cloned()
                    .ok_or(Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let pin_policy = self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY);
        let touch_policy = self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY);

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        yubikey::manage(yubikey)?;

        if let TouchPolicy::Never = touch_policy {
            // No need to touch YubiKey
        } else {
            eprintln!("👆 Please touch the YubiKey");
        }

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            AlgorithmId::EccP256,
            pin_policy,
            touch_policy,
        )?;

        // Pick a random serial for the new self-signed certificate.
        let mut serial = [0; 20];
        OsRng.fill_bytes(&mut serial);

        let cert = Certificate::generate_self_signed(
            yubikey,
            SlotId::Retired(slot),
            serial,
            None,
            "age-plugin-yubikey".to_owned(),
            generated,
        )?;

        let recipient = match cert.subject_pki() {
            PublicKeyInfo::EcP256(pubkey) => {
                Recipient::from_pubkey(*pubkey).expect("YubiKey generates a valid pubkey")
            }
            _ => unreachable!(),
        };

        Ok((
            Stub::new(yubikey.serial(), slot, &recipient),
            recipient,
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ))
    }
}
