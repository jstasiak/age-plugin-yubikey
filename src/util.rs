use der_parser::oid::Oid;
use x509_parser::X509Certificate;
use yubikey_piv::{
    policy::{PinPolicy, TouchPolicy},
    Key, YubiKey,
};

use crate::{error::Error, p256::Recipient, yubikey::Stub, PLUGIN_NAME};

const POLICY_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 8];

pub(crate) fn pin_policy_from_string(s: String) -> Result<PinPolicy, Error> {
    match s.as_str() {
        "always" => Ok(PinPolicy::Always),
        "once" => Ok(PinPolicy::Once),
        "never" => Ok(PinPolicy::Never),
        _ => Err(Error::InvalidPinPolicy(s)),
    }
}

pub(crate) fn touch_policy_from_string(s: String) -> Result<TouchPolicy, Error> {
    match s.as_str() {
        "always" => Ok(TouchPolicy::Always),
        "cached" => Ok(TouchPolicy::Cached),
        "never" => Ok(TouchPolicy::Never),
        _ => Err(Error::InvalidTouchPolicy(s)),
    }
}

pub(crate) fn pin_policy_to_str(policy: Option<PinPolicy>) -> &'static str {
    match policy {
        Some(PinPolicy::Always) => "Always (A PIN is required for every decryption, if set)",
        Some(PinPolicy::Once) => "Once   (A PIN is required once per session, if set)",
        Some(PinPolicy::Never) => "Never  (A PIN is NOT required to decrypt)",
        _ => "Unknown",
    }
}

pub(crate) fn touch_policy_to_str(policy: Option<TouchPolicy>) -> &'static str {
    match policy {
        Some(TouchPolicy::Always) => "Always (A physical touch is required for every decryption)",
        Some(TouchPolicy::Cached) => {
            "Cached (A physical touch is required for decryption, and is cached for 15 seconds)"
        }
        Some(TouchPolicy::Never) => "Never  (A physical touch is NOT required to decrypt)",
        _ => "Unknown",
    }
}

pub(crate) fn extract_name(cert: &X509Certificate, all: bool) -> Option<(String, bool)> {
    // Look at Subject Organization to determine if we created this.
    match cert.subject().iter_organization().next() {
        Some(org) if org.as_str() == Ok(PLUGIN_NAME) => {
            // We store the identity name as a Common Name attribute.
            let name = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(|s| s.to_owned())
                .unwrap_or_default(); // TODO: This should always be present.

            Some((name, true))
        }
        _ => {
            // Not one of ours, but we've already filtered for compatibility.
            if !all {
                return None;
            }

            // Display the entire subject.
            let name = cert.subject().to_string();

            Some((name, false))
        }
    }
}

pub(crate) fn extract_name_and_policies(
    yubikey: &mut YubiKey,
    key: &Key,
    cert: &X509Certificate,
    all: bool,
) -> Option<(String, Option<PinPolicy>, Option<TouchPolicy>)> {
    // We store the PIN and touch policies for identities in their certificates
    // using the same certificate extension as PIV attestations.
    // https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
    let policies = |c: &X509Certificate| {
        let policy = c
            .extensions()
            .get(&Oid::from(POLICY_EXTENSION_OID).unwrap())
            .unwrap();
        let pin_policy = match policy.value[0] {
            0x01 => PinPolicy::Never,
            0x02 => PinPolicy::Once,
            0x03 => PinPolicy::Always,
            _ => unreachable!(),
        };
        let touch_policy = match policy.value[1] {
            0x01 => TouchPolicy::Never,
            0x02 => TouchPolicy::Always,
            0x03 => TouchPolicy::Cached,
            _ => unreachable!(),
        };
        (Some(pin_policy), Some(touch_policy))
    };

    extract_name(cert, all).map(|(name, ours)| {
        if ours {
            let (pin_policy, touch_policy) = policies(&cert);
            (name, pin_policy, touch_policy)
        } else {
            // We can extract the PIN and touch policies via an attestation. This
            // is slow, but the user has asked for all compatible keys, so...
            let (pin_policy, touch_policy) = match yubikey_piv::key::attest(yubikey, key.slot()) {
                Ok(buf) => {
                    let (_, c) = x509_parser::parse_x509_der(&buf).unwrap();
                    policies(&c)
                }
                Err(_) => (None, None),
            };

            (name, pin_policy, touch_policy)
        }
    })
}

pub(crate) fn print_identity(stub: Stub, recipient: Recipient, created: &str) {
    let recipient = recipient.to_string();
    if !console::user_attended() {
        eprintln!("Recipient: {}", recipient);
    }

    println!("# created: {}", created);
    println!("# recipient: {}", recipient);
    println!("{}", stub.to_string());
}
