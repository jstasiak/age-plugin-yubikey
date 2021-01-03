use age_plugin::run_state_machine;
use gumdrop::Options;
use yubikey_piv::{
    certificate::PublicKeyInfo,
    key::{RetiredSlotId, SlotId},
    policy::{PinPolicy, TouchPolicy},
    Key, Readers,
};

mod builder;
mod error;
mod p256;
mod plugin;
mod util;
mod yubikey;

use error::Error;

const PLUGIN_NAME: &str = "age-plugin-yubikey";
const RECIPIENT_PREFIX: &str = "age1yubikey";
const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";

const USABLE_SLOTS: [RetiredSlotId; 20] = [
    RetiredSlotId::R1,
    RetiredSlotId::R2,
    RetiredSlotId::R3,
    RetiredSlotId::R4,
    RetiredSlotId::R5,
    RetiredSlotId::R6,
    RetiredSlotId::R7,
    RetiredSlotId::R8,
    RetiredSlotId::R9,
    RetiredSlotId::R10,
    RetiredSlotId::R11,
    RetiredSlotId::R12,
    RetiredSlotId::R13,
    RetiredSlotId::R14,
    RetiredSlotId::R15,
    RetiredSlotId::R16,
    RetiredSlotId::R17,
    RetiredSlotId::R18,
    RetiredSlotId::R19,
    RetiredSlotId::R20,
];

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(
        help = "Run the given age plugin state machine. Internal use only.",
        meta = "STATE-MACHINE",
        no_short
    )]
    age_plugin: Option<String>,

    #[options(help = "Force --generate to overwrite a filled slot.")]
    force: bool,

    #[options(help = "Generate a new YubiKey identity.")]
    generate: bool,

    #[options(help = "Print the identity stored in a YubiKey slot.")]
    identity: bool,

    #[options(help = "List all age identities in connected YubiKeys.")]
    list: bool,

    #[options(help = "List all YubiKey keys that are compatible with age.", no_short)]
    list_all: bool,

    #[options(
        help = "Name for the generated identity. Defaults to 'age identity HEX_TAG'.",
        no_short
    )]
    name: Option<String>,

    #[options(help = "One of [always, once, never]. Defaults to 'once'.", no_short)]
    pin_policy: Option<String>,

    #[options(
        help = "Specify which YubiKey to use, if more than one is plugged in.",
        no_short
    )]
    serial: Option<u32>,

    #[options(
        help = "Specify which slot to use. Defaults to first usable slot.",
        no_short
    )]
    slot: Option<u8>,

    #[options(
        help = "One of [always, cached, never]. Defaults to 'always'.",
        no_short
    )]
    touch_policy: Option<String>,
}

fn generate(opts: PluginOptions) -> Result<(), Error> {
    let serial = opts.serial.map(|s| s.into());
    let slot = opts
        .slot
        .map(|slot| {
            USABLE_SLOTS
                .get(slot as usize - 1)
                .cloned()
                .ok_or(Error::InvalidSlot(slot))
        })
        .transpose()?;
    let pin_policy = opts
        .pin_policy
        .map(util::pin_policy_from_string)
        .transpose()?;
    let touch_policy = opts
        .touch_policy
        .map(util::touch_policy_from_string)
        .transpose()?;

    let mut yubikey = yubikey::open(serial)?;

    let (stub, recipient, created) = builder::IdentityBuilder::new(slot)
        .with_name(opts.name)
        .with_pin_policy(pin_policy)
        .with_touch_policy(touch_policy)
        .force(opts.force)
        .build(&mut yubikey)?;

    util::print_identity(stub, recipient, &created);

    Ok(())
}

fn identity(opts: PluginOptions) -> Result<(), Error> {
    let serial = opts.serial.map(|s| s.into());
    let slot = opts
        .slot
        .map(|slot| {
            USABLE_SLOTS
                .get(slot as usize - 1)
                .cloned()
                .ok_or(Error::InvalidSlot(slot))
        })
        .transpose()?;

    let mut yubikey = yubikey::open(serial)?;

    let mut keys = Key::list(&mut yubikey)?.into_iter().filter_map(|key| {
        // - We only use the retired slots.
        // - Only P-256 keys are compatible with us.
        match (key.slot(), key.certificate().subject_pki()) {
            (SlotId::Retired(slot), PublicKeyInfo::EcP256(pubkey)) => {
                p256::Recipient::from_pubkey(*pubkey).map(|r| (key, slot, r))
            }
            _ => None,
        }
    });

    let (key, slot, recipient) = if let Some(slot) = slot {
        keys.find(|(_, s, _)| s == &slot)
            .ok_or(Error::SlotHasNoIdentity(slot))
    } else {
        let mut keys = keys.filter(|(key, _, _)| {
            let (_, cert) = x509_parser::parse_x509_der(key.certificate().as_ref()).unwrap();
            let mut org = cert.subject().iter_organization();
            match org.next() {
                Some(org) => org.as_str() == Ok(PLUGIN_NAME),
                _ => false,
            }
        });
        match (keys.next(), keys.next()) {
            (None, None) => Err(Error::NoIdentities),
            (Some(key), None) => Ok(key),
            (Some(_), Some(_)) => Err(Error::MultipleIdentities),
            (None, Some(_)) => unreachable!(),
        }
    }?;

    let stub = yubikey::Stub::new(yubikey.serial(), slot, &recipient);
    let (_, cert) = x509_parser::parse_x509_der(key.certificate().as_ref()).unwrap();
    let created = cert.validity().not_before.to_rfc2822();

    util::print_identity(stub, recipient, &created);

    Ok(())
}

fn list(all: bool) -> Result<(), Error> {
    let mut readers = Readers::open()?;

    for reader in readers.iter()? {
        let mut yubikey = reader.open()?;

        for key in Key::list(&mut yubikey)? {
            // We only use the retired slots.
            let slot = match key.slot() {
                SlotId::Retired(slot) => slot,
                _ => continue,
            };

            // Only P-256 keys are compatible with us.
            let recipient = match key.certificate().subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => match p256::Recipient::from_pubkey(*pubkey) {
                    Some(recipient) => recipient,
                    None => continue,
                },
                _ => continue,
            };

            let (_, cert) = x509_parser::parse_x509_der(key.certificate().as_ref()).unwrap();
            let (name, pin_policy, touch_policy) =
                match util::extract_name_and_policies(&mut yubikey, &key, &cert, all) {
                    Some(res) => res,
                    None => continue,
                };

            println!(
                "#      Serial: {}, Slot: {}",
                yubikey.serial(),
                // Use 1-indexing in the UI for niceness
                USABLE_SLOTS.iter().position(|s| s == &slot).unwrap() + 1,
            );
            println!("#        Name: {}", name);
            println!("#     Created: {}", cert.validity().not_before.to_rfc2822());
            println!("#  PIN policy: {}", util::pin_policy_to_str(pin_policy));
            println!(
                "# Touch policy: {}",
                util::touch_policy_to_str(touch_policy)
            );
            println!("{}", recipient.to_string());
            println!();
        }
        println!();
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if [opts.generate, opts.identity, opts.list, opts.list_all]
        .iter()
        .filter(|&&b| b)
        .count()
        > 1
    {
        return Err(Error::MultipleCommands);
    }

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(
            &state_machine,
            || plugin::RecipientPlugin::default(),
            || plugin::IdentityPlugin::default(),
        )?;
        Ok(())
    } else if opts.generate {
        generate(opts)
    } else if opts.identity {
        identity(opts)
    } else if opts.list {
        list(false)
    } else if opts.list_all {
        list(true)
    } else {
        // TODO: CLI identity generation
        Ok(())
    }
}
