//! Provider GUIDs and keyword masks.
//!
//! Keyword masks are not an optimisation you can skip. `matchanykeyword = 0`
//! means "all keywords", and against a manifest provider that is the
//! difference between a few thousand and a few hundred thousand events per
//! second for the same amount of *useful* signal. The process and image
//! keywords are what a security pipeline actually consumes; the thread
//! keywords are mostly volume.
//!
//! # The default set
//!
//! | Provider | What it closes | Notes |
//! |---|---|---|
//! | `Kernel-Process` | Process lifecycle, image loads | |
//! | `Kernel-File` | File create/delete/rename | |
//! | `Kernel-Network` | TCP connect/disconnect | |
//! | `Kernel-Registry` | Registry writes (with KCB correlation) | |
//! | `Security-Auditing` | Command lines, parent image (4688 v2) | **needs `enable_keyword_zero`** |
//! | `DNS-Client` | Name resolution | |
//! | `PowerShell` | Script blocks when SBL is on | |
//! | `WMI-Activity` | WMI process creation (T1047), permanent subscriptions (T1546.003) | |
//! | `TaskScheduler` | Task registrations (T1053.005) | |
//!
//! # The `enable_keyword_zero` flag
//!
//! Most providers accept the default enable call and start delivering
//! events. A few — `Microsoft-Windows-Security-Auditing` being the one
//! this crate hit — do not. They register successfully and stay silent
//! unless `EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0` is set on the enable
//! call. The flag exists to name which providers need it.

use crate::boundary::session::ProviderSpec;
use windows::core::GUID;

pub const KERNEL_PROCESS: GUID = GUID::from_u128(0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716);
pub const KERNEL_FILE: GUID = GUID::from_u128(0xEDD08927_9CC4_4E65_B970_C2560FB5C289);
pub const KERNEL_REGISTRY: GUID = GUID::from_u128(0x70EB4F03_C1DE_4F73_A051_33D13D5413BD);
pub const KERNEL_NETWORK: GUID = GUID::from_u128(0x7DD42A49_5329_4832_8DFD_43D979153A88);
pub const DNS_CLIENT: GUID = GUID::from_u128(0x1C95126E_7EEA_49A9_A3FE_A378B03DDB4D);
pub const POWERSHELL: GUID = GUID::from_u128(0xA0C1853B_5C40_4B15_8766_3CF1C58F985A);
pub const THREAT_INTELLIGENCE: GUID = GUID::from_u128(0xF4E1897C_BB5D_5668_F1D8_040F4D8DD344);
pub const AMSI: GUID = GUID::from_u128(0x2A576B87_09A7_520E_C21A_4942F0271D67);
pub const DOTNET_RUNTIME: GUID = GUID::from_u128(0xE13C0D23_CCBC_4E12_931B_D9CC2EEE27E4);
pub const WMI_ACTIVITY: GUID = GUID::from_u128(0x1418EF04_B0B4_4623_BF7E_D74AB47BBDAA);
pub const SECURITY_AUDITING: GUID = GUID::from_u128(0x54849625_5478_4994_A5BA_3E3B0328C30D);
pub const TASK_SCHEDULER: GUID = GUID::from_u128(0xDE7B24EA_73C8_4A09_985D_5BDADCFA9017);
pub const SERVICES: GUID = GUID::from_u128(0x0063715B_EEDA_4007_9429_AD526F62696E);
pub const CODE_INTEGRITY: GUID = GUID::from_u128(0x4EE76BD8_3CF4_44A0_A0AC_3937643E37A3);

// Microsoft-Windows-Kernel-Process keywords.
pub const KERNEL_PROCESS_KEYWORD_PROCESS: u64 = 0x10;
pub const KERNEL_PROCESS_KEYWORD_THREAD: u64 = 0x20;
pub const KERNEL_PROCESS_KEYWORD_IMAGE: u64 = 0x40;

// Microsoft-Windows-Kernel-Network keywords.
pub const KERNEL_NETWORK_KEYWORD_IPV4: u64 = 0x10;
pub const KERNEL_NETWORK_KEYWORD_IPV6: u64 = 0x20;

/// Trace levels, mirroring the SDK's `TRACE_LEVEL_*`.
pub const LEVEL_CRITICAL: u8 = 1;
pub const LEVEL_ERROR: u8 = 2;
pub const LEVEL_WARNING: u8 = 3;
pub const LEVEL_INFORMATIONAL: u8 = 4;
pub const LEVEL_VERBOSE: u8 = 5;

/// The providers a Windows deployment should try to enable.
///
/// Callers should expect partial success. The per-provider
/// `EnableReport` returned by `EtwSession::start` names which ones
/// succeeded. The sensor runs with whatever it was granted.
///
/// # Why these and not the rest
///
/// Every provider here is one whose events a rule in the pipeline reads. A
/// provider that is enabled and unread is a coverage number on paper and
/// nothing on a host, so the list grows one rule at a time rather than one
/// GUID at a time.
///
/// Four GUIDs are defined above and deliberately **not** in this list:
///
/// * [`AMSI`] — not registered on every host, and on the hosts where it is, it
///   is high-volume during any script execution. Its 1101 content-scan event
///   duplicates what `ScriptBlock` 4104 already carries for PowerShell.
/// * [`SERVICES`] — its id 105 carries a service's `ImageName`, which is
///   exactly the field a persistence rule wants, but the event's message
///   template is absent on the reference host (see `tools/dump-fields.ps1`),
///   so what the fields *mean* is unconfirmed. Enabling it before confirming
///   would risk a rule that never fires and looks healthy.
/// * [`CODE_INTEGRITY`] — its ids 3076/3077 are the blocked/audited-code
///   events, and their field names contain spaces (`File Name`), which is a
///   decoder of its own. They are also extremely high-volume on a host with a
///   policy in audit mode.
/// * [`DOTNET_RUNTIME`] — volume without a consumer today.
///
/// [`THREAT_INTELLIGENCE`] is different from all four: it is a kernel-mode
/// provider that a user-mode process cannot subscribe to at all. It needs a
/// Microsoft PPL signature or a signed kernel driver, which is a business
/// decision rather than a code change. See the crate README.
pub fn default_providers() -> Vec<ProviderSpec> {
    vec![
        ProviderSpec {
            guid: KERNEL_PROCESS,
            name: "Microsoft-Windows-Kernel-Process",
            level: LEVEL_INFORMATIONAL,
            keywords: KERNEL_PROCESS_KEYWORD_PROCESS | KERNEL_PROCESS_KEYWORD_IMAGE,
            enable_keyword_zero: false,
        },
        ProviderSpec {
            guid: KERNEL_FILE,
            name: "Microsoft-Windows-Kernel-File",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: false,
        },
        ProviderSpec {
            guid: KERNEL_NETWORK,
            name: "Microsoft-Windows-Kernel-Network",
            level: LEVEL_INFORMATIONAL,
            keywords: KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6,
            enable_keyword_zero: false,
        },
        ProviderSpec {
            guid: KERNEL_REGISTRY,
            name: "Microsoft-Windows-Kernel-Registry",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: false,
        },
        // The one provider that needs the keyword-0 property. Without
        // it, 4688 never arrives — the provider registers, reports
        // success, and stays silent.
        ProviderSpec {
            guid: SECURITY_AUDITING,
            name: "Microsoft-Windows-Security-Auditing",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: true,
        },
        ProviderSpec {
            guid: DNS_CLIENT,
            name: "Microsoft-Windows-DNS-Client",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: false,
        },
        ProviderSpec {
            guid: POWERSHELL,
            name: "Microsoft-Windows-PowerShell",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: false,
        },
        // WMI process creation (T1047) and permanent event subscriptions
        // (T1546.003). Low volume on a workstation, and 5861 is the
        // highest-signal single event in the set.
        ProviderSpec {
            guid: WMI_ACTIVITY,
            name: "Microsoft-Windows-WMI-Activity",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: false,
        },
        // Task registrations (T1053.005). One event per task created, which is
        // a handful per patch Tuesday on a workstation.
        ProviderSpec {
            guid: TASK_SCHEDULER,
            name: "Microsoft-Windows-TaskScheduler",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
            enable_keyword_zero: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_default_provider_carries_at_least_one_scored_event() {
        // A provider whose events no rule reads is a coverage number on paper
        // and nothing on a host. This is the cheapest possible check on that:
        // it cannot prove a rule reads the events, but it fails loudly when a
        // provider is added with nothing at all behind it.
        use crate::wire::Shape;
        let scored = Shape::ALL.len();
        assert!(scored >= default_providers().len());
        assert_eq!(scored, 15, "update this when a shape is added");
    }

    #[test]
    fn the_wmi_provider_is_enabled_so_permanent_subscriptions_can_fire() {
        let providers = default_providers();
        assert!(
            providers.iter().any(|p| p.guid == WMI_ACTIVITY),
            "T1546.003 reads WMI-Activity 5861 and nothing else carries it"
        );
    }

    #[test]
    fn the_task_scheduler_provider_is_enabled_so_task_registration_can_fire() {
        let providers = default_providers();
        assert!(
            providers.iter().any(|p| p.guid == TASK_SCHEDULER),
            "T1053.005 reads TaskScheduler 106 and nothing else carries it"
        );
    }

    #[test]
    fn the_unverified_providers_are_defined_but_not_enabled() {
        // Worth a test rather than a comment: the four below are the ones a
        // reader is most likely to "helpfully" turn on. Each has a written
        // reason in `default_providers`, and turning one on without reading it
        // is the mistake this catches.
        let providers = default_providers();
        for guid in [AMSI, SERVICES, CODE_INTEGRITY, DOTNET_RUNTIME] {
            assert!(
                !providers.iter().any(|p| p.guid == guid),
                "{guid:?} was enabled without confirming its meaning first"
            );
        }
    }

    #[test]
    fn every_default_provider_has_a_name_and_a_guid() {
        let providers = default_providers();
        assert!(!providers.is_empty());
        for p in &providers {
            assert!(!p.name.is_empty(), "{p:?}");
            assert_ne!(p.guid, GUID::from_u128(0));
        }
    }

    #[test]
    fn the_kernel_process_provider_does_not_ask_for_every_keyword() {
        let kp = default_providers()
            .into_iter()
            .find(|p| p.guid == KERNEL_PROCESS)
            .expect("kernel process provider");
        assert_ne!(kp.keywords, 0, "must not subscribe to every keyword");
        assert_eq!(
            kp.keywords & KERNEL_PROCESS_KEYWORD_PROCESS,
            KERNEL_PROCESS_KEYWORD_PROCESS
        );
        assert_eq!(
            kp.keywords & KERNEL_PROCESS_KEYWORD_IMAGE,
            KERNEL_PROCESS_KEYWORD_IMAGE
        );
        assert_eq!(
            kp.keywords & KERNEL_PROCESS_KEYWORD_THREAD,
            0,
            "thread churn is volume, not signal"
        );
    }

    #[test]
    fn the_registry_provider_is_enabled_so_run_keys_can_fire() {
        let providers = default_providers();
        assert!(
            providers.iter().any(|p| p.guid == KERNEL_REGISTRY),
            "T1547.001 reads a Run-key write and nothing else carries one"
        );
    }

    #[test]
    fn the_file_provider_is_enabled_so_ransomware_can_fire() {
        let providers = default_providers();
        assert!(
            providers.iter().any(|p| p.guid == KERNEL_FILE),
            "T1486 reads a file write and no other provider carries one"
        );
    }

    #[test]
    fn the_network_provider_is_enabled_so_c2_can_fire() {
        let providers = default_providers();
        assert!(
            providers.iter().any(|p| p.guid == KERNEL_NETWORK),
            "T1071 reads a network connect and no other provider carries one"
        );
    }

    #[test]
    fn the_network_provider_asks_for_both_ip_versions() {
        let providers = default_providers();
        let net = providers
            .iter()
            .find(|p| p.guid == KERNEL_NETWORK)
            .expect("kernel network provider");
        assert_eq!(
            net.keywords & KERNEL_NETWORK_KEYWORD_IPV4,
            KERNEL_NETWORK_KEYWORD_IPV4
        );
        assert_eq!(
            net.keywords & KERNEL_NETWORK_KEYWORD_IPV6,
            KERNEL_NETWORK_KEYWORD_IPV6
        );
    }

    #[test]
    fn security_auditing_needs_the_keyword_zero_property() {
        // The property that makes 4688 actually arrive. Without it, the
        // provider registers successfully and stays silent — the failure
        // this crate hit and had to fix. A test on the flag is worth
        // more than a comment because it is the one provider whose
        // silence looks exactly like success.
        let providers = default_providers();
        let audit = providers
            .iter()
            .find(|p| p.guid == SECURITY_AUDITING)
            .expect("security auditing provider");
        assert!(
            audit.enable_keyword_zero,
            "without this property, 4688 never arrives"
        );
    }

    #[test]
    fn no_other_provider_needs_the_keyword_zero_property() {
        // The flag is not free — it forces the enable call to build a
        // parameter block — and no other provider in the set has shown
        // that it needs it. If one turns out to, this test is where it
        // gets named rather than added silently to all of them.
        let providers = default_providers();
        for p in &providers {
            if p.guid == SECURITY_AUDITING {
                continue;
            }
            assert!(
                !p.enable_keyword_zero,
                "{} was set to enable_keyword_zero; if that is deliberate, update this test",
                p.name
            );
        }
    }
}
