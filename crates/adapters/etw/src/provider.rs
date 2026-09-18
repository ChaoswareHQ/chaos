//! Provider GUIDs and keyword masks.
//!
//! Keyword masks are not an optimisation you can skip. `matchanykeyword = 0`
//! means "all keywords", and against a manifest provider that is the difference
//! between a few thousand and a few hundred thousand events per second for the
//! same amount of *useful* signal. The process and image keywords are what a
//! security pipeline actually consumes; the thread keywords are mostly volume.

use crate::session::ProviderSpec;
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

// Microsoft-Windows-Kernel-Process keywords.
pub const KERNEL_PROCESS_KEYWORD_PROCESS: u64 = 0x10;
pub const KERNEL_PROCESS_KEYWORD_THREAD: u64 = 0x20;
pub const KERNEL_PROCESS_KEYWORD_IMAGE: u64 = 0x40;

/// Trace levels, mirroring the SDK's `TRACE_LEVEL_*`.
pub const LEVEL_CRITICAL: u8 = 1;
pub const LEVEL_ERROR: u8 = 2;
pub const LEVEL_WARNING: u8 = 3;
pub const LEVEL_INFORMATIONAL: u8 = 4;
pub const LEVEL_VERBOSE: u8 = 5;

/// Event ids worth a name, for the providers a security pipeline reads first.
///
/// These come from the shipped manifests. `--dump-schema` in the client
/// enumerates the live manifests so this table can be checked against a real
/// machine rather than trusted.
pub fn event_name(provider: &str, event_id: u16) -> Option<&'static str> {
    match (provider, event_id) {
        ("Microsoft-Windows-Kernel-Process", 1) => Some("ProcessStart"),
        ("Microsoft-Windows-Kernel-Process", 2) => Some("ProcessStop"),
        ("Microsoft-Windows-Kernel-Process", 3) => Some("ThreadStart"),
        ("Microsoft-Windows-Kernel-Process", 4) => Some("ThreadStop"),
        ("Microsoft-Windows-Kernel-Process", 5) => Some("ImageLoad"),
        ("Microsoft-Windows-Kernel-Process", 6) => Some("ImageUnload"),
        ("Microsoft-Windows-DNS-Client", 3006) => Some("DnsQuery"),
        ("Microsoft-Windows-DNS-Client", 3008) => Some("DnsResponse"),
        ("Microsoft-Windows-Kernel-Registry", 1) => Some("RegistryCreateKey"),
        ("Microsoft-Windows-Kernel-Registry", 2) => Some("RegistryOpenKey"),
        ("Microsoft-Windows-Kernel-Registry", 3) => Some("RegistryDeleteKey"),
        ("Microsoft-Windows-Kernel-Registry", 4) => Some("RegistryQueryValue"),
        ("Microsoft-Windows-Kernel-Registry", 5) => Some("RegistrySetValue"),
        ("Microsoft-Windows-Kernel-Registry", 6) => Some("RegistryDeleteValue"),
        ("Microsoft-Windows-Kernel-File", 12) => Some("FileCreate"),
        ("Microsoft-Windows-Kernel-File", 14) => Some("FileWrite"),
        ("Microsoft-Windows-Kernel-File", 15) => Some("FileDelete"),
        _ => None,
    }
}

/// The providers a Windows deployment should try to enable, in priority order.
///
/// Callers should expect partial success: the kernel providers need privileges
/// that an interactive session may not hold, and the correct behaviour is to
/// run with what was granted and report the rest.
pub fn default_providers() -> Vec<ProviderSpec> {
    vec![
        ProviderSpec {
            guid: KERNEL_PROCESS,
            name: "Microsoft-Windows-Kernel-Process",
            level: LEVEL_INFORMATIONAL,
            keywords: KERNEL_PROCESS_KEYWORD_PROCESS | KERNEL_PROCESS_KEYWORD_IMAGE,
        },
        ProviderSpec {
            guid: DNS_CLIENT,
            name: "Microsoft-Windows-DNS-Client",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
        },
        ProviderSpec {
            guid: POWERSHELL,
            name: "Microsoft-Windows-PowerShell",
            level: LEVEL_INFORMATIONAL,
            keywords: 0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // matchanykeyword = 0 means "all", which is how a deployment ends up
        // dropping half its events because it enabled thread churn too.
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
    fn unknown_events_have_no_name_instead_of_a_wrong_one() {
        assert_eq!(
            event_name("Microsoft-Windows-Kernel-Process", 1),
            Some("ProcessStart")
        );
        assert_eq!(event_name("Microsoft-Windows-Kernel-Process", 999), None);
        assert_eq!(event_name("Some-Third-Party-Provider", 1), None);
    }
}
