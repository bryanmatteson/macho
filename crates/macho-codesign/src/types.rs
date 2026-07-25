use std::fmt;

// SuperBlob / blob magic numbers (always big-endian)
/// The CSMAGIC_EMBEDDED_SIGNATURE constant.
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
/// The CSMAGIC_CODEDIRECTORY constant.
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
/// The CSMAGIC_REQUIREMENT constant.
pub const CSMAGIC_REQUIREMENT: u32 = 0xFADE_0C00;
/// The CSMAGIC_REQUIREMENTS constant.
pub const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
/// The CSMAGIC_ENTITLEMENTS constant.
pub const CSMAGIC_ENTITLEMENTS: u32 = 0xFADE_7171;
/// The CSMAGIC_ENTITLEMENTS_DER constant.
pub const CSMAGIC_ENTITLEMENTS_DER: u32 = 0xFADE_7172;
/// The CSMAGIC_BLOBWRAPPER constant.
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
/// The CSMAGIC_EMBEDDED_ENTITLEMENTS constant.
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE_7171;
/// The CSMAGIC_DETACHED_SIGNATURE constant.
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xFADE_0CC1;

// Blob type slots (used in BlobIndex.type)
/// The CS_SLOT_CODEDIRECTORY constant.
pub const CS_SLOT_CODEDIRECTORY: u32 = 0;
/// The CS_SLOT_INFOSLOT constant.
pub const CS_SLOT_INFOSLOT: u32 = 1;
/// The CS_SLOT_REQUIREMENTS constant.
pub const CS_SLOT_REQUIREMENTS: u32 = 2;
/// The CS_SLOT_RESOURCEDIR constant.
pub const CS_SLOT_RESOURCEDIR: u32 = 3;
/// The CS_SLOT_APPLICATION constant.
pub const CS_SLOT_APPLICATION: u32 = 4;
/// The CS_SLOT_ENTITLEMENTS constant.
pub const CS_SLOT_ENTITLEMENTS: u32 = 5;
/// The CS_SLOT_DER_ENTITLEMENTS constant.
pub const CS_SLOT_DER_ENTITLEMENTS: u32 = 7;
/// The CS_SLOT_LAUNCH_CONSTRAINTS constant.
pub const CS_SLOT_LAUNCH_CONSTRAINTS: u32 = 8;
/// The CS_SLOT_SIGNATURESLOT constant.
pub const CS_SLOT_SIGNATURESLOT: u32 = 0x10000;
/// The CS_SLOT_ALTERNATE_CODEDIRECTORIES constant.
pub const CS_SLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;

/// Requirement-set entry type for the code's designated requirement.
pub const CS_REQUIREMENT_TYPE_DESIGNATED: u32 = 3;

// Hash types
/// The CS_HASHTYPE_SHA1 constant.
pub const CS_HASHTYPE_SHA1: u8 = 1;
/// The CS_HASHTYPE_SHA256 constant.
pub const CS_HASHTYPE_SHA256: u8 = 2;
/// The CS_HASHTYPE_SHA256_TRUNCATED constant.
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
/// The CS_HASHTYPE_SHA384 constant.
pub const CS_HASHTYPE_SHA384: u8 = 4;
/// The CS_HASHTYPE_SHA512 constant.
pub const CS_HASHTYPE_SHA512: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The BlobType type.
#[non_exhaustive]
pub enum BlobType {
    /// The CodeDirectory variant.
    CodeDirectory,
    /// The Info variant.
    Info,
    /// The Requirements variant.
    Requirements,
    /// The ResourceDir variant.
    ResourceDir,
    /// The Application variant.
    Application,
    /// The Entitlements variant.
    Entitlements,
    /// The DerEntitlements variant.
    DerEntitlements,
    /// The LaunchConstraints variant.
    LaunchConstraints,
    /// The Signature variant.
    Signature,
    /// The AlternateCodeDirectory variant.
    AlternateCodeDirectory(u32),
    /// The Unknown variant.
    Unknown(u32),
}

impl BlobType {
    /// Performs from_slot.
    pub fn from_slot(slot: u32) -> Self {
        match slot {
            CS_SLOT_CODEDIRECTORY => Self::CodeDirectory,
            CS_SLOT_INFOSLOT => Self::Info,
            CS_SLOT_REQUIREMENTS => Self::Requirements,
            CS_SLOT_RESOURCEDIR => Self::ResourceDir,
            CS_SLOT_APPLICATION => Self::Application,
            CS_SLOT_ENTITLEMENTS => Self::Entitlements,
            CS_SLOT_DER_ENTITLEMENTS => Self::DerEntitlements,
            CS_SLOT_LAUNCH_CONSTRAINTS => Self::LaunchConstraints,
            CS_SLOT_SIGNATURESLOT => Self::Signature,
            s if (CS_SLOT_ALTERNATE_CODEDIRECTORIES..CS_SLOT_SIGNATURESLOT).contains(&s) => {
                Self::AlternateCodeDirectory(s - CS_SLOT_ALTERNATE_CODEDIRECTORIES)
            }
            s => Self::Unknown(s),
        }
    }

    /// Performs name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CodeDirectory => "CodeDirectory",
            Self::Info => "Info",
            Self::Requirements => "Requirements",
            Self::ResourceDir => "ResourceDir",
            Self::Application => "Application",
            Self::Entitlements => "Entitlements",
            Self::DerEntitlements => "DER Entitlements",
            Self::LaunchConstraints => "Launch Constraints",
            Self::Signature => "CMS Signature",
            Self::AlternateCodeDirectory(_) => "Alternate CodeDirectory",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for BlobType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The HashType type.
#[non_exhaustive]
pub enum HashType {
    /// The Sha1 variant.
    Sha1,
    /// The Sha256 variant.
    Sha256,
    /// The Sha256Truncated variant.
    Sha256Truncated,
    /// The Sha384 variant.
    Sha384,
    /// The Sha512 variant.
    Sha512,
    /// The Unknown variant.
    Unknown(u8),
}

impl HashType {
    /// Performs from_u8.
    pub fn from_u8(v: u8) -> Self {
        match v {
            CS_HASHTYPE_SHA1 => Self::Sha1,
            CS_HASHTYPE_SHA256 => Self::Sha256,
            CS_HASHTYPE_SHA256_TRUNCATED => Self::Sha256Truncated,
            CS_HASHTYPE_SHA384 => Self::Sha384,
            CS_HASHTYPE_SHA512 => Self::Sha512,
            v => Self::Unknown(v),
        }
    }

    /// Performs name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha256Truncated => "SHA-256 (truncated)",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A blob within the code signature SuperBlob.
#[derive(Debug, Clone)]
pub struct SignatureBlob<'data> {
    /// The blob_type field.
    pub blob_type: BlobType,
    /// The magic field.
    pub magic: u32,
    /// The offset field.
    pub offset: u32,
    /// The size field.
    pub size: u32,
    /// The data field.
    pub data: &'data [u8],
}

/// Parsed CodeDirectory from the code signature.
#[derive(Debug, Clone)]
pub struct CodeDirectory<'data> {
    /// The version field.
    pub version: u32,
    /// The flags field.
    pub flags: u32,
    /// The hash_type field.
    pub hash_type: HashType,
    /// The hash_size field.
    pub hash_size: u8,
    /// The page_size field.
    pub page_size: u8,
    /// The n_code_slots field.
    pub n_code_slots: u32,
    /// The n_special_slots field.
    pub n_special_slots: u32,
    /// The code_limit field.
    pub code_limit: u32,
    /// The identifier field.
    pub identifier: Option<&'data str>,
    /// The team_id field.
    pub team_id: Option<&'data str>,
    /// The exec_seg_base field.
    pub exec_seg_base: Option<u64>,
    /// The exec_seg_limit field.
    pub exec_seg_limit: Option<u64>,
    /// The exec_seg_flags field.
    pub exec_seg_flags: Option<u64>,
}

impl CodeDirectory<'_> {
    /// Performs version_string.
    pub fn version_string(&self) -> String {
        let major = (self.version >> 16) & 0xFF;
        let minor = (self.version >> 8) & 0xFF;
        let patch = self.version & 0xFF;
        format!("{major}.{minor}.{patch}")
    }
}
