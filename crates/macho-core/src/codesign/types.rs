use std::fmt;

// SuperBlob / blob magic numbers (always big-endian)
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
pub const CSMAGIC_ENTITLEMENTS: u32 = 0xFADE_7171;
pub const CSMAGIC_ENTITLEMENTS_DER: u32 = 0xFADE_7172;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE_7171;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xFADE_0CC1;

// Blob type slots (used in BlobIndex.type)
pub const CS_SLOT_CODEDIRECTORY: u32 = 0;
pub const CS_SLOT_INFOSLOT: u32 = 1;
pub const CS_SLOT_REQUIREMENTS: u32 = 2;
pub const CS_SLOT_RESOURCEDIR: u32 = 3;
pub const CS_SLOT_APPLICATION: u32 = 4;
pub const CS_SLOT_ENTITLEMENTS: u32 = 5;
pub const CS_SLOT_DER_ENTITLEMENTS: u32 = 7;
pub const CS_SLOT_LAUNCH_CONSTRAINTS: u32 = 8;
pub const CS_SLOT_SIGNATURESLOT: u32 = 0x10000;
pub const CS_SLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;

// Hash types
pub const CS_HASHTYPE_SHA1: u8 = 1;
pub const CS_HASHTYPE_SHA256: u8 = 2;
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
pub const CS_HASHTYPE_SHA384: u8 = 4;
pub const CS_HASHTYPE_SHA512: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobType {
    CodeDirectory,
    Info,
    Requirements,
    ResourceDir,
    Application,
    Entitlements,
    DerEntitlements,
    LaunchConstraints,
    Signature,
    AlternateCodeDirectory(u32),
    Unknown(u32),
}

impl BlobType {
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
pub enum HashType {
    Sha1,
    Sha256,
    Sha256Truncated,
    Sha384,
    Sha512,
    Unknown(u8),
}

impl HashType {
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
    pub blob_type: BlobType,
    pub magic: u32,
    pub offset: u32,
    pub size: u32,
    pub data: &'data [u8],
}

/// Parsed CodeDirectory from the code signature.
#[derive(Debug, Clone)]
pub struct CodeDirectory<'data> {
    pub version: u32,
    pub flags: u32,
    pub hash_type: HashType,
    pub hash_size: u8,
    pub page_size: u8,
    pub n_code_slots: u32,
    pub n_special_slots: u32,
    pub code_limit: u32,
    pub identifier: Option<&'data str>,
    pub team_id: Option<&'data str>,
    pub exec_seg_base: Option<u64>,
    pub exec_seg_limit: Option<u64>,
    pub exec_seg_flags: Option<u64>,
}

impl CodeDirectory<'_> {
    pub fn version_string(&self) -> String {
        let major = (self.version >> 16) & 0xFF;
        let minor = (self.version >> 8) & 0xFF;
        let patch = self.version & 0xFF;
        format!("{major}.{minor}.{patch}")
    }
}
