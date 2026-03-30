// Address types
pub use crate::addr::{AddressMap, FatFileOffset, MappingEntry, Rva, ThinFileOffset, Va};

// Error types
pub use crate::error::{Error, Result};

// Extension traits
pub use crate::ext::{MachAnalysis, MachExt};

// IO
pub use crate::io::Endian;

// Constant/flag types
pub use crate::constants::{MachHeaderFlags, SectionAttributes, SegmentFlags, VmProtection};

// Model types
pub use crate::model::{
    ArchSpec, Bitness, CpuSubtype, CpuType, FatArch, FatBinary, FatHeader, FileType, LoadCommand,
    MachContainer, MachFile, MachHeader, MagicNumber, ParsedLoadCommand, Section, SectionName,
    SectionType, Segment, SegmentName,
};

// Load command data types
pub use crate::model::load_command::{
    BuildToolVersion, BuildVersionData, DyldInfoData, DylibData, DysymtabData, EncryptionInfoData,
    EntryPointData, FilesetEntryData, LinkeditData, LinkerOptionData, NoteData, PackedVersion,
    Platform, RoutinesData, SourceVersion, SourceVersionData, StringData, SymtabData, Tool,
    UuidData, VersionMinData, format_uuid,
};

// Symbol and relocation types
pub use crate::model::relocation::{Relocation, ScatteredRelocation, StandardRelocation};
pub use crate::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

// Owned/writable types
pub use crate::model::owned::{OwnedFatArch, OwnedFatBinary, OwnedMachFile};

// ObjC types
pub use crate::objc::{
    ObjCCategory, ObjCClass, ObjCIvar, ObjCMetadata, ObjCMethod, ObjCProperty, ObjCProtocol,
    parse_objc_metadata,
};

// Code signature types
pub use crate::codesign::{
    BlobType, CodeDirectory, CodeSignature, HashType, SignatureBlob, parse_code_signature,
};

// Dyld types
pub use crate::dyld::{
    BindEntry, ChainedFixups, ChainedImport, Export, ExportKind, Fixup, FixupKind, RebaseEntry,
    find_export, parse_bind_entries, parse_chained_fixups, parse_exports, parse_rebase_entries,
};
pub use crate::model::resolution::ResolutionContext;

// Structural editing
pub use crate::edit::MachEditor;

// Top-level parse functions
pub use crate::parse::{parse, parse_symbol_table, relocations_for_section};

// Validation
pub use crate::validate::{self, Diagnostic, DiagnosticCode, Severity};
