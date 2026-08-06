/// The map module.
pub mod map;
pub mod ptrauth;
/// The range module.
pub mod range;
/// The types module.
pub mod types;

pub use map::{AddressMap, MappingEntry};
pub use ptrauth::{has_ptrauth_bits, strip_ptrauth};
pub use range::{AddressRange, FileRange, VaRange};
pub use types::{FatFileOffset, Rva, ThinFileOffset, Va};
