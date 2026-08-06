#![deny(missing_docs)]
//! Architecture-aware executable patch and trampoline planning.

mod error;
pub(crate) use error::Error;
pub use error::{PatchError, PatchErrorKind, PatchErrorSource, Result};

mod plan;
pub use plan::{
    FunctionEntryHookPlan, FunctionEntryPatchPlan, HookJump, HookJumpEncoding, MachoPatcher,
    PatchArch, PatchSectionInfo, PatchSegmentInfo, PatchSymbolEntry, PatchSymbolTable,
    TrampolinePlan, nop_bytes_for_arch, vtable_mangled_prefix,
};
