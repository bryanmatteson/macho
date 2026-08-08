//! Policy-free evidence composition for one already-selected Mach-O image.
//!
//! The session borrows an immutable parsed image, builds the shared
//! pointer/fixup index used for cross-domain projection, and exposes lossless
//! language-leaf batches. Each leaf remains responsible for its own strict
//! validation. The session owns no semantic graph, capability, report,
//! mutation, or orchestration policy.

use crate::core::MachoFile;
use crate::metadata::dyld::resolve::PointerResolver;

/// Closed evidence session for one immutable selected image.
pub struct SelectedImageEvidence<'image, 'data> {
    image: &'image MachoFile<'data>,
    pointers: PointerResolver<'image, 'data>,
}

impl<'image, 'data> SelectedImageEvidence<'image, 'data> {
    /// Admit a parsed selected image and build its shared pointer evidence.
    pub fn new(image: &'image MachoFile<'data>) -> crate::metadata::dyld::Result<Self> {
        let pointers = PointerResolver::new(image)?;
        Ok(Self { image, pointers })
    }

    /// Borrow the immutable selected image.
    #[must_use]
    pub const fn image(&self) -> &'image MachoFile<'data> {
        self.image
    }

    /// Borrow the complete pointer/fixup evidence index.
    #[must_use]
    pub const fn pointers(&self) -> &PointerResolver<'image, 'data> {
        &self.pointers
    }

    /// Enumerate dyld-managed pointers with explicit absence and truncation states.
    pub fn pointer_inventory(
        &self,
        limit: u64,
    ) -> crate::metadata::dyld::Result<crate::metadata::dyld::resolve::PointerInventory> {
        self.pointers.inventory(limit)
    }

    /// Enumerate legacy-bound pointer fields without charging pure rebases to the limit.
    pub fn legacy_bindings(
        &self,
        limit: u64,
    ) -> crate::metadata::dyld::Result<crate::metadata::dyld::resolve::PointerInventory> {
        self.pointers.legacy_bind_inventory(limit)
    }

    /// Enumerate legacy-rebased pointer fields without charging binds to the limit.
    pub fn legacy_rebases(
        &self,
        limit: u64,
    ) -> crate::metadata::dyld::Result<crate::metadata::dyld::resolve::PointerInventory> {
        self.pointers.legacy_rebase_inventory(limit)
    }

    /// Look up an exact name in the authoritative chained-import table.
    pub fn chained_import(
        &self,
        name: &str,
    ) -> crate::metadata::dyld::Result<crate::metadata::dyld::ChainedImportLookup> {
        crate::metadata::dyld::lookup_chained_import(self.image, name)
    }

    /// Decode bounded, source-retaining `LC_FUNCTION_STARTS` evidence.
    pub fn function_starts(
        &self,
        limit: u64,
    ) -> crate::metadata::dyld::Result<crate::metadata::dyld::FunctionStartsOutcome> {
        crate::metadata::dyld::decode_function_starts(self.image, limit)
    }

    /// Decode bounded indirect-symbol bindings for stubs and pointer slots.
    pub fn indirect_bindings(
        &self,
        limit: u64,
    ) -> crate::metadata::symbols::Result<crate::metadata::symbols::IndirectBindingsOutcome> {
        crate::metadata::symbols::decode_indirect_bindings(self.image, limit)
    }

    /// Decode the strict Objective-C evidence batch.
    pub fn objective_c(
        &self,
        limits: crate::metadata::objc::strict::StrictObjCLimits,
    ) -> crate::metadata::objc::Result<crate::metadata::objc::strict::StrictObjCOutcome> {
        crate::metadata::objc::strict::decode_strict_objc(self.image, limits)
    }

    /// Decode the strict Swift ABI evidence batch.
    #[must_use]
    pub fn swift(
        &self,
        limits: &crate::metadata::swift::evidence::SwiftEvidenceLimits,
    ) -> crate::metadata::swift::evidence::SwiftDecodeBatchV1 {
        crate::metadata::swift::evidence::decode_swift_strict(self.image, limits)
    }

    /// Decode already-materialized Swift metadata without executing target code.
    #[must_use]
    pub fn swift_static(
        &self,
        limits: &crate::metadata::swift::evidence::SwiftEvidenceLimits,
    ) -> crate::metadata::swift::evidence::SwiftStaticMetadataBatchV1 {
        crate::metadata::swift::evidence::decode_swift_static_metadata_with_resolver(
            self.image,
            &self.pointers,
            limits,
        )
    }

    /// Decode strict Itanium RTTI evidence.
    pub fn cpp_rtti(
        &self,
        limits: crate::metadata::cpp::StrictRttiLimits,
    ) -> crate::metadata::cpp::Result<crate::metadata::cpp::StrictRttiBatch> {
        crate::metadata::cpp::decode_strict_rtti(self.image, limits)
    }

    /// Decode strict Itanium vtable, construction-vtable, and VTT evidence.
    pub fn cpp_vtables(
        &self,
        limits: crate::metadata::cpp::StrictVtableLimits,
    ) -> crate::metadata::cpp::Result<crate::metadata::cpp::StrictVtableBatch> {
        crate::metadata::cpp::decode_strict_vtables(self.image, limits)
    }
}
