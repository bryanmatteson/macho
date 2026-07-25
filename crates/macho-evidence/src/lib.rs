#![deny(missing_docs)]
//! Policy-free evidence composition for one already-selected Mach-O image.
//!
//! The session borrows an immutable parsed image, builds the shared
//! pointer/fixup index used for cross-domain projection, and exposes lossless
//! language-leaf batches. Each leaf remains responsible for its own strict
//! validation. The session owns no semantic graph, capability, report,
//! mutation, or orchestration policy.

use macho_core::MachoFile;
use macho_dyld::resolve::PointerResolver;

/// Closed evidence session for one immutable selected image.
pub struct SelectedImageEvidence<'image, 'data> {
    image: &'image MachoFile<'data>,
    pointers: PointerResolver<'image, 'data>,
}

impl<'image, 'data> SelectedImageEvidence<'image, 'data> {
    /// Admit a parsed selected image and build its shared pointer evidence.
    pub fn new(image: &'image MachoFile<'data>) -> macho_dyld::Result<Self> {
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

    /// Decode the strict Objective-C evidence batch.
    pub fn objective_c(
        &self,
        limits: macho_objc::strict::StrictObjCLimits,
    ) -> macho_objc::Result<macho_objc::strict::StrictObjCOutcome> {
        macho_objc::strict::decode_strict_objc(self.image, limits)
    }

    /// Decode the strict Swift ABI evidence batch.
    #[must_use]
    pub fn swift(
        &self,
        limits: &macho_swift::evidence::SwiftEvidenceLimits,
    ) -> macho_swift::evidence::SwiftDecodeBatchV1 {
        macho_swift::evidence::decode_swift_strict(self.image, limits)
    }

    /// Decode already-materialized Swift metadata without executing target code.
    #[must_use]
    pub fn swift_static(
        &self,
        limits: &macho_swift::evidence::SwiftEvidenceLimits,
    ) -> macho_swift::evidence::SwiftStaticMetadataBatchV1 {
        macho_swift::evidence::decode_swift_static_metadata_with_resolver(
            self.image,
            &self.pointers,
            limits,
        )
    }

    /// Decode strict Itanium RTTI evidence.
    pub fn cpp_rtti(
        &self,
        limits: macho_cpp::StrictRttiLimits,
    ) -> macho_cpp::Result<macho_cpp::StrictRttiBatch> {
        macho_cpp::decode_strict_rtti(self.image, limits)
    }

    /// Decode strict Itanium vtable, construction-vtable, and VTT evidence.
    pub fn cpp_vtables(
        &self,
        limits: macho_cpp::StrictVtableLimits,
    ) -> macho_cpp::Result<macho_cpp::StrictVtableBatch> {
        macho_cpp::decode_strict_vtables(self.image, limits)
    }
}
