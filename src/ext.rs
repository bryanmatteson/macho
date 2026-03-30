use crate::model::mach::MachFile;

/// Extension trait for layering domain-specific analysis on top of MachFile.
///
/// Extensions are transient borrowed views. Compute what you need and let them
/// drop, or use `MachAnalysis` for owned extraction.
pub trait MachExt<'data>: Sized {
    fn parse<'mf>(mach: &'mf MachFile<'data>) -> crate::Result<Self>
    where
        'data: 'mf;
}

/// Trait for extracting owned analysis results from a MachFile.
pub trait MachAnalysis<'data> {
    type Output;
    fn analyze(mach: &MachFile<'data>) -> crate::Result<Self::Output>;
}

impl<'data> MachFile<'data> {
    pub fn ext<E: MachExt<'data>>(&self) -> crate::Result<E> {
        E::parse(self)
    }
}
