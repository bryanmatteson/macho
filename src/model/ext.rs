use crate::model::mach_file::MachFile;

/// Extension trait for layering domain-specific analysis on top of MachFile.
///
/// Extensions are transient borrowed views. Compute what you need and let them
/// drop when the derived view is no longer needed.
pub trait MachExt<'data>: Sized {
    fn parse<'mf>(mach: &'mf MachFile<'data>) -> crate::Result<Self>
    where
        'data: 'mf;
}

impl<'data> MachFile<'data> {
    pub fn ext<E: MachExt<'data>>(&self) -> crate::Result<E> {
        E::parse(self)
    }
}
