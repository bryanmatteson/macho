use crate::model::macho_file::MachoFile;

/// Extension trait for layering domain-specific analysis on top of MachFile.
///
/// Extensions are transient borrowed views. Compute what you need and let them
/// drop when the derived view is no longer needed.
pub trait MachoExt<'data>: Sized {
    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> crate::Result<Self>
    where
        'data: 'mf;
}

impl<'data> MachoFile<'data> {
    pub fn ext<E: MachoExt<'data>>(&self) -> crate::Result<E> {
        E::parse(self)
    }
}
