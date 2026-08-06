use crate::core::model::macho_file::MachoFile;

/// Extension trait for layering domain-specific analysis on top of MachFile.
///
/// Extensions are transient borrowed views. Compute what you need and let them
/// drop when the derived view is no longer needed.
pub trait MachoExt<'data>: Sized {
    /// The Error associated type.
    type Error;

    /// Performs parse.
    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self, Self::Error>
    where
        'data: 'mf;
}

impl<'data> MachoFile<'data> {
    /// Performs ext.
    pub fn ext<E: MachoExt<'data>>(&self) -> Result<E, E::Error> {
        E::parse(self)
    }
}
