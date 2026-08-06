use crate::metadata::symbols::model::macho_file::MachoFile;
pub use crate::metadata::symbols::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

/// Performs parse.
pub fn parse<'a>(macho: &'a MachoFile<'a>) -> crate::metadata::symbols::Result<SymbolTable<'a>> {
    Ok(macho.ext()?)
}
