use crate::model::macho_file::MachoFile;
pub use crate::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

/// Performs parse.
pub fn parse<'a>(macho: &'a MachoFile<'a>) -> crate::Result<SymbolTable<'a>> {
    Ok(macho.ext()?)
}
