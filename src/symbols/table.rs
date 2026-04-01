use crate::model::macho_file::MachoFile;
pub use crate::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

pub fn parse<'a>(macho: &'a MachoFile<'a>) -> crate::Result<SymbolTable<'a>> {
    macho.ext()
}
