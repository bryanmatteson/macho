use crate::model::mach_file::MachFile;
pub use crate::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

pub fn parse<'a>(mach: &'a MachFile<'a>) -> crate::Result<SymbolTable<'a>> {
    crate::format::parse_symbol_table(mach)
}
