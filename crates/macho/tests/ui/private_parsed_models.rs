use macho::core::model::header::MachoHeader;
use macho::core::model::load_command::ParsedLoadCommand;
use macho::core::model::section::Section;
use macho::core::model::segment::Segment;

fn expose_command(command: &ParsedLoadCommand) {
    let _ = &command.kind;
}

fn expose_header(header: &MachoHeader) {
    let _ = header.ncmds;
}

fn expose_segment(segment: &Segment) {
    let _ = segment.vm_size;
}

fn expose_section(section: &Section) {
    let _ = section.offset;
}

fn main() {}
