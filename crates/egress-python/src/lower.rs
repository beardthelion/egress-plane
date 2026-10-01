use egress_core::ir::FileIr;
use egress_core::model::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    Parse,
    TooDeeplyNested,
}

pub fn lower(_text: &str) -> Result<FileIr, LowerError> {
    Ok(FileIr::new(Language::Python))
}
