//! Positions: gosyn reports Unicode scalar offsets, so this table maps a
//! scalar offset to the byte offset [`LineIndex`](egress_core::ir::LineIndex)
//! expects. Lines split on `\n` only; columns are 1-based scalars.

/// Maps scalar offsets to byte offsets for one file.
pub struct Positions {
    /// Byte offset of each scalar value boundary; `byte[char]` is the byte
    /// offset of the char'th scalar value.
    byte: Vec<u32>,
}

impl Positions {
    pub fn new(text: &str) -> Positions {
        let mut byte: Vec<u32> = text
            .char_indices()
            .map(|(i, _)| u32::try_from(i).unwrap_or(u32::MAX))
            .collect();
        byte.push(u32::try_from(text.len()).unwrap_or(u32::MAX));
        Positions { byte }
    }

    /// The byte offset of scalar offset `pos`, clamped to the text.
    pub fn byte_offset(&self, pos: usize) -> u32 {
        self.byte.get(pos).copied().unwrap_or(u32::MAX)
    }
}
