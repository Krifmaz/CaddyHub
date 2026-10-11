//! A Caddyfile writer (used by the generator) and a tolerant lexer/parser
//! (used by the importer). The writer never edits text; it only emits fresh
//! Caddyfiles from the structured model.

pub mod parse;
pub mod writer;

pub use parse::{Directive, TopBlock, parse};
pub use writer::{Writer, quote};
