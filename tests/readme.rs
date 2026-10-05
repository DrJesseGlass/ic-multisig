// The README says its examples are the crate-root doctests. That claim was
// wrong once already -- the README carried a snippet that named undefined
// variables and used `?` with nothing to return to, while the doctest that
// actually compiled was a different text. A claim about compilation is worth
// only as much as the check behind it, so here is the check: the blocks
// must be the same bytes, and the doctest run makes those bytes compile.

/// The contents of every fenced block in `text`, in order, fences excluded.
fn fenced_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut open: Option<String> = None;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            match open.take() {
                Some(block) => blocks.push(block),
                None => open = Some(String::new()),
            }
        } else if let Some(block) = open.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    assert!(open.is_none(), "a fenced code block is never closed");
    blocks
}

/// `src/lib.rs` with the `//!` markers taken off, so the crate docs can be
/// read as the markdown rustdoc sees.
fn crate_docs(source: &str) -> String {
    source
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("//!"))
        .map(|l| l.strip_prefix(' ').unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn readme_examples_are_the_crate_doctests() {
    let readme = fenced_blocks(include_str!("../README.md"));
    let lib = fenced_blocks(&crate_docs(include_str!("../src/lib.rs")));
    assert!(!readme.is_empty(), "README.md has no fenced code block");
    assert_eq!(
        readme, lib,
        "README.md and the crate-root examples have drifted apart"
    );
}
