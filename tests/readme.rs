// The README says its quick start is the crate-root doctest. That claim was
// wrong once already -- the README carried a snippet that named undefined
// variables and used `?` with nothing to return to, while the doctest that
// actually compiled was a different text. A claim about compilation is worth
// only as much as the check behind it, so here is the check: the two blocks
// must be the same bytes, and the doctest run makes those bytes compile.

/// The contents of the first fenced block in `text`, fences excluded.
fn first_fenced_block(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if inside {
                return out;
            }
            inside = true;
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    panic!("no fenced code block, or no closing fence");
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
fn readme_quick_start_is_the_crate_doctest() {
    let readme = include_str!("../README.md");
    let lib = include_str!("../src/lib.rs");
    assert_eq!(
        first_fenced_block(readme),
        first_fenced_block(&crate_docs(lib)),
        "README.md and the crate-root example have drifted apart"
    );
}
