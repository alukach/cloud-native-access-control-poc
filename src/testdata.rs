//! Locating the sample files the tests read.
//!
//! They are not in the repository -- 24 MB of binaries that never change --
//! so the one thing this module owes a developer is a failure that says what
//! to do about it. A bare `No such file or directory` on a fresh clone sends
//! people looking for a bug in the resolver.
//!
//! `tests/fixtures/` is different and stays in git: those files are small, and
//! each one exists to pin a specific parse failure, so a checkout that could
//! not reproduce them would be a checkout that could not run the suite at all.

use std::path::{Path, PathBuf};

/// A path inside the repository, whatever the working directory is.
pub fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Read a repository file, or explain how to get it.
pub fn read(rel: &str) -> Vec<u8> {
    let path = repo(rel);
    std::fs::read(&path).unwrap_or_else(|e| {
        if e.kind() == std::io::ErrorKind::NotFound && rel.starts_with("data/") {
            panic!(
                "{rel} is missing.\n\n\
                 The sample files are hosted rather than committed. Fetch them with:\n\
                 \n    ./scripts/fetch-data.sh\n\n\
                 They are checksummed against the exact bytes the numbers in \
                 docs/findings.md were measured on."
            );
        }
        panic!("{}: {e}", path.display());
    })
}
