// Copyright 2024 The Mwc Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Wallet-specific secure file helpers.

use std::fs;
use std::io;
use std::path::Path;

/// Remove a file and make the directory-entry removal durable.
///
/// On Unix, the containing directory is synchronized after the file is
/// removed. A synchronization failure is reported even though the file has
/// already been unlinked. Other supported platforms currently provide no
/// portable directory-synchronization operation.
pub fn remove_file_and_sync_parent<P: AsRef<Path>>(path: P) -> io::Result<()> {
	let path = path.as_ref();
	fs::remove_file(path)?;
	sync_parent_dir(path)
}

/// Remove a directory tree and make the root directory-entry removal durable.
///
/// On Unix, the containing directory is synchronized after the tree is
/// removed. A synchronization failure is reported even though the tree has
/// already been removed. Other supported platforms currently provide no
/// portable directory-synchronization operation.
pub fn remove_dir_all_and_sync_parent<P: AsRef<Path>>(path: P) -> io::Result<()> {
	let path = path.as_ref();
	fs::remove_dir_all(path)?;
	sync_parent_dir(path)
}

/// Atomically replace a file by streaming complete contents into an owner-only
/// temporary file in the destination directory.
///
/// The temporary file is synchronized before it is renamed over the
/// destination. On Unix, its classic permission bits are set to `0600` before
/// `write` is called, and the containing directory is synchronized after the
/// rename. Platform-specific ACLs are not inspected or modified.
///
/// If creating, writing, synchronizing, or renaming the temporary file fails,
/// the temporary file is removed on drop and the original destination remains
/// intact. A parent-directory synchronization failure is reported after the
/// replacement has already been installed.
pub fn replace_owner_only_file_with<P, F>(path: P, write: F) -> io::Result<()>
where
	P: AsRef<Path>,
	F: FnOnce(&mut fs::File) -> io::Result<()>,
{
	let path = path.as_ref();
	let mut replacement = mwc_crates::tempfile::Builder::new()
		.prefix(".mwc-owner-only-")
		.tempfile_in(normalized_parent(path))?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		replacement
			.as_file()
			.set_permissions(fs::Permissions::from_mode(0o600))?;
	}

	write(replacement.as_file_mut())?;
	replacement.as_file().sync_all()?;
	replacement.persist(path).map_err(|e| e.error)?;
	sync_parent_dir(path)
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
	fs::File::open(normalized_parent(path))?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
	Ok(())
}

fn normalized_parent(path: &Path) -> &Path {
	let parent = path.parent().unwrap_or_else(|| Path::new("."));
	if parent.as_os_str().is_empty() {
		Path::new(".")
	} else {
		parent
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;

	#[test]
	fn removal_deletes_file_before_synchronizing_parent() {
		let directory = mwc_crates::tempfile::tempdir().unwrap();
		let path = directory.path().join("secret");
		fs::write(&path, b"old contents").unwrap();

		remove_file_and_sync_parent(&path).unwrap();

		assert!(!path.exists());
	}

	#[test]
	fn recursive_removal_deletes_directory_before_synchronizing_parent() {
		let directory = mwc_crates::tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet");
		fs::create_dir(&path).unwrap();
		fs::write(path.join("wallet.seed"), b"encrypted seed").unwrap();

		remove_dir_all_and_sync_parent(&path).unwrap();

		assert!(!path.exists());
	}

	#[test]
	fn replacement_streams_complete_contents() {
		let directory = mwc_crates::tempfile::tempdir().unwrap();
		let path = directory.path().join("secret");
		fs::write(&path, b"old contents").unwrap();

		replace_owner_only_file_with(&path, |file| file.write_all(b"new contents")).unwrap();

		assert_eq!(fs::read(&path).unwrap(), b"new contents");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			assert_eq!(
				fs::metadata(&path).unwrap().permissions().mode() & 0o777,
				0o600
			);
		}
	}

	#[test]
	fn failed_stream_preserves_destination_and_removes_temporary_file() {
		let directory = mwc_crates::tempfile::tempdir().unwrap();
		let path = directory.path().join("secret");
		fs::write(&path, b"old contents").unwrap();

		let error = replace_owner_only_file_with(&path, |file| {
			file.write_all(b"partial contents")?;
			Err(io::Error::new(io::ErrorKind::Other, "injected failure"))
		})
		.unwrap_err();

		assert_eq!(error.kind(), io::ErrorKind::Other);
		assert_eq!(fs::read(&path).unwrap(), b"old contents");
		assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
	}
}
