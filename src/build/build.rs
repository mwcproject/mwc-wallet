// Copyright 2019 The Grin Developers
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

//! Build hooks to spit out version+build time info

use built;
use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
	// Setting up git hooks in the project: rustfmt and so on.
	let hook_config_result = Command::new("git")
		.args(["config", "core.hooksPath", "./.hooks"])
		.status();
	match hook_config_result {
		Ok(status) if status.success() => {}
		Ok(status) => println!(
			"cargo:warning=Unable to configure repository hooks: git exited with status {}",
			status
		),
		Err(e) => println!("cargo:warning=Unable to configure repository hooks: {}", e),
	}

	// build and versioning information
	let out_dir =
		env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR to the build script")?;
	let out_dir_path = PathBuf::from(out_dir).join("built.rs");
	// don't fail the build if something's missing, may just be cargo release
	if let Err(e) = built::write_built_file_with_opts(
		Some(Path::new(env!("CARGO_MANIFEST_DIR"))),
		&out_dir_path,
	) {
		println!("cargo:warning=Unable to write build metadata: {}", e);
	}
	Ok(())
}
