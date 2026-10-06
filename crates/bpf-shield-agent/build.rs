//! Build script for the agent.
//!
//! It builds the kernel-space object and bakes the absolute path of the
//! resulting `.o` into the binary as `BPF_SHIELD_EBPF_OBJECT`.
//!
//! Doing it here rather than making the operator pass `--ebpf-object` keeps the
//! normal case one command (`bpf-shield-agent run`), while `--ebpf-object`
//! stays available for distro packaging, where the object ships as a separate
//! file in `/usr/lib/bpf-shield/` and must be loaded from there rather than
//! from a build directory that may not exist on the target host.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "bpf-shield-ebpf",
            root_dir: "..",
            no_default_features: true,
            features: &[],
        }],
        aya_build::Toolchain::default(),
    )?;

    // aya-build copies each produced binary to `OUT_DIR/<name>`.
    let object = out_dir.join("bpf-shield-ebpf");
    if !object.exists() {
        return Err(format!("aya-build did not produce {}", object.display()).into());
    }

    // Absolute: the agent is almost always started from a different cwd than
    // the build tree.
    println!(
        "cargo:rustc-env=BPF_SHIELD_EBPF_OBJECT={}",
        object.canonicalize()?.display()
    );

    Ok(())
}
