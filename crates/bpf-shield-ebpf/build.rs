//! Build script for the BPF-Shield kernel-space object.
//!
//! `aya-build` re-invokes `cargo` for this package targeting
//! `bpf{el,eb}-unknown-none` with `--cfg bpf_target_arch="..."` and
//! `-Zbuild-std=core`, then drops the resulting `.o` into `OUT_DIR`. The
//! daemon picks it up via `env!("OUT_DIR")`-relative path baked in at compile
//! time by `aya-build`.
//!
//! Only do this when we are *already* building for a BPF target; otherwise
//! (host builds, CI lint jobs) the step is skipped so that `cargo check` on the
//! whole workspace stays fast.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::var("TARGET").unwrap_or_default();

    let packages = if target.contains("bpf") {
        vec![aya_build::Package {
            name: "bpf-shield-ebpf",
            root_dir: ".",
            no_default_features: true,
            features: &[],
        }]
    } else {
        // Host build: do not spawn a nested cargo, but still make the
        // `bpf_target_arch` cfg available so `#[cfg(bpf_target_arch = ...)]`
        // blocks type-check on the host.
        Vec::new()
    };

    aya_build::build_ebpf(packages, aya_build::Toolchain::default())?;

    // Emit the cfg ourselves when we skipped the nested build.
    if target.contains("bpf") {
        aya_build::emit_bpf_target_arch_cfg()?;
    } else {
        println!("cargo:rerun-if-changed=src");
    }

    Ok(())
}
