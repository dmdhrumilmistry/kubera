// Records the target triple, so `kubera update` can pick the release
// archive built for this platform.
fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=KUBERA_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
