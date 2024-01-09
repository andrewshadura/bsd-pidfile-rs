#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
fn main() {
    println!("cargo:rustc-link-lib=util");
    println!("cargo:rerun-if-changed=build.rs");
}

#[cfg(not(any(target_os = "dragonfly", target_os = "freebsd")))]
fn main() {
    system_deps::Config::new().probe().unwrap();
}
