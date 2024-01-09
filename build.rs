#[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}

#[cfg(not(any(target_os = "dragonfly", target_os = "freebsd")))]
fn main() {
    if system_deps::Config::new().probe().is_err() {
        println!("cargo:rustc-link-lib=dylib=bsd");
    }
}
