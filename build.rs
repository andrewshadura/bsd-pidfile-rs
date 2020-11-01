fn main() {
    if pkg_config::Config::new().probe("libbsd").is_ok() {
        println!("cargo:rustc-cfg=pidfile");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
