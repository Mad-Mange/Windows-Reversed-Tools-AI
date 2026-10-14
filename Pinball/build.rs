fn main() {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=generated/original.res");
    println!(
        "cargo:rustc-link-arg-bins={}",
        root.join("generated/original.res").display()
    );
    // The reference's data addresses are absolute, so leave 0x01000000 free.
    println!("cargo:rustc-link-arg-bins=/BASE:0x10000000");
    println!("cargo:rustc-link-arg-bins=/DYNAMICBASE:NO");
    println!("cargo:rustc-link-arg-bins=/FIXED:NO");
    println!("cargo:rustc-link-arg-bins=/LARGEADDRESSAWARE:NO");
}
