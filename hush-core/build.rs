fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=csrc/nwudp.c");
        cc::Build::new()
            .file("csrc/nwudp.c")
            .flag("-fblocks")
            .flag("-Wno-unused-parameter")
            .compile("nwudp");
        println!("cargo:rustc-link-lib=framework=Network");
    }
}
