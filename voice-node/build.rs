fn main() {
    println!("cargo:rerun-if-changed=../protocol/lnex.proto");
    prost_build::compile_protos(&["../protocol/lnex.proto"], &["../protocol/"]).unwrap();
}
