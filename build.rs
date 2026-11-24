fn main() {
    println!("cargo:rerun-if-env-changed=RS_PROXY_UPDATE_REPOSITORY");
    println!("cargo:rerun-if-env-changed=RS_PROXY_UPDATE_PUBLIC_KEY");
}
