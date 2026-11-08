//! Embeds every `mappings/*.yaml` pipeline into the binary, so dropping a file there is
//! still all it takes to add one (after a rebuild).
use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=mappings");
    let mut names: Vec<String> = fs::read_dir("mappings")
        .expect("mappings/ directory")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_stem()?.to_str()?.to_owned();
            (path.extension()? == "yaml").then_some(name)
        })
        .collect();
    names.sort();
    let entries: Vec<String> = names
        .iter()
        .map(|name| format!("({name:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/mappings/{name}.yaml\")))"))
        .collect();
    let code = format!(
        "pub const PIPELINES: &[(&str, &str)] = &[{}];\n",
        entries.join(", ")
    );
    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("pipelines.rs");
    fs::write(out, code).unwrap();
}
