use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn collect(root: &Path, directory: &Path, files: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(directory).expect("read built web UI") {
        let path = entry.expect("web UI entry").path();
        if path.is_dir() {
            collect(root, &path, files);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .expect("UTF-8 asset path")
                .replace('\\', "/");
            files.push((name, path));
        }
    }
}
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut files = Vec::new();
    if env::var_os("CARGO_FEATURE_BUNDLED_UI").is_some() {
        let root = Path::new(&env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("../../target/local-web-ui")
            .canonicalize()
            .expect("run npm run web:build in apps/desktop before building bundled-ui");
        assert!(
            root.join("index.html").is_file(),
            "missing built index.html"
        );
        println!("cargo:rerun-if-changed={}", root.display());
        collect(&root, &root, &mut files);
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut source = String::from("pub static BUNDLED: &[(&str, &[u8])] = &[\n");
    for (name, path) in files {
        source.push_str(&format!(
            "({name:?}, include_bytes!({:?})),\n",
            path.to_str().unwrap()
        ));
    }
    source.push_str("];\n");
    fs::write(
        Path::new(&env::var_os("OUT_DIR").unwrap()).join("web_assets.rs"),
        source,
    )
    .unwrap();
}
