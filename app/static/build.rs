use std::fs;
use std::env;
use std::path::Path;
use rand::Rng;
use sha2::{Sha256, Digest};
use toml::Value;
use std::collections::HashMap;
use serde_json;

const SECRET_FILE_NAME: &str = "secret.txt";

fn main() {
    // Generate a random secret key
    let secret_key: [u8; 32] = rand::thread_rng().gen();

    // Hash the secret key to derive a verification token
    let mut hasher = Sha256::new();
    hasher.update(&secret_key);
    let verification_hash = hasher.finalize();

    // Convert to hex
    let secret_hex = hex::encode(secret_key);
    let hash_hex = hex::encode(verification_hash);

    // Store the key as an environment variable for build-time embedding
    println!("cargo:rustc-env=PINNED_SECRET={}", secret_hex);
    println!("cargo:rustc-env=PINNED_SECRET_HASH={}", hash_hex);

    // Also write to a file for server-side validation if needed
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join(SECRET_FILE_NAME);
    println!("cargo:warning=OUT_DIR is set to: {}", out_dir);
    fs::write(
        &dest_path,
        format!(
            "{{\n  \"PINNED_SECRET\": \"{}\",\n  \"PINNED_SECRET_HASH\": \"{}\"\n}}",
            secret_hex, hash_hex
        ),
    )
    .unwrap();

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");

    // Define where the WASM files are deployed
    let wasm_deploy_dir = Path::new(&manifest_dir)
        .join("pkg");

    // Define the final path inside the WASM deployment directory
    let final_dest = wasm_deploy_dir.join(SECRET_FILE_NAME);

    // Move or copy the file to the deployment directory
    fs::rename(&dest_path, &final_dest).expect("Failed to move the file");

    let cargo_toml = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");
    
    // Read and parse Cargo.toml
    let cargo_toml_content = fs::read_to_string(&cargo_toml).expect("Failed to read Cargo.toml");
    let cargo_toml: Value = cargo_toml_content.parse().expect("Failed to parse Cargo.toml");

    let metadata = cargo_toml.get("package")
        .and_then(|pkg| pkg.get("metadata"))
        .and_then(|metadata| metadata.get("wasm"))
        .expect("Missing package.metadata.wasm section");

    // Create a JSON object of features
    let mut features_map = HashMap::new();

    let features = [
        "local_domain_check",
        "server_verification",
        "same_network_check",
        "static_qr_code",
        "dynamic_qr_code",
        "pinned_secret",
        "e2e_encryption",
        "digital_signature_verification",
        "digital_receipts",
        "physical_signature",
        "browser_identity_key",
        "third_party_confirm",
        "user_agent_fingerprint",
        "utc_timecode_check",
    ];

    for &feature in &features {
        let enabled = metadata.get(feature)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        features_map.insert(feature, enabled);
    }

    // Convert to JSON string
    let features_json = serde_json::to_string(&features_map)
        .expect("Failed to serialize features");

    // Inject as environment variable
    println!("cargo:rustc-env=FEATURES_JSON={}", features_json);

    // Extract allowed domains from `package.metadata.wasm`
    let allowed_domains = cargo_toml
        .get("package")
        .and_then(|pkg| pkg.get("security"))
        .and_then(|security| security.get("wasm"))
        .and_then(|wasm| wasm.get("allowed_domains"))
        .and_then(|domains| domains.as_str())
        .unwrap_or("localhost:8000"); // Default value if missing

    // Set the allowed domains as an environment variable
    println!("cargo:rustc-env=ALLOWED_DOMAINS={}", allowed_domains);

    // Tell Cargo to re-run if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}
