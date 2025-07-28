use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsValue;
use p256::{PublicKey, ecdh::EphemeralSecret};
use rand_core::OsRng;
use web_sys::{Request};
use wasm_bindgen::JsCast;
use std::sync::OnceLock;
use js_sys::Promise;
use web_sys::RequestMode;
use web_sys::RequestInit;
use js_sys::eval;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hkdf::HKDF_SHA256;
use ring::hkdf::Algorithm;
use ring::hkdf::Okm;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::Nonce;
use aes_gcm::Aes256Gcm;
use rand_core::RngCore;


pub static FEATURES: OnceLock<HashMap<String, bool>> = OnceLock::new();
pub static PRIVATE_KEY: OnceLock<EphemeralSecret> = OnceLock::new();
pub static PUBLIC_KEY: OnceLock<PublicKey> = OnceLock::new();
pub static SEK: OnceLock<String> = OnceLock::new();

/// Initializes the key pair only once
pub fn generate_keypair() {
    let private = EphemeralSecret::random(&mut OsRng);
    let public = PublicKey::from(&private);

    PRIVATE_KEY.set(private).unwrap_or_else(|_| panic!("Private key was already set"));
    PUBLIC_KEY.set(public).unwrap_or_else(|_| panic!("Public key was already set"));
}

/// Gets the public key (panics if not initialized)
pub fn get_public_key() -> &'static PublicKey {
    PUBLIC_KEY.get().expect("Public key not initialized")
}

/// Gets the private key (panics if not initialized)
pub fn get_private_key() -> &'static EphemeralSecret {
    PRIVATE_KEY.get().expect("Private key not initialized")
}

pub fn get_sek() -> &'static String {
    SEK.get().expect("SEK not initialized")
}

pub fn set_sek(sek: String) {
    let sanitized = sanitize_base64(&sek);
    log_debug(&format!("Setting SEK: {:?}", sanitized));
    SEK.set(sanitized).expect("SEK already initialized");
}

pub fn sanitize_base64(ciphertext_b64: &str) -> String {
    let trimmed = ciphertext_b64.trim_matches('"');
    let sanitized: String = trimmed.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();   
    sanitized
}

pub fn initialize_features() {
    let features_json = env!("FEATURES_JSON");
    let parsed_features: HashMap<String, bool> = serde_json::from_str(features_json)
        .expect("Failed to parse features JSON");

    FEATURES.set(parsed_features).expect("FEATURES already initialized");
}

pub fn is_feature_enabled(feature: &str) -> bool {
    FEATURES.get()
        .and_then(|features| features.get(feature).copied())
        .unwrap_or(false)
}

pub fn generate_sek(server_pk_b64: String) -> Result<String, JsValue> {
    log_debug(&format!("Public Key (Server Base64): {}", server_pk_b64));
    let server_pk_bytes = STANDARD.decode(server_pk_b64)
        .map_err(|_| JsValue::from_str("Failed to decode server public key"))?;
    let server_pk = PublicKey::from_sec1_bytes(&server_pk_bytes)
        .map_err(|_| JsValue::from_str("Invalid server public key"))?;
    
    // Compute shared secret
    let private_key = get_private_key();
    let shared_secret = private_key.diffie_hellman(&server_pk);
    
    // Derive SEK using HKDF
    let shared_secret_encoded = STANDARD.encode(shared_secret.raw_secret_bytes());
    let sanitized_shared_secret = sanitize_base64(&shared_secret_encoded);
    log_debug(&format!("Shared Secret (Client Base64): {}", sanitized_shared_secret));
    
    let sek = derive_sek(shared_secret.raw_secret_bytes().as_slice())
        .map_err(|_| JsValue::from_str("Failed to derive SEK"))?;

    // Encode SEK in Base64
    let sek_b64 = STANDARD.encode(sek);
    log_debug(&format!("Session Encryption Key (SEK) (Base64): {}", sek_b64));

    // Store SEK in global state
    set_sek(sek_b64.clone());
    
    // Return the SEK
    Ok(sek_b64)
}

fn derive_sek(shared_secret: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared_secret);

    let info: &[&[u8]] = &[b"session encryption key"]; // Correct info
    let output_key_material: Okm<Algorithm> = prk.expand(info, HKDF_SHA256)?;

    let mut result = [0u8; SHA256_OUTPUT_LEN];
    output_key_material.fill(&mut result)?;

    Ok(result.to_vec())
}

pub fn verify_signature(payload: &str, public_key_b64: &str, signature_b64: &str) -> Result<bool, JsValue> {
    let public_key_bytes = STANDARD.decode(public_key_b64).map_err(|_| JsValue::from_str("Failed to decode public key"))?;
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_bytes)
        .map_err(|_| JsValue::from_str("Invalid public key"))?;

    let signature_bytes = STANDARD.decode(signature_b64).map_err(|_| JsValue::from_str("Failed to decode signature"))?;
    let signature = p256::ecdsa::Signature::from_der(&signature_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature format"))?;

    log_debug(&format!("Public Key (Server Base64): {}", public_key_b64));
    log_debug(&format!("Signature (Base64): {}", signature_b64));
    log_debug(&format!("Data to Verify: {}", payload));

    if verifying_key.verify(payload.as_bytes(), &signature).is_err() {
        log_debug("Signature verification failed");
        Ok(false)  // Return Result<bool, JsValue>
    } else {
        log_debug("Signature verification passed");
        Ok(true)   // Return Result<bool, JsValue>
    }
}

pub async fn fetch(endpoint: &str, method: &str, body: &str) -> Result<JsValue, JsValue> {
    let window = web_sys::window().expect("No window object found");
    
    let opts = RequestInit::new();
    opts.set_method(method);
    opts.set_mode(RequestMode::Cors);
    
    // Only set body for non-GET requests
    if method != "GET" && !body.is_empty() {
        opts.set_body(&JsValue::from_str(body));
    }

    let request = Request::new_with_str_and_init(
        &format!("{}{}", get_server_url(), endpoint), 
        &opts
    )?;

    request.headers().set("Content-Type", "application/json")?;
    if is_feature_enabled("pinned_secret") {
        request.headers().set("X-WASM-Auth", &get_pinned_secret_hash())?;
    }

    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let response: web_sys::Response = resp_value.dyn_into()?;

    // Check response status
    let status = response.status();
    if status < 200 || status >= 300 {
        let text = JsFuture::from(response.text()?).await?;
        return Err(JsValue::from_str(&format!(
            "HTTP error! status: {}, body: {}", 
            status,
            text.as_string().unwrap_or_default()
        )));
    }

    // Get text first
    let text = JsFuture::from(response.text()?).await?;
    let text_str = text.as_string()
        .ok_or_else(|| JsValue::from_str("Response was not valid text"))?;

    // Convert to JsValue
    Ok(JsValue::from_str(&text_str))
}

pub async fn fetch_e2ee(endpoint: &str, method: &str, body: &str) -> Result<JsValue, JsValue> {
    log_debug(&format!("Fetching E2EE with endpoint: {}, method: {}, body: {}", endpoint, method, body));
    if !SEK.get().is_some() {
        let public_key = get_public_key();
        let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        let public_key_b64 = STANDARD.encode(&public_key_bytes);
        log_debug(&format!("Public Key (Client Base64): {}", public_key_b64));
    
        log_debug(&format!("Fetching exchange-public-key with client_pk: {}", public_key_b64));
        let json = fetch(&format!("/exchange-public-key?client_pk={}", public_key_b64), "GET", "").await?;
        
        // Convert JsValue to serde_json::Value
        let json_str = json.as_string()
            .ok_or_else(|| JsValue::from_str("Response was not valid text"))?;
        let json_value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;
        
        // Now we can safely index into json_value
        let server_pk = json_value["server_pk"].as_str()
            .ok_or_else(|| JsValue::from_str("Missing server_pk"))?;

        generate_sek(server_pk.to_string())?;
    }
    
    // Now make the actual request with encryption
    let encrypted_body = encrypt_message(&get_sek(), body)?;
    let encrypted_str = encrypted_body.as_string()
        .ok_or_else(|| JsValue::from_str("Failed to convert encrypted body to string"))?;
    
    // Create the JSON payload
    let mut payload = serde_json::Map::new();
    payload.insert("encrypted_payload".to_string(), serde_json::Value::String(encrypted_str));
    
    // Log the payload before sending
    log_debug(&format!("Payload: {}", serde_json::to_string(&payload).unwrap_or_default()));
    
    // Convert the payload to a JSON string
    let json_str = serde_json::to_string(&payload)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize payload: {}", e)))?;
    
    let json = fetch(endpoint, method, &json_str).await?;
    let json_str = json.as_string()
        .ok_or_else(|| JsValue::from_str("Response was not valid text"))?;
    
    let response_json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse response JSON: {}", e)))?;
    
    // Extract the encrypted payload
    let encrypted_payload = response_json["encrypted_payload"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing encrypted_payload in response"))?;
    
    // Decrypt the payload
    let decrypted_json = decrypt_message(&get_sek(), encrypted_payload)?;
    
    // Log for debugging (using {:?} for Debug formatting)
    log_debug(&format!("Decrypted JSON: {:?}", decrypted_json));
    
    Ok(decrypted_json)
}

pub fn get_pinned_secret_hash() -> String {
    let secret_hash = env!("PINNED_SECRET_HASH");
    secret_hash.to_string()
}

pub fn get_allowed_domains() -> Vec<String> {
    let domains = env!("ALLOWED_DOMAINS"); // Read the injected build-time variable
    log_debug(&format!("Allowed Domains: {:?}", domains));
    domains.split(',').map(|s| s.to_string()).collect()
}

pub fn get_current_domain() -> String {
    let window = web_sys::window().expect("No window object found");
    let hostname = window.location().host().expect("Could not get hostname");
    log_debug(&format!("Hostname: {:?}", hostname));
    hostname
}

pub fn is_domain_allowed(domain: &str) -> bool {
    let result = get_allowed_domains().contains(&domain.to_string());
    log_debug(&format!("Domain allowed: {:?}", result));
    result
}

// Update the SERVER_URL to be a function instead of a constant
pub fn get_server_url() -> String {
    let window = web_sys::window().expect("No window object found");
    let hostname = window.location().origin().expect("Could not get hostname");
    hostname
}

#[cfg(feature = "debug_logs")]
pub fn log_debug(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

#[cfg(not(feature = "debug_logs"))]
pub fn log_debug(_: &str) {
    // No-op in release builds
}

pub fn encrypt_message(sek_b64: &str, plaintext: &str) -> Result<JsValue, JsValue> {
    let sek_bytes = STANDARD.decode(sek_b64).map_err(|_| JsValue::from_str("Invalid SEK base64"))?;
    let key = GenericArray::from_slice(&sek_bytes);
    let cipher = Aes256Gcm::new(key);
    
    log_debug(&format!("Encrypting message: {:?}, with SEK: {:?}", plaintext, sek_b64));
    // Generate random nonce using RngCore trait
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| JsValue::from_str("Encryption failed"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(JsValue::from_str(&STANDARD.encode(combined)))
}


pub fn decrypt_message(sek_b64: &str, ciphertext_b64: &str) -> Result<JsValue, JsValue> {
    // Decode SEK
    let sek_bytes = STANDARD.decode(sek_b64).map_err(|_| JsValue::from_str("Invalid SEK base64"))?;
    let key = GenericArray::from_slice(&sek_bytes);
    let cipher = Aes256Gcm::new(key);

    // Decode the ciphertext
    let sanitized = sanitize_base64(ciphertext_b64);
    let decoded = STANDARD.decode(&sanitized).map_err(|e| {
        log_debug(&format!("Base64 decode error: {}", e));
        JsValue::from_str("Invalid ciphertext base64")
    })?;

    // Ensure that decoded ciphertext length is at least (nonce + tag) size
    if decoded.len() < 28 {
        return Err(JsValue::from_str("Ciphertext too short"));
    }

    // Extract nonce (12 bytes), ciphertext, and authentication tag (16 bytes)
    let (nonce_bytes, rest) = decoded.split_at(12);
    let (ciphertext, tag_bytes) = rest.split_at(rest.len() - 16);
    
    let nonce = Nonce::from_slice(nonce_bytes); // Nonce should be correct
    
    
    let mut full_ciphertext = Vec::from(ciphertext);
    full_ciphertext.extend_from_slice(tag_bytes);


    let nonce_b64 = STANDARD.encode(nonce);
    let ciphertext_b64 = STANDARD.encode(&full_ciphertext);
    let tag_b64 = STANDARD.encode(tag_bytes);

    // Log the extracted components
    log_debug(&format!("Nonce (Base64): {}", nonce_b64));
    log_debug(&format!("Tag (Base64): {}", tag_b64));
    log_debug(&format!("Ciphertext (Base64): {}", STANDARD.encode(ciphertext_b64)));

    // Attempt decryption
    match cipher.decrypt(nonce, full_ciphertext.as_ref()) {
        Ok(plaintext) => {
            log_debug(&format!("Decrypted Text: {:?}", String::from_utf8_lossy(&plaintext)));
            Ok(JsValue::from_str(&String::from_utf8_lossy(&plaintext)))
        },
        Err(e) => {
            log_debug(&format!("Decryption failed: {:?}", e));
            Err(JsValue::from_str("Decryption failed"))
        }
    }
}


// Internal function to execute JavaScript dynamically
pub fn execute_js_code(js_code: &str) -> Result<JsValue, JsValue> {
    let _win = web_sys::window().ok_or_else(|| JsValue::from_str("No global `window` found"))?;
    let result = eval(js_code)?;
    Ok(result)
}

pub async fn create_indexeddb_store(db_name: &str, store_name: &str) -> Result<(), JsValue> {
    let js_code = format!(
        r#"
        (async function() {{
            return new Promise((resolve, reject) => {{
                let versionRequest = indexedDB.open("{db_name}");

                versionRequest.onerror = () => reject("IndexedDB error");

                versionRequest.onsuccess = function(event) {{
                    let db = event.target.result;

                    // If the object store already exists, resolve immediately
                    if (db.objectStoreNames.contains("{store_name}")) {{
                        console.log("Object store '{store_name}' already exists.");
                        db.close();
                        resolve("Store already exists.");
                        return;
                    }}

                    // Otherwise, increase the version to trigger onupgradeneeded
                    let newVersion = db.version + 1;
                    db.close();
                    let upgradeRequest = indexedDB.open("{db_name}", newVersion);

                    upgradeRequest.onupgradeneeded = function(event) {{
                        let upgradeDb = event.target.result;
                        if (!upgradeDb.objectStoreNames.contains("{store_name}")) {{
                            upgradeDb.createObjectStore("{store_name}", {{ keyPath: "id" }});
                            console.log("Created object store: {store_name} (Key as string)");
                        }}
                    }};

                    upgradeRequest.onsuccess = function() {{
                        resolve("Database and object store checked/created successfully.");
                    }};
                    
                    upgradeRequest.onerror = () => reject("Error upgrading IndexedDB.");
                }};
            }});
        }})()
        "#
    );

    let promise: Promise = execute_js_code(&js_code)?.into();
    JsFuture::from(promise).await?;
    Ok(())
}

pub async fn insert_into_indexeddb(db_name: &str, store_name: &str, key: &str, value: &str) -> Result<(), JsValue> {
    let js_code = format!(
        r#"
        (async function() {{
            return new Promise((resolve, reject) => {{
                let request = indexedDB.open("{db_name}");

                request.onerror = () => reject("IndexedDB error");
                request.onsuccess = function() {{
                    let db = request.result;
                    if (!db.objectStoreNames.contains("{store_name}")) {{
                        reject("Object store '{store_name}' does not exist.");
                        return;
                    }}

                    let transaction = db.transaction("{store_name}", "readwrite");
                    let store = transaction.objectStore("{store_name}");
                    let putRequest = store.put({{ id: "{key}", value: "{value}" }});

                    putRequest.onsuccess = () => resolve("Inserted successfully.");
                    putRequest.onerror = () => reject("Error inserting into IndexedDB");
                }};
            }});
        }})()
        "#
    );

    let promise: Promise = execute_js_code(&js_code)?.into();
    JsFuture::from(promise).await?;
    Ok(())
}

// 🔹 Function to remove a key from IndexedDB
#[wasm_bindgen]
pub async fn remove_from_indexeddb(db_name: &str, store_name: &str, key: &str) -> Result<(), JsValue> {
    let js_code = format!(
        r#"
        (async function() {{
            return new Promise((resolve, reject) => {{
                let request = indexedDB.open("{db_name}");

                request.onerror = () => reject("IndexedDB error");
                request.onsuccess = function() {{
                    let db = request.result;
                    if (!db.objectStoreNames.contains("{store_name}")) {{
                        reject("Object store '{store_name}' does not exist.");
                        return;
                    }}

                    let transaction = db.transaction("{store_name}", "readwrite");
                    let store = transaction.objectStore("{store_name}");
                    let deleteRequest = store.delete("{key}");

                    deleteRequest.onsuccess = () => resolve("Deleted successfully.");
                    deleteRequest.onerror = () => reject("Error deleting from IndexedDB");
                }};
            }});
        }})()
        "#
    );

    let promise: Promise = execute_js_code(&js_code)?.into();
    JsFuture::from(promise).await?;
    Ok(())
}

pub async fn read_from_indexeddb(db_name: &str, store_name: &str, key: &str) -> Result<JsValue, JsValue> {
    let js_code = format!(
        r#"
        (async function() {{
            return new Promise((resolve, reject) => {{
                let request = indexedDB.open("{db_name}");

                request.onerror = () => reject("IndexedDB error");
                request.onsuccess = function() {{
                    let db = request.result;
                    if (!db.objectStoreNames.contains("{store_name}")) {{
                        reject("Object store '{store_name}' not found.");
                        return;
                    }}

                    let transaction = db.transaction("{store_name}", "readonly");
                    let store = transaction.objectStore("{store_name}");
                    let getRequest = store.get("{key}");

                    getRequest.onsuccess = () => {{
                        if (getRequest.result) {{
                            resolve(getRequest.result.value);
                        }} else {{
                            reject("Key '{key}' not found in IndexedDB.");
                        }}
                    }};
                    getRequest.onerror = () => reject("Error reading IndexedDB");
                }};
            }});
        }})()
        "#
    );

    let promise: Promise = execute_js_code(&js_code)?.into();
    let result = JsFuture::from(promise).await?;
    Ok(result)
}


