use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, HtmlCanvasElement, CanvasRenderingContext2d};
use qrcode::QrCode;
use wasm_bindgen::JsValue;
use js_sys::Math::random;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use serde_wasm_bindgen::from_value;
use serde_json::Value;
use hex;
use p256::{PublicKey, ecdh::EphemeralSecret};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng; // Requires rand_core crate
use aes_gcm::Aes256Gcm; // Or another AES variant
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::Nonce; // 96-bits; unique per message
use std::cell::RefCell;
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hkdf::HKDF_SHA256;
use ring::hkdf::Algorithm;
use ring::hkdf::Okm;
use rand::RngCore;

mod tag36h11;
use tag36h11::TAG36H11_CODES;

//const SERVER_URL: &str = "http://localhost:8000";
//const SERVER_URL: &str = "https://devide.io";
const SERVER_URL: &str = "https://stronghold-test.onrender.com";

// Define a global variable using RefCell for interior mutability
thread_local! {
    static GLOBAL_SEK: RefCell<Option<String>> = RefCell::new(None);
}

// Import the JavaScript function from the global scope
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = window)]
    fn store_uuid_in_js(uuid: &str);
}

#[wasm_bindgen]
pub async fn verify_domain_and_display_qr() -> Result<(), JsValue> {
    let window = web_sys::window().unwrap();
    let document = window.document().expect("Should have a document on window");

    // Create a canvas element for QR code rendering
    let canvas: HtmlCanvasElement = document
        .create_element("canvas")?
        .dyn_into::<HtmlCanvasElement>()?;
    canvas.set_width(300);
    canvas.set_height(300);

    let container = document.get_element_by_id("qr-container")
                            .expect("QR container does not exist");
    container.append_child(&canvas)?;
    
    let ctx: CanvasRenderingContext2d = canvas
        .get_context("2d")?
        .unwrap()
        .dyn_into::<CanvasRenderingContext2d>()?;

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    match e2ee().await {
        Ok(sek) => {
            // Print the returned key to the console
            web_sys::console::log_1(&format!("Shared Encryption Key (SEK): {:?}", sek).into());

            // Store SEK in global state
            GLOBAL_SEK.with(|global_sek| {
                *global_sek.borrow_mut() = Some(sek.as_string().unwrap());
            });
        }
        Err(err) => {
            // Handle the error, log it, and continue
            web_sys::console::log_1(&format!("Failed to get SEK: {:?}", err).into());
        }
    }

    web_sys::console::log_1(&format!("SEK (Base64): {}", get_global_sek().unwrap()).into());
    

    let request = Request::new_with_str_and_init(&format!("{}/verify-domain", SERVER_URL), &opts)?;
    let response: Response = JsFuture::from(window.fetch_with_request(&request)).await?.dyn_into()?;

    let json = JsFuture::from(response.json()?).await?;
    web_sys::console::log_1(&format!("Response JSON: {:?}", json).into());

    let payload: serde_json::Value = from_value(json).map_err(|_| JsValue::from_str("Failed to deserialize JSON"))?;
    // Convert the payload to a string
    let payload_str = payload.to_string();
    // Log the payload string to the console
    web_sys::console::log_1(&format!("Payload: {}", payload_str).into());

    //let result = debug_base64_decoding(&payload_str);
    //web_sys::console::log_1(&format!("Result: {:?}", result).into());

    let decrypted_payload = decrypt_message(&get_global_sek().unwrap(), &payload_str).unwrap();
    web_sys::console::log_1(&format!("Decrypted Payload: {:?}", decrypted_payload).into());   
    let decrypted_str = decrypted_payload.as_string().ok_or(JsValue::from_str("Failed to convert JsValue to string"))?;

    // Parse the JSON string
    let json_value: Value = serde_json::from_str(&decrypted_str)
        .map_err(|_| JsValue::from_str("Failed to parse decrypted JSON"))?;

    let payload = json_value["payload"].as_str().ok_or(JsValue::from_str("Missing payload"))?;
    let public_key_b64 = json_value["public_key"].as_str().ok_or(JsValue::from_str("Missing public_key"))?;
    let signature_b64 = json_value["signature"].as_str().ok_or(JsValue::from_str("Missing signature"))?;

    web_sys::console::log_1(&format!("Payload: {}", payload).into());
    web_sys::console::log_1(&format!("Public Key: {}", public_key_b64).into());
    web_sys::console::log_1(&format!("Signature: {}", signature_b64).into());

    
    // Decode the public key and signature from Base64
    let public_key_bytes = STANDARD.decode(public_key_b64).map_err(|_| JsValue::from_str("Failed to decode public key"))?;
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_bytes)
        .map_err(|_| JsValue::from_str("Invalid public key"))?;

    let signature_bytes = STANDARD.decode(signature_b64).map_err(|_| JsValue::from_str("Failed to decode signature"))?;
    let signature = p256::ecdsa::Signature::from_der(&signature_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature format"))?;

    web_sys::console::log_1(&format!("Public Key (Server Base64): {}", public_key_b64).into());
    web_sys::console::log_1(&format!("Signature (Base64): {}", signature_b64).into());
    web_sys::console::log_1(&format!("Data to Verify: {}", payload).into());

    if verifying_key.verify(payload.as_bytes(), &signature).is_err() {
        web_sys::console::log_1(&format!("Signature verification failed").into());
        return Err(JsValue::from_str("Signature verification failed"));
    } else {
        web_sys::console::log_1(&format!("Signature verification passed").into());
    }

    let code = QrCode::new(&payload).unwrap();
    ctx.set_fill_style_str("black");
    for (y, row) in code.to_colors().chunks(code.width() as usize).enumerate() {
        for (x, &color) in row.iter().enumerate() {
            if color == qrcode::Color::Dark {
                let scale = 300.0 / code.width() as f64;
                ctx.fill_rect(x as f64 * scale, y as f64 * scale, scale, scale);
            }
        }
    }

    let closure = Closure::wrap(Box::new(move || {
        let random_number = (random() * 587.0).floor() as usize;
        draw_apriltag(&ctx, random_number);
    }) as Box<dyn FnMut()>);
    
    window.set_interval_with_callback_and_timeout_and_arguments_0(closure.as_ref().unchecked_ref(), 100)?;
    
    closure.forget();

    let status_container = document.get_element_by_id("status-container")
    .expect("QR container does not exist");
    let text_element = document.create_element("p")?.dyn_into::<web_sys::HtmlElement>()?;
    text_element.set_inner_html(&format!("QR Code Payload:<br><code>{}</code>", payload));

    status_container.append_child(&text_element)?;

    let payload_value: Value = serde_json::from_str(&payload)
    .map_err(|_| JsValue::from_str("Failed to parse payload JSON"))?;

    let uuid_value = payload_value["uuid"].as_str().ok_or(JsValue::from_str("Missing payload"))?;
    web_sys::console::log_1(&format!("json_value: {}", uuid_value.to_string()).into());

    store_uuid_in_js(uuid_value);

    Ok(())
}

/// The 6x6 bit positions of AprilTag (official mapping)
const BIT_POSITIONS: [(usize, usize); 36] = [
    (1, 1), (2, 1), (3, 1), (4, 1), (5, 1),
    (2, 2), (3, 2), (4, 2), (3, 3),
    (6, 1), (6, 2), (6, 3), (6, 4), (6, 5),
    (5, 2), (5, 3), (5, 4), (4, 3),
    (6, 6), (5, 6), (4, 6), (3, 6), (2, 6),
    (5, 5), (4, 5), (3, 5), (4, 4),
    (1, 6), (1, 5), (1, 4), (1, 3), (1, 2),
    (2, 5), (2, 4), (2, 3), (3, 4),
];

/// Generates a 6x6 AprilTag matrix
fn generate_apriltag_matrix(tag_id: u64) -> [[u8; 6]; 6] {
    let mut matrix = [[0; 6]; 6];

    // Set the 1-pixel-wide border to black (AprilTag convention)
    for i in 0..6 {
        matrix[0][i] = 1;
        matrix[5][i] = 1;
        matrix[i][0] = 1;
        matrix[i][5] = 1;
    }

    // Extract 36-bit pattern and map to 6x6 grid
    for (i, &(x, y)) in BIT_POSITIONS.iter().enumerate() {
        let bit = (tag_id >> (35 - i)) & 1;
        matrix[y - 1][x - 1] = bit as u8;
    }

    matrix
}


pub fn draw_apriltag(ctx: &CanvasRenderingContext2d, tag_index: usize) {
    if tag_index >= TAG36H11_CODES.len() {
        return; // Invalid index
    }

    let tag_id = TAG36H11_CODES[tag_index];
    let matrix = generate_apriltag_matrix(tag_id);

    let start_container_x = 110.0;
    let start_container_y = 110.0;
    let size = 50.0;
    let grid_size = 6; // 6x6 binary grid
    let cell_size = size / grid_size as f64;
    let start_x = start_container_x + cell_size;
    let start_y = start_container_y + cell_size;
    let apriltag_size = size + (cell_size*4.0);

    ctx.set_fill_style_str("white");
    ctx.fill_rect(start_container_x, start_container_y, apriltag_size, apriltag_size);
    ctx.set_line_width(2.0);
    ctx.set_stroke_style_str("black");
    ctx.stroke_rect(start_container_x, start_container_y, apriltag_size, apriltag_size);


    for (i, row) in matrix.iter().enumerate() {
        for (j, &val) in row.iter().enumerate() {
            let color = if val == 1 { "white" } else { "black" };
            ctx.set_fill_style_str(color);
            ctx.fill_rect(
                (start_x + cell_size) + j as f64 * cell_size,
                (start_y + cell_size) + i as f64 * cell_size,
                cell_size,
                cell_size,
            );
        }
    }

    ctx.set_line_width(cell_size);
    ctx.set_stroke_style_str("black");
    ctx.stroke_rect(start_x + (cell_size*0.5), start_y + (cell_size*0.5), size+cell_size, size+cell_size);
}


fn derive_sek(shared_secret: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared_secret);

    web_sys::console::log_1(&format!("Shared secret (raw hex): {}", hex::encode(shared_secret)).into());

    let info: &[&[u8]] = &[b"session encryption key"]; // Correct info
    let output_key_material: Okm<Algorithm> = prk.expand(info, HKDF_SHA256)?;

    let mut result = [0u8; SHA256_OUTPUT_LEN];
    output_key_material.fill(&mut result)?;
    web_sys::console::log_1(&format!("Derived output key material: {}", hex::encode(&result)).into());

    Ok(result.to_vec())
}

pub async fn e2ee() -> Result<JsValue, JsValue> {

    let opts = web_sys::RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(web_sys::RequestMode::Cors);

    // Generate ECDH key pair
    let private_key = EphemeralSecret::random(&mut OsRng);
    let public_key = PublicKey::from(&private_key);
    let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
    let public_key_b64 = STANDARD.encode(&public_key_bytes);
    web_sys::console::log_1(&format!("Public Key (Client Base64): {}", public_key_b64).into());

    // Send public key to server
    let request = Request::new_with_str_and_init(&format!("{}/exchange-public-key?client_pk={}", SERVER_URL, public_key_b64), &opts)?;

    let window = web_sys::window().expect("no global `window` exists");
    let response: Response = JsFuture::from(window.fetch_with_request(&request)).await?.dyn_into()?;
    let json = JsFuture::from(response.json()?).await?;
    web_sys::console::log_1(&format!("Response JSON: {:?}", json).into());


    let response_data: serde_json::Value = serde_wasm_bindgen::from_value(json)?;
    
    // Decode server public key
    let server_pk_b64 = response_data["server_pk"].as_str().ok_or(JsValue::from_str("Missing server public key"))?;
    let server_pk_bytes = STANDARD.decode(server_pk_b64).map_err(|_| JsValue::from_str("Failed to decode server public key"))?;
    let server_pk = PublicKey::from_sec1_bytes(&server_pk_bytes).map_err(|_| JsValue::from_str("Invalid server public key"))?;
    web_sys::console::log_1(&format!("Public Key (Server Base64): {}", server_pk_b64).into());
    
    // Compute shared secret
    let shared_secret = private_key.diffie_hellman(&server_pk);
    web_sys::console::log_1(&format!("Shared Secret (Client Base64): {:?}", STANDARD.encode(shared_secret.raw_secret_bytes())).into());
    
    // Derive SEK using HKDF
    let shared_secret_encoded = STANDARD.encode(shared_secret.raw_secret_bytes());
    let sanitized_shared_secret = sanitize_base64(&shared_secret_encoded);
    web_sys::console::log_1(&format!("Sanitized Shared Secret (Base64): {}", sanitized_shared_secret).into());
//    let sek = Sha256::digest(sanitized_shared_secret.as_bytes());
    
    let sek = derive_sek(shared_secret.raw_secret_bytes().as_slice())
        .map_err(|_| JsValue::from_str("Failed to derive SEK"))?;


    // Encode SEK in Base64
    let sek_b64 = STANDARD.encode(sek);
    web_sys::console::log_1(&format!("SEK (Base64): {}", sek_b64).into());

    // Store SEK in global state
    GLOBAL_SEK.with(|sek| {
        *sek.borrow_mut() = Some(sek_b64.clone());
    });

    Ok(JsValue::from_str(&sek_b64))
}

pub fn get_global_sek() -> Option<String> {
    GLOBAL_SEK.with(|sek| sek.borrow().clone())
}

pub fn encrypt_message(sek_b64: &str, plaintext: &str) -> Result<JsValue, JsValue> {
    let sek_bytes = STANDARD.decode(sek_b64).map_err(|_| JsValue::from_str("Invalid SEK base64"))?;
    let key = GenericArray::from_slice(&sek_bytes);
    let cipher = Aes256Gcm::new(key);
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
    web_sys::console::log_1(&format!("SEK for decryption (Base64): {}", sek_b64).into());

    // Decode SEK
    let sek_bytes = STANDARD.decode(sek_b64).map_err(|_| JsValue::from_str("Invalid SEK base64"))?;
    let key = GenericArray::from_slice(&sek_bytes);
    let cipher = Aes256Gcm::new(key);

    // Decode the ciphertext
    web_sys::console::log_1(&format!("Ciphertext (Base64) before decoding: {}", ciphertext_b64).into());
    let sanitized = sanitize_base64(ciphertext_b64);
    let decoded = STANDARD.decode(&sanitized).map_err(|e| {
        web_sys::console::log_1(&format!("Base64 decode error: {}", e).into());
        JsValue::from_str("Invalid ciphertext base64")
    })?;

    // Ensure that decoded ciphertext length is at least (nonce + tag) size
    if decoded.len() < 28 {
        return Err(JsValue::from_str("Ciphertext too short"));
    }

    // Extract nonce (12 bytes), ciphertext, and authentication tag (16 bytes)
    let (nonce_bytes, rest) = decoded.split_at(12);
    let (tag_bytes, ciphertext) = rest.split_at(16);
    
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let mut full_ciphertext = Vec::from(ciphertext);
    full_ciphertext.extend_from_slice(tag_bytes);


    let nonce_b64 = STANDARD.encode(nonce);
    let ciphertext_b64 = STANDARD.encode(&full_ciphertext);
    let tag_b64 = STANDARD.encode(tag_bytes);

    // Log the extracted components
    web_sys::console::log_1(&format!("Nonce (Base64): {}", nonce_b64).into());
    web_sys::console::log_1(&format!("Ciphertext (Base64): {}", STANDARD.encode(ciphertext_b64)).into());
    web_sys::console::log_1(&format!("Tag (Base64): {}", tag_b64).into());
    web_sys::console::log_1(&format!("SEK bytes (hex): {}", hex::encode(&sek_bytes)).into());
    web_sys::console::log_1(&format!("Nonce bytes (hex): {}", hex::encode(nonce_bytes)).into());
    web_sys::console::log_1(&format!("Ciphertext bytes (hex): {}", hex::encode(&full_ciphertext)).into());
    web_sys::console::log_1(&format!("Tag bytes (hex): {}", hex::encode(tag_bytes)).into());
    web_sys::console::log_1(&format!("Ciphertext Length: {}", ciphertext.len()).into());
    web_sys::console::log_1(&format!("Nonce Length: {}", nonce.len()).into());

    // Attempt decryption
    match cipher.decrypt(nonce, full_ciphertext.as_ref()) {
        Ok(plaintext) => {
            web_sys::console::log_1(&format!("Decrypted Text: {:?}", String::from_utf8_lossy(&plaintext)).into());
            Ok(JsValue::from_str(&String::from_utf8_lossy(&plaintext)))
        },
        Err(e) => {
            web_sys::console::error_1(&format!("Decryption failed: {:?}", e).into());
            Err(JsValue::from_str("Decryption failed"))
        }
    }
}

pub fn sanitize_base64(ciphertext_b64: &str) -> String {
    let sanitized: String = ciphertext_b64.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    
    sanitized
}
