use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, HtmlCanvasElement, CanvasRenderingContext2d};
use qrcode::QrCode;
use wasm_bindgen::JsValue;
use js_sys::Math::random;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use serde_wasm_bindgen::from_value;
use hex;

const PATTERN_SET: [[[u8; 3]; 3]; 3] = [
    [[1, 0, 1], [0, 1, 0], [1, 0, 1]], // Pattern 1
    [[0, 1, 0], [1, 0, 1], [0, 1, 0]], // Pattern 2
    [[1, 1, 0], [0, 1, 0], [0, 1, 1]], // Pattern 3
];


#[wasm_bindgen]
pub async fn verify_domain_and_display_qr() -> Result<(), JsValue> {
    let window = web_sys::window().unwrap();
    let document = window.document().expect("Should have a document on window");

    // Create a canvas element for QR code rendering
    let body = document.body().expect("Document should have a body");
    let canvas: HtmlCanvasElement = document
        .create_element("canvas")?
        .dyn_into::<HtmlCanvasElement>()?;
    canvas.set_width(300);
    canvas.set_height(300);
    body.append_child(&canvas)?;

    let ctx: CanvasRenderingContext2d = canvas
        .get_context("2d")?
        .unwrap()
        .dyn_into::<CanvasRenderingContext2d>()?;

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init("http://localhost:8000/verify-domain", &opts)?;
    let response: Response = JsFuture::from(window.fetch_with_request(&request)).await?.dyn_into()?;

    let json = JsFuture::from(response.json()?).await?;
    web_sys::console::log_1(&format!("Response JSON: {:?}", json).into());

    let payload: serde_json::Value = from_value(json).map_err(|_| JsValue::from_str("Failed to deserialize JSON"))?;
    // Convert the payload to a string
    let payload_str = payload.to_string();
    // Log the payload string to the console
    web_sys::console::log_1(&format!("Payload: {}", payload_str).into());

    let message = payload["payload"].as_str().ok_or(JsValue::from_str("Missing payload"))?;
    let public_key_b64 = payload["public_key"].as_str().ok_or(JsValue::from_str("Missing public_key"))?;
    let signature_b64 = payload["signature"].as_str().ok_or(JsValue::from_str("Missing signature"))?;

    web_sys::console::log_1(&format!("Received Public Key (Base64): {}", public_key_b64).into());
    web_sys::console::log_1(&format!("Received Signature (Base64): {}", signature_b64).into());
    web_sys::console::log_1(&format!("Received Payload: {}", message).into());

    let public_key_bytes = STANDARD.decode(public_key_b64).map_err(|_| JsValue::from_str("Failed to decode public key"))?;
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_bytes)
        .map_err(|_| JsValue::from_str("Invalid public key"))?;

    let signature_bytes = STANDARD.decode(signature_b64).map_err(|_| JsValue::from_str("Failed to decode signature"))?;
    let signature = p256::ecdsa::Signature::from_der(&signature_bytes)
        .map_err(|_| JsValue::from_str("Invalid signature format"))?;

    // Convert signature bytes to a hex string for logging
    let signature_hex = hex::encode(&signature_bytes);
    web_sys::console::log_1(&format!("Signature (Hex): {}", signature_hex).into());

    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return Err(JsValue::from_str("Signature verification failed"));
    } else {
        web_sys::console::log_1(&format!("Signature verification passed").into());
    }

    let code = QrCode::new(&message).unwrap();
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
        let index = (random() * 3.0) as usize; // Rotate between 3 patterns
        let pattern = PATTERN_SET[index];
    
        draw_center_pattern(&ctx, pattern);
    }) as Box<dyn FnMut()>);
    
    window.set_interval_with_callback_and_timeout_and_arguments_0(closure.as_ref().unchecked_ref(), 1000)?;
    
    closure.forget();

    let text_element = document.create_element("p")?.dyn_into::<web_sys::HtmlElement>()?;
    text_element.set_inner_html(&format!("QR Code Payload:<br><code>{}</code>", message));
    body.append_child(&text_element)?;

    Ok(())
}


fn draw_center_pattern(ctx: &CanvasRenderingContext2d, pattern: [[u8; 3]; 3]) {

    let bg_pattern_size = 90.0;
    let bg_start_x = 105.0;
    let bg_start_y = 105.0;

    let pattern_size = 80.0;
    let start_x = 110.0;
    let start_y = 110.0;
    let cell_size = pattern_size / 3.0;

    // Draw the white background
    ctx.set_fill_style_str("white");
    ctx.fill_rect(bg_start_x, bg_start_y, bg_pattern_size, bg_pattern_size);

    for i in 0..3 {
        for j in 0..3 {
            let color = if pattern[i][j] == 1 { "black" } else { "white" };
            ctx.set_fill_style_str(color);
            ctx.fill_rect(
                start_x + (j as f64 * cell_size),
                start_y + (i as f64 * cell_size),
                cell_size,
                cell_size,
            );
        }
    }
}
