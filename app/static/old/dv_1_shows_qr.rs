use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, HtmlCanvasElement, CanvasRenderingContext2d};
use qrcode::QrCode;
use js_sys::{Object, Reflect};

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

    // Convert response body to JSON
    let json = JsFuture::from(response.json()?).await?;
    let json_obj: Object = json.dyn_into()?;

    // Extract fields
    let uuid = Reflect::get(&json_obj, &JsValue::from_str("uuid"))?
        .as_string()
        .unwrap_or_else(|| "unknown_uuid".to_string());

    let timestamp = Reflect::get(&json_obj, &JsValue::from_str("timestamp"))?
        .as_f64()
        .unwrap_or(0.0) as u64;

    let signature = Reflect::get(&json_obj, &JsValue::from_str("signature"))?
        .as_string()
        .unwrap_or_else(|| "no_signature".to_string());

    // Format extracted data for QR code
    let qr_payload = format!(
        "{{\"uuid\": \"{}\", \"timestamp\": {}, \"signature\": \"{}\"}}",
        uuid, timestamp, signature
    );

    // Generate QR code from extracted JSON data
    let code = QrCode::new(qr_payload).unwrap();

    // Draw QR code onto the canvas
    ctx.set_fill_style(&JsValue::from_str("black"));
    
    for (y, row) in code.to_colors().chunks(code.width() as usize).enumerate() {
        for (x, &color) in row.iter().enumerate() {
            if color == qrcode::Color::Dark {
                let scale = 300.0 / code.width() as f64;
                ctx.fill_rect(x as f64 * scale, y as f64 * scale, scale, scale);
            }
        }
    }

    Ok(())
}
