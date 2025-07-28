use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, HtmlCanvasElement, CanvasRenderingContext2d, HtmlElement};
use qrcode::{QrCode, EcLevel};
use wasm_bindgen::JsValue;
use js_sys::Math::random;

const SERVER_URL: &str = "http://localhost:8000/verify-domain";

// Hardcoded shifting patterns (3x3 grid, 1 = Black, 0 = White)
const PATTERN_SET: [[[u8; 3]; 3]; 3] = [
    [[1, 0, 1], [0, 1, 0], [1, 0, 1]], // Pattern 1
    [[0, 1, 0], [1, 0, 1], [0, 1, 0]], // Pattern 2
    [[1, 1, 0], [0, 1, 0], [0, 1, 1]], // Pattern 3
];

#[wasm_bindgen]
pub async fn generate_qr_with_shifting_pattern() -> Result<(), JsValue> {
    console_error_panic_hook::set_once(); // Enable better debugging

    let window = web_sys::window().ok_or("No window found")?;
    let document = window.document().ok_or("No document found")?;

    // ✅ Create Canvas for QR Code
    let body = document.body().ok_or("Document should have a body")?;
    let canvas: HtmlCanvasElement = document
        .create_element("canvas")?
        .dyn_into::<HtmlCanvasElement>()?;
    canvas.set_width(300);
    canvas.set_height(300);
    body.append_child(&canvas)?;

    let ctx: CanvasRenderingContext2d = canvas
        .get_context("2d")?
        .ok_or("Failed to get 2D context")?
        .dyn_into::<CanvasRenderingContext2d>()?;

    // ✅ Create Text Element to Show QR Payload
    let qr_text: HtmlElement = document
        .create_element("div")?
        .dyn_into::<HtmlElement>()?;
    qr_text.set_inner_text("Fetching QR payload...");
    body.append_child(&qr_text)?;

    // ✅ Fetch QR payload from server
    let qr_payload = fetch_qr_payload().await?;
    qr_text.set_inner_text(&qr_payload); // Update text display

    // ✅ Generate QR Code with High Error Correction (H)
    let code = QrCode::with_error_correction_level(&qr_payload, EcLevel::H)
        .map_err(|_| JsValue::from_str("QR code generation failed"))?;

    // ✅ Draw QR Code
    ctx.clear_rect(0.0, 0.0, 300.0, 300.0);
    let scale = 300.0 / code.width() as f64;

    for (y, row) in code.to_colors().chunks(code.width() as usize).enumerate() {
        for (x, &color) in row.iter().enumerate() {
            if color == qrcode::Color::Dark {
                ctx.fill_rect(x as f64 * scale, y as f64 * scale, scale, scale);
            }
        }
    }

    // ✅ Function to update the **center pattern** every 1 second
    let ctx_clone = ctx.clone();
    let text_clone = qr_text.clone();
    let closure = Closure::wrap(Box::new(move || {
        let index = (random() * 3.0) as usize; // Rotate between 3 patterns
        let pattern = PATTERN_SET[index];

        draw_center_pattern(&ctx_clone, pattern);
        text_clone.set_inner_text(&format!("QR Data (Pattern {}): {}", index + 1, qr_payload));
    }) as Box<dyn FnMut()>);

    window.set_interval_with_callback_and_timeout_and_arguments_0(
        closure.as_ref().unchecked_ref(),
        1000 // Update every **1 second**
    )?;

    closure.forget();

    Ok(())
}

// ✅ Fetch QR Payload from Server
async fn fetch_qr_payload() -> Result<String, JsValue> {
    let window = web_sys::window().ok_or("No window found")?;

    let request = Request::new_with_str_and_init(SERVER_URL, &RequestInit::new().method("GET").mode(RequestMode::Cors))?;
    let response: Response = JsFuture::from(window.fetch_with_request(&request)).await?.dyn_into()?;

    if response.status() == 200 {
        let json = JsFuture::from(response.json()?).await?;
        let payload = js_sys::JSON::stringify(&json)
            .map_err(|_| JsValue::from_str("Failed to parse JSON"))?
            .as_string()
            .ok_or("Invalid JSON")?;
        Ok(payload)
    } else {
        Err(JsValue::from_str("Failed to fetch QR payload"))
    }
}

// ✅ Draws the **center shifting pattern** inside the reserved area
fn draw_center_pattern(ctx: &CanvasRenderingContext2d, pattern: [[u8; 3]; 3]) {
    let pattern_size = 90.0;
    let start_x = 105.0;
    let start_y = 105.0;
    let cell_size = pattern_size / 3.0;

    for i in 0..3 {
        for j in 0..3 {
            let color = if pattern[i][j] == 1 { "black" } else { "white" };
            ctx.set_fill_style(&JsValue::from_str(color));
            ctx.fill_rect(
                start_x + (j as f64 * cell_size),
                start_y + (i as f64 * cell_size),
                cell_size,
                cell_size,
            );
        }
    }
}
