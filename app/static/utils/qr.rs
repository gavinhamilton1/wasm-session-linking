use crate::utils::tag36h11::TAG36H11_CODES;
use urlencoding;
use qrcode::QrCode;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{HtmlCanvasElement, CanvasRenderingContext2d};
use js_sys::Math::random;
use wasm_bindgen::JsValue;

const CANVAS_SIZE: u32 = 200;

pub fn render_qr_code(payload_str: &str, domain: &str) -> Result<bool, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
    let document = window.document().ok_or_else(|| JsValue::from_str("No document found"))?;

    let canvas: HtmlCanvasElement = document
    .create_element("canvas")?
    .dyn_into::<HtmlCanvasElement>()?;
    canvas.set_width(CANVAS_SIZE);
    canvas.set_height(CANVAS_SIZE);

    let container = document.get_element_by_id("qr-container")
                        .expect("QR container does not exist");
    container.append_child(&canvas)?;

    let ctx: CanvasRenderingContext2d = canvas
        .get_context("2d")?
        .unwrap()
        .dyn_into::<CanvasRenderingContext2d>()?;

    let payload = serde_json::to_string(&payload_str).unwrap();
    let payload = format!("https://{}/m?data={}", &domain, urlencoding::encode(&payload));
    let code = QrCode::new(&payload.to_string()).unwrap();
    ctx.set_fill_style_str("black");
    for (y, row) in code.to_colors().chunks(code.width() as usize).enumerate() {
        for (x, &color) in row.iter().enumerate() {
            if color == qrcode::Color::Dark {
                let scale = CANVAS_SIZE as f64 / code.width() as f64;
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
    //text_element.set_inner_html(&format!("QR Code Payload:<br><code>{}</code>", payload));

    status_container.append_child(&text_element)?;

        Ok(true)  // Return true if everything succeeded
}

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

    
    let start_container_x = (CANVAS_SIZE as f64 / 3.0) * 1.1;
    let start_container_y = start_container_x;
    let size = CANVAS_SIZE as f64 / 6.0;
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