mod utils;
use crate::utils::common::*; 
use crate::utils::qr::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use serde_wasm_bindgen::from_value;
use serde_json::Value;
use uuid::Uuid;

const DB_NAME: &str = "devide"; 
const STORE_NAME: &str = "identity";
const KEY: &str = "bik";


// Import the JavaScript function from the global scope
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = window)]
    fn store_uuid_in_js(uuid: &str);
}

#[wasm_bindgen]
pub async fn verify_domain_and_display_qr() -> Result<(), JsValue> {
    let domain = get_current_domain();
    initialize_features();

    if is_feature_enabled("e2e_encryption") {
        generate_keypair();
    }

    // Local domain check
    if is_feature_enabled("local_domain_check") {
        log_debug("Local domain check is enabled");
        if is_domain_allowed(&domain) {
            log_debug("local_domain_check: passed");
        }
    } else {
        log_debug(&format!("local_domain_check: {}", FEATURES.get().unwrap().get("local_domain_check").unwrap_or(&false)));
    }

        let mut payload = serde_json::Map::new();
        let mut verify = serde_json::Map::new();
        verify.insert("local_domain".to_string(), serde_json::Value::String(domain.clone()));
        
        // Check if BIK exists in IndexedDB
        let bik_result = read_from_indexeddb(DB_NAME, STORE_NAME, KEY).await;
        if let Ok(js_value) = bik_result {
            if let Some(bik_str) = js_value.as_string() {
                log_debug(&format!("Retrieved Value from IndexDB: {}", bik_str));
                verify.insert("bik".to_string(), serde_json::Value::String(bik_str));
            } else {
                log_debug("Failed to convert BIK to string");
            }
        } else {
            log_debug("Error retrieving BIK from IndexDB");
        }
        
        payload.insert("verify".to_string(), serde_json::Value::Object(verify));
        payload.insert("client_uuid".to_string(), serde_json::Value::String(Uuid::new_v4().to_string()));

        // Convert complete payload to JSON string
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize payload: {}", e)))?;

        log_debug(&format!("Payload JSON: {}", payload_json));

        let mut payload_str = String::new();
        let mut session_id = String::new();
        let mut timestamp = 0;

        match fetch_e2ee("/create-session", "POST", &payload_json).await {
            Ok(response) => {
                log_debug("E2EE Session created successfully");
    
                // ✅ Step 1: Convert `JsValue` to `String`
                if let Ok(json_str) = from_value::<String>(response) {
                    log_debug(&format!("Extracted JSON String: {}", json_str));
    
                    // ✅ Step 2: Convert JSON String to `Value`
                    if let Ok(json) = serde_json::from_str::<Value>(&json_str) {
                        log_debug(&format!("Deserialized JSON: {:?}", json));
    
                        // ✅ Step 3: Extract "payload", "signature", "public_key"
                        let response_payload = json.get("payload")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
    
                        let signature = json.get("signature")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
    
                        let public_key = json.get("public_key")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
    
                        log_debug(&format!("Payload String: {}", response_payload));
                        log_debug(&format!("Signature: {}", signature));
                        log_debug(&format!("Public Key: {}", public_key));
    
                        let payload_json: Value = serde_json::from_str(&response_payload).unwrap_or(Value::Null);
                        log_debug(&format!("Parsed Payload JSON: {:?}", payload_json));
    
                        // ✅ Step 5: Extract `uuid` and `timestamp` from `payload_json`
                        payload_str = response_payload.to_string();
                        session_id = payload_json.get("session_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("missing-session_id")
                            .to_string();
    
                        timestamp = payload_json.get("timestamp")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
    
                        log_debug(&format!("Extracted Session ID: {}", session_id));
                        log_debug(&format!("Extracted Timestamp: {}", timestamp));

                        verify_signature(&payload_str, &public_key, &signature).unwrap();
    
                    } else {
                        log_debug("Failed to parse response as JSON");
                    }
                } else {
                    log_debug("Failed to extract JSON string from response");
                }
            }
            Err(err) => {
                log_debug("E2EE Session creation failed");
                log_debug(&format!("Error: {:?}", err));
            }
        } 

        log_debug(&format!("Extracted Payload: {}", payload_str));
        log_debug(&format!("Extracted Session ID: {}", session_id));
        log_debug(&format!("Extracted Timestamp: {}", timestamp));

   
        // Create a canvas element for QR code rendering
   if render_qr_code(&payload_str, &domain)? {
    log_debug("QR code rendered successfully");
   } else {
    log_debug("Failed to render QR code");
   }

    let payload_value: Value = serde_json::from_str(&payload_str)
    .map_err(|_| JsValue::from_str("Failed to parse payload JSON"))?;

    let session_id_value = payload_value["session_id"].as_str().ok_or(JsValue::from_str("Missing payload"))?;
    log_debug(&format!("json_value: {}", session_id_value.to_string()));

    store_uuid_in_js(session_id_value);

    let result = read_from_indexeddb(DB_NAME, STORE_NAME, KEY).await;
    if result.is_ok() {
        log_debug(&format!("Retrieved Value: {:?}", result));
    } else {
        log_debug(&format!("No DB: {:?}", result));
        let result = create_indexeddb_store(DB_NAME, STORE_NAME).await;
        if result.is_ok() {
            log_debug(&format!("DB Store Created: {:?}", result));
            let result = insert_into_indexeddb("myDatabase", "myStore", "myKey", "MyValue").await;
            if result.is_ok() {
                log_debug(&format!("Added key to DB: {:?}", result));
            } else {
                log_debug(&format!("Error adding key to DB: {:?}", result));
            }
        } else {
            log_debug(&format!("Error creating DB: {:?}", result));
        }
    }

    Ok(())
}

/// The 6x6 bit positions of AprilTag (official mapping)



pub fn get_global_sek() -> Option<String> {
    Some(get_sek().to_string())
}











