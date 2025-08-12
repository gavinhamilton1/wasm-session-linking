import datetime
import hashlib
import json
import uuid
from fastapi import APIRouter, File, Request, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, FastAPI, Body
from pydantic import BaseModel
from starlette.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
import os
import mimetypes
import asyncio
from typing import Dict, List, Set
from contextlib import asynccontextmanager
import logging
import jwt  # For signing responses
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from fastecdsa import keys, curve, ecdsa
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii
import secure
from fastapi.middleware.cors import CORSMiddleware
from datetime import UTC
import secrets


class VerifyRequest(BaseModel):
    encrypted_payload: str
    
ALLOWED_DOMAINS = ["localhost:8000", "stronghold.onrender.com", "stronghold-test.onrender.com", "test.devide.io", "devide.io", "192.168.1.171:8000"]

# Generate the server's private key
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()
sek_b64: str = ""

# Set up logging with more detailed output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Track connected clients by session ID active broadcast tasks by session ID
connected_clients: Dict[str, Set[WebSocket]] = {}
broadcast_tasks: Dict[str, asyncio.Task] = {}

app = FastAPI()
secure_headers = secure.Secure()
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_DOMAINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*", "X-WASM-Auth"],  # Explicitly allow your custom header
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("main/index.html", {"request": request})


def generate_signed_data(uuid: str, timestamp: int):
    """Generate a signed JWT-like structure containing UUID and timestamp."""
    payload = json.dumps({
        "session_id": uuid,
        "timestamp": timestamp
    })

    logger.info(f"Signing message: {payload}")  # Debugging print
    signature = private_key.sign(payload.encode(), ec.ECDSA(hashes.SHA256()))

    # Correctly serialize public key in DER format
    public_key_der = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo  # Must be this format for correct deserialization
    )

    # Encode the key and signature in base64
    signature_b64 = base64.b64encode(signature).decode()
    public_key_b64 = base64.b64encode(public_key_der).decode()
    
    logger.info(f"Generated Signature (Base64): {signature_b64}")  # Debugging print
    logger.info(f"Generated Public Key (Base64): {public_key_b64}")  # Debugging print
    logger.info(f"Payload: {payload}")

    return signature_b64, public_key_b64, payload

def add_padding(base64_string: str) -> str:
    """Add padding to a Base64 string if necessary."""
    return base64_string + '=' * (-len(base64_string) % 4)

@router.get("/exchange-public-key")
async def exchange_public_key(client_pk: str):
    global sek_b64  # Explicitly declare we're using the global variable

    client_pk = client_pk.replace(' ', '+')
    logger.info(f"Received client_pk: {client_pk}")    
    client_pk_padded = add_padding(client_pk)
    
    try:
        client_pk_bytes = base64.b64decode(client_pk_padded)
    except binascii.Error as e:
        logger.error(f"Base64 decoding error: {e}")
        raise HTTPException(status_code=400, detail="Invalid Base64 string")
    
    client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pk_bytes)

    # Compute shared secret
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    shared_secret_b64 = base64.b64encode(shared_secret).decode()
    logger.info(f"Shared secret (Server b64): {shared_secret_b64}")
    
    logger.info(f"Shared secret (raw hex): {binascii.hexlify(shared_secret).decode()}")
    
    # Derive SEK using HKDF
    sek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session encryption key",
    ).derive(shared_secret)

    # Update the global SEK variable
    sek_b64 = base64.b64encode(sek).decode()
    logger.info(f"Updated SEK (Base64): {sek_b64}")
    
    return JSONResponse({"server_pk": base64.b64encode(server_private_key.public_key().public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)).decode(), "sek": sek_b64})


@router.get("/sl", response_class=HTMLResponse)
async def dv(request: Request):
    return templates.TemplateResponse("dv.html", {"request": request})

@router.get("/w", response_class=HTMLResponse)
async def dv(request: Request):
    return templates.TemplateResponse("webauthn.html", {"request": request})


@router.post("/create-session")
async def verify(request: Request, request_data: VerifyRequest):
    """Verify endpoint that handles verification requests."""
    try:
        logger.info(f"Received encrypted payload: {request_data.encrypted_payload}")
        logger.info(f"Using SEK: {sek_b64}")
        decrypted_payload = decrypt_message(sek_b64, request_data.encrypted_payload)
        logger.info(f"Decrypted payload: {decrypted_payload}")

        verify_data = decrypted_payload.get("verify", {})
        local_domain = verify_data.get("local_domain")
        bik_payload = verify_data.get("bik", {})

        logger.info(f"Verifying domain: {local_domain}")

        if local_domain in ALLOWED_DOMAINS:
            logger.info(f"Domain {local_domain} is allowed")
        else:
            logger.info(f"Domain {local_domain} is not allowed")
            return JSONResponse(status_code=403, content={
                "result": False,
                "error": "Domain not allowed"
            })

        # Verify origin from headers
        origin = request.headers.get("origin") or request.headers.get("referer") or request.headers.get("host")
        origin = origin.replace("https://", "").replace("http://", "")
        logger.info(f"Origin: {origin}")

        if origin and any(domain in origin for domain in ALLOWED_DOMAINS):
            logger.info(f"Origin is {origin}")
        else:
            logger.error("Origin not allowed")
            return JSONResponse({
                "result": False,
                "error": "Origin not allowed"
            })

        # Verify BIK if provided
        if bik_payload:
            try:
                logger.info(f"BIK payload: {bik_payload}")
                at = generate_mock_access_token()
                if await verify_signature(bik_payload["bik"], bik_payload["signature"], bik_payload["public_key"]):
                    logger.info("BIK verification successful")
                else:
                    logger.error("BIK verification failed")
                    return JSONResponse({
                        "result": False,
                        "error": "BIK verification failed"
                    })
            except HTTPException as e:
                return JSONResponse({
                    "result": False,
                    "error": f"BIK verification failed: {str(e.detail)}"
                })

        session_id = str(uuid.uuid4())        
        timestamp = int(time.time())

        signature, public_key, payload = generate_signed_data(session_id, timestamp)
        
        response_json = {
            "payload": payload,
            "signature": signature,
            "public_key": public_key
        }
        
        logger.info(f"Response JSON: {response_json}")
        response_json_encrypted = encrypt_message(sek_b64, json.dumps(response_json))
        logger.info(f"Returning JSON encrypted: {response_json_encrypted}")
        
        # Wrap the encrypted payload in a JSON object
        wrapped_response = { "encrypted_payload": response_json_encrypted }
            
        
        return JSONResponse(content=wrapped_response)

    except Exception as e:
        logger.error(f"Verification failed: {str(e)}")
        return JSONResponse({
            "result": False,
            "error": f"Session creation failed: {str(e)}"
        })


@router.post("/verify-test-bik")
async def verify_test_bik(request: Dict[str, Dict[str, str]] = Body(...)):
    """Test endpoint to verify a BIK using a mock access token."""
    at = generate_mock_access_token()
    # Extract the bik_payload from the nested structure
    bik_payload = request.get("bik_payload", {})
    # Pass the bik_payload directly to verify_bik
    result = await verify_bik(access_token=at, bik_payload=bik_payload)
    return result

    

@router.get("/verify-domain")
async def verify_domain(request: Request):

        generated_uuid = str(uuid.uuid4())  
        timestamp = int(time.time())

        signature, public_key, payload = generate_signed_data(generated_uuid, timestamp)
        
        response_json = {
            "payload": payload,
            "signature": signature,
            "public_key": public_key
        }

    
        response_json_encrypted = encrypt_message(sek_b64, json.dumps(response_json))
        logger.info(f"Returning JSON encrypted: {response_json_encrypted}")
        test_decrypted = decrypt_message(sek_b64, response_json_encrypted)
        logger.info(f"Test decrypted: {test_decrypted}")
        return JSONResponse(content=response_json_encrypted)



@router.get("/m", response_class=HTMLResponse)
async def pass_page(request: Request):
    return templates.TemplateResponse("pass.html", {"request": request})

@router.get("/manifest.json")
async def manifest():
    return FileResponse("app/static/manifest.json")

@router.get("/static/sw.js")
async def service_worker():
    """Serve service worker with correct headers"""
    return FileResponse(
        "static/sw.js",
        media_type="application/javascript",
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": "no-cache"
        }
    )

UPLOAD_FOLDER = "app/static/phish";

@router.post("/qrupload")
async def upload_file(file: UploadFile = File(...)):
    try:
        # Generate a unique filename with timestamp
        filename = f"qrcode.png"
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        # Save the uploaded file
        with open(filepath, "wb") as buffer:
            buffer.write(await file.read())

        print(f"Received and saved {filename}")
        return {"message": "File uploaded successfully", "filename": filename}
    except Exception as e:
        return {"error": str(e)}


@router.get("/static/{file_path:path}")
@router.get("/js/{file_path:path}")
@router.get("/images/{file_path:path}")
@router.get("/weights/{file_path:path}")
@router.get("/pkg/{file_path:path}")
@router.get("/apriltag/{file_path:path}")
@router.get("/phish/{file_path:path}")
async def serve_static(file_path: str):
    # List of possible base directories to check
    base_dirs = [
        "app/static",
        "app/static/js",
        "app/static/images",
        "app/static/weights",
        "app/static/pkg",
        "app/static/apriltag",
        "app/static/phish"
    ]
    
    # Special case for js files
    if file_path.startswith('js/') or file_path.endswith('.js'):
        base_dirs = ["app", ""] + base_dirs  # Try app/js/file.js and js/file.js first
    
    # Try each possible location
    for base_dir in base_dirs:
        file_location = os.path.join(base_dir, file_path)
        if os.path.isfile(file_location):
            # Determine the MIME type based on file extension
            mime_type, _ = mimetypes.guess_type(file_location)
            if not mime_type:
                mime_type = 'application/octet-stream'  # Default MIME type
            
            # Set cache control headers based on file type
            cache_control = "public, max-age=86400" # 1 day for static assets
            if mime_type.startswith(('text/', 'application/javascript')):
                cache_control = "public, max-age=86400"  # 1 day for text files
            
            return FileResponse(
                file_location,
                media_type=mime_type,
                headers={
                    "Cache-Control": cache_control,
                    "Access-Control-Allow-Origin": "*"
                }
            )
    
    # If we get here, the file wasn't found in any location
    raise HTTPException(status_code=404, detail=f"File not found: {file_path}")


@router.websocket("/ws/{session_id}/{uuid}")
async def websocket_endpoint(websocket: WebSocket, session_id: str, uuid: str):
    """Handle new WebSocket connections."""
    await websocket.accept()
    logger.info(f"✅ New WebSocket connection for session: {session_id} (UUID: {uuid})")

    if session_id not in connected_clients:
        connected_clients[session_id] = set()

    connected_clients[session_id].add(websocket)
    logger.info(f"➕ Client added to session {session_id}. Total: {len(connected_clients[session_id])}")

    try:
        await websocket.send_text(f"Connected to session {session_id}")
        logger.info(f"📤 Sent connection confirmation to client {uuid} in session {session_id}")

        while True:
            message = await websocket.receive_text()
            logger.info(f"📩 Received message from {uuid} in session {session_id}: {message}")

            # Forward message to other clients in the same session
            for client in connected_clients[session_id]:
                if client != websocket:  # Avoid sending back to sender
                    await client.send_text(message)
                    logger.info(f"📤 Forwarded message to client in session {session_id}: {message}")

    except WebSocketDisconnect:
        logger.warning(f"⚠️ WebSocket disconnected for client {uuid} in session {session_id}")
    except Exception as e:
        logger.error(f"❌ WebSocket error in session {session_id}: {e}")
    finally:
        # Remove disconnected client
        if session_id in connected_clients:
            connected_clients[session_id].discard(websocket)
            logger.info(f"➖ Client removed from session {session_id}. Remaining: {len(connected_clients[session_id])}")

            # Clean up session if empty
            if not connected_clients[session_id]:
                logger.info(f"🗑️ Removing empty session {session_id}")
                del connected_clients[session_id]




@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event for background tasks."""
    logger.info("Starting WebSocket background broadcaster...")
    yield
    
    # Clean up all broadcast tasks on shutdown
    logger.info("Shutting down background tasks...")
    for session_id, task in list(broadcast_tasks.items()):
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                logger.info(f"Broadcast task for session {session_id} successfully cancelled")
            except Exception as e:
                logger.error(f"Error cancelling broadcast task for session {session_id}: {e}")
    logger.info("Background tasks shutdown complete")

# Create the FastAPI app with the lifespan context
app = FastAPI(lifespan=lifespan)

# Include the router in the app
app.include_router(router)
    

def encrypt_message(sek_b64: str, plaintext: str) -> str:
    try:
        sek_b64 = add_padding(sek_b64)
        sek_bytes = base64.b64decode(sek_b64)

        if len(sek_bytes) != 32:
            raise ValueError(f"Invalid SEK length ({len(sek_bytes)} bytes), expected 32 bytes")

        nonce = os.urandom(12)  # AES-GCM nonce (IV)
        cipher = Cipher(algorithms.AES(sek_bytes), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag

        # Changed order: Concatenate nonce + ciphertext + tag
        encrypted_message_bytes = nonce + ciphertext + tag
        encrypted_message_b64 = base64.b64encode(encrypted_message_bytes).decode()

        # Log the structure before sending
        print(f"Nonce (Base64): {base64.b64encode(nonce).decode()} (Size: {len(nonce)})")
        print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()} (Size: {len(ciphertext)})")
        print(f"Tag (Base64): {base64.b64encode(tag).decode()} (Size: {len(tag)})")
        print(f"Final Encrypted Message (Base64): {encrypted_message_b64}")

        return encrypted_message_b64
    except Exception as e:
        print(f"Encryption failed: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_message(sek_b64: str, ciphertext_b64: str) -> str:
    try:
        # Decode the SEK and ciphertext from Base64
        sek_bytes = base64.b64decode(sek_b64)
        encrypted_data = base64.b64decode(ciphertext_b64)
        
        # Extract components in order: nonce(12) + ciphertext + tag(16)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]  # Changed: get ciphertext between nonce and tag
        tag = encrypted_data[-16:]  # Changed: get tag from end
        
        # Create a cipher object
        cipher = Cipher(algorithms.AES(sek_bytes), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Parse the decrypted JSON string
        return json.loads(plaintext.decode())
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

@router.post("/send-message/{session_id}")
async def send_message(session_id: str, request: Request):
    try:
        # Parse the JSON payload from the request
        payload = await request.json()
        
        # Add the 'status' field to the payload
        payload['status'] = 'SESSION_OK'
        
        # Log the received payload
        logger.info(f"Received payload for session {session_id}: {payload}")
        
        # Check if there are any connected clients for the session
        if session_id in connected_clients and connected_clients[session_id]:
            # Send the payload to all connected clients in the session
            for client in connected_clients[session_id]:
                await client.send_text(json.dumps(payload))
            return JSONResponse(content={"status": "Message sent to all clients in session"}, status_code=200)
        else:
            return JSONResponse(content={"error": "No clients connected for this session"}, status_code=404)
    except Exception as e:
        logger.error(f"Error sending message to session {session_id}: {e}")
        return JSONResponse(content={"error": "Failed to send message"}, status_code=500)



@router.get("/lc")
async def log_connection(request: Request):
    # Get client's IP address
    client_ip = request.client.host
        
    # Loop through all headers
    headers = {key: value for key, value in request.headers.items()}

    # Log all headers dynamically
    logger.info(f"🔹 Connection from: {client_ip}")
    for key, value in headers.items():
        logger.info(f"🔹 {key}: {value}")

    return {
        "client_ip": client_ip,
        "headers": headers  # Returns all headers dynamically
    }
    
clients: List[WebSocket] = []

@router.websocket("/webrpc")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Relay the message to all clients except the sender
            for client in clients:
                if client != websocket:
                    await client.send_text(data)
    except WebSocketDisconnect:
        clients.remove(websocket)



# Generate ECDSA Keypair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

def hash_bik(sub: str, iss: str, aud: str) -> str:
    """Creates a hash-based BIK from sub, iss, and aud claims."""
    bik_data = f"{sub}.{iss}.{aud}".encode()
    bik_hash = hashlib.sha256(bik_data).hexdigest()
    return bik_hash


def sign_bik(bik: str) -> str:
    """Signs the BIK using ECDSA and returns a base64-encoded signature."""
    signature = private_key.sign(bik.encode(), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def verify_signature(bik: str, signature: str, public_key_pem: str) -> bool:
    """Verifies the signature of the BIK."""
    try:
        pub_key_bytes = base64.b64decode(public_key_pem)
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_key_bytes)

        decoded_signature = base64.b64decode(signature)
        pub_key.verify(decoded_signature, bik.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


@router.get("/get-test-bik")
async def get_test_bik():
    at = generate_mock_access_token()
    bik_payload = await generate_bik(at)
    return bik_payload

@router.post("/verify-test-bik")
async def verify_test_bik(request: Dict[str, Dict[str, str]] = Body(...)):
    """Test endpoint to verify a BIK using a mock access token."""
    at = generate_mock_access_token()
    # Extract the bik_payload from the nested structure
    bik_payload = request.get("bik_payload", {})
    # Pass the bik_payload directly to verify_bik
    result = await verify_bik(access_token=at, bik_payload=bik_payload)
    return result

@router.post("/generate-bik")
async def generate_bik(access_token: str = Body(...)):
    """Generates a BIK from a JWT access token."""
    try:
        # Verify and decode the JWT
        try:
            payload = jwt.decode(access_token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=400, detail="Invalid JWT format")
            
        # Extract required claims
        sub = payload.get("sub")
        iss = payload.get("iss")
        aud = payload.get("aud")
        
        if not all([sub, iss, aud]):
            raise HTTPException(status_code=400, detail="Missing required claims in token")
            
        # Generate BIK hash
        bik = hash_bik(sub, iss, aud)
        
        # Sign the BIK
        signature = sign_bik(bik)
        
        # Get the public key for verification
        public_key_pem = base64.b64encode(
            public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        ).decode()
        
        return {
            "bik": bik,
            "signature": signature,
            "public_key": public_key_pem
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate BIK: {str(e)}")


@router.post("/verify-bik")
async def verify_bik(access_token: str | None = Body(None), bik_payload: Dict[str, str] = Body(...)):
    """Verifies the BIK hash and its signature against a JWT access token."""
    try:
        # Use mock token if none provided
        if access_token is None:
            access_token = generate_mock_access_token()
            
        # Verify and decode the JWT
        try:
            payload = jwt.decode(access_token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=400, detail="Invalid JWT format")
            
        # Extract required claims
        sub = payload.get("sub")
        iss = payload.get("iss")
        aud = payload.get("aud")
        
        if not all([sub, iss, aud]):
            raise HTTPException(status_code=400, detail="Missing required claims in token")
            
        bik = bik_payload.get("bik")
        signature = bik_payload.get("signature")
        public_key = bik_payload.get("public_key")
        
        if not all([bik, signature, public_key]):
            logger.error(f"Missing required BIK fields: {bik}, {signature}, {public_key}")
            return False

        # Recompute BIK from JWT claims
        new_bik = hash_bik(sub, iss, aud)

        # Ensure BIK matches
        if new_bik != bik:
            logger.error(f"BIK mismatch: {new_bik} != {bik}")
            return False

        # Verify signature
        if not verify_signature(new_bik, signature, public_key):
            logger.error(f"BIK signature verification failed: {new_bik}, {signature}, {public_key}")
            return False

        logger.info(f"BIK verified successfully: {new_bik}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to verify BIK: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to verify BIK: {str(e)}")
    
    
def generate_mock_access_token():
    """Generates a mock OAuth2 access token with sub, iss, and aud claims."""
    payload = {
        "sub": "test-user",
        "iss": "https://auth.devide.io",
        "aud": "devide-sample-app",
        "iat": datetime.datetime.now(UTC),
        "exp": datetime.datetime.now(UTC) + datetime.timedelta(hours=1),
        "scope": "read write",
        "jti": "unique-token-id-12345"
    }

    # Generate a secure random secret key
    secret = secrets.token_hex(32)  # Generates a 64-character hex string
    token = jwt.encode(payload, secret, algorithm="HS256")
    return token