from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
import logging
import json

logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.info(f"Request: {request.method} {request.url}")
        if request.method in ["POST", "PUT"]:
            try:
                content_type = request.headers.get('content-type', '')
                if 'multipart/form-data' in content_type:
                    logger.info("  [Binary data omitted]")
                else:
                    body = await request.body()
                    if body:
                        try:
                            json_body = json.loads(body)
                            log_body = json_body.copy()
                            if 'image' in log_body:
                                log_body['image'] = '<image data>'
                            logger.info(f"  {json.dumps(log_body, indent=2)}")
                        except:
                            log_text = body.decode()[:100] + '...' if len(body) > 100 else body.decode()
                            logger.info(f"  {log_text}")
            except Exception as e:
                logger.error(f"Error reading request body: {e}")
        response = await call_next(request)
        logger.info(f"Response: {response.status_code}")
        return response