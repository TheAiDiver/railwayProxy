# main.py
import os
import logging
from typing import Optional
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import StreamingResponse
import secrets

# Create FastAPI application
app = FastAPI(title="Railway Security Proxy Service")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")

# Set up security authentication
security = HTTPBasic()

# Get configuration from environment variables
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "changeme")
TARGET_SERVICE = os.environ.get("TARGET_SERVICE", "app.railway.internal")
ALLOWED_IPS = [ip for ip in os.environ.get("ALLOWED_IPS", "").split(",") if ip]

# Create HTTP client
http_client = httpx.AsyncClient(base_url=f"http://{TARGET_SERVICE}")

async def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify user credentials"""
    correct_username = secrets.compare_digest(credentials.username, AUTH_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, AUTH_PASSWORD)
    
    if not (correct_username and correct_password):
        logger.warning(f"Authentication failed: username '{credentials.username}'")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials

async def verify_ip(request: Request):
    """Verify if IP address is in whitelist"""
    if not ALLOWED_IPS:
        return True
        
    client_ip = request.client.host
    if client_ip not in ALLOWED_IPS:
        logger.warning(f"Unauthorized IP address: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not authorized"
        )
    return True

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "target_service": TARGET_SERVICE}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(
    request: Request, 
    path: str, 
    credentials: HTTPBasicCredentials = Depends(verify_credentials)
):
    """Proxy all requests to target service"""
    # Verify IP whitelist (if enabled)
    await verify_ip(request)
    
    # Get request content
    body = await request.body()
    
    # Transform headers (exclude unnecessary headers)
    excluded_headers = {"host", "authorization", "connection", "content-length"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    
    url = f"/{path}"
    method = request.method
    
    # Log request information
    logger.info(f"User '{credentials.username}' requested [{method}] {path}")

    try:
        # Forward request
        response = await http_client.request(
            method=method,
            url=url,
            content=body,
            headers=headers,
            params=request.query_params,
            follow_redirects=True
        )
        
        # Create response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
        )
    except httpx.RequestError as exc:
        logger.error(f"Forward request error: {str(exc)}")
        raise HTTPException(status_code=503, detail=f"Failed to request target service: {str(exc)}")

@app.on_event("shutdown")
async def shutdown_event():
    """Close HTTP client"""
    await http_client.aclose()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Security proxy service started on port {port}")
    logger.info(f"Forwarding to internal service: {TARGET_SERVICE}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")