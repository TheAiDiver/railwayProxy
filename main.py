import os
import logging
from typing import Optional, Dict, Any
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import StreamingResponse, HTMLResponse
import secrets

# Create FastAPI application
app = FastAPI(title="Railway Security Proxy Service")

# Configure logging - Set to DEBUG level for more detailed logs
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("proxy")

# Set up security authentication
security = HTTPBasic()

# Get configuration from environment variables
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "changeme")
TARGET_SERVICE = os.environ.get("TARGET_SERVICE", "app.railway.internal")
ALLOWED_IPS = [ip for ip in os.environ.get("ALLOWED_IPS", "").split(",") if ip]

# Create HTTP client with timeout setting
http_client = httpx.AsyncClient(
    base_url=f"http://{TARGET_SERVICE}",
    timeout=30.0,
    follow_redirects=True
)

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
    excluded_headers = {"host", "authorization", "connection", "content-length", "content-security-policy"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    
    # Add important headers for proxy
    headers["X-Forwarded-For"] = request.client.host
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    
    url = f"/{path}"
    method = request.method
    
    # Log request information
    logger.info(f"User '{credentials.username}' requested [{method}] {path}")
    # Log request headers for debugging
    logger.debug(f"Request headers: {headers}")

    try:
        # Forward request
        response = await http_client.request(
            method=method,
            url=url,
            content=body,
            headers=headers,
            params=request.query_params
        )
        
        # Get all response headers
        response_headers = dict(response.headers)
        
        # Remove or modify problematic headers
        headers_to_remove = ["content-encoding", "content-security-policy", 
                             "content-security-policy-report-only", "strict-transport-security"]
        for header in headers_to_remove:
            if header in response_headers:
                del response_headers[header]
        
        # Enable CORS headers
        response_headers["Access-Control-Allow-Origin"] = "*"
        response_headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response_headers["Access-Control-Allow-Headers"] = "*"
        
        # Get content type
        content_type = response_headers.get("content-type", "")
        logger.debug(f"Response status: {response.status_code}, Content-Type: {content_type}")
        
        # Log the first 200 characters of the response for debugging
        if "text/html" in content_type:
            logger.debug(f"HTML Response preview: {response.text[:200]}...")
        
        # Handle HTML responses - special handling for Next.js
        if "text/html" in content_type.lower():
            html_content = response.text
            
            # Return HTML response
            return HTMLResponse(
                content=html_content,
                status_code=response.status_code,
                headers=response_headers
            )
            
        # Use streaming response for large binary content
        elif any(ct in content_type.lower() for ct in ["stream", "video", "audio", "application/", "image/"]) or response.status_code == 206:
            return StreamingResponse(
                response.aiter_bytes(),
                status_code=response.status_code,
                headers=response_headers,
                media_type=content_type.split(";")[0] if ";" in content_type else content_type
            )
        
        # Default response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response_headers,
            media_type=content_type.split(";")[0] if ";" in content_type else content_type
        )
    except httpx.RequestError as exc:
        logger.error(f"Forward request error: {str(exc)}")
        logger.error(f"Target URL: {TARGET_SERVICE}{url}")
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
