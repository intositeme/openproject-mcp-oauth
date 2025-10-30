"""
OAuth-Protected MCP Server Wrapper
Adds OAuth 2.0 authentication layer to the OpenProject MCP Server
Supports PKCE (Proof Key for Code Exchange) for enhanced security
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import json
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional
import secrets
import uvicorn
from jose import JWTError, jwt

# Configuration
SECRET_KEY = os.getenv("OAUTH_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# OAuth Configuration (for Custom Connectors)
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "openproject-mcp-server")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", secrets.token_urlsafe(32))
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://claude.ai/oauth/callback")

# In-memory token storage (use Redis/database in production)
authorization_codes = {}
access_tokens = {}

app = FastAPI(title="OAuth-Protected OpenProject MCP Server")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def verify_pkce(code_verifier: str, code_challenge: str, code_challenge_method: str = "S256") -> bool:
    """Verify PKCE code challenge"""
    if code_challenge_method == "S256":
        # SHA256 hash of verifier, then base64url encode
        hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
        computed_challenge = base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')
        return computed_challenge == code_challenge
    elif code_challenge_method == "plain":
        return code_verifier == code_challenge
    return False


async def get_current_user(authorization: Optional[str] = None):
    """Dependency to get current authenticated user from Bearer token"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    
    payload = verify_token(token)
    return payload


async def handle_authorization(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256"
):
    """Handle OAuth authorization request (supports PKCE)"""
    
    # Validate client_id
    if client_id != OAUTH_CLIENT_ID:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    # Validate response_type
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    authorization_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "used": False,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method
    }
    
    # Redirect back to client with authorization code
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"
    
    return RedirectResponse(url=redirect_url)


# OAuth 2.0 Authorization Endpoint (both paths for compatibility)
@app.get("/oauth/authorize")
async def oauth_authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256"
):
    """OAuth authorization endpoint - /oauth/authorize path"""
    return await handle_authorization(
        response_type, client_id, redirect_uri, scope, state, 
        code_challenge, code_challenge_method
    )


@app.get("/authorize")
async def root_authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256"
):
    """OAuth authorization endpoint - /authorize path (for Claude compatibility)"""
    return await handle_authorization(
        response_type, client_id, redirect_uri, scope, state, 
        code_challenge, code_challenge_method
    )


# OAuth 2.0 Token Endpoint
@app.post("/oauth/token")
@app.post("/token")
async def token(
    grant_type: str,
    code: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    refresh_token: Optional[str] = None,
    code_verifier: Optional[str] = None
):
    """OAuth token endpoint - Exchange authorization code for access token (supports PKCE)"""
    
    if grant_type == "authorization_code":
        # Validate authorization code
        if code not in authorization_codes:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        auth_data = authorization_codes[code]
        
        # Check if code is expired
        if datetime.utcnow() > auth_data["expires_at"]:
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Check if code was already used
        if auth_data["used"]:
            raise HTTPException(status_code=400, detail="Authorization code already used")
        
        # Verify PKCE if code_challenge was provided
        if auth_data.get("code_challenge"):
            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier required")
            
            if not verify_pkce(code_verifier, auth_data["code_challenge"], auth_data.get("code_challenge_method", "S256")):
                raise HTTPException(status_code=400, detail="Invalid code_verifier")
        else:
            # If no PKCE, validate client credentials
            if client_id != OAUTH_CLIENT_ID or client_secret != OAUTH_CLIENT_SECRET:
                raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Mark code as used
        authorization_codes[code]["used"] = True
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": auth_data["client_id"], "scope": auth_data["scope"]},
            expires_delta=access_token_expires
        )
        
        # Create refresh token
        refresh_token_value = secrets.token_urlsafe(32)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token_value,
            "scope": auth_data["scope"]
        }
    
    elif grant_type == "refresh_token":
        # Handle refresh token (implement if needed)
        raise HTTPException(status_code=400, detail="Refresh token not implemented")
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


# Protected MCP SSE Endpoint
@app.get("/sse")
async def sse_endpoint(request: Request):
    """SSE endpoint - protected by OAuth"""
    
    # Get authorization header
    auth_header = request.headers.get("Authorization")
    
    # Verify token
    try:
        user = await get_current_user(auth_header)
    except HTTPException:
        # For SSE, we might want to be more lenient during initial connection
        # Or require token in query params
        token = request.query_params.get("access_token")
        if token:
            try:
                user = verify_token(token)
            except:
                raise HTTPException(status_code=401, detail="Invalid token")
        else:
            raise HTTPException(status_code=401, detail="Authentication required")
    
    # Forward to actual MCP server (running on port 8081)
    mcp_server_url = os.getenv("MCP_SERVER_URL", "http://localhost:8081/sse")
    
    async with httpx.AsyncClient(timeout=None) as client:
        try:
            async with client.stream("GET", mcp_server_url) as response:
                # Stream the SSE response
                from fastapi.responses import StreamingResponse
                return StreamingResponse(
                    response.aiter_bytes(),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "X-Accel-Buffering": "no",
                    }
                )
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="MCP server unavailable")


# Health check endpoint (public)
@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# OAuth metadata endpoint (for Claude Custom Connectors)
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    """OAuth 2.0 Authorization Server Metadata"""
    base_url = os.getenv("BASE_URL", "https://example.com")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": ["api"]
    }


if __name__ == "__main__":
    print("=" * 60)
    print("OAuth-Protected OpenProject MCP Server")
    print("=" * 60)
    print(f"OAuth Client ID: {OAUTH_CLIENT_ID}")
    print(f"OAuth Client Secret: {OAUTH_CLIENT_SECRET[:10]}...")
    print(f"Authorization Endpoints: /authorize and /oauth/authorize")
    print(f"Token Endpoints: /token and /oauth/token")
    print(f"Protected SSE Endpoint: /sse")
    print(f"PKCE Support: Enabled")
    print("=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8080)
