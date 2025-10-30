"""
MCP OAuth Server Wrapper for Claude AI
Implements MCP OAuth specification (6/18) for Claude Custom Connectors
"""

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import secrets
import uvicorn
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import json
import asyncio
from urllib.parse import urlencode

# Configuration
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "openproject-mcp-server")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", secrets.token_urlsafe(32))

# Claude's official MCP OAuth callback URL
CLAUDE_CALLBACK_URL =     "https://claude.ai/api/mcp/auth_callback"
CLAUDE_CALLBACK_URL_ALT = "https://claude.com/api/mcp/auth_callback"
CLAUDE_CALLBACK_URL_ALT2 = "https://claude.ai/oauth/callback"
CLAUDE_CALLBACK_URL_ALT3 = "http://localhost:6274/oauth/callback"


# Token storage (use Redis/database in production)
authorization_codes: Dict[str, Dict[str, Any]] = {}
access_tokens: Dict[str, Dict[str, Any]] = {}
refresh_tokens: Dict[str, Dict[str, Any]] = {}

# Internal MCP server URL
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://openproject-mcp-server:8081")
MCP_SERVER_SSE_URL = os.getenv("MCP_SERVER_SSE_URL", "http://openproject-mcp-server:39127")


BASE_URL = os.getenv("BASE_URL", "https://this.mcpserver.domain")

app = FastAPI(
    title="OpenProject MCP Server with OAuth",
    description="MCP OAuth-protected server for Claude AI",
    version="1.0.0"
)

# CORS configuration for Claude
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://claude.ai",
        "https://claude.com",
        "https://*.claude.ai",
        "https://*.claude.com"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def generate_token(prefix: str = "") -> str:
    """Generate a secure random token"""
    return f"{prefix}{secrets.token_urlsafe(32)}" if prefix else secrets.token_urlsafe(32)


def validate_redirect_uri(redirect_uri: str) -> bool:
    """Validate that redirect URI is from Claude"""
    allowed_uris = [CLAUDE_CALLBACK_URL, CLAUDE_CALLBACK_URL_ALT, CLAUDE_CALLBACK_URL_ALT2, CLAUDE_CALLBACK_URL_ALT3]
    return redirect_uri in allowed_uris


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "openproject-mcp-oauth",
        "timestamp": datetime.utcnow().isoformat(),
        "mcp_server": MCP_SERVER_URL
    }

@app.get("/.well-known/oauth-authorization-server")
async def oauth_discovery():
    """
    Standard OAuth 2.0 Discovery (Claude expects this)
    """
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": ["claudeai", "mcp"],
    }

@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    """
    Optional but Claude probes this too
    """
    return {
        "issuer": BASE_URL,
        "authorization_server": f"{BASE_URL}/.well-known/oauth-authorization-server"
    }

@app.get("/authorize")
async def alias_authorize(request: Request):
    """
    Redirect /authorize → /oauth/authorize
    """
    qs = request.url.query
    return RedirectResponse(url=f"{BASE_URL}/oauth/authorize?{qs}")


@app.post("/token")
async def alias_token(request: Request):
    """
    Redirect /token → /oauth/token
    """
    return await token_endpoint(request)


@app.get("/.well-known/mcp-oauth-server")
async def mcp_oauth_metadata():
    """
    MCP OAuth Server Metadata Endpoint
    Required by MCP OAuth spec
    """
    base_url = os.getenv("BASE_URL", "https://your-server.com")
    
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": ["mcp"],
        "service_documentation": f"{base_url}/docs"
    }


@app.get("/oauth/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scope: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None
):
    """
    OAuth Authorization Endpoint
    Implements MCP OAuth spec authorization flow
    """
    
    # Validate response_type
    if response_type != "code":
        return RedirectResponse(
            url=f"{redirect_uri}?error=unsupported_response_type&state={state}"
        )
    
    # Validate client_id
    if client_id != OAUTH_CLIENT_ID:
        return RedirectResponse(
            url=f"{redirect_uri}?error=unauthorized_client&state={state}"
        )
    
    # Validate redirect_uri (Claude's callback)
    if not validate_redirect_uri(redirect_uri):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid redirect_uri. Expected {CLAUDE_CALLBACK_URL}"
        )
    
    # Generate authorization code
    auth_code = generate_token("auth_")
    
    # Store authorization code with PKCE challenge if provided
    authorization_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope or "mcp",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "used": False
    }
    
    # Redirect back to Claude with authorization code
    params = {
        "code": auth_code,
        "state": state
    }
    
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    return RedirectResponse(url=redirect_url)


@app.post("/oauth/token")
async def token_endpoint(request: Request):
    """
    OAuth Token Endpoint
    Exchanges authorization code for access token
    Supports both authorization_code and refresh_token grants
    """
    
    # Parse form data
    form_data = await request.form()
    grant_type = form_data.get("grant_type")
    
    if grant_type == "authorization_code":
        code = form_data.get("code")
        client_id = form_data.get("client_id")
        client_secret = form_data.get("client_secret")
        redirect_uri = form_data.get("redirect_uri")
        code_verifier = form_data.get("code_verifier")
        
        # Validate authorization code exists
        if code not in authorization_codes:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        auth_data = authorization_codes[code]
        
        # Check expiration
        if datetime.utcnow() > auth_data["expires_at"]:
            del authorization_codes[code]
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Check if already used
        if auth_data["used"]:
            raise HTTPException(status_code=400, detail="Authorization code already used")
        
        # Validate client credentials
        if client_id != OAUTH_CLIENT_ID:
            raise HTTPException(status_code=401, detail="Invalid client_id")
        
        if client_secret != OAUTH_CLIENT_SECRET:
            raise HTTPException(status_code=401, detail="Invalid client_secret")
        
        # Validate redirect_uri matches
        if redirect_uri != auth_data["redirect_uri"]:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")
        
        # Validate PKCE if code_challenge was provided
        if auth_data.get("code_challenge"):
            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier required")
            
            # Verify PKCE challenge (S256 method)
            import hashlib
            import base64
            
            verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
            verifier_challenge = base64.urlsafe_b64encode(verifier_hash).decode().rstrip("=")
            
            if verifier_challenge != auth_data["code_challenge"]:
                raise HTTPException(status_code=400, detail="Invalid code_verifier")
        
        # Mark code as used
        authorization_codes[code]["used"] = True
        
        # Generate tokens
        access_token = generate_token("mcp_access_")
        refresh_token = generate_token("mcp_refresh_")
        
        # Store tokens
        token_data = {
            "client_id": client_id,
            "scope": auth_data["scope"],
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=1)
        }
        
        access_tokens[access_token] = token_data.copy()
        refresh_tokens[refresh_token] = {
            **token_data,
            "access_token": access_token,
            "expires_at": datetime.utcnow() + timedelta(days=30)
        }
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,  # 1 hour
            "refresh_token": refresh_token,
            "scope": auth_data["scope"]
        }
    
    elif grant_type == "refresh_token":
        refresh_token_value = form_data.get("refresh_token")
        client_id = form_data.get("client_id")
        client_secret = form_data.get("client_secret")
        
        # Validate refresh token
        if refresh_token_value not in refresh_tokens:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        
        refresh_data = refresh_tokens[refresh_token_value]
        
        # Check expiration
        if datetime.utcnow() > refresh_data["expires_at"]:
            del refresh_tokens[refresh_token_value]
            raise HTTPException(status_code=400, detail="Refresh token expired")
        
        # Validate client credentials
        if client_id != OAUTH_CLIENT_ID or client_secret != OAUTH_CLIENT_SECRET:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Revoke old access token
        old_access_token = refresh_data.get("access_token")
        if old_access_token in access_tokens:
            del access_tokens[old_access_token]
        
        # Generate new access token
        new_access_token = generate_token("mcp_access_")
        
        token_data = {
            "client_id": client_id,
            "scope": refresh_data["scope"],
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=1)
        }
        
        access_tokens[new_access_token] = token_data
        refresh_tokens[refresh_token_value]["access_token"] = new_access_token
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token_value,
            "scope": refresh_data["scope"]
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


def verify_access_token(token: str) -> bool:
    """Verify access token is valid and not expired"""
    if token not in access_tokens:
        return False
    
    token_data = access_tokens[token]
    if datetime.utcnow() > token_data["expires_at"]:
        del access_tokens[token]
        return False
    
    return True


async def stream_mcp_response(url: str, method: str, headers: dict, body: bytes = None):
    """
    Generator function to stream response from MCP server
    This keeps the connection alive while streaming
    """
    async with httpx.AsyncClient(timeout=None) as client:
        if method == "GET":
            async with client.stream("GET", url, headers=headers) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk
        else:  # POST
            async with client.stream("POST", url, content=body, headers=headers) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk


@app.api_route("/sse", methods=["GET", "POST"])
async def sse_proxy(request: Request):
    """
    Proxy SSE endpoint to internal MCP server
    Handles authentication via Bearer token
    """
    
    # Extract access token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    access_token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Verify token
    if not verify_access_token(access_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Proxy to internal MCP server
    target_url = f"{MCP_SERVER_URL}/sse"
    
    try:
        # Prepare headers to forward (exclude host and authorization)
        forward_headers = {
            k: v for k, v in request.headers.items() 
            if k.lower() not in ["host", "authorization"]
        }
        
        # Get request body for POST requests
        body = await request.body() if request.method == "POST" else None
        
        # Return streaming response with the generator function
        return StreamingResponse(
            stream_mcp_response(target_url, request.method, forward_headers, body),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )
    
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=f"Cannot connect to MCP server at {MCP_SERVER_URL}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error proxying to MCP server: {str(e)}"
        )


@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "OpenProject MCP Server with OAuth",
        "status": "running",
        "oauth_spec": "MCP OAuth 6/18",
        "endpoints": {
            "metadata": "/.well-known/mcp-oauth-server",
            "authorize": "/oauth/authorize",
            "token": "/oauth/token",
            "sse": "/sse",
            "health": "/health"
        },
        "docs": "/docs"
    }


if __name__ == "__main__":
    print("=" * 70)
    print("OpenProject MCP Server with OAuth Authentication")
    print("=" * 70)
    print(f"OAuth Client ID: {OAUTH_CLIENT_ID}")
    print(f"OAuth Client Secret: {OAUTH_CLIENT_SECRET[:20]}...")
    print(f"Claude Callback URL: {CLAUDE_CALLBACK_URL}")
    print(f"MCP Server URL: {MCP_SERVER_URL}")
    print("=" * 70)
    print("\nEndpoints:")
    print(f"  Metadata: /.well-known/mcp-oauth-server")
    print(f"  Authorize: /oauth/authorize")
    print(f"  Token: /oauth/token")
    print(f"  SSE Proxy: /sse")
    print(f"  Health: /health")
    print("=" * 70)
    
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
