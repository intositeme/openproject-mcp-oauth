"""
MCP SSE Bridge - Wraps stdio MCP server with HTTP/SSE transport
Enables stdio-based MCP servers to work with Claude Custom Connectors
"""

import asyncio
import json
import subprocess
import sys
import os
from typing import Optional, Dict, Any, AsyncIterator
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.middleware.cors import CORSMiddleware
import uvicorn
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MCP SSE Bridge", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MCP server process
mcp_process: Optional[subprocess.Popen] = None
request_id_counter = 0
pending_responses: Dict[int, asyncio.Queue] = {}
reader_task: Optional[asyncio.Task] = None


async def start_mcp_server():
    """Start the stdio MCP server as subprocess"""
    global mcp_process, reader_task
    
    # Command to run the OpenProject MCP server
    # The server is installed in the container at /app
    command = ["python", "-m", "openproject_mcp_server.main"]
    
    logger.info(f"Starting MCP server: {' '.join(command)}")
    
    mcp_process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1"
        }
    )
    
    # Start reader tasks
    reader_task = asyncio.create_task(read_mcp_stdout())
    asyncio.create_task(log_mcp_stderr())
    
    # Initialize the MCP server
    await initialize_mcp_server()
    
    logger.info("MCP server started and initialized")


async def read_mcp_stdout():
    """Read JSON-RPC responses from MCP server stdout"""
    global mcp_process
    
    try:
        while mcp_process and mcp_process.poll() is None:
            line = await asyncio.get_event_loop().run_in_executor(
                None, mcp_process.stdout.readline
            )
            
            if not line:
                continue
            
            line = line.strip()
            if not line:
                continue
            
            try:
                response = json.loads(line)
                logger.info(f"<-- Received from MCP: {json.dumps(response)[:200]}")
                
                # Route response to waiting request
                response_id = response.get("id")
                if response_id is not None and response_id in pending_responses:
                    await pending_responses[response_id].put(response)
                else:
                    logger.warning(f"Received response for unknown/expired ID: {response_id}")
                    
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {line[:100]} - {e}")
                
    except Exception as e:
        logger.error(f"Error reading stdout: {e}", exc_info=True)


async def log_mcp_stderr():
    """Log stderr from MCP server"""
    global mcp_process
    
    try:
        while mcp_process and mcp_process.poll() is None:
            line = await asyncio.get_event_loop().run_in_executor(
                None, mcp_process.stderr.readline
            )
            
            if line:
                logger.info(f"MCP stderr: {line.strip()}")
                
    except Exception as e:
        logger.error(f"Error reading stderr: {e}")


async def send_mcp_request(method: str, params: Optional[dict] = None, timeout: float = 30.0) -> dict:
    """Send JSON-RPC request to MCP server and wait for response"""
    global mcp_process, request_id_counter, pending_responses
    
    if not mcp_process or mcp_process.poll() is not None:
        raise HTTPException(status_code=503, detail="MCP server not running")
    
    request_id_counter += 1
    request_id = request_id_counter
    
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {}
    }
    
    logger.info(f"--> Sending to MCP: {json.dumps(request)[:200]}")
    
    # Create queue for this request
    response_queue = asyncio.Queue(maxsize=1)
    pending_responses[request_id] = response_queue
    
    try:
        # Send request
        request_line = json.dumps(request) + "\n"
        await asyncio.get_event_loop().run_in_executor(
            None, mcp_process.stdin.write, request_line
        )
        await asyncio.get_event_loop().run_in_executor(
            None, mcp_process.stdin.flush
        )
        
        # Wait for response with timeout
        try:
            response = await asyncio.wait_for(response_queue.get(), timeout=timeout)
            return response
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail=f"MCP server timeout for method: {method}")
            
    finally:
        # Clean up
        pending_responses.pop(request_id, None)


async def initialize_mcp_server():
    """Initialize the MCP server with required handshake"""
    try:
        response = await send_mcp_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-sse-bridge",
                    "version": "1.0.0"
                }
            }
        )
        
        if "error" in response:
            raise Exception(f"MCP initialization failed: {response['error']}")
        
        logger.info(f"MCP initialized: {response.get('result', {})}")
        
        # Send initialized notification
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        
        notification_line = json.dumps(notification) + "\n"
        await asyncio.get_event_loop().run_in_executor(
            None, mcp_process.stdin.write, notification_line
        )
        await asyncio.get_event_loop().run_in_executor(
            None, mcp_process.stdin.flush
        )
        
    except Exception as e:
        logger.error(f"Failed to initialize MCP server: {e}", exc_info=True)
        raise


@app.on_event("startup")
async def startup_event():
    """Start MCP server on application startup"""
    await start_mcp_server()


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up MCP server on shutdown"""
    global mcp_process
    
    if mcp_process:
        mcp_process.terminate()
        try:
            mcp_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mcp_process.kill()


@app.get("/health")
async def health():
    """Health check endpoint"""
    is_healthy = mcp_process is not None and mcp_process.poll() is None
    
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "service": "mcp-sse-bridge",
        "mcp_server_running": is_healthy,
        "timestamp": datetime.utcnow().isoformat()
    }


async def sse_event_stream(request: Request) -> AsyncIterator[str]:
    """
    Generate SSE event stream for MCP communication
    This handles the bidirectional MCP protocol over SSE
    """
    try:
        # Read the incoming request body (JSON-RPC message)
        body = await request.body()
        
        if body:
            try:
                rpc_request = json.loads(body)
                logger.info(f"SSE Request: {rpc_request}")
                
                # Forward to MCP server
                method = rpc_request.get("method")
                params = rpc_request.get("params", {})
                request_id = rpc_request.get("id")
                
                if method:
                    response = await send_mcp_request(method, params)
                    
                    # Send response as SSE event
                    event_data = json.dumps(response)
                    yield f"event: message\n"
                    yield f"data: {event_data}\n\n"
                else:
                    # Invalid request
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32600,
                            "message": "Invalid Request"
                        }
                    }
                    event_data = json.dumps(error_response)
                    yield f"event: message\n"
                    yield f"data: {event_data}\n\n"
                    
            except json.JSONDecodeError:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": "Parse error"
                    }
                }
                event_data = json.dumps(error_response)
                yield f"event: message\n"
                yield f"data: {event_data}\n\n"
        else:
            # No body - send endpoint event
            endpoint_event = {
                "jsonrpc": "2.0",
                "method": "endpoint",
                "params": {
                    "uri": str(request.url)
                }
            }
            event_data = json.dumps(endpoint_event)
            yield f"event: endpoint\n"
            yield f"data: {event_data}\n\n"
            
            # Keep connection alive
            while True:
                await asyncio.sleep(15)
                yield f": keepalive\n\n"
                
    except Exception as e:
        logger.error(f"Error in SSE stream: {e}", exc_info=True)
        error_event = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        }
        event_data = json.dumps(error_event)
        yield f"event: message\n"
        yield f"data: {event_data}\n\n"


@app.get("/sse")
@app.post("/sse")
async def sse_endpoint(request: Request):
    """
    SSE endpoint for MCP communication
    Supports both GET (for establishing stream) and POST (for sending messages)
    """
    return StreamingResponse(
        sse_event_stream(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.post("/messages")
async def messages_endpoint(request: Request):
    """
    Alternative endpoint for JSON-RPC messages
    Returns single JSON response instead of SSE stream
    """
    try:
        rpc_request = await request.json()
        logger.info(f"Message request: {rpc_request}")
        
        method = rpc_request.get("method")
        params = rpc_request.get("params", {})
        
        if not method:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": rpc_request.get("id"),
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request"
                    }
                }
            )
        
        response = await send_mcp_request(method, params)
        return JSONResponse(content=response)
        
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error"
                }
            }
        )
    except Exception as e:
        logger.error(f"Error handling message: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
        )


@app.get("/")
async def root():
    """Root endpoint with service info"""
    return {
        "service": "MCP SSE Bridge",
        "version": "1.0.0",
        "description": "Bridges stdio MCP servers to HTTP/SSE transport",
        "endpoints": {
            "sse": "/sse (GET/POST)",
            "messages": "/messages (POST)",
            "health": "/health"
        }
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
