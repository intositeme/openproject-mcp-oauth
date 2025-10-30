# OpenProject MCP Server with OAuth Authentication

A production-ready Model Context Protocol (MCP) server for OpenProject with OAuth 2.0 authentication, designed for use with Claude AI and other MCP clients.

## Features

- 🔐 **OAuth 2.0 Authentication** - Secure access control for MCP server
- 🚀 **FastAPI-based** - High-performance async API wrapper
- 🐳 **Docker-ready** - Complete containerized setup
- 🔌 **Pangolin Compatible** - Works with Pangolin tunnel for secure access
- 📊 **Full OpenProject API** - Create projects, work packages, manage dependencies
- 🎯 **Claude AI Integration** - Built for Claude Custom Connectors

## Architecture

```
Claude Custom Connector
    ↓ OAuth 2.0
Your Public Domain
    ↓ Pangolin/Reverse Proxy
OAuth Wrapper Container
    ↓ Internal Network
MCP Server Container
    ↓ API Token
Your OpenProject Instance
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- OpenProject instance with API access
- (Optional) Pangolin or reverse proxy for public access
- Python 3.11+ (for generating secrets)

### 1. Clone/Download Files

Download these files to your server:
- `docker-compose.yml`
- `Dockerfile.oauth`
- `oauth_mcp_wrapper.py`
- `.env.example`

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and fill in all required values
nano .env
```

Required settings:
- `OPENPROJECT_URL` - Your OpenProject instance URL
- `OPENPROJECT_API_KEY` - API token from OpenProject
- `OAUTH_SECRET_KEY` - Generate with the command below
- `OAUTH_CLIENT_ID` - Generate with the command below
- `OAUTH_CLIENT_SECRET` - Generate with the command below
- `BASE_URL` - Your public MCP server URL
- `PANGOLIN_ENDPOINT` - Your Pangolin server
- `NEWT_ID` and `NEWT_SECRET` - From Pangolin tunnel

### 3. Generate OAuth Credentials

```bash
# Generate SECRET_KEY
python3 -c "import secrets; print('OAUTH_SECRET_KEY=' + secrets.token_urlsafe(32))"

# Generate CLIENT_ID
python3 -c "import secrets; print('OAUTH_CLIENT_ID=openproject-mcp-' + secrets.token_hex(8))"

# Generate CLIENT_SECRET
python3 -c "import secrets; print('OAUTH_CLIENT_SECRET=' + secrets.token_urlsafe(32))"
```

Copy these values into your `.env` file.

### 4. Get OpenProject API Token

1. Login to your OpenProject instance
2. Go to **My Account** → **Access Tokens**
3. Click **+ API**
4. Copy the 40-character token
5. Add to `.env` as `OPENPROJECT_API_KEY`

### 5. Configure Pangolin (if using)

1. Create a new site in Pangolin for your domain
2. Create a new Newt tunnel
3. Copy `NEWT_ID` and `NEWT_SECRET` to `.env`
4. Configure route:
   - Path: `/` (root)
   - Target: `oauth-wrapper:8080`

### 6. Deploy

```bash
# Build and start containers
docker compose up -d --build

# Check logs
docker compose logs -f

# Verify health
curl http://localhost:8080/health
# Or via your public URL:
curl https://your-domain.com/health
```

### 7. Configure Claude Custom Connector

In Claude:

1. Create a new **Custom Connector**
2. **Name**: OpenProject MCP
3. **Base URL**: Your `BASE_URL` from `.env`
4. **Authentication**: OAuth 2.0
5. **OAuth Settings**:
   - **Authorization URL**: `{BASE_URL}/oauth/authorize`
   - **Token URL**: `{BASE_URL}/oauth/token`
   - **Client ID**: Your `OAUTH_CLIENT_ID`
   - **Client Secret**: Your `OAUTH_CLIENT_SECRET`
   - **Scope**: `api` (optional)
6. **Endpoints**:
   - Add endpoint: `GET /sse` (SSE Stream)

### 8. Test

Once connected, try in Claude:
```
List all my OpenProject projects
```

```
Create a new project called "Test Project"
```

```
Show me available work package types
```

## Environment Variables Reference

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `OPENPROJECT_URL` | Your OpenProject instance | `https://openproject.example.com` |
| `OPENPROJECT_API_KEY` | OpenProject API token | `abc123...` (40 chars) |
| `OAUTH_SECRET_KEY` | JWT signing key | Generated random string |
| `OAUTH_CLIENT_ID` | OAuth client identifier | `openproject-mcp-abc123` |
| `OAUTH_CLIENT_SECRET` | OAuth client secret | Generated random string |
| `BASE_URL` | Public MCP server URL | `https://mcp.example.com` |
| `PANGOLIN_ENDPOINT` | Pangolin server URL | `https://pangolin.example.com` |
| `PANGOLIN_IP` | Pangolin server IP | `192.168.1.100` |
| `NEWT_ID` | Pangolin tunnel ID | From Pangolin |
| `NEWT_SECRET` | Pangolin tunnel secret | From Pangolin |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_REDIRECT_URI` | `https://claude.ai/oauth/callback` | OAuth callback |
| `MCP_LOG_LEVEL` | `INFO` | Log level |
| `CACHE_TIMEOUT` | `5` | Cache timeout (minutes) |
| `PAGINATION_SIZE` | `100` | API pagination size |
| `MAX_RETRIES` | `3` | API retry attempts |
| `DATA_PATH` | `./data` | Data storage path |

## Project Structure

```
.
├── docker-compose.yml        # Container orchestration
├── Dockerfile.oauth          # OAuth wrapper container
├── oauth_mcp_wrapper.py      # OAuth authentication layer
├── .env.example             # Environment template
└── README.md                # This file
```

## Security Best Practices

1. **Keep `.env` secure** - Never commit to public repositories
2. **Use strong secrets** - Generate with `secrets.token_urlsafe(32)`
3. **Enable HTTPS** - Use Pangolin or reverse proxy with SSL
4. **Rotate credentials** - Regularly update OAuth secrets and API tokens
5. **Monitor access** - Check logs for unauthorized attempts
6. **Limit permissions** - Use least-privilege OpenProject API tokens

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose logs oauth-wrapper
docker compose logs openproject-mcp-server

# Verify environment variables
docker compose config
```

### Can't access via public URL

```bash
# Test locally first
curl http://localhost:8080/health

# Check Pangolin tunnel
docker compose logs mcp-oauth-newt

# Verify DNS
nslookup your-domain.com
```

### OAuth authentication fails

```bash
# Verify OAuth endpoints
curl https://your-domain.com/.well-known/oauth-authorization-server

# Check credentials match in both .env and Claude config
# Ensure OAUTH_REDIRECT_URI matches Claude's callback URL
```

### MCP server can't connect to OpenProject

```bash
# Test API token
docker compose exec openproject-mcp-server curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://your-openproject.com/api/v3/projects

# Check OpenProject URL is accessible from container
docker compose exec openproject-mcp-server ping your-openproject-domain
```

## Available MCP Tools

Once connected, Claude can use these tools:

- `openproject:create_project` - Create new projects
- `openproject:get_projects` - List all projects
- `openproject:create_work_package` - Create work packages
- `openproject:get_work_packages` - List work packages
- `openproject:update_work_package` - Update work packages
- `openproject:create_work_package_dependency` - Create dependencies
- `openproject:get_users` - List users
- `openproject:assign_work_package_by_email` - Assign work packages
- `openproject:get_project_summary` - Get project overview
- And more...

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for use with OpenProject and Claude AI.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review container logs
3. Verify all environment variables
4. Test each component separately

## Credits

- Built on [firsthalfhero/openproject-mcp-server](https://github.com/firsthalfhero/openproject-mcp-server)
- Uses [FastAPI](https://fastapi.tiangolo.com/) for OAuth wrapper
- Compatible with [Pangolin](https://pangolin.net/) tunneling
- Designed for [Claude AI](https://claude.ai/) integration

## Version

Current version: 1.0.0

Built for:
- OpenProject 16.5+
- Claude AI with Custom Connectors
- MCP Protocol 2025-06-18
