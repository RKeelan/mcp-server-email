# mcp-server-email MCP server

Give your AI assistant an email address

## Quickstart

### Inspect

```
uv add "mcp[cli]" google-auth google-auth-oauthlib google-api-python-client
mcp dev server.py
```

### Install

#### Claude Desktop

1. Set up an email address
2. Set up OAuth 2.0 Credentials and save them to `.env`
3. Install for Claude Desktop
```
mcp install server.py --env-file .env
```