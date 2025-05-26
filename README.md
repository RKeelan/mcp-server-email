# mcp-server-email MCP server

[![Changelog](https://img.shields.io/github/v/release/RKeelan/mcp-server-email?include_prereleases&label=changelog)](https://github.com/RKeelan/mcp-server-email/releases)
[![Tests](https://github.com/RKeelan/mcp-server-email/actions/workflows/test.yml/badge.svg)](https://github.com/RKeelan/mcp-server-email/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/RKeelan/mcp-server-email/blob/main/LICENSE)

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