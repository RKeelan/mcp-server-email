import asyncio
import os
import pickle
from typing import Any, Dict, List, Optional, Union

from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

# Load environment variables from .env file
load_dotenv()

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
CREDENTIALS_FILE = 'creds.json'
TOKEN_FILE = 'token.pickle'
LABEL = os.getenv('LABEL', 'Safe')

server = Server("mcp-server-email")

def get_gmail_service(
    credentials_file: str = CREDENTIALS_FILE, 
    token_file: str = TOKEN_FILE, 
    scopes: Optional[List[str]] = SCOPES
) -> Resource:
    """
    Authenticate with Gmail using OAuth2 credentials and return a service object.
    
    Args:
        credentials_file: Path to credentials.json file from Google Cloud Console
        token_file: Path to store/retrieve the token
        scopes: List of scopes needed for the Gmail API
        
    Returns:
        service: Authenticated Gmail API service object
    """
    if scopes is None:
        # Default scope for reading, sending, and managing emails
        scopes = ['https://www.googleapis.com/auth/gmail.modify']
    
    creds: Optional[Credentials] = None
    
    # Load the token from file if it exists
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
    
    # Check if credentials are invalid or don't exist
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Refresh the token if it's expired
            creds.refresh(Request())
        else:
            # Create a flow instance with client secrets from file
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes)
            # Run local server to get authentication code
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for next run
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
    
    # Build the Gmail service
    service: Resource = build('gmail', 'v1', credentials=creds)
    print("Successfully authenticated with Gmail!")
    
    return service

def get_label_id(service: Resource, label_name: str) -> str:
    """Get the ID of a label by name, creating it if it doesn't exist."""
    results = service.users().labels().list(userId='me').execute()
    labels: List[Dict[str, Any]] = results.get('labels', [])
    
    for label in labels:
        if label['name'] == label_name:
            return label['id']
    
    # Label doesn't exist, create it
    label = service.users().labels().create(
        userId='me',
        body={'name': label_name}
    ).execute()
    
    return label['id']

def list_emails_sync(max_results: int = 10) -> List[str]:
    service: Resource = get_gmail_service()
    label_id: str = get_label_id(service, LABEL)
    
    results = service.users().messages().list(
        userId='me', 
        labelIds=[label_id],
        maxResults=max_results
    ).execute()
    messages = results.get('messages', [])
    
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload']['headers']
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
        sender = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
        print(f"Subject: {subject} | From: {sender}")
    
async def list_emails(max_results: int = 10) -> List[types.TextContent]:
    service: Resource = get_gmail_service()
    label_id: str = get_label_id(service, LABEL)
    
    results = service.users().messages().list(
        userId='me', 
        labelIds=[label_id],
        maxResults=max_results
    ).execute()
    
    messages: List[Dict[str, Any]] = results.get('messages', [])
    
    if not messages:
        return [types.TextContent(type="text", text=f"No emails found with label '{LABEL}'")]
    
    email_list: List[str] = []
    for message in messages:
        msg_id: str = message['id']
        msg: Dict[str, Any] = service.users().messages().get(userId='me', id=msg_id).execute()
        
        # Extract subject and sender
        subject: str = "No Subject"
        sender: str = "Unknown"
        
        for header in msg['payload']['headers']:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']
        
        email_list.append(f"ID: {msg_id} | Subject: {subject} | From: {sender}")
    
    return [types.TextContent(
        type="text", 
        text=f"Found {len(email_list)} emails with label '{LABEL}':\n\n" + "\n".join(email_list)
    )]

async def mark_email_as_handled(email_id: str) -> None:
    service: Resource = get_gmail_service()
    label_id: str = get_label_id(service, LABEL)
    
    service.users().messages().modify(
        userId='me',
        id=email_id,
        body={'removeLabelIds': [label_id]}
    ).execute()
    
    return [types.TextContent(
        type="text",
        text=f"Email {email_id} has been marked as handled (removed label '{LABEL}')"
    )]

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """List available email tools."""
    return [
        types.Tool(
            name="list-emails",
            description="List emails",
            inputSchema={
                "type": "object",
                "properties": {
                    "maxResults": {"type": "integer", "description": "Maximum number of emails to list"},
                },
                "required": []
            },
            annotations={
                "readOnlyHint": True
            }
        ),
        types.Tool(
            name="mark-handled",
            description="Mark an email as handled",
            inputSchema={
                "type": "object",
                "properties": {
                    "emailId": {"type": "string", "description": "ID of the email to mark as handled"}
                },
                "required": ["emailId"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle email tool execution."""
    if name == "list-emails":
        arguments = arguments or {}
        max_results = arguments.get("maxResults", 10)
        return await list_emails(max_results)
    
    elif name == "mark-handled":
        if not arguments or "emailId" not in arguments:
            raise ValueError("Missing emailId argument")
        
        email_id = arguments["emailId"]
        
        return await mark_email_as_handled(email_id)
    
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-server-email",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
    # list_emails_sync()

