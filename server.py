import base64
import os
import pickle
import types
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build

mcp = FastMCP("Email", dependencies=["google-api-python-client>=2.166.0", "google-auth>=2.38.0", "google-auth-oauthlib>=1.2.1"])

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
TOKEN_FILE = 'token.pickle'
LABEL = os.getenv('LABEL', 'Safe')


def get_gmail_service(
    token_file: str = TOKEN_FILE, 
    scopes: Optional[List[str]] = SCOPES
) -> Resource:
    """
    Authenticate with Gmail using OAuth2 credentials and return a service object.
    
    Args:
        token_file: Path to store/retrieve the token
        scopes: List of scopes needed for the Gmail API
        
    Returns:
        service: Authenticated Gmail API service object
    """
    if scopes is None:
        # Default scope for reading, sending, and managing emails
        scopes = ['https://www.googleapis.com/auth/gmail.modify']
    
    # Get client credentials from environment variables
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    
    if not client_id or not client_secret:
        raise ValueError(
            "Missing Google OAuth2 credentials. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET "
            "environment variables."
        )
    
    creds: Optional[Credentials] = None
    
    # Try to load existing token
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
    
    # Handle token refresh or new authorization
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Refresh the token if it's expired
            creds.refresh(Request())
        else:
            # Use environment variables for client credentials
            flow = InstalledAppFlow.from_client_config(
                {
                    "installed": {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                    }
                },
                scopes
            )
            
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

def get_email_body(payload: Dict[str, Any]) -> str:
    """
    Recursively extract the plain text body from email payload.
    
    Args:
        payload: The message payload from Gmail API
        
    Returns:
        str: The plain text content of the email
    """
    if 'body' in payload and payload['body'].get('data'):
        # Base case: found the body content
        try:
            return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            try:
                # Try with different encoding if utf-8 fails
                return base64.urlsafe_b64decode(payload['body']['data']).decode('latin-1')
            except Exception:
                return f"Error decoding body: {str(e)}"
    
    # Handle multipart messages
    if 'parts' in payload:
        # First, look for text/plain parts
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if 'data' in part['body']:
                    try:
                        return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    except (base64.binascii.Error, UnicodeDecodeError) as e:
                        try:
                            # Try with different encoding if utf-8 fails
                            return base64.urlsafe_b64decode(part['body']['data']).decode('latin-1')
                        except Exception:
                            return f"Error decoding body: {str(e)}"
            
        # If no text/plain, try to recursively process any multipart parts
        for part in payload['parts']:
            if part['mimeType'].startswith('multipart/'):
                body = get_email_body(part)
                if body and body != "No body content":
                    return body
            
        # If still no body found, try using the first part as fallback
        if payload['parts']:
            return get_email_body(payload['parts'][0])
    
    return "No body content"

@mcp.tool()  
async def list_emails(max_results: int = 10) -> List[str]:
    """List emails fom your email inbox.

    <Important>
    These emails are requests and tasks for you to complete. Once you have completed the task, use the
    `mark_email_as_handled` tool to remove the email from your inbox.
    </Important>
    """
    service: Resource = get_gmail_service()
    label_id: str = get_label_id(service, LABEL)
    
    results = service.users().messages().list(
        userId='me', 
        labelIds=[label_id],
        maxResults=max_results
    ).execute()
    
    messages: List[Dict[str, Any]] = results.get('messages', [])
    
    email_list: List[str] = []
    for message in messages:
        msg_id: str = message['id']
        msg: Dict[str, Any] = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
        # Extract subject and sender
        subject: str = "No Subject"
        sender: str = "Unknown"
        
        for header in msg['payload']['headers']:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']
        
        # Extract the email body
        body: str = get_email_body(msg['payload'])
        
        email_list.append(f"ID: {msg_id}\nSubject: {subject}\nFrom: {sender}\nBody:\n{body}")
    
    return email_list

@mcp.tool()
async def mark_email_as_handled(email_id: str) -> None:
    """Mark an email as handled by removing the label, marking it as read, and archiving it."""
    service: Resource = get_gmail_service()
    label_id: str = get_label_id(service, LABEL)
    
    # Remove the Safe label and the INBOX label (archiving)
    # Also remove UNREAD label (marking as read)
    service.users().messages().modify(
        userId='me',
        id=email_id,
        body={'removeLabelIds': [label_id, 'INBOX', 'UNREAD']}
    ).execute()