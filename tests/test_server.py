"""Comprehensive tests for the MCP email server."""

import base64
import os
import pickle
import tempfile
from unittest.mock import AsyncMock, MagicMock, Mock, patch, mock_open
from typing import Any, Dict, List

import pytest
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials

# Mock FastMCP before importing server to prevent initialization issues
with patch('mcp.server.fastmcp.FastMCP') as mock_fastmcp:
    # Create a mock MCP instance that properly handles the tool decorator
    mock_mcp_instance = Mock()
    mock_mcp_instance.tool.return_value = lambda func: func  # Return the function unchanged
    mock_fastmcp.return_value = mock_mcp_instance
    import server


class TestGetGmailService:
    """Tests for the get_gmail_service function."""

    @patch.dict(os.environ, {'GOOGLE_CLIENT_ID': 'test_id', 'GOOGLE_CLIENT_SECRET': 'test_secret'})
    @patch('server.build')
    @patch('server.pickle.load')
    @patch('server.os.path.exists')
    def test_get_gmail_service_with_valid_token(self, mock_exists, mock_pickle_load, mock_build):
        """Test getting Gmail service with valid existing token."""
        # Setup
        mock_exists.return_value = True
        mock_creds = Mock(spec=Credentials)
        mock_creds.valid = True
        mock_pickle_load.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        # Execute
        with patch('builtins.open', mock_open()):
            result = server.get_gmail_service()

        # Assert
        assert result == mock_service
        mock_build.assert_called_once_with('gmail', 'v1', credentials=mock_creds)

    @patch.dict(os.environ, {'GOOGLE_CLIENT_ID': 'test_id', 'GOOGLE_CLIENT_SECRET': 'test_secret'})
    @patch('server.build')
    @patch('server.pickle.load')
    @patch('server.pickle.dump')
    @patch('server.os.path.exists')
    @patch('server.Request')
    def test_get_gmail_service_with_expired_token(self, mock_request, mock_exists, mock_pickle_dump, 
                                                  mock_pickle_load, mock_build):
        """Test getting Gmail service with expired token that can be refreshed."""
        # Setup
        mock_exists.return_value = True
        mock_creds = Mock(spec=Credentials)
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = 'refresh_token'
        mock_pickle_load.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service
        mock_request_instance = Mock()
        mock_request.return_value = mock_request_instance

        # Execute
        with patch('builtins.open', mock_open()):
            result = server.get_gmail_service()

        # Assert
        mock_creds.refresh.assert_called_once_with(mock_request_instance)
        mock_pickle_dump.assert_called_once()
        assert result == mock_service

    @patch.dict(os.environ, {'GOOGLE_CLIENT_ID': 'test_id', 'GOOGLE_CLIENT_SECRET': 'test_secret'})
    @patch('server.build')
    @patch('server.pickle.dump')
    @patch('server.os.path.exists')
    @patch('server.InstalledAppFlow.from_client_config')
    def test_get_gmail_service_new_auth(self, mock_flow_class, mock_exists, mock_pickle_dump, mock_build):
        """Test getting Gmail service with new authentication flow."""
        # Setup
        mock_exists.return_value = False
        mock_flow = Mock()
        mock_flow_class.return_value = mock_flow
        mock_creds = Mock(spec=Credentials)
        mock_flow.run_local_server.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        # Execute
        with patch('builtins.open', mock_open()):
            result = server.get_gmail_service()

        # Assert
        mock_flow.run_local_server.assert_called_once_with(port=0)
        mock_pickle_dump.assert_called_once()
        assert result == mock_service

    @patch.dict(os.environ, {}, clear=True)
    def test_get_gmail_service_missing_credentials(self):
        """Test that ValueError is raised when credentials are missing."""
        with pytest.raises(ValueError, match="Missing Google OAuth2 credentials"):
            server.get_gmail_service()

    @patch.dict(os.environ, {'GOOGLE_CLIENT_ID': 'test_id', 'GOOGLE_CLIENT_SECRET': 'test_secret'})
    @patch('server.build')
    @patch('server.pickle.load')
    @patch('server.os.path.exists')
    def test_get_gmail_service_with_none_scopes(self, mock_exists, mock_pickle_load, mock_build):
        """Test getting Gmail service with None scopes (should use default)."""
        # Setup
        mock_exists.return_value = True
        mock_creds = Mock(spec=Credentials)
        mock_creds.valid = True
        mock_pickle_load.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        # Execute
        with patch('builtins.open', mock_open()):
            result = server.get_gmail_service(scopes=None)

        # Assert
        assert result == mock_service

    @patch.dict(os.environ, {'GOOGLE_CLIENT_ID': 'test_id', 'GOOGLE_CLIENT_SECRET': 'test_secret'})
    @patch('server.build')
    @patch('server.pickle.load')
    @patch('server.pickle.dump')
    @patch('server.os.path.exists')
    @patch('server.InstalledAppFlow.from_client_config')
    def test_get_gmail_service_invalid_creds_no_refresh_token(self, mock_flow_class, mock_exists, 
                                                              mock_pickle_dump, mock_pickle_load, mock_build):
        """Test getting Gmail service with invalid credentials and no refresh token."""
        # Setup
        mock_exists.return_value = True
        mock_creds = Mock(spec=Credentials)
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = None
        mock_pickle_load.return_value = mock_creds
        
        mock_flow = Mock()
        mock_flow_class.return_value = mock_flow
        mock_new_creds = Mock(spec=Credentials)
        mock_flow.run_local_server.return_value = mock_new_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        # Execute
        with patch('builtins.open', mock_open()):
            result = server.get_gmail_service()

        # Assert
        mock_flow.run_local_server.assert_called_once_with(port=0)
        assert result == mock_service


class TestGetLabelId:
    """Tests for the get_label_id function."""

    def test_get_label_id_existing_label(self):
        """Test getting ID of existing label."""
        # Setup
        mock_service = Mock()
        mock_service.users().labels().list().execute.return_value = {
            'labels': [
                {'id': 'label1', 'name': 'Test'},
                {'id': 'label2', 'name': 'Safe'},
                {'id': 'label3', 'name': 'Other'}
            ]
        }

        # Execute
        result = server.get_label_id(mock_service, 'Safe')

        # Assert
        assert result == 'label2'

    def test_get_label_id_empty_labels(self):
        """Test creating label when no labels exist."""
        # Setup
        mock_service = Mock()
        mock_service.users().labels().list().execute.return_value = {'labels': []}
        mock_service.users().labels().create().execute.return_value = {'id': 'first_label_id'}

        # Execute
        result = server.get_label_id(mock_service, 'FirstLabel')

        # Assert
        assert result == 'first_label_id'


class TestGetEmailBody:
    """Tests for the get_email_body function."""

    def test_get_email_body_simple_body(self):
        """Test extracting body from simple email payload."""
        # Setup
        test_content = "Hello, this is a test email!"
        encoded_content = base64.urlsafe_b64encode(test_content.encode('utf-8')).decode('ascii')
        payload = {
            'body': {
                'data': encoded_content
            }
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result == test_content

    def test_get_email_body_multipart_text_plain(self):
        """Test extracting body from multipart email with text/plain part."""
        # Setup
        test_content = "This is plain text content"
        encoded_content = base64.urlsafe_b64encode(test_content.encode('utf-8')).decode('ascii')
        payload = {
            'parts': [
                {
                    'mimeType': 'text/html',
                    'body': {'data': 'html_content'}
                },
                {
                    'mimeType': 'text/plain',
                    'body': {'data': encoded_content}
                }
            ]
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result == test_content

    def test_get_email_body_nested_multipart(self):
        """Test extracting body from nested multipart email."""
        # Setup
        test_content = "Nested content"
        encoded_content = base64.urlsafe_b64encode(test_content.encode('utf-8')).decode('ascii')
        payload = {
            'parts': [
                {
                    'mimeType': 'multipart/alternative',
                    'parts': [
                        {
                            'mimeType': 'text/plain',
                            'body': {'data': encoded_content}
                        }
                    ]
                }
            ]
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result == test_content

    def test_get_email_body_fallback_to_first_part(self):
        """Test fallback to first part when no text/plain found."""
        # Setup
        test_content = "Fallback content"
        encoded_content = base64.urlsafe_b64encode(test_content.encode('utf-8')).decode('ascii')
        payload = {
            'parts': [
                {
                    'mimeType': 'text/html',
                    'body': {'data': encoded_content}
                },
                {
                    'mimeType': 'application/pdf',
                    'body': {'data': 'pdf_content'}
                }
            ]
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result == test_content

    def test_get_email_body_no_content(self):
        """Test handling email with no body content."""
        # Setup
        payload = {}

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result == "No body content"

    def test_get_email_body_decode_error_utf8_fallback_latin1(self):
        """Test handling decode error with fallback to latin-1."""
        # Setup - create invalid UTF-8 that's valid latin-1
        invalid_utf8_bytes = b'\xff\xfe'  # Invalid UTF-8, valid latin-1
        encoded_content = base64.urlsafe_b64encode(invalid_utf8_bytes).decode('ascii')
        payload = {
            'body': {
                'data': encoded_content
            }
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result == invalid_utf8_bytes.decode('latin-1')

    def test_get_email_body_decode_error_both_encodings(self):
        """Test handling decode error when both UTF-8 and latin-1 fail."""
        # Setup - create content that will fail base64 decode
        payload = {
            'body': {
                'data': 'invalid_base64!'
            }
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result.startswith("Error decoding body:")

    def test_get_email_body_multipart_decode_error(self):
        """Test handling decode error in multipart email."""
        # Setup
        payload = {
            'parts': [
                {
                    'mimeType': 'text/plain',
                    'body': {'data': 'invalid_base64!'}
                }
            ]
        }

        # Execute
        result = server.get_email_body(payload)

        # Assert
        assert result.startswith("Error decoding body:")


class TestListEmails:
    """Tests for the list_emails function."""

    @patch('server.get_gmail_service')
    @patch('server.get_label_id')
    async def test_list_emails_success(self, mock_get_label_id, mock_get_gmail_service):
        """Test successful email listing."""
        # Setup
        mock_service = Mock()
        mock_get_gmail_service.return_value = mock_service
        mock_get_label_id.return_value = 'test_label_id'
        
        # Mock the messages list response
        mock_service.users().messages().list().execute.return_value = {
            'messages': [
                {'id': 'msg1'},
                {'id': 'msg2'}
            ]
        }
        
        # Mock individual message responses
        def mock_get_message(userId, id, format):
            if id == 'msg1':
                return Mock(execute=Mock(return_value={
                    'payload': {
                        'headers': [
                            {'name': 'Subject', 'value': 'Test Subject 1'},
                            {'name': 'From', 'value': 'test1@example.com'}
                        ],
                        'body': {
                            'data': base64.urlsafe_b64encode(b'Test body 1').decode('ascii')
                        }
                    }
                }))
            elif id == 'msg2':
                return Mock(execute=Mock(return_value={
                    'payload': {
                        'headers': [
                            {'name': 'Subject', 'value': 'Test Subject 2'},
                            {'name': 'From', 'value': 'test2@example.com'}
                        ],
                        'body': {
                            'data': base64.urlsafe_b64encode(b'Test body 2').decode('ascii')
                        }
                    }
                }))
        
        mock_service.users().messages().get.side_effect = mock_get_message

        # Execute
        result = await server.list_emails(max_results=2)

        # Assert
        assert len(result) == 2
        assert 'ID: msg1' in result[0]
        assert 'Subject: Test Subject 1' in result[0]
        assert 'From: test1@example.com' in result[0]
        assert 'Test body 1' in result[0]

    @patch('server.get_gmail_service')
    @patch('server.get_label_id')
    async def test_list_emails_no_messages(self, mock_get_label_id, mock_get_gmail_service):
        """Test listing emails when no messages exist."""
        # Setup
        mock_service = Mock()
        mock_get_gmail_service.return_value = mock_service
        mock_get_label_id.return_value = 'test_label_id'
        
        mock_service.users().messages().list().execute.return_value = {'messages': []}

        # Execute
        result = await server.list_emails()

        # Assert
        assert result == []

    @patch('server.get_gmail_service')
    @patch('server.get_label_id')
    async def test_list_emails_missing_headers(self, mock_get_label_id, mock_get_gmail_service):
        """Test listing emails with missing subject/from headers."""
        # Setup
        mock_service = Mock()
        mock_get_gmail_service.return_value = mock_service
        mock_get_label_id.return_value = 'test_label_id'
        
        mock_service.users().messages().list().execute.return_value = {
            'messages': [{'id': 'msg1'}]
        }
        
        mock_service.users().messages().get.return_value.execute.return_value = {
            'payload': {
                'headers': [],  # No headers
                'body': {
                    'data': base64.urlsafe_b64encode(b'Test body').decode('ascii')
                }
            }
        }

        # Execute
        result = await server.list_emails()

        # Assert
        assert len(result) == 1
        assert 'Subject: No Subject' in result[0]
        assert 'From: Unknown' in result[0]


class TestMarkEmailAsHandled:
    """Tests for the mark_email_as_handled function."""

    @patch('server.get_gmail_service')
    @patch('server.get_label_id')
    async def test_mark_email_as_handled_success(self, mock_get_label_id, mock_get_gmail_service):
        """Test successfully marking email as handled."""
        # Setup
        mock_service = Mock()
        mock_get_gmail_service.return_value = mock_service
        mock_get_label_id.return_value = 'test_label_id'

        # Execute
        await server.mark_email_as_handled('test_email_id')

        # Assert
        mock_service.users().messages().modify.assert_called_once_with(
            userId='me',
            id='test_email_id',
            body={'removeLabelIds': ['test_label_id', 'INBOX', 'UNREAD']}
        )


class TestConstants:
    """Tests for module constants and configuration."""

    def test_default_constants(self):
        """Test that default constants are set correctly."""
        assert server.SCOPES == ['https://www.googleapis.com/auth/gmail.modify']
        assert server.TOKEN_FILE == 'token.pickle'

    @patch.dict(os.environ, {'LABEL': 'CustomLabel'})
    def test_label_from_environment(self):
        """Test that LABEL can be set from environment variable."""
        # Need to reload the module to pick up the new environment variable
        import importlib
        importlib.reload(server)
        assert server.LABEL == 'CustomLabel'

    def test_mcp_instance(self):
        """Test that MCP instance is created correctly."""
        assert server.mcp is not None
        assert hasattr(server.mcp, 'tool')
