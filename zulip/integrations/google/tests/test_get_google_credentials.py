#!/usr/bin/env python3
import json
import os
import runpy
from unittest.mock import MagicMock, patch

import pytest
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


TOKENS: dict = {
    "token": "mock_token",
    "refresh_token": "mock_refresh_token",
    "token_uri": "mock_token_uri",
    "client_id": "mock_client_id",
    "client_secret": "mock_client_secret",
    "scopes": ["https://www.googleapis.com/auth/calendar.events.readonly"],
    "universe_domain": "googleapis.com",
    "account": "",
    "expiry": "mock_expiry",
}

CLIENT_SECRET: dict = {
    "installed": {
        "client_id": "mock_client_id",
        "project_id": "mock_project_id",
        "auth_uri": "mock_auth_uri",
        "token_uri": "mock_token_uri",
        "auth_provider_x509_cert_url": "mock_auth_provider_x509_cert_url",
        "client_secret": "mock_client_secret",
    }
}


@pytest.fixture
def generate_tokens(tmp_path) -> str:
    """
    Generate a temporary tokens.json file for testing.
    Args:
        tmp_path: The temporary path fixture provided by pytest.
    Returns:
        str: The path to the generated tokens.json file.
    """
    tokens_path: str = tmp_path / "tokens.json"
    tokens: dict = TOKENS
    tokens_path.write_text(json.dumps(tokens))
    return str(tokens_path)


@pytest.fixture
def generate_client_secret(tmp_path: str) -> str:
    """
    Generate a temporary client_secret.json file for testing.

    Args:
        tmp_path: The temporary path fixture provided by pytest.

    Returns:
        str: The path to the generated client_secret.json file.
    """
    client_secret_path: str = tmp_path / "client_secret.json"
    client_secret: dict = CLIENT_SECRET
    client_secret_path.write_text(json.dumps(client_secret))
    return str(client_secret_path)


@patch("google.oauth2.credentials.Credentials.from_authorized_user_file")
@patch("google.auth.transport.requests.Request")
def test_get_valid_credentials(
    _: MagicMock,
    mock_from_authorized_user_file: MagicMock,
    generate_tokens: str,
    generate_client_secret: str,
) -> None:
    """
    Test the get_credentials function with valid credentials.

    Args:
        _: MagicMock: Mock for the Request class.
        mock_from_authorized_user_file: MagicMock: Mock for the from_authorized_user_file method.
        generate_tokens: str: Path to the generated tokens.json file.
        generate_client_secret: str: Path to the generated client_secret.json file.

    Returns:
        None
    """
    mock_credentials: MagicMock = MagicMock(spec=Credentials)
    mock_credentials.valid = True
    mock_from_authorized_user_file.return_value = mock_credentials
    creds: Credentials = runpy.run_path("../get-google-credentials")["get_credentials"](
        tokens_path=generate_tokens,
        client_secret_path=generate_client_secret,
        scopes=["https://www.googleapis.com/auth/calendar.events.readonly"],
    )
    assert creds.valid
    mock_from_authorized_user_file.assert_called_once_with(
        generate_tokens, ["https://www.googleapis.com/auth/calendar.events.readonly"]
    )


@patch("google.oauth2.credentials.Credentials.from_authorized_user_file")
@patch("google.auth.transport.requests.Request")
def test_get_expired_credentials(
    mock_request: MagicMock,
    mock_from_authorized_user_file: MagicMock,
    generate_tokens: str,
    generate_client_secret: str,
) -> None:
    """
    Test the get_credentials function with expired credentials.

    Args:
        mock_request: MagicMock: Mock for the Request class.
        mock_from_authorized_user_file: MagicMock: Mock for the from_authorized_user_file method.
        generate_tokens: str: Path to the generated tokens.json file.
        generate_client_secret: str: Path to the generated client_secret.json file.

    Returns:
        None
    """
    mock_credentials: MagicMock = MagicMock(spec=Credentials)
    mock_credentials.valid = False
    mock_credentials.expired = True
    mock_credentials.refresh_token = "mock_refresh_token"
    mock_credentials.to_json.return_value = json.dumps(TOKENS)
    mock_from_authorized_user_file.return_value = mock_credentials
    creds: Credentials = runpy.run_path("../get-google-credentials")["get_credentials"](
        tokens_path=generate_tokens,
        client_secret_path=generate_client_secret,
        scopes=["https://www.googleapis.com/auth/calendar.events.readonly"],
        noauth_local_webserver=False,
    )
    assert not creds.valid
    mock_from_authorized_user_file.assert_called_once_with(
        generate_tokens, ["https://www.googleapis.com/auth/calendar.events.readonly"]
    )
    mock_credentials.refresh.assert_called_once_with(mock_request())
    mock_credentials.to_json.assert_called_once()
    with open(generate_tokens, "w") as token_file:
        token_file.write(mock_credentials.to_json())
    with open(generate_tokens, "r") as token_file:
        token_data = json.load(token_file)
    assert token_data == json.loads(mock_credentials.to_json())


@patch("google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file")
def test_get_none_credentials(
    mock_from_client_secrets_file: MagicMock,
    generate_tokens: str,
    generate_client_secret: str,
) -> None:
    """
    Test the get_credentials function with None credentials.

    Args:
        mock_from_client_secrets_file: MagicMock: Mock for the from_client_secrets_file method.
        generate_tokens: str: Path to the generated tokens.json file.
        generate_client_secret: str: Path to the generated client_secret.json file.

    Returns:
        None
    """
    if os.path.exists(generate_tokens):
        os.remove(generate_tokens)
    mock_credentials: MagicMock = MagicMock(spec=Credentials)
    mock_credentials.valid = False
    mock_credentials.expired = False
    mock_credentials.refresh_token = None
    mock_credentials.to_json.return_value = json.dumps(TOKENS)
    mock_flow = mock_from_client_secrets_file.return_value
    mock_flow.run_local_server.return_value = mock_credentials
    creds: Credentials = runpy.run_path("../get-google-credentials")["get_credentials"](
        tokens_path=generate_tokens,
        client_secret_path=generate_client_secret,
        scopes=["https://www.googleapis.com/auth/calendar.events.readonly"],
        noauth_local_webserver=False,
    )
    assert creds == mock_credentials
    mock_flow.run_local_server.assert_called_once_with(
        port=0,
    )
    mock_from_client_secrets_file.assert_called_once_with(
        client_secrets_file=generate_client_secret,
        scopes=["https://www.googleapis.com/auth/calendar.events.readonly"],
        redirect_uri=None,
    )
    assert os.path.exists(generate_tokens)
