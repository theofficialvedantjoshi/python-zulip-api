#!/usr/bin/env python3
import json
import os
import runpy
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from google.oauth2.credentials import Credentials

TOKENS: dict[str, Any] = {
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

CLIENT_SECRET: dict[str, dict[str, str]] = {
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
def generate_tokens(tmp_path: Path) -> str:
    # Generate a temporary tokens.json file for testing.
    tokens_path: Path = tmp_path / Path("tokens.json")
    tokens_path.write_text(json.dumps(TOKENS))
    return str(tokens_path)


@pytest.fixture
def generate_client_secret(tmp_path: Path) -> str:
    # Generate a temporary client_secret.json file for testing.
    client_secret_path: Path = tmp_path / Path("client_secret.json")
    client_secret_path.write_text(json.dumps(CLIENT_SECRET))
    return str(client_secret_path)


@patch("google.oauth2.credentials.Credentials.from_authorized_user_file")
@patch("google.auth.transport.requests.Request")
def test_get_valid_credentials(
    _: MagicMock,
    mock_from_authorized_user_file: MagicMock,
    generate_tokens: str,
    generate_client_secret: str,
) -> None:
    # Test the get_credentials function with valid credentials.
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
    # Test the get_credentials function with expired credentials.
    mock_credentials: MagicMock = MagicMock(spec=Credentials)
    mock_credentials.valid = False
    mock_credentials.expired = True
    mock_credentials.refresh_token = "mock_refresh_token"  # noqa: S105
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
    with open(generate_tokens) as token_file:
        token_data = json.load(token_file)
    assert token_data == json.loads(mock_credentials.to_json())


@patch("google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file")
def test_get_none_credentials(
    mock_from_client_secrets_file: MagicMock,
    generate_tokens: str,
    generate_client_secret: str,
) -> None:
    # Test the get_credentials function with None credentials.
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
