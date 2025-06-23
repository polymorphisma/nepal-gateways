# tests/test_khalti_client.py

import pytest
from unittest.mock import patch, MagicMock
import requests  # For requests.exceptions
import json

# Import necessary components from your library
from nepal_gateways import (
    KhaltiClient,
    ConfigurationError,
    InitiationError,
    VerificationError,
    APIConnectionError,
    APITimeoutError,
)
from nepal_gateways.khalti.config import (  # Ensure these names match your config.py
    KHALTI_SANDBOX_BASE_URL_V2,
    KHALTI_LIVE_BASE_URL_V2,
    KHALTI_MIN_TRANSACTION_AMOUNT_PAISA,  # Ensure this is correctly named in your config
)

# --- Test Configurations ---
VALID_KHALTI_SANDBOX_CONFIG = {
    "live_secret_key": "d9a25c8411024a4abf56669b98a6c740",  # Your actual sandbox key
    "return_url_config": "https://merchant.com/khalti/callback",
    "website_url_config": "https://merchant.com",
    "mode": "sandbox",
}

VALID_KHALTI_LIVE_CONFIG = {
    "live_secret_key": "dummy-live-secret-key-for-testing-only-12345",  # Dummy for live config tests
    "return_url_config": "https://merchant.com/khalti/callback",
    "website_url_config": "https://merchant.com",
    "mode": "live",
}


# --- Pytest Fixtures ---
@pytest.fixture
def khalti_sandbox_client():
    """Returns a KhaltiClient instance configured for sandbox."""
    return KhaltiClient(config=VALID_KHALTI_SANDBOX_CONFIG)


@pytest.fixture
def khalti_live_client():
    """Returns a KhaltiClient instance configured for live."""
    return KhaltiClient(config=VALID_KHALTI_LIVE_CONFIG)


# --- Test Cases ---


# 1. Test Client Initialization
class TestKhaltiClientInitialization:
    def test_sandbox_initialization_success(self, khalti_sandbox_client):
        assert khalti_sandbox_client.mode == "sandbox"
        assert (
            khalti_sandbox_client.live_secret_key
            == VALID_KHALTI_SANDBOX_CONFIG["live_secret_key"]
        )
        assert (
            khalti_sandbox_client.default_return_url
            == VALID_KHALTI_SANDBOX_CONFIG["return_url_config"]
        )
        assert (
            khalti_sandbox_client.default_website_url
            == VALID_KHALTI_SANDBOX_CONFIG["website_url_config"]
        )
        assert khalti_sandbox_client.base_api_url == KHALTI_SANDBOX_BASE_URL_V2
        auth_header = khalti_sandbox_client.http_session.headers.get("Authorization")
        assert auth_header == f"Key {VALID_KHALTI_SANDBOX_CONFIG['live_secret_key']}"

    def test_live_initialization_success(self, khalti_live_client):
        assert khalti_live_client.mode == "live"
        assert khalti_live_client.base_api_url == KHALTI_LIVE_BASE_URL_V2
        auth_header = khalti_live_client.http_session.headers.get("Authorization")
        assert auth_header == f"Key {VALID_KHALTI_LIVE_CONFIG['live_secret_key']}"

    def test_initialization_missing_live_secret_key(self):
        config = VALID_KHALTI_SANDBOX_CONFIG.copy()
        del config["live_secret_key"]
        with pytest.raises(
            ConfigurationError,
            match="Missing required configuration key.*live_secret_key",
        ):
            KhaltiClient(config=config)

    def test_initialization_missing_return_url(self):
        config = VALID_KHALTI_SANDBOX_CONFIG.copy()
        del config["return_url_config"]
        with pytest.raises(
            ConfigurationError,
            match="Missing required configuration key.*return_url_config",
        ):
            KhaltiClient(config=config)

    def test_initialization_missing_website_url(self):
        config = VALID_KHALTI_SANDBOX_CONFIG.copy()
        del config["website_url_config"]
        with pytest.raises(
            ConfigurationError,
            match="Missing required configuration key.*website_url_config",
        ):
            KhaltiClient(config=config)


# 2. Test Payment Initiation
@patch("nepal_gateways.khalti.client.requests.Session.post")
class TestKhaltiInitiatePayment:
    def test_initiate_payment_success(self, mock_requests_post, khalti_sandbox_client):
        order_id = "test-order-kh001"
        amount_paisa = 1500
        description = "Khalti Test Product"

        mock_api_response = MagicMock()
        mock_api_response.status_code = 200
        expected_pidx = "KH-PIDX-123"
        expected_payment_url = f"https://test-pay.khalti.com/?pidx={expected_pidx}"
        mock_api_response.json.return_value = {
            "pidx": expected_pidx,
            "payment_url": expected_payment_url,
            "expires_at": "2025-01-01T12:00:00Z",
            "expires_in": 1800,
        }
        mock_requests_post.return_value = mock_api_response

        response = khalti_sandbox_client.initiate_payment(
            amount=amount_paisa,
            order_id=order_id,
            description=description,
            website_url="https://override-site.com",  # Test overriding default
        )

        assert response.is_redirect_required is True
        assert response.redirect_method == "GET"
        assert response.redirect_url == expected_payment_url
        assert response.payment_instructions["pidx"] == expected_pidx
        assert response.raw_response == mock_api_response.json.return_value

        mock_requests_post.assert_called_once()
        # Corrected way to access call arguments when json=payload is used
        called_url = mock_requests_post.call_args.args[0]
        called_json_payload = mock_requests_post.call_args.kwargs["json"]

        assert called_url == khalti_sandbox_client.initiation_endpoint
        assert called_json_payload["amount"] == amount_paisa
        assert called_json_payload["purchase_order_id"] == order_id
        assert called_json_payload["purchase_order_name"] == description
        assert (
            called_json_payload["return_url"]
            == VALID_KHALTI_SANDBOX_CONFIG["return_url_config"]
        )
        assert called_json_payload["website_url"] == "https://override-site.com"

    def test_initiate_payment_invalid_amount_too_low(
        self, mock_requests_post, khalti_sandbox_client
    ):
        with pytest.raises(
            InitiationError,
            match=f"Khalti amount must be an integer in paisa and greater than {KHALTI_MIN_TRANSACTION_AMOUNT_PAISA -1} paisa",
        ):
            khalti_sandbox_client.initiate_payment(
                amount=KHALTI_MIN_TRANSACTION_AMOUNT_PAISA - 1,
                order_id="test",
                description="test",
            )
        mock_requests_post.assert_not_called()

    def test_initiate_payment_invalid_amount_not_integer(
        self, mock_requests_post, khalti_sandbox_client
    ):
        with pytest.raises(
            InitiationError, match="Khalti amount must be an integer in paisa"
        ):
            khalti_sandbox_client.initiate_payment(amount=1000.50, order_id="test", description="test")  # type: ignore
        mock_requests_post.assert_not_called()

    def test_initiate_payment_api_validation_error(
        self, mock_requests_post, khalti_sandbox_client
    ):
        mock_api_response = MagicMock()
        mock_api_response.status_code = 400
        error_detail = {
            "amount": ["Amount should be greater than Rs. 10, that is 1000 paisa."],
            "error_key": "validation_error",
        }
        mock_api_response.json.return_value = error_detail
        mock_api_response.text = json.dumps(error_detail)
        mock_requests_post.return_value = mock_api_response

        with pytest.raises(
            InitiationError,
            match="Khalti initiation API error: amount: Amount should be greater than Rs. 10",
        ) as excinfo:
            khalti_sandbox_client.initiate_payment(
                amount=1100, order_id="test", description="test"
            )

        assert excinfo.value.gateway_response == error_detail
        assert excinfo.value.error_code == "validation_error"

    def test_initiate_payment_api_auth_error(
        self, mock_requests_post, khalti_sandbox_client
    ):
        mock_api_response = MagicMock()
        mock_api_response.status_code = 401
        error_detail = {"detail": "Invalid token.", "status_code": 401}
        mock_api_response.json.return_value = error_detail
        mock_api_response.text = json.dumps(error_detail)
        mock_requests_post.return_value = mock_api_response

        with pytest.raises(
            ConfigurationError, match="Khalti initiation API error: Invalid token."
        ) as excinfo:
            khalti_sandbox_client.initiate_payment(
                amount=1100, order_id="test", description="test"
            )

        assert excinfo.value.gateway_response == error_detail
        assert excinfo.value.error_code == 401

    def test_initiate_payment_network_timeout(
        self, mock_requests_post, khalti_sandbox_client
    ):
        mock_requests_post.side_effect = requests.exceptions.Timeout(
            "Connection timed out"
        )
        with pytest.raises(APITimeoutError):
            khalti_sandbox_client.initiate_payment(
                amount=1100, order_id="test", description="test"
            )

    def test_initiate_payment_connection_error(
        self, mock_requests_post, khalti_sandbox_client
    ):
        mock_requests_post.side_effect = requests.exceptions.ConnectionError(
            "Failed to connect"
        )
        with pytest.raises(APIConnectionError):
            khalti_sandbox_client.initiate_payment(
                amount=1100, order_id="test", description="test"
            )


# 3. Test Payment Verification (verify_payment method - mocking external API call)
@patch("nepal_gateways.khalti.client.requests.Session.post")
class TestKhaltiVerifyPayment:
    def test_verify_payment_success(self, mock_requests_post, khalti_sandbox_client):
        pidx_from_callback = "valid-pidx-001"
        callback_data = {
            "pidx": pidx_from_callback,
            "status": "Completed",
            "amount": "2000",
        }

        mock_api_response = MagicMock()
        mock_api_response.status_code = 200
        lookup_api_json = {
            "pidx": pidx_from_callback,
            "total_amount": 2000,
            "status": "Completed",
            "transaction_id": "KHALTI-TXN-ID-FINAL",
            "fee": 50,
            "refunded": False,
        }
        mock_api_response.json.return_value = lookup_api_json
        mock_requests_post.return_value = mock_api_response

        result = khalti_sandbox_client.verify_payment(callback_data)

        assert result.is_successful is True
        assert result.status_code == "Completed"
        assert result.transaction_id == "KHALTI-TXN-ID-FINAL"
        assert result.order_id == pidx_from_callback
        assert result.verified_amount == 2000

        mock_requests_post.assert_called_once()
        # Corrected way to access call arguments
        called_url = mock_requests_post.call_args.args[0]
        called_json_payload = mock_requests_post.call_args.kwargs["json"]

        assert called_url == khalti_sandbox_client.lookup_endpoint
        assert called_json_payload == {"pidx": pidx_from_callback}

    def test_verify_payment_lookup_status_pending(
        self, mock_requests_post, khalti_sandbox_client
    ):
        pidx_from_callback = "pending-pidx-002"
        callback_data = {"pidx": pidx_from_callback, "status": "Pending"}

        mock_api_response = MagicMock()
        mock_api_response.status_code = 200
        mock_api_response.json.return_value = {
            "pidx": pidx_from_callback,
            "total_amount": 1500,
            "status": "Pending",
            "transaction_id": None,
            "fee": 0,
            "refunded": False,
        }
        mock_requests_post.return_value = mock_api_response

        result = khalti_sandbox_client.verify_payment(callback_data)
        assert result.is_successful is False
        assert result.status_code == "Pending"

    def test_verify_payment_missing_pidx_in_callback(
        self, mock_requests_post, khalti_sandbox_client
    ):
        callback_data = {"status": "Completed"}
        with pytest.raises(
            VerificationError, match="Missing 'pidx' in Khalti callback data"
        ):
            khalti_sandbox_client.verify_payment(callback_data)
        mock_requests_post.assert_not_called()

    def test_verify_payment_lookup_api_error_not_found(
        self, mock_requests_post, khalti_sandbox_client
    ):
        pidx_from_callback = "error-pidx-003"
        callback_data = {"pidx": pidx_from_callback}

        mock_api_response = MagicMock()
        mock_api_response.status_code = 404
        error_detail = {"detail": "Not found.", "error_key": "validation_error"}
        mock_api_response.json.return_value = error_detail
        mock_api_response.text = json.dumps(error_detail)
        mock_requests_post.return_value = mock_api_response

        with pytest.raises(
            VerificationError, match="Khalti lookup API error: Not found."
        ) as excinfo:
            khalti_sandbox_client.verify_payment(callback_data)

        assert excinfo.value.gateway_response == error_detail
        assert excinfo.value.error_code == "validation_error"

    def test_verify_payment_lookup_api_network_timeout(
        self, mock_requests_post, khalti_sandbox_client
    ):
        pidx_from_callback = "timeout-pidx-004"
        callback_data = {"pidx": pidx_from_callback}
        mock_requests_post.side_effect = requests.exceptions.Timeout("Lookup timed out")

        with pytest.raises(APITimeoutError):
            khalti_sandbox_client.verify_payment(callback_data)

    def test_verify_payment_lookup_api_connection_error(
        self, mock_requests_post, khalti_sandbox_client
    ):
        pidx_from_callback = "conn-err-pidx-005"
        callback_data = {"pidx": pidx_from_callback}
        mock_response = requests.Response()
        mock_response.status_code = 503
        mock_response._content = b"Service Down"  # Set content for text attribute
        mock_requests_post.side_effect = requests.exceptions.ConnectionError(
            "Failed to connect", response=mock_response
        )

        with pytest.raises(APIConnectionError) as excinfo:
            khalti_sandbox_client.verify_payment(callback_data)
        # Note: requests.exceptions.ConnectionError often doesn't have a response attached
        # in the same way HTTPError does, so e.response might be None.
        # The error_code on APIConnectionError might be None in this specific case.
        # Let's check the message.
        assert "Failed to connect" in str(excinfo.value)

    def test_verify_payment_lookup_api_returns_non_json(
        self, mock_requests_post, khalti_sandbox_client
    ):
        pidx_from_callback = "non-json-pidx-006"
        callback_data = {"pidx": pidx_from_callback}

        mock_api_response = MagicMock()
        mock_api_response.status_code = 200  # API call itself is "OK"
        mock_api_response.json.side_effect = json.JSONDecodeError(
            "Expecting value", "doc", 0
        )  # Simulate JSON error
        mock_api_response.text = "This is not JSON"  # What response.text would be
        mock_requests_post.return_value = mock_api_response

        with pytest.raises(
            VerificationError, match="Invalid JSON response from Khalti Lookup API."
        ):
            khalti_sandbox_client.verify_payment(callback_data)
