# tests/test_esewa_client_v2.py

import pytest
from unittest.mock import patch, MagicMock # For mocking requests.Session.get/post
import requests # For requests.exceptions
import base64
import json
import hmac # For hmac.compare_digest

# Import necessary components from your library
from nepal_gateways import (
    EsewaClient,
    ConfigurationError,
    InitiationError,
    VerificationError,
    InvalidSignatureError,
    APIConnectionError,
    APITimeoutError
)
# For testing internal helper if needed (usually test public API, but signature is key)
from nepal_gateways.esewa.client import _generate_esewa_signature
from nepal_gateways.esewa.config import ESEWA_SANDBOX_SECRET_KEY_DEFAULT, ESEWA_DEFAULT_REQUEST_SIGNED_FIELD_NAMES

# --- Test Configurations ---
VALID_SANDBOX_CONFIG = {
    "product_code": "EPAYTEST",
    "secret_key": ESEWA_SANDBOX_SECRET_KEY_DEFAULT, # "8gBm/:&EnhH.1/q"
    "success_url": "https://merchant.com/esewa/success",
    "failure_url": "https://merchant.com/esewa/failure",
    "mode": "sandbox"
}

VALID_LIVE_CONFIG = {
    "product_code": "LIVEPRODCODE",
    "secret_key": "LIVE_SECRET_KEY_ABC_123",
    "success_url": "https://merchant.com/esewa/success",
    "failure_url": "https://merchant.com/esewa/failure",
    "mode": "live"
}

# --- Pytest Fixtures ---
@pytest.fixture
def sandbox_client():
    """Returns an EsewaClient instance configured for sandbox."""
    return EsewaClient(config=VALID_SANDBOX_CONFIG)

@pytest.fixture
def live_client():
    """Returns an EsewaClient instance configured for live."""
    return EsewaClient(config=VALID_LIVE_CONFIG)

# --- Test Cases ---

# 1. Test Client Initialization
class TestEsewaClientInitialization:
    def test_sandbox_initialization_success(self, sandbox_client):
        assert sandbox_client.mode == "sandbox"
        assert sandbox_client.product_code == VALID_SANDBOX_CONFIG["product_code"]
        assert sandbox_client.secret_key == VALID_SANDBOX_CONFIG["secret_key"]
        assert "rc-epay.esewa.com.np" in sandbox_client.initiation_endpoint
        assert "rc.esewa.com.np" in sandbox_client.status_check_endpoint

    def test_live_initialization_success(self, live_client):
        assert live_client.mode == "live"
        assert live_client.product_code == VALID_LIVE_CONFIG["product_code"]
        assert live_client.secret_key == VALID_LIVE_CONFIG["secret_key"]
        assert "epay.esewa.com.np" in live_client.initiation_endpoint # Main live domain
        assert "epay.esewa.com.np" in live_client.status_check_endpoint

    def test_initialization_missing_product_code(self):
        config = VALID_SANDBOX_CONFIG.copy()
        del config["product_code"]
        with pytest.raises(ConfigurationError, match="Missing required configuration key.*product_code"):
            EsewaClient(config=config)

    def test_initialization_missing_secret_key_live_mode(self):
        config = VALID_LIVE_CONFIG.copy()
        del config["secret_key"]
        with pytest.raises(ConfigurationError, match="eSewa 'secret_key' is absolutely required for live mode"):
            EsewaClient(config=config)

    def test_initialization_sandbox_uses_default_secret_if_not_provided(self):
        config = VALID_SANDBOX_CONFIG.copy()
        del config["secret_key"] # User doesn't provide it
        client = EsewaClient(config=config)
        assert client.secret_key == ESEWA_SANDBOX_SECRET_KEY_DEFAULT

    def test_initialization_invalid_mode(self):
        config = VALID_SANDBOX_CONFIG.copy()
        config["mode"] = "invalid_mode"
        with pytest.raises(ConfigurationError, match="Invalid 'mode' configuration"):
            EsewaClient(config=config)


# 2. Test Payment Initiation
class TestEsewaInitiatePayment:
    def test_initiate_payment_signature_and_fields(self, sandbox_client):
        order_id = "test-order-001"
        amount = 100.00 # Will be formatted to "100"
        tax = 0.0
        psc = 0.0
        pdc = 0.0
        total_amount_expected_str = "100" # Based on _format_amount_for_esewa

        response = sandbox_client.initiate_payment(
            amount=amount, order_id=order_id, tax_amount=tax,
            product_service_charge=psc, product_delivery_charge=pdc
        )

        assert response.is_redirect_required is True
        assert response.redirect_method == "POST"
        assert sandbox_client.initiation_endpoint == response.redirect_url

        form_fields = response.form_fields
        assert form_fields["amount"] == "100"
        assert form_fields["tax_amount"] == "0"
        assert form_fields["total_amount"] == total_amount_expected_str
        assert form_fields["transaction_uuid"] == order_id
        assert form_fields["product_code"] == sandbox_client.product_code
        assert form_fields["product_service_charge"] == "0"
        assert form_fields["product_delivery_charge"] == "0"
        assert form_fields["success_url"] == VALID_SANDBOX_CONFIG["success_url"]
        assert form_fields["failure_url"] == VALID_SANDBOX_CONFIG["failure_url"]
        assert form_fields["signed_field_names"] == ESEWA_DEFAULT_REQUEST_SIGNED_FIELD_NAMES

        # Verify signature
        expected_message = f"total_amount={total_amount_expected_str},transaction_uuid={order_id},product_code={sandbox_client.product_code}"
        expected_signature = _generate_esewa_signature(expected_message, sandbox_client.secret_key)
        assert form_fields["signature"] == expected_signature

    def test_initiate_payment_with_decimal_amounts(self, sandbox_client):
        order_id = "test-order-002"
        amount = 100.50
        tax = 10.25
        # total = 110.75
        total_amount_expected_str = "110.75" # _format_amount_for_esewa for 110.75 -> "110.75"

        response = sandbox_client.initiate_payment(amount=amount, order_id=order_id, tax_amount=tax)
        form_fields = response.form_fields
        assert form_fields["amount"] == "100.5" # str(100.50) is "100.5"
        assert form_fields["tax_amount"] == "10.25"
        assert form_fields["total_amount"] == total_amount_expected_str

        expected_message = f"total_amount={total_amount_expected_str},transaction_uuid={order_id},product_code={sandbox_client.product_code}"
        expected_signature = _generate_esewa_signature(expected_message, sandbox_client.secret_key)
        assert form_fields["signature"] == expected_signature

    def test_initiate_payment_override_urls(self, sandbox_client):
        custom_success = "https://custom.com/success"
        custom_failure = "https://custom.com/failure"
        response = sandbox_client.initiate_payment(
            amount=50, order_id="test-urls",
            success_url=custom_success, failure_url=custom_failure
        )
        assert response.form_fields["success_url"] == custom_success
        assert response.form_fields["failure_url"] == custom_failure

# 3. Test Callback Signature Verification (_verify_callback_signature - internal method but crucial)
class TestEsewaCallbackSignature:
    def test_verify_valid_callback_signature(self, sandbox_client):
        # Data based on eSewa documentation example, adjusted for consistency
        callback_data = {
            "transaction_code": "000AWEO",
            "status": "COMPLETE",
            "total_amount": "1000.0", # String as per eSewa example
            "transaction_uuid": "250610-162413",
            "product_code": "EPAYTEST", # Ensure client is configured with this for test
            "signed_field_names": "transaction_code,status,total_amount,transaction_uuid,product_code,signed_field_names",
            # This signature is from eSewa docs for the above data and UAT key
            "signature": "62GcfZTmVkzhtUeh+QJ1AqiJrjoWWGof3U+eTPTZ7fA="
        }
        # Temporarily set product_code to match example if fixture is different
        original_product_code = sandbox_client.product_code
        sandbox_client.product_code = "EPAYTEST"
        assert sandbox_client._verify_callback_signature(callback_data) is True
        sandbox_client.product_code = original_product_code # Reset

    def test_verify_invalid_callback_signature(self, sandbox_client):
        callback_data = {
            "transaction_code": "000AWEO", "status": "COMPLETE", "total_amount": "1000.0",
            "transaction_uuid": "250610-162413", "product_code": "EPAYTEST",
            "signed_field_names": "transaction_code,status,total_amount,transaction_uuid,product_code,signed_field_names",
            "signature": "TAMPERED_SIGNATURE_VALUE"
        }
        original_product_code = sandbox_client.product_code
        sandbox_client.product_code = "EPAYTEST"
        assert sandbox_client._verify_callback_signature(callback_data) is False
        sandbox_client.product_code = original_product_code

    def test_verify_callback_signature_missing_fields(self, sandbox_client):
        callback_data = {"signature": "abc", "signed_field_names": "field_a"} # field_a missing
        assert sandbox_client._verify_callback_signature(callback_data) is False


# 4. Test Payment Verification (verify_payment method - mocking external API call)
@patch('nepal_gateways.esewa.client.requests.Session.get') # Patch where 'get' is looked up
class TestEsewaVerifyPayment:

    def _prepare_valid_signed_callback_data(self, transaction_uuid, total_amount_str, product_code, secret_key):
        callback_json_data = {
            "transaction_code": "TC123", "status": "COMPLETE", "total_amount": total_amount_str,
            "transaction_uuid": transaction_uuid, "product_code": product_code,
            # eSewa includes 'signed_field_names' itself in the string for response signature.
            "signed_field_names": "transaction_code,status,total_amount,transaction_uuid,product_code,signed_field_names",
        }
        msg_parts = []
        for field in callback_json_data["signed_field_names"].split(','):
            field_value = str(callback_json_data.get(field, '')) # Use get for signed_field_names itself
            if field == "signed_field_names" and field not in callback_json_data : # Special handling if signed_field_names is not yet in dict but is being added to string
                 field_value = callback_json_data["signed_field_names"]

            msg_parts.append(f"{field}={field_value}")

        sig_msg = ",".join(msg_parts)
        callback_json_data["signature"] = _generate_esewa_signature(sig_msg, secret_key)

        base64_encoded_callback = base64.b64encode(json.dumps(callback_json_data).encode('utf-8')).decode('utf-8')
        return {"data": base64_encoded_callback}, callback_json_data # Return raw for client, and parsed for assertions


    def test_verify_payment_success(self, mock_requests_get, sandbox_client):
        tx_uuid = "verify-success-001"
        total_amt_str = "150.0" # Note: eSewa callback example has amount as string "100.0"
        
        raw_callback, parsed_callback_for_assert = self._prepare_valid_signed_callback_data(
            tx_uuid, total_amt_str, sandbox_client.product_code, sandbox_client.secret_key
        )

        # Mock the Status Check API response
        mock_api_response = MagicMock()
        mock_api_response.status_code = 200
        mock_api_response.json.return_value = {
            "status": "COMPLETE", "ref_id": "ESEWA-REF-001", "transaction_uuid": tx_uuid,
            "total_amount": float(total_amt_str), "product_code": sandbox_client.product_code,
            "message": "Transaction is complete."
        }
        mock_requests_get.return_value = mock_api_response

        result = sandbox_client.verify_payment(raw_callback)

        assert result.is_successful is True
        assert result.status_code == "COMPLETE"
        assert result.transaction_id == "ESEWA-REF-001"
        assert result.order_id == tx_uuid
        assert result.verified_amount == float(total_amt_str)
        mock_requests_get.assert_called_once()
        # Check params of the GET request to status check API
        called_args, called_kwargs = mock_requests_get.call_args
        api_params = called_kwargs['params']
        assert api_params['product_code'] == sandbox_client.product_code
        assert api_params['total_amount'] == float(total_amt_str)
        assert api_params['transaction_uuid'] == tx_uuid


    def test_verify_payment_callback_invalid_signature(self, mock_requests_get, sandbox_client):
        # Prepare callback data with a known invalid signature
        raw_callback, _ = self._prepare_valid_signed_callback_data(
            "invalid-sig-tx", "50.0", sandbox_client.product_code, sandbox_client.secret_key
        )
        # Tamper the signature
        decoded_json_str = base64.b64decode(raw_callback['data']).decode('utf-8')
        tampered_data = json.loads(decoded_json_str)
        tampered_data['signature'] = "INVALID_SIGNATURE_HERE"
        raw_callback['data'] = base64.b64encode(json.dumps(tampered_data).encode('utf-8')).decode('utf-8')

        with pytest.raises(InvalidSignatureError):
            sandbox_client.verify_payment(raw_callback)
        mock_requests_get.assert_not_called() # Status API should not be called if signature fails


    def test_verify_payment_status_api_failure(self, mock_requests_get, sandbox_client):
        tx_uuid = "api-fail-001"
        total_amt_str = "75.0"
        raw_callback, _ = self._prepare_valid_signed_callback_data(
            tx_uuid, total_amt_str, sandbox_client.product_code, sandbox_client.secret_key
        )

        mock_api_response = MagicMock()
        mock_api_response.status_code = 200
        mock_api_response.json.return_value = {"status": "FAILURE", "message": "Payment declined by bank"}
        mock_requests_get.return_value = mock_api_response

        result = sandbox_client.verify_payment(raw_callback)
        assert result.is_successful is False
        assert result.status_code == "FAILURE"
        assert result.status_message == "Payment declined by bank"


    def test_verify_payment_status_api_network_timeout(self, mock_requests_get, sandbox_client):
        tx_uuid = "api-timeout-001"
        total_amt_str = "25.0"
        raw_callback, _ = self._prepare_valid_signed_callback_data(
            tx_uuid, total_amt_str, sandbox_client.product_code, sandbox_client.secret_key
        )
        mock_requests_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        with pytest.raises(APITimeoutError):
            sandbox_client.verify_payment(raw_callback)


    def test_verify_payment_status_api_connection_error(self, mock_requests_get, sandbox_client):
        tx_uuid = "api-conn-err-001"
        total_amt_str = "10.0"
        raw_callback, _ = self._prepare_valid_signed_callback_data(
            tx_uuid, total_amt_str, sandbox_client.product_code, sandbox_client.secret_key
        )
        # Simulate a requests.Response object for the exception
        mock_response = requests.Response()
        mock_response.status_code = 503 # Example server error
        mock_response._content = b"Service Unavailable"

        mock_requests_get.side_effect = requests.exceptions.ConnectionError("Failed to connect", response=mock_response)


        with pytest.raises(APIConnectionError) as excinfo:
            sandbox_client.verify_payment(raw_callback)
        assert excinfo.value.error_code == 503


    def test_verify_payment_malformed_base64_callback(self, mock_requests_get, sandbox_client):
        raw_callback = {"data": "this-is-not-base64-or-json"}
        with pytest.raises(VerificationError, match="Invalid Base64 encoded callback data"):
            sandbox_client.verify_payment(raw_callback)
        mock_requests_get.assert_not_called()

    def test_verify_payment_callback_product_code_mismatch(self, mock_requests_get, sandbox_client):
        tx_uuid = "product-mismatch-001"
        total_amt_str = "100.0"
        # Prepare callback with a product_code different from the client's configured one
        raw_callback, _ = self._prepare_valid_signed_callback_data(
            tx_uuid, total_amt_str, "DIFFERENT_PRODUCT_CODE", sandbox_client.secret_key
        )
        # Note: _verify_callback_signature might pass if the signature was generated with DIFFERENT_PRODUCT_CODE
        # but the check is after signature verification, before status API call.

        with pytest.raises(VerificationError, match="Product code mismatch in callback"):
            sandbox_client.verify_payment(raw_callback)
        mock_requests_get.assert_not_called()