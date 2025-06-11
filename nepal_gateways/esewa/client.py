# nepal_gateways/esewa/client.py

import logging
import hmac
import hashlib
import base64
import json
from typing import Dict, Any, Optional, Union
import requests

from ..core.base import (
    BasePaymentGateway,
    PaymentInitiationResponse,
    PaymentVerificationResult,
    Amount, OrderID, CallbackURL, HTTPMethod
)
from ..core.exceptions import (
    ConfigurationError,
    InitiationError,
    VerificationError,
    InvalidSignatureError,
    APIConnectionError,
    APITimeoutError
)
from .config import (
    ESEWA_SANDBOX_INITIATION_URL_V2,
    ESEWA_LIVE_INITIATION_URL_V2,
    ESEWA_SANDBOX_STATUS_CHECK_URL,
    ESEWA_LIVE_STATUS_CHECK_URL,
    ESEWA_SANDBOX_SECRET_KEY_DEFAULT,
    ESEWA_DEFAULT_REQUEST_SIGNED_FIELD_NAMES,
    ESEWA_CALLBACK_DATA_PARAM_NAME
)

logger = logging.getLogger(__name__)

# --- Helper for Signature Generation ---
def _generate_esewa_signature(message: str, secret_key: str) -> str:
    """Generates HMAC-SHA256 signature and encodes it in Base64."""
    try:
        hashed_object = hmac.new(secret_key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(hashed_object.digest()).decode('utf-8')
    except Exception as e:
        logger.error(f"Error during signature generation: {e}")
        raise # Re-raise to be caught by calling function


# --- Concrete Response Implementations for eSewa (v2) ---
class EsewaV2InitiationResponse(PaymentInitiationResponse):
    def __init__(self, redirect_url: str, form_fields: Dict[str, Any]):
        self._redirect_url = redirect_url
        self._form_fields = form_fields
        logger.debug(
            f"EsewaV2InitiationResponse created: URL='{redirect_url}', Method='POST', "
            f"Fields={list(form_fields.keys())}"
        )

    @property
    def is_redirect_required(self) -> bool: 
        return True
    @property
    def redirect_url(self) -> str: 
        return self._redirect_url
    @property
    def redirect_method(self) -> HTTPMethod: 
        return "POST"
    @property
    def form_fields(self) -> Dict[str, Any]: 
        return self._form_fields
    @property
    def payment_instructions(self) -> Optional[Dict[str, Any]]: 
        return None
    @property
    def raw_response(self) -> Any:
        return {"message": "Form data prepared for eSewa v2 POST redirect."}


class EsewaV2VerificationResult(PaymentVerificationResult):
    def __init__(self, is_successful: bool, status_code: Optional[str], status_message: str,
                 raw_api_response: Dict[str, Any], transaction_id: Optional[str] = None,
                 order_id: Optional[OrderID] = None, verified_amount: Optional[Amount] = None):
        self._is_successful = is_successful
        self._status_code = status_code # e.g., "COMPLETE", "PENDING"
        self._status_message = status_message
        self._raw_response = raw_api_response # This will be the JSON from Status Check API
        self._transaction_id = transaction_id # eSewa's ref_id or transaction_code
        self._order_id = order_id # Merchant's transaction_uuid
        self._verified_amount = verified_amount
        self._gateway_specific_details = raw_api_response # The full parsed JSON

        logger.debug(
            f"EsewaV2VerificationResult created: Successful={is_successful}, Status='{status_code}', "
            f"TxID='{transaction_id}', OrderID='{order_id}', Amount='{verified_amount}'"
        )

    @property
    def is_successful(self) -> bool: 
        return self._is_successful
    @property
    def status_code(self) -> Optional[str]: 
        return self._status_code
    @property
    def status_message(self) -> str: 
        return self._status_message
    @property
    def transaction_id(self) -> Optional[str]: 
        return self._transaction_id
    @property
    def order_id(self) -> Optional[OrderID]: 
        return self._order_id
    @property
    def verified_amount(self) -> Optional[Amount]: 
        return self._verified_amount
    @property
    def raw_response(self) -> Dict[str, Any]: 
        return self._raw_response
    @property
    def gateway_specific_details(self) -> Dict[str, Any]: 
        return self._gateway_specific_details


# --- eSewa Client (v2) Implementation ---
class EsewaClient(BasePaymentGateway):
    """
    Client for interacting with the eSewa ePay v2 payment gateway (with HMAC signature).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config) # Handles 'mode'
        self.product_code: str = self._get_config_value('product_code', required=True) # This is the merchant code
        self.secret_key: str = self._get_config_value('secret_key', required=(self.mode == 'live'))
        if self.mode == 'sandbox' and not self.secret_key:
            self.secret_key = ESEWA_SANDBOX_SECRET_KEY_DEFAULT
            logger.warning(f"Using default SANDBOX secret key for eSewa. Product Code: {self.product_code[:4]}...")
        elif not self.secret_key: # Should be caught by required=True if live, but defensive check
             raise ConfigurationError("eSewa 'secret_key' is required for live mode.")


        self.default_success_url: CallbackURL = self._get_config_value('success_url', required=True)
        self.default_failure_url: CallbackURL = self._get_config_value('failure_url', required=True)

        if self.mode == 'sandbox':
            self.initiation_endpoint = ESEWA_SANDBOX_INITIATION_URL_V2
            self.status_check_endpoint = ESEWA_SANDBOX_STATUS_CHECK_URL
        else: # live mode
            self.initiation_endpoint = ESEWA_LIVE_INITIATION_URL_V2
            self.status_check_endpoint = ESEWA_LIVE_STATUS_CHECK_URL

        logger.info(
            f"EsewaClient (v2) initialized for Product Code: {self.product_code[:4]}... in {self.mode} mode. "
            f"Initiation: {self.initiation_endpoint}, Status Check: {self.status_check_endpoint}"
        )
        self.http_session = requests.Session()


    def _build_initiation_signature_message(self, total_amount: Amount, transaction_uuid: OrderID) -> str:
        # Message format: "total_amount=TA,transaction_uuid=TUUID,product_code=PCODE"
        # Values must be exactly as sent in the form.
        # Product code is from self.product_code
        # Order of fields in message string MUST BE total_amount,transaction_uuid,product_code
        msg = f"total_amount={total_amount},transaction_uuid={transaction_uuid},product_code={self.product_code}"
        logger.debug(f"eSewa initiation signature message: \"{msg}\"")
        return msg

    def initiate_payment(
        self,
        amount: Amount, # Base amount of product
        order_id: OrderID, # Maps to eSewa's transaction_uuid
        description: Optional[str] = None, # Not directly used by eSewa v2 form
        success_url: Optional[CallbackURL] = None,
        failure_url: Optional[CallbackURL] = None,
        # eSewa v2 specific amount fields:
        tax_amount: Amount = 0.0,
        product_service_charge: Amount = 0.0,
        product_delivery_charge: Amount = 0.0,
        # Other params from base are not directly used by eSewa v2 form
        customer_info: Optional[Dict[str, Any]] = None,
        product_details: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        **kwargs: Any
    ) -> EsewaV2InitiationResponse:

        amt_val = float(amount)
        tax_val = float(tax_amount)
        psc_val = float(product_service_charge)
        pdc_val = float(product_delivery_charge)

        total_amount_val = round(amt_val + tax_val + psc_val + pdc_val, 2) # Ensure 2 decimal places for amount
        transaction_uuid = str(order_id) # Use the merchant's order_id as transaction_uuid

        logger.info(
            f"Initiating eSewa v2 payment for TxUUID: '{transaction_uuid}', Total Amount: {total_amount_val}"
        )

        final_success_url = success_url or self.default_success_url
        final_failure_url = failure_url or self.default_failure_url

        # Generate signature
        signature_message = self._build_initiation_signature_message(total_amount_val, transaction_uuid)
        try:
            signature = _generate_esewa_signature(signature_message, self.secret_key)
        except Exception as e:
            logger.error(f"Failed to generate signature for eSewa initiation: {e}")
            raise InitiationError(f"Signature generation failed: {e}", original_exception=e)

        form_fields = {
            "amount": str(amt_val),
            "tax_amount": str(tax_val),
            "total_amount": str(total_amount_val),
            "transaction_uuid": transaction_uuid,
            "product_code": self.product_code,
            "product_service_charge": str(psc_val),
            "product_delivery_charge": str(pdc_val),
            "success_url": final_success_url,
            "failure_url": final_failure_url,
            "signed_field_names": ESEWA_DEFAULT_REQUEST_SIGNED_FIELD_NAMES,
            "signature": signature,
        }
        logger.debug(f"eSewa v2 initiation form fields prepared: {form_fields}")

        return EsewaV2InitiationResponse(
            redirect_url=self.initiation_endpoint,
            form_fields=form_fields
        )

    def _verify_callback_signature(self, callback_data: Dict[str, Any]) -> bool:
        """Verifies the signature received in the callback from eSewa."""
        received_signature = callback_data.get("signature")
        signed_fields_str = callback_data.get("signed_field_names")

        if not received_signature or not signed_fields_str:
            logger.error("Missing signature or signed_field_names in eSewa callback.")
            return False

        # Construct the message string from callback_data based on signed_fields_str
        # Order of fields in message string MUST BE as listed in signed_fields_str
        fields_to_sign = signed_fields_str.split(',')
        message_parts = []
        for field_name in fields_to_sign:
            field_name = field_name.strip() # Clean up field name
            if field_name in callback_data:
                 # Ensure values are strings, as they would be in an HTTP request/form context
                message_parts.append(f"{field_name}={str(callback_data[field_name])}")
            else:
                logger.error(f"Field '{field_name}' listed in signed_field_names not found in callback data.")
                return False # Or raise an error

        message_to_verify = ",".join(message_parts)
        logger.debug(f"eSewa callback signature verification message: \"{message_to_verify}\"")

        try:
            expected_signature = _generate_esewa_signature(message_to_verify, self.secret_key)
            logger.debug(f"Generated signature: {expected_signature}, Received signature: {received_signature}")
            return hmac.compare_digest(expected_signature, received_signature)
        except Exception as e:
            logger.error(f"Error during callback signature generation for verification: {e}")
            return False


    def verify_payment(
        self,
        transaction_data_from_callback: Dict[str, Any], # This is the raw callback data (query params or POST body)
        order_id_from_merchant_system: Optional[OrderID] = None, # Not directly used for API call, but for pre-check
        amount_from_merchant_system: Optional[Amount] = None,   # Not directly used for API call, but for pre-check
        **kwargs: Any
    ) -> EsewaV2VerificationResult:

        logger.info(f"Verifying eSewa v2 payment. Raw callback data: {transaction_data_from_callback}")

        # Step 1: Decode callback data if it's Base64 encoded JSON
        # Assuming data comes in a field specified by ESEWA_CALLBACK_DATA_PARAM_NAME if GET
        # Or if POST, transaction_data_from_callback might already be the decoded JSON dict.
        # This part NEEDS CLARIFICATION FROM ESEWA DOCS or TESTING.
        # For now, let's assume transaction_data_from_callback IS the decoded JSON if it's a dict,
        # or it's a string that needs Base64 decoding then JSON parsing if it's a single param.

        parsed_callback_data: Dict[str, Any]
        if isinstance(transaction_data_from_callback.get(ESEWA_CALLBACK_DATA_PARAM_NAME), str):
            # If data is in a single base64 encoded parameter
            base64_encoded_str = transaction_data_from_callback[ESEWA_CALLBACK_DATA_PARAM_NAME]
            logger.debug(f"Decoding Base64 callback data: {base64_encoded_str[:50]}...")
            try:
                decoded_json_str = base64.b64decode(base64_encoded_str).decode('utf-8')
                parsed_callback_data = json.loads(decoded_json_str)
                logger.debug(f"Parsed JSON from callback: {parsed_callback_data}")
            except Exception as e:
                logger.error(f"Failed to decode/parse Base64 callback data: {e}")
                raise VerificationError("Invalid Base64 encoded callback data from eSewa.", original_exception=e)
        elif isinstance(transaction_data_from_callback, dict) and "transaction_code" in transaction_data_from_callback:
            # If the callback data is already a parsed dictionary (e.g., from a JSON POST body)
            parsed_callback_data = transaction_data_from_callback
            logger.debug(f"Using provided dict as parsed callback data: {parsed_callback_data}")
        else:
            logger.error(f"Unrecognized eSewa callback data format: {transaction_data_from_callback}")
            raise VerificationError("Unrecognized eSewa callback data format.")


        # Step 2: Verify callback signature (CRUCIAL)
        if not self._verify_callback_signature(parsed_callback_data):
            logger.error("eSewa callback signature verification failed!")
            raise InvalidSignatureError(
                "eSewa callback signature mismatch. Potential tampering or misconfiguration.",
                gateway_response=parsed_callback_data
            )
        logger.info("eSewa callback signature verified successfully.")

        # Step 3: Extract necessary details for Status Check API
        # The callback data should contain transaction_uuid, product_code, total_amount needed for status check
        callback_transaction_uuid = parsed_callback_data.get("transaction_uuid")
        callback_product_code = parsed_callback_data.get("product_code") # Should match self.product_code
        callback_total_amount_str = parsed_callback_data.get("total_amount")
        # eSewa's transaction ID from callback
        esewa_transaction_code = parsed_callback_data.get("transaction_code")


        if not all([callback_transaction_uuid, callback_product_code, callback_total_amount_str]):
            msg = "Missing critical data (transaction_uuid, product_code, total_amount) in parsed eSewa callback for status check."
            logger.error(msg + f" Parsed Data: {parsed_callback_data}")
            raise VerificationError(msg, gateway_response=parsed_callback_data)

        if str(callback_product_code) != str(self.product_code):
            msg = f"Product code mismatch in callback. Expected: {self.product_code}, Got: {callback_product_code}"
            logger.error(msg)
            raise VerificationError(msg, gateway_response=parsed_callback_data)

        try:
            callback_total_amount = float(callback_total_amount_str)
        except ValueError:
            msg = f"Invalid total_amount format in parsed eSewa callback: '{callback_total_amount_str}'"
            logger.error(msg)
            raise VerificationError(msg, gateway_response=parsed_callback_data)


        # Step 4: Call eSewa's Status Check API
        status_check_params = {
            "product_code": self.product_code,
            "total_amount": callback_total_amount, # Use amount from trusted callback (after signature check)
            "transaction_uuid": callback_transaction_uuid,
        }
        logger.debug(f"Calling eSewa Status Check API: {self.status_check_endpoint} with params: {status_check_params}")

        try:
            response = self.http_session.get(
                self.status_check_endpoint,
                params=status_check_params,
                timeout=kwargs.get('timeout', 30)
            )
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            api_response_json = response.json()
            logger.debug(f"eSewa Status Check API JSON response: {api_response_json}")

            api_status = str(api_response_json.get("status", "UNKNOWN")).upper()
            api_ref_id = api_response_json.get("ref_id") # This is eSewa's transaction ID

            is_verified_successfully = (api_status == "COMPLETE")
            status_message = api_response_json.get("message", f"Status from API: {api_status}") # Or a more generic message

            if is_verified_successfully:
                logger.info(
                    f"eSewa payment VERIFIED (via Status API) for TxUUID: '{callback_transaction_uuid}', "
                    f"eSewa RefID: '{api_ref_id}', Status: {api_status}"
                )
            else:
                logger.warning(
                    f"eSewa payment status (via Status API) for TxUUID: '{callback_transaction_uuid}' is '{api_status}'. "
                    f"eSewa RefID: '{api_ref_id}'. Full Response: {api_response_json}"
                )

            return EsewaV2VerificationResult(
                is_successful=is_verified_successfully,
                status_code=api_status,
                status_message=status_message,
                raw_api_response=api_response_json,
                transaction_id=api_ref_id or esewa_transaction_code, # Prefer ref_id from status API
                order_id=callback_transaction_uuid, # This is the merchant's ID
                verified_amount=float(api_response_json.get("total_amount", callback_total_amount))
            )

        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during eSewa Status Check API call for TxUUID: {callback_transaction_uuid}. Error: {e}")
            raise APITimeoutError("eSewa Status Check API call timed out.", original_exception=e)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network/HTTP error during eSewa Status Check API call for TxUUID: {callback_transaction_uuid}. Error: {e}")
            error_code_from_response = e.response.status_code if e.response is not None else None
            gateway_response_text = e.response.text if e.response is not None else None
            raise APIConnectionError(
                f"Error calling eSewa Status Check API: {e}",
                original_exception=e,
                error_code=error_code_from_response,
                gateway_response=gateway_response_text
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response from eSewa Status Check API. Response text: {response.text[:200] if 'response' in locals() else 'N/A'}")
            raise VerificationError("Invalid JSON response from eSewa Status Check API.", original_exception=e)
        except Exception as e:
            logger.exception(f"Unexpected error during eSewa Status Check API call for TxUUID: {callback_transaction_uuid}. Error: {e}")
            raise VerificationError("An unexpected error occurred during eSewa status check.", original_exception=e)