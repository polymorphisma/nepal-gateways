# nepal_gateways/esewa/client.py

import logging
import hmac
import hashlib
import base64
import json
from typing import Dict, Any, Optional, Union, List
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
        self.product_code: str = self._get_config_value('product_code', required=True)

        # _get_config_value will return None if 'secret_key' is not in config and no default is passed.
        user_provided_secret_key = self._get_config_value(
            'secret_key',
            required=False,
            default=None 
        )

        if self.mode == 'live':
            if not user_provided_secret_key:
                raise ConfigurationError("eSewa 'secret_key' is absolutely required for live mode.")
            self.secret_key: str = user_provided_secret_key
        elif self.mode == 'sandbox':
            if user_provided_secret_key:
                self.secret_key: str = user_provided_secret_key
            else:
                self.secret_key: str = ESEWA_SANDBOX_SECRET_KEY_DEFAULT
                logger.warning(
                    f"Using default SANDBOX secret key for eSewa. Product Code: {self.product_code[:4]}..."
                )

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

    def _format_amount_for_esewa(self, value: Amount) -> str:
        """
        Formats an amount value as a string for eSewa.
        If it's a whole number, returns an integer string (e.g., "100").
        Otherwise, returns a float string (e.g., "100.50", "100.5").
        eSewa seems to prefer integer strings for whole numbers in signatures.
        """
        f_value = float(value)
        if f_value.is_integer():
            return str(int(f_value))
        else:
            # For non-integers, eSewa likely expects a certain precision.
            # Let's use up to 2 decimal places, but str() on a float like 100.50 becomes "100.5"
            # If eSewa needs "100.50", you'd use "{:.2f}".format(f_value)
            # For now, let's try str() which is "100.5" for 100.50 or 100.5
            # The HTML form examples show integers for total_amount, so this path might be less common.
            # The API doc for status check shows "total_amount": 100.0 (with decimal) for a float.
            # This needs careful watching based on eSewa's strictness.
            # Let's stick to simple str() for non-integers for now, assuming eSewa is flexible.
            # If signature fails for 100.5 vs 100.50, then use "{:.2f}".format(f_value)
            return str(f_value) # Example: 100.5 -> "100.5", 100.0 (if not caught by is_integer) -> "100.0" (this case should be caught by is_integer)

    def _build_initiation_signature_message(self, total_amount_as_string: str, transaction_uuid_as_string: str) -> str:
        msg = f"total_amount={total_amount_as_string},transaction_uuid={transaction_uuid_as_string},product_code={self.product_code}"
        logger.debug(f"eSewa INITIATION signature message (for hashing): \"{msg}\"")
        return msg

    def initiate_payment(
        self,
        amount: Amount,                             # Base amount of product (maps to eSewa 'amount')
        order_id: OrderID,                          # Merchant's unique ID (maps to eSewa 'transaction_uuid')
        description: Optional[str] = None,          # General description, not directly used by eSewa v2 form
        success_url: Optional[CallbackURL] = None,  # Override default success_url
        failure_url: Optional[CallbackURL] = None,  # Override default failure_url
        customer_info: Optional[Dict[str, Any]] = None, # Not directly used by eSewa v2 form
        product_details: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None, # Not directly used by eSewa v2 form
        # eSewa v2 specific amount fields:
        tax_amount: Amount = 0.0,
        product_service_charge: Amount = 0.0,
        product_delivery_charge: Amount = 0.0,
        **kwargs: Any  # For any other gateway-specific parameters (not used by eSewa v2 std form)
    ) -> EsewaV2InitiationResponse:
        """
        Prepares the data required to initiate a payment with eSewa ePay v2.
        This involves generating a signature and constructing form fields for a POST redirect.

        Args:
            amount (Amount): The base amount of the product/service.
            order_id (OrderID): Your unique identifier for this transaction (will be used as transaction_uuid).
            description (Optional[str]): Not directly used by eSewa.
            success_url (Optional[CallbackURL]): Overrides the client's default success URL.
            failure_url (Optional[CallbackURL]): Overrides the client's default failure URL.
            customer_info (Optional[Dict[str, Any]]): Not directly used by eSewa.
            product_details (Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]): Not directly used by eSewa.
            tax_amount (Amount): Tax amount on the base product amount.
            product_service_charge (Amount): Service charge, if any.
            product_delivery_charge (Amount): Delivery charge, if any.
            **kwargs: Not used by standard eSewa v2 initiation.

        Returns:
            EsewaV2InitiationResponse: Contains the URL to POST to and the form fields.

        Raises:
            ConfigurationError: If success/failure URLs are not properly configured.
            InitiationError: If signature generation fails or other initiation issues occur.
        """

        # Converting all amount components to float first for calculation
        amt_val_float = float(amount)
        tax_val_float = float(tax_amount)
        psc_val_float = float(product_service_charge)
        pdc_val_float = float(product_delivery_charge)

        # Calculating total_amount as a float, ensuring rounding to 2 decimal places for currency
        total_amount_float = round(amt_val_float + tax_val_float + psc_val_float + pdc_val_float, 2)

        # Format amounts into strings as eSewa expects (integer string for whole numbers)
        amount_str_esewa = self._format_amount_for_esewa(amt_val_float)
        tax_amount_str_esewa = self._format_amount_for_esewa(tax_val_float)
        psc_str_esewa = self._format_amount_for_esewa(psc_val_float)
        pdc_str_esewa = self._format_amount_for_esewa(pdc_val_float)
        total_amount_str_esewa = self._format_amount_for_esewa(total_amount_float) # This is key for signature

        transaction_uuid_str = str(order_id) # Use merchant's order_id as transaction_uuid

        logger.info(
            f"Initiating eSewa v2 payment for TxUUID: '{transaction_uuid_str}', "
            f"Details: amount={amount_str_esewa}, tax={tax_amount_str_esewa}, "
            f"psc={psc_str_esewa}, pdc={pdc_str_esewa}, total_amount={total_amount_str_esewa}"
        )

        # Determine active success and failure URLs
        active_success_url = success_url if success_url is not None else self.default_success_url
        active_failure_url = failure_url if failure_url is not None else self.default_failure_url

        if not active_success_url or not active_failure_url:
            raise ConfigurationError(
                "Success and Failure URLs must be configured either in client "
                "or passed to initiate_payment."
            )

        # Generating the signature
        # The message for signature must use the correctly formatted total_amount_str_esewa
        signature_message = self._build_initiation_signature_message(
            total_amount_str_esewa,
            transaction_uuid_str
        )
        try:
            signature = _generate_esewa_signature(signature_message, self.secret_key)
        except Exception as e:
            logger.error(f"Failed to generate signature for eSewa initiation: {e}")
            raise InitiationError(f"Signature generation failed: {e}", original_exception=e)

        # Prepare all form fields that will be POSTed to eSewa
        form_fields = {
            "amount": amount_str_esewa,
            "tax_amount": tax_amount_str_esewa,
            "total_amount": total_amount_str_esewa, # CRITICAL: Must match value used in signature
            "transaction_uuid": transaction_uuid_str,
            "product_code": self.product_code, # This is the merchant code
            "product_service_charge": psc_str_esewa,
            "product_delivery_charge": pdc_str_esewa,
            "success_url": active_success_url,
            "failure_url": active_failure_url,
            "signed_field_names": ESEWA_DEFAULT_REQUEST_SIGNED_FIELD_NAMES, # "total_amount,transaction_uuid,product_code"
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

        fields_to_sign = signed_fields_str.split(',')
        message_parts = []
        for field_name in fields_to_sign:
            field_name = field_name.strip()
            if field_name in callback_data:
                message_parts.append(f"{field_name}={str(callback_data[field_name])}")
            else:
                logger.error(f"Field '{field_name}' listed in signed_field_names not found in callback data.")
                return False

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