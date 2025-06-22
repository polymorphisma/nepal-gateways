# nepal_gateways/khalti/client.py

import logging
import json
from typing import Dict, Any, Optional, Union, List
import requests

from ..core.base import (
    BasePaymentGateway,
    PaymentInitiationResponse,
    PaymentVerificationResult,
    Amount as BaseAmount , # General-purpose Amount: Union[int, float]
    OrderID, CallbackURL, HTTPMethod
)
from ..core.exceptions import (
    ConfigurationError,
    InitiationError,
    VerificationError,
    APIConnectionError,
    APITimeoutError,
    PaymentGatewayError
)
from .config import (
    KHALTI_SANDBOX_BASE_URL_V2,
    KHALTI_LIVE_BASE_URL_V2,
    KHALTI_INITIATE_PATH,
    KHALTI_LOOKUP_PATH,
    KHALTI_MIN_TRANSACTION_AMOUNT_PAISA
)

logger = logging.getLogger(__name__)

# Override the generic Amount type for Khalti-specific use
# Khalti deals strictly in paisa (smallest currency unit), which is always an integer.
# Therefore, we redefine Amount here as int to reflect that constraint.
Amount = int  

# --- Concrete Response Implementations for Khalti (Keep as is) ---
class KhaltiInitiationResponse(PaymentInitiationResponse):
    def __init__(self, payment_url: str, pidx: str, raw_api_response: Dict[str, Any]):
        self._payment_url = payment_url
        self._pidx = pidx
        self._raw_response = raw_api_response
        logger.debug(
            f"KhaltiInitiationResponse created: PaymentURL='{payment_url}', pidx='{pidx}'"
        )

    @property
    def is_redirect_required(self) -> bool: return True
    @property
    def redirect_url(self) -> str: return self._payment_url
    @property
    def redirect_method(self) -> HTTPMethod: return "GET"
    @property
    def form_fields(self) -> Optional[Dict[str, Any]]: return None
    @property
    def payment_instructions(self) -> Dict[str, Any]: return {"pidx": self._pidx, "message": "Redirect user to the payment_url."}
    @property
    def raw_response(self) -> Any: return self._raw_response

class KhaltiVerificationResult(PaymentVerificationResult):
    def __init__(self,
                 is_successful: bool, khalti_status: str, status_message: str,
                 raw_lookup_api_response: Dict[str, Any], transaction_id: Optional[str] = None,
                 pidx: Optional[str] = None, verified_amount_paisa: Optional[int] = None,
                 fee_paisa: Optional[int] = None, refunded: Optional[bool] = None):
        self._is_successful = is_successful
        self._status_code = khalti_status
        self._status_message = status_message
        self._raw_response = raw_lookup_api_response
        self._transaction_id = transaction_id
        self._order_id = pidx
        self._verified_amount = verified_amount_paisa
        self._gateway_specific_details = {
            "fee_paisa": fee_paisa, "refunded": refunded, **raw_lookup_api_response
        }
        logger.debug(
            f"KhaltiVerificationResult created: Successful={is_successful}, Status='{khalti_status}', "
            f"KhaltiTxID='{transaction_id}', pidx='{pidx}', AmountPaisa='{verified_amount_paisa}'"
        )

    @property
    def is_successful(self) -> bool: return self._is_successful
    @property
    def status_code(self) -> str: return self._status_code
    @property
    def status_message(self) -> str: return self._status_message
    @property
    def transaction_id(self) -> Optional[str]: return self._transaction_id
    @property
    def order_id(self) -> Optional[OrderID]: return self._order_id
    @property
    def verified_amount(self) -> Optional[Amount]: return self._verified_amount
    @property
    def raw_response(self) -> Dict[str, Any]: return self._raw_response
    @property
    def gateway_specific_details(self) -> Dict[str, Any]: return self._gateway_specific_details

# --- Khalti Client Implementation ---
class KhaltiClient(BasePaymentGateway):
    REQUIRED_CONFIG_KEYS_INITIAL = ['live_secret_key', 'return_url_config', 'website_url_config']

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.live_secret_key: str = self._get_config_value('live_secret_key', required=True)
        self.default_return_url: CallbackURL = self._get_config_value('return_url_config', required=True)
        self.default_website_url: str = self._get_config_value('website_url_config', required=True)
        self.timeout: int = int(self.config.get('timeout', 30))

        if self.mode == 'sandbox':
            self.base_api_url = KHALTI_SANDBOX_BASE_URL_V2
        else:
            self.base_api_url = KHALTI_LIVE_BASE_URL_V2
        self.initiation_endpoint = self.base_api_url + KHALTI_INITIATE_PATH
        self.lookup_endpoint = self.base_api_url + KHALTI_LOOKUP_PATH
        logger.info(
            f"KhaltiClient initialized in {self.mode} mode. "
            f"API Base: {self.base_api_url}. Default timeout: {self.timeout}s"
        )
        self.http_session = requests.Session()
        self.http_session.headers.update({
            "Authorization": f"Key {self.live_secret_key}",
            "Content-Type": "application/json"
        })

    def _handle_api_error_response(self, response: requests.Response, operation: str):
        error_data: Union[Dict[str, Any], str]
        try:
            error_data = response.json()
        except json.JSONDecodeError:
            error_data = response.text
        
        error_message_parts = []
        error_key_from_payload = None

        if isinstance(error_data, dict):
            detail = error_data.get('detail')
            if detail and isinstance(detail, str):
                error_message_parts.append(detail)
            
            for field, messages_val in error_data.items():
                if field in ['detail', 'error_key', 'status_code', 'idx']: continue
                if detail and isinstance(messages_val, str) and messages_val == detail and len(error_message_parts) == 1: continue
                if isinstance(messages_val, list):
                    error_message_parts.append(f"{field}: {', '.join(str(m) for m in messages_val)}")
                elif isinstance(messages_val, str):
                     error_message_parts.append(f"{field}: {messages_val}")
            if not error_message_parts and response.text:
                error_message_parts.append(response.text[:200])
            error_key_from_payload = error_data.get('error_key')
        else:
            error_data = response.text # Ensure error_data is the raw text
            error_message_parts.append(str(error_data)[:200])

        if not error_message_parts:
            error_message_parts.append(f"Khalti API responded with status {response.status_code} but no detailed error message could be parsed.")
        full_error_message = f"Khalti {operation} API error: {'; '.join(filter(None, error_message_parts))}"
        final_error_code: Union[str, int] = error_key_from_payload or response.status_code
        logger.warning(
            f"Khalti API Error. Operation: {operation}, Status: {response.status_code}, "
            f"Message: {full_error_message}, Code: {final_error_code}, Response Body (snippet): {str(error_data)[:200]}"
        )
        common_kwargs_for_exception = {
            "message": full_error_message, "gateway_response": error_data, "error_code": final_error_code
        }
        if response.status_code == 401:
             raise ConfigurationError(**common_kwargs_for_exception)
        if operation == "lookup" and response.status_code == 404:
            raise VerificationError(**common_kwargs_for_exception)
        if operation == "initiation":
            raise InitiationError(**common_kwargs_for_exception)
        elif operation == "lookup":
            raise VerificationError(**common_kwargs_for_exception)
        else:
            logger.error(f"Unhandled operation '{operation}' in _handle_api_error_response. Raising generic PaymentGatewayError.")
            raise PaymentGatewayError(**common_kwargs_for_exception)

    def initiate_payment(
        self, amount: Amount, order_id: OrderID, description: str,
        success_url: Optional[CallbackURL] = None, website_url: Optional[str] = None,
        customer_info: Optional[Dict[str, Any]] = None, amount_breakdown: Optional[List[Dict[str, Any]]] = None,
        product_details: Optional[List[Dict[str, Any]]] = None, **kwargs: Any
    ) -> KhaltiInitiationResponse:
        if not isinstance(amount, int):
            msg = "Khalti amount must be an integer in paisa."
            logger.error(msg + f" Received type: {type(amount)}, value: {amount}")
            raise InitiationError(msg, error_code="invalid_amount_type")
        if amount < KHALTI_MIN_TRANSACTION_AMOUNT_PAISA:
            msg = f"Khalti amount must be an integer in paisa and greater than {KHALTI_MIN_TRANSACTION_AMOUNT_PAISA -1} paisa. Received: {amount}"
            logger.error(msg)
            raise InitiationError(msg, error_code="invalid_amount_value")

        purchase_order_id_str, purchase_order_name_str = str(order_id), str(description)
        active_return_url = success_url if success_url is not None else self.default_return_url
        active_website_url = website_url if website_url is not None else self.default_website_url
        if not active_return_url: raise ConfigurationError("Khalti 'return_url' (success_url) must be configured or passed.")
        if not active_website_url: raise ConfigurationError("Khalti 'website_url' must be configured or passed.")

        payload = {
            "return_url": active_return_url, "website_url": active_website_url, "amount": amount,
            "purchase_order_id": purchase_order_id_str, "purchase_order_name": purchase_order_name_str,
        }
        if customer_info: payload["customer_info"] = customer_info
        if amount_breakdown: payload["amount_breakdown"] = amount_breakdown
        if product_details: payload["product_details"] = product_details
        for key, value in kwargs.items():
            if key.startswith("merchant_"): payload[key] = value
            elif key == "timeout": pass
            else: logger.warning(f"KhaltiClient: Unknown kwarg '{key}' passed to initiate_payment. Ignoring.")

        logger.info(f"Initiating Khalti payment for OrderID: '{purchase_order_id_str}', Amount (Paisa): {amount}")
        logger.debug(f"Khalti initiation payload: {payload}")
        response_obj: requests.Response
        try:
            response_obj = self.http_session.post(self.initiation_endpoint, json=payload, timeout=self.timeout)
            if response_obj.status_code == 200:
                response_data = response_obj.json()
                pidx, payment_url = response_data.get("pidx"), response_data.get("payment_url")
                if not pidx or not payment_url:
                    msg = "Khalti initiation success response (200 OK) missing 'pidx' or 'payment_url'."
                    logger.error(msg + f" Response: {response_data}")
                    raise InitiationError(msg, gateway_response=response_data, error_code="MISSING_INITIATION_FIELDS")
                logger.info(f"Khalti payment initiated. pidx: {pidx}, payment_url: {payment_url}")
                return KhaltiInitiationResponse(payment_url=payment_url, pidx=pidx, raw_api_response=response_data)
            else:
                logger.error(f"Khalti initiation API request failed. Status: {response_obj.status_code}, Body: {response_obj.text[:500]}")
                self._handle_api_error_response(response_obj, "initiation")
                logger.critical(f"BUG: _handle_api_error_response did not raise for status {response_obj.status_code} in initiation.")
                raise InitiationError(f"Khalti initiation failed with status {response_obj.status_code} and _handle_api_error_response did not raise.", gateway_response=response_obj.text)
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during Khalti initiation for OrderID: {purchase_order_id_str}. Error: {e}")
            raise APITimeoutError("Khalti initiation API call timed out.", original_exception=e)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during Khalti initiation for OrderID: {purchase_order_id_str}. Error: {e}")
            # FIX: Pass requests_response to gateway_response, not 'response'
            requests_response_obj = getattr(e, 'response', None)
            gateway_resp_text = requests_response_obj.text if requests_response_obj is not None else None
            raise APIConnectionError(
                f"Error connecting to Khalti initiation API: {e}",
                original_exception=e,
                gateway_response=gateway_resp_text # Store text of response if available
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Network/HTTP error during Khalti initiation for OrderID: {purchase_order_id_str}. Error: {e}")
            requests_response_obj = getattr(e, 'response', None)
            gateway_resp_text = requests_response_obj.text if requests_response_obj is not None else None
            status_code_from_req_ex = requests_response_obj.status_code if requests_response_obj is not None else None
            raise APIConnectionError(
                f"Error during Khalti initiation API call: {e}",
                original_exception=e,
                gateway_response=gateway_resp_text,
                error_code=status_code_from_req_ex
            )

    def verify_payment(
        self, transaction_data_from_callback: Dict[str, Any],
        order_id_from_merchant_system: Optional[OrderID] = None, amount_from_merchant_system: Optional[Amount] = None,
        **kwargs: Any
    ) -> KhaltiVerificationResult:
        logger.info(f"Verifying Khalti payment. Callback data: {transaction_data_from_callback}")
        pidx_from_callback = transaction_data_from_callback.get('pidx')
        status_from_callback = transaction_data_from_callback.get('status')
        if not pidx_from_callback:
            msg = "Missing 'pidx' in Khalti callback data. Cannot verify."
            logger.error(msg + f" Data: {transaction_data_from_callback}")
            raise VerificationError(msg, gateway_response=transaction_data_from_callback, error_code="MISSING_PIDX_CALLBACK")
        logger.info(f"Khalti callback received for pidx: {pidx_from_callback}, status from callback: '{status_from_callback}'. Proceeding with Lookup API.")
        lookup_payload = {"pidx": pidx_from_callback}
        logger.debug(f"Calling Khalti Lookup API: {self.lookup_endpoint} with payload: {lookup_payload}")
        response_obj: requests.Response
        try:
            response_obj = self.http_session.post(self.lookup_endpoint, json=lookup_payload, timeout=self.timeout)
            if response_obj.status_code == 200:
                try:
                    lookup_response_data = response_obj.json()
                except json.JSONDecodeError as e_json:
                    # FIX: Change message to match test expectation
                    msg = "Invalid JSON response from Khalti Lookup API."
                    # msg = f"Khalti Lookup API (200 OK) returned non-JSON. pidx: {pidx_from_callback}. Error: {e_json}. Body: {response_obj.text[:200]}"
                    logger.error(msg + f" Original error: {e_json}. pidx: {pidx_from_callback}. Body: {response_obj.text[:200]}")
                    raise VerificationError(msg, original_exception=e_json, gateway_response=response_obj.text, error_code="INVALID_JSON_LOOKUP_OK")
                
                logger.debug(f"Khalti Lookup API JSON response: {lookup_response_data}")
                khalti_api_status = str(lookup_response_data.get("status", "Unknown")).strip()
                khalti_transaction_id, pidx_from_api = lookup_response_data.get("transaction_id"), lookup_response_data.get("pidx")
                total_amount_paisa_from_api, fee_paisa = lookup_response_data.get("total_amount"), lookup_response_data.get("fee")
                refunded = lookup_response_data.get("refunded", False)
                if pidx_from_api != pidx_from_callback:
                    msg = f"pidx mismatch between callback ('{pidx_from_callback}') and Lookup API ('{pidx_from_api}')."
                    logger.error(msg)
                    raise VerificationError(msg, gateway_response=lookup_response_data, error_code="PIDX_MISMATCH")
                is_verified_successfully = (khalti_api_status.lower() == "completed")
                status_message_for_result = f"Khalti Lookup API status: {khalti_api_status}"
                detail_msg = lookup_response_data.get('detail') or lookup_response_data.get('message')
                if detail_msg and isinstance(detail_msg, str): status_message_for_result += f". Detail: {detail_msg}"
                log_fn = logger.info if is_verified_successfully else logger.warning
                log_fn(
                    f"Khalti payment status for pidx: '{pidx_from_api}' is '{khalti_api_status}'. "
                    f"TxID: '{khalti_transaction_id}', Amount: {total_amount_paisa_from_api}"
                )
                return KhaltiVerificationResult(
                    is_successful=is_verified_successfully, khalti_status=khalti_api_status,
                    status_message=status_message_for_result, raw_lookup_api_response=lookup_response_data,
                    transaction_id=khalti_transaction_id, pidx=pidx_from_api,
                    verified_amount_paisa=int(total_amount_paisa_from_api) if total_amount_paisa_from_api is not None else None,
                    fee_paisa=int(fee_paisa) if fee_paisa is not None else None, refunded=refunded
                )
            else:
                logger.error(f"Khalti Lookup API request failed. Status: {response_obj.status_code}, Body: {response_obj.text[:500]}")
                self._handle_api_error_response(response_obj, "lookup")
                logger.critical(f"BUG: _handle_api_error_response did not raise for status {response_obj.status_code} in lookup.")
                raise VerificationError(f"Khalti lookup failed with status {response_obj.status_code} and _handle_api_error_response did not raise.", gateway_response=response_obj.text)
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during Khalti Lookup API call for pidx: {pidx_from_callback}. Error: {e}")
            raise APITimeoutError("Khalti Lookup API call timed out.", original_exception=e)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during Khalti Lookup API call for pidx: {pidx_from_callback}. Error: {e}")
            # FIX: Pass requests_response to gateway_response, not 'response'
            requests_response_obj = getattr(e, 'response', None)
            gateway_resp_text = requests_response_obj.text if requests_response_obj is not None else None
            raise APIConnectionError(
                f"Error calling Khalti Lookup API: {e}",
                original_exception=e,
                gateway_response=gateway_resp_text # Store text of response if available
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Network/HTTP error during Khalti Lookup API call for pidx: {pidx_from_callback}. Error: {e}")
            requests_response_obj = getattr(e, 'response', None)
            gateway_resp_text = requests_response_obj.text if requests_response_obj is not None else None
            status_code_from_req_ex = requests_response_obj.status_code if requests_response_obj is not None else None
            raise APIConnectionError(
                f"Error during Khalti Lookup API call: {e}",
                original_exception=e,
                gateway_response=gateway_resp_text,
                error_code=status_code_from_req_ex
            )