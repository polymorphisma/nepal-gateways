import logging
from typing import Optional, Any, Union
logger = logging.getLogger(__name__)


class PaymentGatewayError(Exception):
    """Base exception class for all errors in the nepal_gateways package."""
    def __init__(
        self,
        message: str,
        original_exception: Optional[Exception] = None,
        gateway_response: Optional[Any] = None,
        error_code: Optional[Union[str, int]] = None
    ):
        super().__init__(message)
        self.message = message
        self.original_exception = original_exception
        self.gateway_response = gateway_response
        self.error_code = error_code

        # Basic logging when an exception from this library is created
        log_parts = [f"{self.__class__.__name__}: {message}"]

        if error_code:
            log_parts.append(f"(Code: {error_code})")

        if original_exception:
            log_parts.append(f"| Original: {type(original_exception).__name__}: {str(original_exception)}")

        if gateway_response:
            log_parts.append(f"| Gateway Response Hint: {str(gateway_response)[:200]}...") # Log a snippet

        logger.warning(" ".join(log_parts))


class ConfigurationError(PaymentGatewayError):
    """Exception raised for errors in configuration of a payment gateway client."""
    pass


class NetworkError(PaymentGatewayError):
    """Base exception for network-related errors during API calls to the gateway."""
    pass


class APIConnectionError(NetworkError):
    """Exception raised specifically for problems establishing a connection to the gateway's API."""
    pass


class APITimeoutError(NetworkError):
    """Exception raised when an API call to the gateway times out."""
    pass


class InitiationError(PaymentGatewayError):
    """Exception raised when payment initiation with the gateway fails."""
    pass


class VerificationError(PaymentGatewayError):
    """Exception raised when payment verification with the gateway fails or data mismatches."""
    pass


class InvalidSignatureError(VerificationError): # Or PaymentGatewayError if used more broadly
    """Exception raised for signature validation failures, typically during callback verification."""
    pass

