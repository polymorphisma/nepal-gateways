# Nepal Gateways 🇳🇵

[![PyPI version](https://badge.fury.io/py/nepal-gateways.svg)](https://pypi.org/project/nepal-gateways/)
[![Python Version](https://img.shields.io/pypi/pyversions/nepal-gateways.svg)](https://pypi.org/project/nepal-gateways/)
[![License](https://img.shields.io/pypi/l/nepal-gateways.svg)](https://github.com/polymorphisma/nepal-gateways/blob/main/LICENSE)
<!-- Add badges for build status (GitHub Actions), code coverage etc. once you set them up -->

A Python library providing a unified interface for integrating various Nepali payment gateways and digital wallets into your Python applications.

## Overview

Integrating multiple payment gateways can be complex due to differing APIs, authentication mechanisms, and response formats. `nepal-gateways` aims to simplify this by offering:

*   A consistent API structure for common operations like payment initiation and verification across different gateways.
*   Clear error handling with custom exceptions.
*   Type-hinted and well-documented code.

## Supported Gateways

Currently, the following gateways are supported:

*   **eSewa (ePay v2 - with HMAC Signature)** - See [eSewa Client Documentation](./docs/EsewaClient.md)
*   **Khalti (ePayment v2 API)** - See [Khalti Client Documentation](./docs/KhaltiClient.md)
*   *(Other gateways will be added based on demand and API availability)*

## Installation

You can install `nepal-gateways` using pip:

```bash
pip install nepal-gateways
```
Or with `uv`:
```bash
uv pip install nepal-gateways
```

The library requires the `requests` package for making HTTP calls, which will be installed automatically as a dependency.

## Quick Start Examples

Below are quick start examples for the supported gateways. For full details, please refer to the specific documentation linked above.

---

### Quick Start - eSewa Example

For full details, please see the [eSewa Client Documentation](./docs/EsewaClient.md).

**1. Configuration & Initialization (eSewa):**

```python
from nepal_gateways import EsewaClient, ConfigurationError
from typing import Union # For Amount type alias if used in example

# Define type alias for clarity (Amount for eSewa can be float or int)
EsewaAmount = Union[int, float]
OrderID = str # Common OrderID type

# For Sandbox/UAT
esewa_sandbox_config = {
    "product_code": "EPAYTEST",  # Your sandbox merchant code from eSewa
    "secret_key": "8gBm/:&EnhH.1/q", # eSewa's official UAT secret key
    "success_url": "https://yourdomain.com/payment/esewa/success",
    "failure_url": "https://yourdomain.com/payment/esewa/failure",
    "mode": "sandbox"
}

try:
    esewa_client = EsewaClient(config=esewa_sandbox_config)
except ConfigurationError as e:
    print(f"eSewa Configuration Error: {e}")
    # Handle error
```

**2. Initiating a Payment (eSewa):**

```python
from nepal_gateways import InitiationError

merchant_order_id: OrderID = "ESORDER-001"
payment_amount: EsewaAmount = 100 # Base amount (e.g., Rs. 100)

try:
    # For eSewa, 'amount' is the base, other charges are separate parameters.
    # Total amount for signature will be amount + tax_amount + product_service_charge + product_delivery_charge
    init_response = esewa_client.initiate_payment(
        amount=payment_amount,
        order_id=merchant_order_id,
        tax_amount=0,           # Example: 0 tax (formatted to "0" by client)
        product_service_charge=0, # Example: 0 service charge
        product_delivery_charge=0 # Example: 0 delivery charge
    )

    if init_response.is_redirect_required:
        print(f"eSewa: Redirect User to: {init_response.redirect_url}")
        print(f"eSewa: With Method: {init_response.redirect_method}") # Should be POST
        print(f"eSewa: And Form Fields: {init_response.form_fields}")
        # In a web app, render an HTML form that auto-submits these fields.
except InitiationError as e:
    print(f"eSewa Initiation Failed: {e}")
```

**3. Verifying a Payment (eSewa - in your callback handler):**

eSewa redirects to your `success_url` with a `data` query parameter (Base64 encoded JSON).

```python
from nepal_gateways import VerificationError, InvalidSignatureError

# Example: request_data_from_esewa = {"data": "ACTUAL_BASE64_STRING_FROM_ESEWA_CALLBACK"}
# Replace placeholder with actual data for testing
request_data_from_esewa = {"data": "GET_THIS_FROM_A_REAL_SANDBOX_TRANSACTION_CALLBACK"}

try:
    verification = esewa_client.verify_payment(
        transaction_data_from_callback=request_data_from_esewa
    )

    if verification.is_successful:
        print(f"eSewa: Payment Verified for Order ID: {verification.order_id}, eSewa Txn ID: {verification.transaction_id}")
        # Update your database, fulfill order
    else:
        print(f"eSewa: Payment Not Verified for Order ID: {verification.order_id}. Status: {verification.status_code}")
except InvalidSignatureError:
    print("eSewa CRITICAL: Callback signature is invalid!")
except VerificationError as e:
    print(f"eSewa Verification process error: {e}")
except Exception as e:
    print(f"eSewa: Unexpected error during verification: {e}")
```

---

### Quick Start - Khalti Example

For full details, please see the [Khalti Client Documentation](./docs/KhaltiClient.md).

**1. Configuration & Initialization (Khalti):**

```python
from nepal_gateways import KhaltiClient, ConfigurationError # Assuming Esewa types already imported

# For Khalti, amount is always in Paisa (integer)
KhaltiAmount = int

# For Sandbox/UAT
khalti_sandbox_config = {
    "live_secret_key": "your_khalti_sandbox_live_secret_key", # Get from test-admin.khalti.com
    "return_url_config": "https://yourdomain.com/payment/khalti/callback",
    "website_url_config": "https://yourdomain.com",
    "mode": "sandbox"
}

try:
    khalti_client = KhaltiClient(config=khalti_sandbox_config)
except ConfigurationError as e:
    print(f"Khalti Configuration Error: {e}")
    # Handle error
```

**2. Initiating a Payment (Khalti):**

```python
# from nepal_gateways import InitiationError # Already imported

merchant_order_id_khalti: OrderID = "KHORDER-002"
payment_amount_paisa: KhaltiAmount = 15000  # Rs. 150 in Paisa
purchase_description = "Monthly Subscription"

try:
    init_response_khalti = khalti_client.initiate_payment(
        amount=payment_amount_paisa,
        order_id=merchant_order_id_khalti,
        description=purchase_description,
        customer_info={"name": "Test Customer", "email": "test@example.com"} # Optional
    )

    if init_response_khalti.is_redirect_required:
        print(f"Khalti: PIDX: {init_response_khalti.payment_instructions.get('pidx')}")
        print(f"Khalti: Redirect User to: {init_response_khalti.redirect_url}") # This is a GET redirect
        # In a web app, perform an HTTP redirect to this URL.
except InitiationError as e:
    print(f"Khalti Initiation Failed: {e}")
```

**3. Verifying a Payment (Khalti - in your callback handler):**

Khalti redirects to your `return_url` (a GET request) with query parameters like `pidx`, `status`, `txnId`, etc.

```python
# from nepal_gateways import VerificationError # Already imported

# Example: query_params_from_khalti = {"pidx": "actual_pidx", "txnId": "actual_txnid", ...}
# Replace placeholder with actual data for testing
query_params_from_khalti = {"pidx": "GET_PIDX_FROM_REAL_SANDBOX_CALLBACK"}

try:
    verification_khalti = khalti_client.verify_payment(
        transaction_data_from_callback=query_params_from_khalti
    )

    if verification_khalti.is_successful: # Checks Khalti Lookup API status "Completed"
        print(f"Khalti: Payment Verified for Order ID (PIDX): {verification_khalti.order_id}, Khalti Txn ID: {verification_khalti.transaction_id}")
        # Update your database, fulfill order
    else:
        print(f"Khalti: Payment Not Verified for Order ID (PIDX): {verification_khalti.order_id}. Status: {verification_khalti.status_code}")

except VerificationError as e: # Covers various verification issues including API errors
    print(f"Khalti Verification process error: {e}")
except Exception as e:
    print(f"Khalti: Unexpected error during verification: {e}")

```

---

## Logging

This library uses Python's standard `logging` module. All loggers within this package are children of the `nepal_gateways` logger.

To enable logging (e.g., for debugging), configure the `nepal_gateways` logger in your application:

```python
import logging

# Simplest configuration to see debug messages on console
logging.basicConfig(level=logging.DEBUG)

# Or, more specific configuration:
# logger = logging.getLogger('nepal_gateways')
# logger.setLevel(logging.DEBUG)
# stream_handler = logging.StreamHandler() # Example handler
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# stream_handler.setFormatter(formatter)
# logger.addHandler(stream_handler)
```
The library itself does not add any handlers by default (except a `NullHandler` at the package level to prevent "No handler found" warnings if the application has not configured logging).

## Contributing

Contributions are welcome! If you'd like to add support for a new gateway, improve existing ones, or fix bugs, please refer to our [CONTRIBUTING.md](./CONTRIBUTING.md) file.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Disclaimer

This is an unofficial library. While efforts are made to ensure correctness and security, always perform thorough testing, especially with live credentials and real transactions. The maintainers are not responsible for any financial loss or issues arising from the use of this software. Always refer to the official documentation of the respective payment gateways.
