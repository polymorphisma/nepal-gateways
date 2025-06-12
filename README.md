# Nepal Gateways 🇳🇵

[![PyPI version](https://badge.fury.io/py/nepal-gateways.svg)](https://badge.fury.io/py/nepal-gateways) <!-- Replace with your actual PyPI link when published -->
[![Python Version](https://img.shields.io/pypi/pyversions/nepal-gateways.svg)](https://pypi.org/project/nepal-gateways/) <!-- Replace -->
[![License](https://img.shields.io/pypi/l/nepal-gateways.svg)](https://github.com/polymorphisma/nepal-gateways/blob/main/LICENSE) <!-- Replace -->
<!-- Add badges for build status, coverage etc. once you set them up -->

A Python library providing a unified interface for integrating various Nepali payment gateways and digital wallets into your Python applications.

## Overview

Integrating multiple payment gateways can be complex due to differing APIs, authentication mechanisms, and response formats. `nepal-gateways` aims to simplify this by offering:

*   A consistent API structure for common operations like payment initiation and verification across different gateways.
*   Clear error handling with custom exceptions.
*   Type-hinted and well-documented code.

## Supported Gateways

Currently, the following gateways are supported:

*   **eSewa (ePay v2 - with HMAC Signature)**
*   *Khalti (Coming Soon)*
*   *(Other gateways will be added based on demand and API availability)*

## Installation

You can install `nepal-gateways` using pip:

```bash
pip install nepal-gateways
```

The library requires the `requests` package for making HTTP calls, which will be installed automatically as a dependency.

## Quick Start - eSewa Example

Here's a brief example of how to use the `EsewaClient`. For full details, please see the [eSewa Client Documentation](./docs/EsewaClient.md).

**1. Configuration & Initialization:**

```python
from nepal_gateways import EsewaClient, ConfigurationError
from typing import Union # For Amount type alias if used in example

# Define type alias for clarity
Amount = Union[int, float]
OrderID = str

# For Sandbox/UAT
esewa_sandbox_config = {
    "product_code": "EPAYTEST",  # Your sandbox merchant code from eSewa
    "secret_key": "8gBm/:&EnhH.1/q", # eSewa's official UAT secret key
    "success_url": "https://yourdomain.com/payment/esewa/success",
    "failure_url": "https://yourdomain.com/payment/esewa/failure",
    "mode": "sandbox"
}

try:
    client = EsewaClient(config=esewa_sandbox_config)
except ConfigurationError as e:
    print(f"Configuration Error: {e}")
    # Handle error
```

**2. Initiating a Payment:**

```python
from nepal_gateways import InitiationError

merchant_order_id: OrderID = "MYORDER-001"
payment_amount: Amount = 100 # Total amount for the order

try:
    # For eSewa, 'amount' is the base, other charges are separate parameters
    # Total amount for signature will be amount + tax_amount + product_service_charge + product_delivery_charge
    init_response = client.initiate_payment(
        amount=payment_amount, # Base amount
        order_id=merchant_order_id,
        tax_amount=0,           # Example: 0 tax
        product_service_charge=0, # Example: 0 service charge
        product_delivery_charge=0 # Example: 0 delivery charge
    )

    if init_response.is_redirect_required:
        print(f"Redirect User to: {init_response.redirect_url}")
        print(f"With Method: {init_response.redirect_method}") # Should be POST
        print(f"And Form Fields: {init_response.form_fields}")
        # In a web app, render an HTML form that auto-submits these fields.
except InitiationError as e:
    print(f"Initiation Failed: {e}")
```

**3. Verifying a Payment (in your callback handler):**

eSewa will redirect the user to your `success_url` or `failure_url` with a `data` query parameter containing a Base64 encoded JSON string.

```python
from nepal_gateways import VerificationError, InvalidSignatureError

# Example: In a Flask route handling the callback
# @app.route('/payment/esewa/success', methods=['GET'])
# def esewa_callback_handler():
#     request_data = request.args.to_dict() # e.g., {"data": "BASE64_STRING_FROM_ESEWA"}

# For this standalone example, let's assume request_data is populated:
# Replace with actual data from a test transaction
# This is what your web framework's request object would give you
# For a GET callback: request_data = {"data": "ACTUAL_BASE64_ENCODED_STRING_FROM_ESEWA_CALLBACK"}
# For a POST callback (if eSewa POSTs JSON): request_data = ACTUAL_PARSED_JSON_OBJECT_FROM_ESEWA

# Placeholder for example - replace with real callback data for testing
request_data_from_esewa_callback = {"data": "GET_THIS_FROM_A_REAL_SANDBOX_TRANSACTION_CALLBACK"}

try:
    verification = client.verify_payment(
        transaction_data_from_callback=request_data_from_esewa_callback
    )

    if verification.is_successful:
        print(f"Payment Verified for Order ID: {verification.order_id}, eSewa Txn ID: {verification.transaction_id}")
        # Update your database, fulfill order
    else:
        print(f"Payment Not Verified or Failed for Order ID: {verification.order_id}. Status: {verification.status_code}")
        # Check verification.status_message and verification.raw_response for details

except InvalidSignatureError:
    print("CRITICAL: Callback signature is invalid! Do not trust this transaction.")
except VerificationError as e:
    print(f"Verification process error: {e}")
except Exception as e:
    print(f"Unexpected error during verification: {e}")
```

For more detailed information on using the `EsewaClient`, including all configuration options and error handling, please refer to the [eSewa Client Documentation](./docs/EsewaClient.md).

## Logging

This library uses Python's standard `logging` module. All loggers within this package are children of the `nepal_gateways` logger.

To enable logging (e.g., for debugging), configure the `nepal_gateways` logger in your application:

```python
import logging

# Simplest configuration to see debug messages on console
logging.basicConfig(level=logging.DEBUG)

# Or, more specific configuration:
logger = logging.getLogger('nepal_gateways')
logger.setLevel(logging.DEBUG)
# Add your desired handlers
# stream_handler = logging.StreamHandler()
# logger.addHandler(stream_handler)
```
The library itself does not add any handlers by default (except a `NullHandler` to prevent "No handler found" warnings if the application has not configured logging).

## Contributing

Contributions are welcome! If you'd like to add support for a new gateway, improve existing ones, or fix bugs, please feel free to:

1.  Fork the repository.
2.  Create a new branch for your feature or fix.
3.  Write tests for your changes.
4.  Submit a pull request.

Please ensure your code adheres to basic linting standards (e.g., `ruff`, `black`) and that all tests pass.

*(More details can be added to a `CONTRIBUTING.md` file later.)*

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Disclaimer

This is an unofficial library. While efforts are made to ensure correctness and security, always perform thorough testing, especially with live credentials and real transactions. The maintainers are not responsible for any financial loss or issues arising from the use of this software. Always refer to the official documentation of the respective payment gateways.
