# `KhaltiClient` Documentation (for Khalti ePayment v2)

The `KhaltiClient` provides an interface to integrate with the Khalti ePayment v2 gateway, which uses an API Key for authorization and provides a redirect-based checkout flow.

### 1. Installation

Ensure the `nepal-gateways` package is installed:
```bash
pip install nepal-gateways
```
This client also requires the `requests` library for making HTTP calls, which is installed as a dependency.

### 2. Configuration

To use the `KhaltiClient`, you need to initialize it with a configuration dictionary.

**Required Configuration Parameters:**

*   `live_secret_key` (str): Your "Live Secret Key" obtained from your Khalti Merchant Dashboard. This key is used for both sandbox and live environments, as Khalti's API authorization uses this key directly.
*   `return_url_config` (str): The absolute URL on your server where Khalti will redirect the user (via a GET request) after they complete or cancel the payment attempt. This URL will receive query parameters like `pidx`, `status`, `txnId`, etc.
*   `website_url_config` (str): The main URL of your website/application. Khalti requires this during payment initiation.
*   `mode` (str, optional): Set to `"sandbox"` for testing with Khalti's developer environment, or `"live"` for production. Defaults to `"sandbox"`.
*   `timeout` (int, optional): Timeout in seconds for API calls to Khalti. Defaults to `30`.

**Example Configuration:**

```python
# For Sandbox/UAT (use your actual Sandbox Live Secret Key)
khalti_sandbox_config = {
    "live_secret_key": "your_khalti_sandbox_live_secret_key", # Get from test-admin.khalti.com
    "return_url_config": "https://yourdomain.com/payment/khalti/callback",
    "website_url_config": "https://yourdomain.com",
    "mode": "sandbox",
    "timeout": 60 # Optional, example of setting a longer timeout
}

# For Live/Production
khalti_live_config = {
    "live_secret_key": "YOUR_ACTUAL_LIVE_SECRET_KEY_FROM_KHALTI", # Get from admin.khalti.com
    "return_url_config": "https://yourdomain.com/payment/khalti/callback",
    "website_url_config": "https://yourdomain.com",
    "mode": "live"
}
```
**Note:** Khalti uses the term "Live Secret Key" even for its sandbox environment. Ensure you use the appropriate key from your Khalti sandbox merchant dashboard for testing.

### 3. Initialization

Import and initialize the client:

```python
from nepal_gateways import KhaltiClient, ConfigurationError
# Define type aliases for clarity in your application code if desired
from typing import Union, Optional, Dict, Any, List
Amount = int # For Khalti, amount is always in Paisa (integer)
OrderID = str
CallbackURL = str

try:
    # Use the appropriate config (sandbox or live)
    client = KhaltiClient(config=khalti_sandbox_config)
    # For live: client = KhaltiClient(config=khalti_live_config)
except ConfigurationError as e:
    print(f"Khalti client configuration error: {e}")
    # Handle error appropriately
```

### 4. Initiating a Payment

To start a payment, call the `initiate_payment` method. This method makes a server-to-server POST request to Khalti's `/epayment/initiate/` API. If successful, Khalti returns a `payment_url` to which you should redirect the user.

**Method Signature (from `KhaltiClient`):**
```python
def initiate_payment(
    self,
    amount: Amount,  # Must be an integer (Paisa)
    order_id: OrderID, # Maps to Khalti's 'purchase_order_id'
    description: str,  # Maps to Khalti's 'purchase_order_name'
    success_url: Optional[CallbackURL] = None, # Overrides client's default 'return_url_config'
    website_url: Optional[str] = None,    # Overrides client's default 'website_url_config'
    customer_info: Optional[Dict[str, Any]] = None,
    amount_breakdown: Optional[List[Dict[str, Any]]] = None,
    product_details: Optional[List[Dict[str, Any]]] = None,
    # You can also pass additional 'merchant_keyname': 'value' in kwargs
    **kwargs: Any
) -> KhaltiInitiationResponse # Type of response object specific to this client
```

**Parameters for Khalti:**

*   `amount` (int): The total amount to be paid, **in Paisa** (e.g., for Rs. 100, pass `10000`). Must be an integer. Minimum amount is typically Rs. 10 (1000 paisa).
*   `order_id` (str): Your unique transaction/order identifier. This is sent as `purchase_order_id` to Khalti.
*   `description` (str): A name or description for the purchase. This is sent as `purchase_order_name` to Khalti.
*   `success_url` (str, optional): If provided, overrides the `return_url_config` from the client's initial configuration for this specific transaction. This is where Khalti redirects after payment.
*   `website_url` (str, optional): If provided, overrides the `website_url_config`.
*   `customer_info` (dict, optional): A dictionary with customer details (e.g., `{"name": "Test User", "email": "test@example.com", "phone": "9800000000"}`).
*   `amount_breakdown` (list of dicts, optional): For itemizing amounts (e.g., `[{"label": "Item A", "amount": 5000}, {"label": "VAT", "amount": 500}]`). The sum must match the main `amount`.
*   `product_details` (list of dicts, optional): For providing details about the products being purchased.
*   `**kwargs`: Any additional keyword arguments starting with `merchant_` (e.g., `merchant_remarks="Special note"`) will be passed to Khalti as custom merchant data.

**Example Usage:**

```python
from nepal_gateways import InitiationError, APIConnectionError # Assuming KhaltiClient is 'client'

merchant_order_id: OrderID = "MYKHORDER-001"
payment_amount_paisa: Amount = 15000 # Rs. 150 in Paisa
purchase_name = "Subscription Monthly"

try:
    response = client.initiate_payment(
        amount=payment_amount_paisa,
        order_id=merchant_order_id,
        description=purchase_name,
        customer_info={"name": "Khalti Test User", "email": "test@khalti.com"},
        # Example merchant_extra kwarg
        merchant_shipping_address="123 Test Street, Kathmandu"
    )

    # The 'response' object is a KhaltiInitiationResponse instance.
    if response.is_redirect_required:
        payment_redirect_url = response.redirect_url
        pidx = response.payment_instructions.get("pidx") # Khalti's payment identifier

        print(f"Khalti PIDX: {pidx}")
        print(f"Redirect user to: {payment_redirect_url}") # This is a GET redirect

        # In a web framework, you would perform an HTTP redirect:
        # For Flask: return redirect(payment_redirect_url)
        # For Django: return HttpResponseRedirect(payment_redirect_url)

except InitiationError as e:
    print(f"Khalti payment initiation failed: {e}")
    # Log e.gateway_response and e.error_code for details from Khalti
except APIConnectionError as e:
    print(f"Network error during Khalti initiation: {e}")
except Exception as e:
    print(f"An unexpected error occurred during initiation: {e}")
```

The `KhaltiInitiationResponse` object has properties like:
*   `is_redirect_required` (bool): Always `True` for Khalti.
*   `redirect_url` (str): The Khalti payment URL (e.g., `https://test-pay.khalti.com/?pidx=...`) to which the user must be redirected.
*   `redirect_method` (str): Always `"GET"` for Khalti.
*   `form_fields` (Optional[dict]): `None` for Khalti as it's a GET redirect.
*   `payment_instructions` (dict): Contains the `pidx` (Khalti's payment identifier) and a message.
*   `raw_response` (dict): The full JSON response from Khalti's initiation API.

### 5. Verifying a Payment

After the user interacts with Khalti's payment page, Khalti redirects them to your `return_url` (specified as `success_url` during initiation or client config) via a **GET request**. This URL will have several query parameters.

**Callback Query Parameters from Khalti (Example):**
`https://yourdomain.com/payment/khalti/callback?pidx=bZQLD9wR...&txnId=4H7AhoX...&amount=1000&status=Completed&mobile=98XXXXX904&purchase_order_id=test12...`

**It is STRONGLY RECOMMENDED by Khalti to use their Lookup API for final transaction validation, rather than solely relying on the callback parameters.** Your `verify_payment` method does this.

**Method Signature (from `KhaltiClient`):**
```python
def verify_payment(
    self,
    transaction_data_from_callback: Dict[str, Any], # Dict of query params from Khalti's redirect
    order_id_from_merchant_system: Optional[OrderID] = None, # Not directly used by Khalti lookup API
    amount_from_merchant_system: Optional[Amount] = None,    # Not directly used by Khalti lookup API
    **kwargs: Any # e.g., timeout for the API call
) -> KhaltiVerificationResult # Type of response object specific to this client
```

**Parameters:**

*   `transaction_data_from_callback` (dict): A dictionary of all query parameters received from Khalti in the redirect to your `return_url`. The client primarily needs the `pidx` from this dictionary to call the Lookup API.

**Verification Process within `verify_payment`:**
1.  Extracts `pidx` from `transaction_data_from_callback`.
2.  Makes a server-to-server **POST request to Khalti's Lookup API** (`/epayment/lookup/`) with the `pidx`.
3.  Parses the JSON response from the Lookup API.
4.  Returns a `KhaltiVerificationResult` object based on the Lookup API's response.

**Example Usage (in your callback handler):**

```python
from flask import Flask, request, jsonify # Example using Flask
from nepal_gateways import VerificationError, APIConnectionError, ConfigurationError

# app = Flask(__name__) # client would be initialized globally or via app context

# @app.route('/payment/khalti/callback', methods=['GET'])
# def khalti_callback_handler():
#     callback_query_params = request.args.to_dict() # Get all query parameters
#     print(f"Received Khalti callback data: {callback_query_params}")

try:
    # client is your initialized KhaltiClient instance
    verification = client.verify_payment(
        transaction_data_from_callback=callback_query_params
    )

    if verification.is_successful: # Checks if Khalti Lookup API status is "Completed"
        print(f"Khalti Payment Verified Successfully!")
        print(f"  Khalti Transaction ID: {verification.transaction_id}") # From Lookup API
        print(f"  PIDX (Order ID): {verification.order_id}") # PIDX from Lookup API
        print(f"  Amount (Paisa): {verification.verified_amount}") # From Lookup API
        print(f"  Status: {verification.status_code}") # From Lookup API
        # IMPORTANT: Update your database - mark order as paid.
        # Use verification.order_id (which is pidx) or the original purchase_order_id
        # from the callback_query_params if needed to identify your order.
        # Store verification.transaction_id as Khalti's confirmed transaction reference.
        # return "Payment Successful!", 200
    else:
        print(f"Khalti Payment Verification Failed or Status is not COMPLETE.")
        print(f"  Status from Khalti API: {verification.status_code}")
        print(f"  Message from Khalti API: {verification.status_message}")
        # Update your database accordingly (e.g., pending, failed).
        # Check verification.status_code for "Pending", "Refunded", "Expired", "User canceled".
        # return "Payment Not Complete or Failed.", 400

    # For debugging, you can inspect the raw API response from Khalti's lookup:
    # print(f"Raw API response from Khalti Lookup: {verification.raw_response}")

except VerificationError as e: # Covers issues like missing pidx, API errors from lookup
    print(f"Khalti verification process error: {e}")
    # Log e.gateway_response and e.error_code for details
    # return f"Verification error: {e}", 500
except APIConnectionError as e: # Includes APITimeoutError
    print(f"Network error during Khalti verification: {e}")
    # Consider an internal retry mechanism for status check or marking as 'pending review'.
    # return f"Network error: {e}", 500
except ConfigurationError as e: # e.g. if Auth key was wrong and Lookup API gave 401
    print(f"Configuration error during Khalti verification: {e}")
except Exception as e: # Catch-all for other unexpected issues
    print(f"An unexpected error occurred during verification: {e}")
    # return "Unexpected server error.", 500
```

The `KhaltiVerificationResult` object has properties like:
*   `is_successful` (bool): `True` if status from Khalti Lookup API is "Completed".
*   `status_code` (str): The status string from Khalti Lookup API (e.g., "Completed", "Pending", "Refunded").
*   `status_message` (str): Message from the API or library.
*   `transaction_id` (str): Khalti's unique transaction ID for the payment (from Lookup API).
*   `order_id` (str): The `pidx` of the transaction.
*   `verified_amount` (int): Amount in Paisa confirmed by Khalti (from Lookup API).
*   `raw_response` (dict): The parsed JSON response from Khalti's Lookup API.
*   `gateway_specific_details` (dict): Contains more details like `fee_paisa`, `refunded`, and all fields from `raw_response`.

### 6. Error Handling

The `KhaltiClient` can raise the following exceptions (all inherit from `PaymentGatewayError`):
*   `ConfigurationError`: Problem with the initial client setup (e.g., missing keys, invalid API key resulting in 401).
*   `InitiationError`: Failure during `initiate_payment` (e.g., invalid amount, validation error from Khalti API).
*   `VerificationError`: Errors during `verify_payment` (e.g., missing `pidx` in callback, Lookup API returns error, pidx mismatch).
*   `APIConnectionError`: Network issues (connection refused, DNS failure) when calling Khalti APIs.
*   `APITimeoutError`: Timeout when calling Khalti APIs.

Always wrap calls to `initiate_payment` and `verify_payment` in `try...except` blocks.
