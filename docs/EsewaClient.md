## `EsewaClient` Documentation (for eSewa ePay v2)

The `EsewaClient` provides an interface to integrate with the eSewa ePay v2 payment gateway, which uses HMAC/SHA256 signatures for secure transactions.

### 1. Installation

First, ensure the `nepal-gateways` package is installed:
```bash
pip install nepal-gateways
```
This client also requires the `requests` library for making HTTP calls, which should be installed as a dependency.

### 2. Configuration

To use the `EsewaClient`, you need to initialize it with a configuration dictionary.

**Required Configuration Parameters:**

*   `product_code` (str): Your unique merchant code provided by eSewa (sometimes referred to as Service Code or `scd` in older contexts, but for v2, it's `product_code`).
*   `secret_key` (str): The secret key provided by eSewa for HMAC/SHA256 signature generation and verification.
    *   For **sandbox/UAT mode**, if this is not provided, the client will use the default UAT secret key: `8gBm/:&EnhH.1/q`. It's still recommended to provide it explicitly.
    *   For **live mode**, this is **mandatory**.
*   `success_url` (str): The absolute URL on your server where eSewa will redirect the user after a successful payment attempt.
*   `failure_url` (str): The absolute URL on your server where eSewa will redirect the user after a failed or cancelled payment attempt.
*   `mode` (str, optional): Set to `"sandbox"` for testing with eSewa's UAT environment, or `"live"` for production. Defaults to `"sandbox"`.

**Example Configuration:**

```python
# For Sandbox/UAT
esewa_sandbox_config = {
    "product_code": "EPAYTEST",  # Your sandbox merchant code
    "secret_key": "8gBm/:&EnhH.1/q", # eSewa's UAT secret key
    "success_url": "https://yourdomain.com/payment/esewa/success",
    "failure_url": "https://yourdomain.com/payment/esewa/failure",
    "mode": "sandbox"
}

# For Live/Production
esewa_live_config = {
    "product_code": "YOUR_LIVE_PRODUCT_CODE",
    "secret_key": "YOUR_LIVE_SECRET_KEY_FROM_ESEWA",
    "success_url": "https://yourdomain.com/payment/esewa/success",
    "failure_url": "https://yourdomain.com/payment/esewa/failure",
    "mode": "live"
}
```

### 3. Initialization

Import and initialize the client:

```python
from nepal_gateways import EsewaClient, ConfigurationError

try:
    # Use the appropriate config (sandbox or live)
    client = EsewaClient(config=esewa_sandbox_config)
    # For live: client = EsewaClient(config=esewa_live_config)
except ConfigurationError as e:
    print(f"eSewa client configuration error: {e}")
    # Handle error appropriately
```

### 4. Initiating a Payment

To start a payment, call the `initiate_payment` method. This method prepares the necessary data for a form POST to eSewa. It does not make an API call itself but returns the data needed for redirection.

**Method Signature:**
```python
initiate_payment(
    self,
    amount: Amount,
    order_id: OrderID, # Maps to eSewa's 'transaction_uuid'
    tax_amount: Amount = 0.0,
    product_service_charge: Amount = 0.0,
    product_delivery_charge: Amount = 0.0,
    success_url: Optional[CallbackURL] = None, # To override client's default
    failure_url: Optional[CallbackURL] = None, # To override client's default
    description: Optional[str] = None, # Not used by eSewa v2 standard form
    customer_info: Optional[Dict[str, Any]] = None, # Not used by eSewa v2 standard form
    product_details: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None # Not used
) -> EsewaV2InitiationResponse
```

**Parameters for eSewa v2:**

*   `amount` (float/int): The base amount of the product/service.
*   `order_id` (str): Your unique transaction identifier. This will be used as `transaction_uuid` for eSewa.
*   `tax_amount` (float/int, optional): Tax amount on the base product amount. Defaults to `0.0`.
*   `product_service_charge` (float/int, optional): Service charge, if any. Defaults to `0.0`.
*   `product_delivery_charge` (float/int, optional): Delivery charge, if any. Defaults to `0.0`.
*   `success_url` (str, optional): If provided, overrides the `success_url` from the initial client configuration for this specific transaction.
*   `failure_url` (str, optional): If provided, overrides the `failure_url` from the initial client configuration for this specific transaction.

The `total_amount` for eSewa is calculated internally as `amount + tax_amount + product_service_charge + product_delivery_charge`.

**Example Usage:**

```python
from nepal_gateways import InitiationError

merchant_order_id = "MYORDER-12345"
payment_amount = 100.00 # Base amount

try:
    response = client.initiate_payment(
        amount=payment_amount,
        order_id=merchant_order_id,
        tax_amount=10.0, # Example: 10 units of tax
        product_service_charge=5.0 # Example: 5 units of service charge
        # product_delivery_charge will be 0.0 by default
    )

    # The 'response' object is an EsewaV2InitiationResponse instance.
    # You need to use its properties to redirect the user.
    if response.is_redirect_required:
        redirect_url = response.redirect_url
        form_fields = response.form_fields
        http_method = response.redirect_method # Will be "POST" for eSewa v2

        # In a web framework (e.g., Flask/Django), you would render an HTML page
        # with a form that auto-submits this data to eSewa.
        print(f"Redirect to: {redirect_url} using {http_method}")
        print("Form fields to submit:")
        for key, value in form_fields.items():
            print(f"  {key}: {value}")

        # Example: render_template("auto_submit_form.html", action_url=redirect_url, fields=form_fields, method=http_method)

except InitiationError as e:
    print(f"eSewa payment initiation failed: {e}")
    # Log error, inform user
except Exception as e:
    print(f"An unexpected error occurred during initiation: {e}")
```

The `EsewaV2InitiationResponse` object has the following properties:
*   `is_redirect_required` (bool): Always `True` for eSewa.
*   `redirect_url` (str): The eSewa URL to POST the form to.
*   `redirect_method` (str): Always `"POST"` for eSewa v2.
*   `form_fields` (dict): A dictionary of all fields (including the generated `signature`) that must be submitted in the POST request to `redirect_url`.

### 5. Verifying a Payment

After the user attempts payment on eSewa's site, they are redirected to your `success_url` or `failure_url`. eSewa includes transaction data in this redirect, which **must be verified** for authenticity and status.

**Callback Data:**
eSewa will send data to your callback URL. The documentation indicates this data is a **Base64 encoded JSON string**. The exact method of delivery (e.g., as a GET query parameter named `data`, or in a POST request body) needs to be handled by your web application.

The decoded JSON from eSewa will look something like this:
```json
{
  "transaction_code": "000XXXX",
  "status": "COMPLETE",
  "total_amount": "100.0",
  "transaction_uuid": "YOUR_ORDER_ID",
  "product_code": "YOUR_PRODUCT_CODE",
  "signed_field_names": "transaction_code,status,total_amount,transaction_uuid,product_code,signed_field_names",
  "signature": "SIGNATURE_FROM_ESEWA"
}
```

**Method Signature:**
```python
verify_payment(
    self,
    transaction_data_from_callback: Dict[str, Any],
    order_id_from_merchant_system: Optional[OrderID] = None, # For local cross-check (optional)
    amount_from_merchant_system: Optional[Amount] = None,    # For local cross-check (optional)
    **kwargs: Any
) -> EsewaV2VerificationResult
```

**Parameters:**

*   `transaction_data_from_callback` (dict): This is the raw data your server receives from eSewa.
    *   If eSewa sends a GET request like `?data=<BASE64_STRING>`, this dict should be `{"data": "<BASE64_STRING>"}`.
    *   If eSewa sends a POST request with a JSON body, this dict should be the parsed JSON body directly.
    The client will attempt to decode the Base64 string if it finds a `data` key, otherwise it assumes the dictionary is already the decoded JSON data.

**Verification Process within `verify_payment`:**
1.  Decodes the Base64 JSON data (if applicable).
2.  **Verifies the `signature`** received from eSewa against a signature generated using your `secret_key` and the received data. This is crucial for security.
3.  If the callback signature is valid, it then makes a **server-to-server GET request to eSewa's Status Check API** to get the definitive transaction status.
4.  Returns an `EsewaV2VerificationResult` object.

**Example Usage (in your callback handler):**

```python
from nepal_gateways import VerificationError, InvalidSignatureError, APIConnectionError

# Assume 'request_data' is the dictionary of query parameters from a GET callback
# or the parsed JSON body from a POST callback.
# Example for GET: request_data = {"data": "eyJ0cmFuc2FjZ..."}
# Example for POST (JSON body already parsed): request_data = {"transaction_code": "000ABC", ...}

# This would be inside your web framework's request handler for the success_url
# e.g., in Flask: @app.route('/payment/esewa/success', methods=['GET', 'POST'])
# def esewa_success_handler():
#     if request.method == 'GET':
#         request_data = request.args.to_dict()
#     elif request.method == 'POST':
#         if request.is_json:
#             request_data = request.get_json()
#         else:
#             # Handle form data if eSewa POSTs form data with a 'data' field
#             request_data = request.form.to_dict()
#     else:
#         # Handle error
#         return "Unsupported method", 405

try:
    # client is your initialized EsewaClient instance
    verification = client.verify_payment(
        transaction_data_from_callback=request_data
        # You can optionally pass your system's order_id and amount for cross-checking
        # before the API call, though the primary verification is via eSewa's API.
        # order_id_from_merchant_system=session.get('current_order_id'),
        # amount_from_merchant_system=session.get('current_order_amount')
    )

    if verification.is_successful:
        print(f"Payment Verified Successfully!")
        print(f"  eSewa Transaction ID: {verification.transaction_id}")
        print(f"  Merchant Order ID: {verification.order_id}")
        print(f"  Amount: {verification.verified_amount}")
        print(f"  Status: {verification.status_code}")
        # Update your database: Mark order as paid.
    else:
        print(f"Payment Verification Failed or Pending.")
        print(f"  Status: {verification.status_code}")
        print(f"  Message: {verification.status_message}")
        # Update your database: Mark order as failed or pending. Check status_code.

    # Log verification.raw_response for debugging if needed
    # print(f"Raw API response from eSewa: {verification.raw_response}")

except InvalidSignatureError:
    print("CRITICAL: eSewa callback signature is invalid! Potential tampering.")
    # Do NOT process this transaction. Log an alert.
except VerificationError as e:
    print(f"eSewa verification process error: {e}")
    # Handle error, perhaps retry status check later if appropriate.
except APIConnectionError as e:
    print(f"Network error during eSewa verification: {e}")
    # Consider retrying status check later.
except Exception as e:
    print(f"An unexpected error occurred during verification: {e}")

```

The `EsewaV2VerificationResult` object has properties like:
*   `is_successful` (bool): `True` if status from API is "COMPLETE".
*   `status_code` (str): e.g., "COMPLETE", "PENDING", "FAILURE".
*   `status_message` (str): Message from the API or library.
*   `transaction_id` (str): eSewa's unique reference ID for the transaction (e.g., `ref_id` from status API).
*   `order_id` (str): Your `transaction_uuid` that you sent.
*   `verified_amount` (float): Amount confirmed by eSewa.
*   `raw_response` (dict): The parsed JSON response from eSewa's Status Check API.
*   `gateway_specific_details` (dict): Same as `raw_response`.

### 6. Error Handling

The client can raise the following exceptions (all inherit from `PaymentGatewayError`):
*   `ConfigurationError`: Problem with the initial client setup.
*   `InitiationError`: Failure during the `initiate_payment` call (e.g., signature generation error).
*   `InvalidSignatureError`: If the signature in the callback from eSewa is invalid. **Treat this seriously.**
*   `VerificationError`: General errors during the `verify_payment` process (e.g., missing data in callback, unexpected response from Status API).
*   `APIConnectionError`: Network issues (connection refused, DNS failure) when calling the Status Check API.
*   `APITimeoutError`: Timeout when calling the Status Check API.

Always wrap calls to `initiate_payment` and `verify_payment` in `try...except` blocks to handle these potential errors gracefully.
