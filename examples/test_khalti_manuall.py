# examples/test_khalti_manual.py
import logging
import sys
import os
# import webbrowser # To automatically open the Khalti payment URL # REMOVED

# Ensure your package is findable if not installed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from nepal_gateways import (
    KhaltiClient,
    ConfigurationError,
    InitiationError,
    VerificationError,
    APIConnectionError,
    APITimeoutError,
)

# --- SETUP LOGGING FOR DEVELOPMENT ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)-25s - %(message)s (%(filename)s:%(lineno)d)",
    style="%",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# --- SANDBOX CONFIGURATION FOR KHALTI ---
# Replace with YOUR Khalti Sandbox Merchant Secret Key
# You can get this from your Khalti Merchant Dashboard (developer.khalti.com)
KHALTI_SANDBOX_MERCHANT_SECRET_KEY = "d9a25c8411024a4abf56669b98a6c740" # Using your provided key

if KHALTI_SANDBOX_MERCHANT_SECRET_KEY == "YOUR_KHALTI_SANDBOX_SECRET_KEY": # Keep check in case it's reverted
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! ERROR: Please replace 'YOUR_KHALTI_SANDBOX_SECRET_KEY' in this script !!!")
    print("!!! with your actual Khalti Sandbox Merchant Live Secret Key.             !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    sys.exit(1)


KHALTI_SANDBOX_CONFIG = {
    "live_secret_key": KHALTI_SANDBOX_MERCHANT_SECRET_KEY,
    "return_url_config": "http://localhost:8000/khalti/callback/", # Must match server
    "website_url_config": "http://merchant.example.com", # Your merchant website
    "mode": "sandbox",
    "timeout": 60 # Optional: set a longer timeout for API calls
}

def test_initiation(client: KhaltiClient, order_id: str, amount_paisa: int, description: str):
    print("\n--- Testing Khalti Payment Initiation ---")
    try:
        init_response = client.initiate_payment(
            amount=amount_paisa,
            order_id=order_id,
            description=description,
            # Optionally add customer_info, amount_breakdown, product_details here
            # customer_info={"name": "Test User", "email": "test@example.com", "phone": "9800000000"},
        )
        print("Payment initiation successful with Khalti!")
        print(f"  Payment URL: {init_response.redirect_url}")
        print(f"  PIDX: {init_response.payment_instructions.get('pidx')}")

        # REMOVED webbrowser.open()
        print(f"\nACTION REQUIRED: Please manually open this URL in your browser:")
        print(f"  ==> {init_response.redirect_url}")
        print("Then complete the payment in the Khalti sandbox environment.")

        return True  # Indicate success
    except (ConfigurationError, InitiationError, APIConnectionError, APITimeoutError) as e:
        print(f"Khalti Initiation FAILED: {type(e).__name__} - {e}")
        if hasattr(e, "gateway_response") and e.gateway_response:
            print(f"  Gateway Response: {e.gateway_response}")
        if hasattr(e, "error_code") and e.error_code:
            print(f"  Error Code: {e.error_code}")
        logging.exception("Initiation error details:")
        return False


def test_verification_manually(client: KhaltiClient):
    print("\n--- Testing Khalti Payment Verification (Manual Input from Callback) ---")
    print("After completing the payment in the Khalti sandbox, Khalti will redirect you to:")
    print(f"  {KHALTI_SANDBOX_CONFIG['return_url_config']}")
    print("The URL will contain query parameters like 'pidx', 'txnId', 'amount', 'status', etc.")
    print("Your simple_callback_server.py (if running) should also log these parameters.")

    print("\nPlease provide the callback parameters from the Khalti redirect URL or server log:")

    callback_params = {}
    params_to_collect = ['pidx', 'txnId', 'amount', 'purchase_order_id', 'purchase_order_name', 'status', 'message', 'mobile']
    
    print("\nEnter the value for each parameter when prompted. Press Enter if a parameter is not present in your callback.")
    for param_name in params_to_collect:
        value = input(f"  Enter value for '{param_name}': ").strip()
        if value:
            callback_params[param_name] = value
    
    if not callback_params.get("pidx"):
        print("ERROR: 'pidx' is essential for verification. Cannot proceed.")
        return

    print(f"\nAttempting verification with callback data: {callback_params}")

    try:
        verification_result = client.verify_payment(
            transaction_data_from_callback=callback_params
        )
        print("\nKhalti Verification Result (from Lookup API):")
        print(f"  Is Successful: {verification_result.is_successful}")
        print(f"  Khalti Status (from API): {verification_result.status_code}")
        print(f"  Status Message (from API): {verification_result.status_message}")
        print(f"  Transaction ID (Khalti TxnId from API): {verification_result.transaction_id}")
        print(f"  Order ID (PIDX from API): {verification_result.order_id}")
        print(f"  Verified Amount (Paisa from API): {verification_result.verified_amount}")
        print("\n  Gateway Specific Details (from API):")
        for k, v in verification_result.gateway_specific_details.items():
            if k in ['fee_paisa', 'refunded', 'status', 'transaction_id', 'pidx', 'total_amount', 'state', 'created_on', 'user']:
                 print(f"    {k}: {v}")

    except (VerificationError, APIConnectionError, APITimeoutError, ConfigurationError) as e:
        print(f"Khalti Verification FAILED: {type(e).__name__} - {e}")
        if hasattr(e, "gateway_response") and e.gateway_response:
            print(f"  Gateway Response (from API call or problematic callback data): {e.gateway_response}")
        if hasattr(e, "error_code") and e.error_code:
            print(f"  Error Code: {e.error_code}")
        logging.exception("Verification error details:")


if __name__ == "__main__":
    print("--- Khalti Client Manual Test Script ---")
    try:
        khalti_client = KhaltiClient(config=KHALTI_SANDBOX_CONFIG)
    except ConfigurationError as e:
        print(f"Configuration Error: {e}")
        sys.exit(1)

    unique_order_id = f"sdk-test-{os.urandom(4).hex()}"
    payment_amount_paisa = 1500
    product_description = f"Test Product for {unique_order_id}"

    print(f"Test Order ID: {unique_order_id}")
    print(f"Test Amount (Paisa): {payment_amount_paisa}")

    initiation_succeeded = test_initiation(
        khalti_client,
        order_id=unique_order_id,
        amount_paisa=payment_amount_paisa,
        description=product_description
    )

    if initiation_succeeded:
        print("\nNEXT STEP: Complete the payment in the Khalti Sandbox window/tab.")
        print("After Khalti redirects you to the callback URL (e.g., http://localhost:8000/khalti/callback/),")
        print("note down the query parameters from the URL or your server log.")
        print("Then, come back here to provide them for verification.")
        
        test_verification_manually(khalti_client)
    else:
        print("\nInitiation failed, skipping verification test.")

    print("\n--- Test Script Finished ---")