# examples/test_esewa_v2.py
import logging
import json
import base64
from urllib.parse import urlencode # For simulating callback if needed

# Ensure your package is findable if not installed (adjust path if needed)
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from nepal_gateways import EsewaClient, ConfigurationError, InitiationError, VerificationError, InvalidSignatureError, APIConnectionError, APITimeoutError

# --- SETUP LOGGING FOR DEVELOPMENT ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)-25s - %(message)s (%(filename)s:%(lineno)d)",
    style="%",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# --- SANDBOX CONFIGURATION ---
ESEWA_SANDBOX_CONFIG = {
    "product_code": "EPAYTEST",
    "secret_key": "8gBm/:&EnhH.1/q", # CORRECTED KEY
    "success_url": "http://localhost:8000/esewa/success_callback/",
    "failure_url": "http://localhost:8000/esewa/failure_callback/",
    "mode": "sandbox"
}

def generate_auto_submit_html(form_action_url: str, form_fields: dict, filename="esewa_redirect.html"):
    """Generates an HTML file with a form that auto-submits."""
    html_fields = ""
    for key, value in form_fields.items():
        # Ensure values are properly escaped for HTML attributes
        # For this simple case, direct insertion is usually fine for basic string/numeric values
        # For more complex values, consider using an HTML escaping library if needed.
        html_fields += f'    <input type="hidden" name="{key}" value="{value}">\n'

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Redirecting to eSewa...</title>
</head>
<body onload="document.getElementById('esewaRedirectForm').submit();">
    <p>Please wait, you are being redirected to eSewa for payment...</p>
    <form id="esewaRedirectForm" action="{form_action_url}" method="POST">
{html_fields}
        <noscript>
            <p>Your browser does not support JavaScript, or it is disabled.</p>
            <input type="submit" value="Click here to continue to eSewa">
        </noscript>
    </form>
</body>
</html>
"""
    try:
        with open(filename, "w") as f:
            f.write(html_content)
        print(f"Generated auto-submit HTML page: {os.path.abspath(filename)}")
        print(f"Please open this file in your web browser to proceed.")
    except IOError as e:
        print(f"Error writing HTML file {filename}: {e}")


def test_initiation(client: EsewaClient, order_id: str, amount: float):
    print("\n--- Testing eSewa Payment Initiation (HTML Auto-Submit) ---")
    try:
        init_response = client.initiate_payment(
            amount=amount,
            order_id=order_id,
            tax_amount=0.0,
            product_service_charge=0.0,
            product_delivery_charge=0.0
        )
        print(f"Initiation form data prepared successfully for eSewa!")
        print(f"Target URL: {init_response.redirect_url}")
        print(f"Form Fields to be submitted:")
        for key, value in init_response.form_fields.items():
            print(f"  {key}: {value}")

        generate_auto_submit_html(init_response.redirect_url, init_response.form_fields)
        return True # Indicate success
    except (ConfigurationError, InitiationError) as e:
        print(f"Initiation FAILED: {e}")
        logging.exception("Initiation error details:")
        return False


def test_verification_manually(client: EsewaClient, current_order_id_for_simulation: str): # Pass the order_id
    print("\n--- Testing eSewa Payment Verification (Manual Input) ---")
    print("After completing a payment in the eSewa sandbox using the auto-submitted HTML form,")
    print("eSewa will redirect to your success_url.")
    print("The callback will likely contain a Base64 encoded 'data' parameter or a JSON POST body.")

    base64_callback_data_str = input("Enter the Base64 encoded 'data' from eSewa callback (or press Enter to use SIMULATED): ").strip()

    # Define the SIMULATED data structure here, using the passed current_order_id
    simulated_decoded_callback_json_if_skipped = {
        "transaction_code": "000DUMMY",
        "status": "COMPLETE",
        "total_amount": "100.0", # Ensure this matches the initiated amount for consistency
        "transaction_uuid": current_order_id_for_simulation, # Use the actual order_id
        "product_code": ESEWA_SANDBOX_CONFIG["product_code"],
        "signed_field_names": "transaction_code,status,total_amount,transaction_uuid,product_code",
        "signature": "this_is_a_dummy_signature_replace_with_real_one" # This will fail signature check
    }

    if not base64_callback_data_str:
        print(f"\nUsing SIMULATED DECODED callback data for verification: {simulated_decoded_callback_json_if_skipped}")
        transaction_data_for_verification = simulated_decoded_callback_json_if_skipped
    else:
        transaction_data_for_verification = {"data": base64_callback_data_str}

    try:
        verification_result = client.verify_payment(transaction_data_for_verification)
        # ... (rest of the verification print logic) ...
        print(f"\nVerification Result:")
        print(f"  Is Successful: {verification_result.is_successful}")
        print(f"  Status Code: {verification_result.status_code}")
        print(f"  Status Message: {verification_result.status_message}")
        print(f"  Transaction ID (eSewa): {verification_result.transaction_id}")
        print(f"  Order ID (Merchant): {verification_result.order_id}")
        print(f"  Verified Amount: {verification_result.verified_amount}")
        print(f"  Raw API Response: {verification_result.raw_response}")

    except (InvalidSignatureError, VerificationError, APIConnectionError, APITimeoutError) as e:
        print(f"Verification FAILED: {type(e).__name__} - {e}")
        if hasattr(e, 'gateway_response') and e.gateway_response:
            print(f"  Gateway/Callback Data: {e.gateway_response}")
        logging.exception("Verification error details:")

if __name__ == "__main__":
    print("--- eSewa v2 Client Test Script (with HTML auto-submit) ---")
    # ... (client initialization) ...
    try:
        esewa_client = EsewaClient(config=ESEWA_SANDBOX_CONFIG)
    except ConfigurationError as e:
        print(f"Configuration Error: {e}")
        sys.exit(1)


    unique_order_id = f"html-test-{os.urandom(4).hex()}"
    payment_amount = 100.00
    initiation_succeeded = test_initiation(esewa_client, order_id=unique_order_id, amount=payment_amount)

    if initiation_succeeded:
        print("\nNEXT STEP: Open 'esewa_redirect.html' in your browser to proceed with payment.")
        print("After payment, come back here to test verification (if needed).")
        # Now call test_verification_manually, passing the unique_order_id
        test_verification_manually(esewa_client, current_order_id_for_simulation=unique_order_id)
    else:
        print("Initiation failed, skipping verification test.")


    print("\n--- Test Script Finished ---")