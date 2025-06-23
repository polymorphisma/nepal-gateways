from nepal_gateways import KhaltiClient, ConfigurationError, InitiationError, VerificationError, APIConnectionError, APITimeoutError

import logging
import sys
import os
from urllib.parse import urlparse, parse_qs
from typing import Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)


# --- SETUP LOGGING FOR DEVELOPMENT ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)-25s - %(message)s (%(filename)s:%(lineno)d)",
    style="%",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# --- SANDBOX CONFIGURATION ---
KHALTI_SANDBOX_CONFIG = {
    "live_secret_key": "your_khalti_sandbox_live_secret_key", # Get this from test-admin.khalti.com
    "return_url_config": "http://localhost:8001/khalti/callback/", # Use a specific port
    "website_url_config": "http://localhost:8001", # Your test website URL (Khalti requires this)
    "mode": "sandbox"
}

def test_initiation(client: KhaltiClient, order_id: str, amount_paisa: int):
    print("\n--- Testing Khalti Payment Initiation ---")
    try:
        # Khalti expects amount in PAISA
        # Description maps to purchase_order_name
        init_response = client.initiate_payment(
            amount=amount_paisa,
            order_id=order_id, # This will be purchase_order_id
            description="Test SDK Product Purchase", # This will be purchase_order_name
            # Optional parameters can be added via kwargs or specific params if you modify client
            customer_info={"name": "Khalti Test User", "email": "testuser@example.com", "phone": "9800000000"},
            amount_breakdown=[ # Example, sum must match 'amount'
                {"label": "Item A", "amount": int(amount_paisa * 0.7)},
                {"label": "Service Fee", "amount": int(amount_paisa * 0.3)}
            ],
            product_details=[{
                "identity": "item-123", "name": "Test Item",
                "total_price": amount_paisa, "quantity": 1, "unit_price": amount_paisa
            }],
            merchant_extra="some_extra_info_123" # Example custom merchant field
        )
        print("Khalti Initiation Successful!")
        print(f"  Payment URL: {init_response.redirect_url}")

        if init_response.payment_instructions and 'pidx' in init_response.payment_instructions:
            print(f"  pidx: {init_response.payment_instructions['pidx']}")

        print(f"  Raw API Response: {init_response.raw_response}")
        print("\nACTION: Open the Payment URL above in your browser to complete the payment.")

        return init_response.payment_instructions.get('pidx') if init_response.payment_instructions else None

    except (ConfigurationError, InitiationError, APIConnectionError, APITimeoutError) as e:
        print(f"Khalti Initiation FAILED: {type(e).__name__} - {e}")

        if hasattr(e, 'gateway_response') and e.gateway_response:
             print(f"  Gateway Response: {e.gateway_response}")

        logging.exception("Khalti initiation error details:")

        return None
    except Exception as e:
        print(f"An UNEXPECTED error occurred during Khalti initiation: {e}")
        logging.exception("Unexpected Khalti initiation error details:")
        return None


def test_verification(client: KhaltiClient, pidx_for_verification: Optional[str]):
    print("\n--- Testing Khalti Payment Verification ---")

    if not pidx_for_verification:
        full_callback_url = input("Enter FULL callback URL from Khalti (e.g., http://localhost:8001/...?pidx=...&status=...): ").strip()
        if not full_callback_url:
            print("No callback URL or pidx provided. Skipping verification.")
            return
        try:
            parsed_url = urlparse(full_callback_url)
            query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
            pidx_from_url = query_params.get('pidx')
            if not pidx_from_url:
                print("Could not find 'pidx' in the provided callback URL.")
                return
            pidx_for_verification = pidx_from_url
            print(f"Parsed callback data for verification (using pidx='{pidx_for_verification}'): {query_params}")
            transaction_data_for_verification = query_params
        except Exception as e:
            print(f"Error parsing callback URL: {e}. Please enter pidx manually.")
            pidx_for_verification = input("Enter pidx from Khalti callback: ").strip()
            if not pidx_for_verification:
                print("No pidx provided. Skipping verification.")
                return
            transaction_data_for_verification = {"pidx": pidx_for_verification}
    else:
        # If pidx was passed from a successful initiation in the same script run
        print(f"Using pidx='{pidx_for_verification}' from initiation for verification.")
        # The callback data would contain more than just pidx, but for Khalti lookup, pidx is key.
        # To make this part more robust if called immediately, we'd simulate a minimal callback.
        transaction_data_for_verification = {"pidx": pidx_for_verification, "status": "AwaitingLookup"}


    try:
        verify_response = client.verify_payment(
            transaction_data_from_callback=transaction_data_for_verification
        )
        print("\nKhalti Verification Result:")
        print(f"  Is Successful: {verify_response.is_successful}")
        print(f"  Status: {verify_response.status_code}")
        print(f"  Message: {verify_response.status_message}")
        print(f"  Khalti Txn ID: {verify_response.transaction_id}")
        print(f"  pidx (Payment ID): {verify_response.order_id}") # order_id in result maps to pidx
        print(f"  Amount (Paisa): {verify_response.verified_amount}")
        if verify_response.gateway_specific_details:
            print(f"  Fee (Paisa): {verify_response.gateway_specific_details.get('fee_paisa')}")
            print(f"  Refunded: {verify_response.gateway_specific_details.get('refunded')}")
        print(f"  Raw API Response: {verify_response.raw_response}")

    except (VerificationError, ConfigurationError, APIConnectionError, APITimeoutError) as e:
        print(f"Khalti Verification FAILED: {type(e).__name__} - {e}")
        if hasattr(e, 'gateway_response') and e.gateway_response:
             print(f"  Gateway Response: {e.gateway_response}")
        logging.exception("Khalti verification error details:")
    except Exception as e:
        print(f"An UNEXPECTED error occurred during Khalti verification: {e}")
        logging.exception("Unexpected Khalti verification error details:")


if __name__ == "__main__":
    print("--- Khalti Client Test Script ---")
    try:
        khalti_client = KhaltiClient(config=KHALTI_SANDBOX_CONFIG)
    except ConfigurationError as e:
        print(f"Khalti Client Configuration Error: {e}")
        sys.exit(1)

    # --- Test Initiation ---
    # Khalti requires amounts in Paisa and > Rs. 10 (i.e., > 1000 paisa)
    # KHALTI_MIN_TRANSACTION_AMOUNT_PAISA from config.py should be 1000
    # So, 1100 paisa (Rs. 11.00) is a good test amount.
    test_order_id = f"khalti-sdktest-{os.urandom(4).hex()}"
    test_amount_paisa = 1100

    # For a more complete manual flow, you'd run initiation, then manually do payment,
    # then run verification with the callback data.
    # This script will run them sequentially, prompting for callback data.

    print("Step 1: Initiating payment...")
    returned_pidx = test_initiation(khalti_client, order_id=test_order_id, amount_paisa=test_amount_paisa)

    if returned_pidx:
        print("\nStep 2: Complete payment using the URL above.")
        print("Once payment is done and you are redirected to your callback URL,")
        print("copy the FULL callback URL from your browser's address bar.")
        test_verification(khalti_client, pidx_for_verification=None) # Will prompt for full URL
    else:
        print("\nInitiation failed. Skipping verification.")


    # Example of calling verification if you already have a pidx from a previous run
    # print("\n--- You can also test verification with a known pidx ---")
    # known_pidx = input("Enter a known pidx for verification (or press Enter to skip): ").strip()
    # if known_pidx:
    #     test_verification(khalti_client, pidx_for_verification=known_pidx)


    print("\n--- Khalti Test Script Finished ---")