# For Payment Initiation (Form POST)
ESEWA_SANDBOX_INITIATION_URL_V2 = "https://rc-epay.esewa.com.np/api/epay/main/v2/form"
ESEWA_LIVE_INITIATION_URL_V2 = "https://epay.esewa.com.np/api/epay/main/v2/form"

# For Transaction Status Check (Server-to-server GET request for verification)
ESEWA_SANDBOX_STATUS_CHECK_URL = "https://rc.esewa.com.np/api/epay/transaction/status/"
ESEWA_LIVE_STATUS_CHECK_URL = "https://epay.esewa.com.np/api/epay/transaction/status/"

ESEWA_SANDBOX_SECRET_KEY_DEFAULT = "8gBm/:&EnhH.1/q"

# Default field names for request signature generation
# As per documentation: total_amount,transaction_uuid,product_code
ESEWA_DEFAULT_REQUEST_SIGNED_FIELD_NAMES = "total_amount,transaction_uuid,product_code"

# Default field names for response signature verification from callback
# As per documentation example: transaction_code,status,total_amount,transaction_uuid,product_code,signed_field_names
ESEWA_DEFAULT_RESPONSE_SIGNED_FIELD_NAMES = "transaction_code,status,total_amount,transaction_uuid,product_code"

# Callback query parameter name that might contain the Base64 encoded JSON data
# This is an assumption; needs verification. Could also be in POST body.
ESEWA_CALLBACK_DATA_PARAM_NAME = "data"