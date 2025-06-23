# nepal_gateways/khalti/config.py

# Khalti API v2 Base Endpoints
KHALTI_SANDBOX_BASE_URL_V2 = "https://dev.khalti.com/api/v2/"
KHALTI_LIVE_BASE_URL_V2 = "https://khalti.com/api/v2/"

# Specific Paths
KHALTI_INITIATE_PATH = "epayment/initiate/"
KHALTI_LOOKUP_PATH = "epayment/lookup/"

# Default minimum amount (Khalti requires amount > 10 Rs, i.e., > 1000 paisa)
# This is for validation, not directly used in API calls unless you enforce it.
KHALTI_MIN_TRANSACTION_AMOUNT_PAISA = 1001  # Amount must be greater than 1000 paisa
