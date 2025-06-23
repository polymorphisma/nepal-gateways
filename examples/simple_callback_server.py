# examples/simple_callback_server.py
from flask import Flask, request, jsonify  # Added jsonify
import base64
import json
import logging

# Configure basic logging for the server
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.route("/")
def home():
    return "Simple Callback Server is running. Ready to receive callbacks."


# --- eSewa Specific Callback Handler ---
@app.route("/esewa/success_callback/", methods=["GET", "POST"])
def esewa_success():
    logger.info("\n--- eSewa Success Callback Received ---")
    callback_data = {}
    method = request.method

    if method == "POST":
        logger.info(f"Method: POST, Content-Type: {request.content_type}")
        if request.content_type == "application/x-www-form-urlencoded":
            logger.info("Form Data (POST):")
            for key, value in request.form.items():
                logger.info(f"  {key}: {value}")
                callback_data[key] = value
            if "data" in request.form:
                logger.info(
                    f"Base64 'data' field found in POST form: {request.form['data']}"
                )
                try:
                    decoded_json_str = base64.b64decode(request.form["data"]).decode(
                        "utf-8"
                    )
                    parsed_callback_data = json.loads(decoded_json_str)
                    logger.info(
                        f"Decoded and Parsed JSON from 'data' field: {parsed_callback_data}"
                    )
                    callback_data[
                        "decoded_data_field"
                    ] = parsed_callback_data  # Store decoded for reference
                except Exception as e:
                    logger.error(f"Error decoding/parsing 'data' field: {e}")
        elif request.content_type == "application/json":
            logger.info("JSON Data (POST Body):")
            try:
                data = request.get_json()
                logger.info(json.dumps(data, indent=2))
                callback_data = data
            except Exception as e:
                logger.error(f"Could not parse JSON body: {e}")
                logger.info(f"Raw body: {request.data}")
        else:
            logger.info(f"Raw Data (POST): {request.data}")
        return jsonify(
            {"status": "eSewa POST Callback received", "data_received": callback_data}
        )

    elif method == "GET":
        logger.info("Method: GET")
        logger.info("Query Parameters (GET):")
        for key, value in request.args.items():
            logger.info(f"  {key}: {value}")
            callback_data[key] = value
        if "data" in request.args:
            logger.info(f"Base64 'data' param found in GET: {request.args['data']}")
            try:
                decoded_json_str = base64.b64decode(request.args["data"]).decode(
                    "utf-8"
                )
                parsed_callback_data = json.loads(decoded_json_str)
                logger.info(
                    f"Decoded and Parsed JSON from 'data' param: {parsed_callback_data}"
                )
                callback_data["decoded_data_field"] = parsed_callback_data
            except Exception as e:
                logger.error(f"Error decoding/parsing 'data' param: {e}")
        return jsonify(
            {"status": "eSewa GET Callback received", "data_received": callback_data}
        )

    return "Unsupported method for eSewa callback.", 405


# --- Khalti Specific Callback Handler ---
@app.route(
    "/khalti/callback/", methods=["GET"]
)  # Khalti typically uses GET for its redirect
def khalti_callback():
    logger.info("\n--- Khalti Callback Received ---")
    method = request.method
    callback_data = {}

    if method == "GET":
        logger.info("Method: GET")
        logger.info("Query Parameters from Khalti:")
        for key, value in request.args.items():
            logger.info(f"  {key}: {value}")
            callback_data[key] = value

        # You can add further processing here if needed, e.g., display a nicer page.
        # For this test script, just logging and returning JSON is fine.
        response_message = "Khalti GET Callback received by test server. Check terminal for parameters."
        logger.info(response_message)
        return jsonify(
            {"status": "Khalti GET Callback received", "parameters": callback_data}
        )
    else:
        logger.warning(f"Received unexpected {method} request to Khalti callback URL.")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"Khalti callback expects GET, received {method}",
                }
            ),
            405,
        )


if __name__ == "__main__":
    host = "localhost"
    port = 8000
    print(f"Starting simple Flask server on http://{host}:{port}")
    print("Ensure your gateway configurations use this server for callback URLs:")
    print(
        f"  eSewa success_url (example): http://{host}:{port}/esewa/success_callback/"
    )
    print(f"  Khalti return_url (example): http://{host}:{port}/khalti/callback/")
    # Use threaded=False if debugging with breakpoints in callbacks, otherwise True is fine
    app.run(host=host, port=port, debug=True, threaded=True)
