# examples/simple_callback_server.py
from flask import Flask, request, jsonify
import base64
import json

app = Flask(__name__)

@app.route('/esewa/success_callback/', methods=['GET', 'POST'])
def esewa_success():
    print("\n--- eSewa Success Callback Received ---")
    if request.method == 'POST':
        print("Method: POST")
        print(f"Content-Type: {request.content_type}")
        if request.content_type == 'application/x-www-form-urlencoded':
            print("Form Data (POST):")
            for key, value in request.form.items():
                print(f"  {key}: {value}")
            # If 'data' is a form field containing Base64
            if 'data' in request.form:
                 print(f"\nBase64 'data' field found in POST form: {request.form['data']}")
                 try:
                    decoded_json_str = base64.b64decode(request.form['data']).decode('utf-8')
                    parsed_callback_data = json.loads(decoded_json_str)
                    print(f"Decoded and Parsed JSON from 'data' field: {parsed_callback_data}")
                 except Exception as e:
                    print(f"Error decoding/parsing 'data' field: {e}")

        elif request.content_type == 'application/json':
            print("JSON Data (POST Body):")
            try:
                data = request.get_json()
                print(json.dumps(data, indent=2)) # This is likely the decoded data
                # You'd copy this JSON to use in your test_esewa_v2.py
            except Exception as e:
                print(f"Could not parse JSON body: {e}")
                print(f"Raw body: {request.data}")
        else:
            print(f"Raw Data (POST): {request.data}")
        return "POST Callback received by test server. Check terminal."

    elif request.method == 'GET':
        print("Method: GET")
        print("Query Parameters (GET):")
        for key, value in request.args.items():
            print(f"  {key}: {value}")
        if 'data' in request.args:
             print(f"\nBase64 'data' param found in GET: {request.args['data']}")
             try:
                decoded_json_str = base64.b64decode(request.args['data']).decode('utf-8')
                parsed_callback_data = json.loads(decoded_json_str)
                print(f"Decoded and Parsed JSON from 'data' param: {parsed_callback_data}")
             except Exception as e:
                print(f"Error decoding/parsing 'data' param: {e}")

        return "GET Callback received by test server. Check terminal."

if __name__ == '__main__':
    print("Starting simple Flask server on http://localhost:8000")
    print("eSewa success_url should be set to: http://localhost:8000/esewa/success_callback/")
    print("eSewa failure_url should be set to: http://localhost:8000/esewa/failure_callback/ (or similar)")
    app.run(port=8000, debug=True)