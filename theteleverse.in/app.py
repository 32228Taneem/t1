from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
import logging
import os  # Added for path handling
from calculator.calculator_api import el1_rx_cal,el1_tx_power_cal, test_api, earfcn_to_dl_freq, lte_dl_tput_calculations, conv_te_sfn_to_ue_sfn, calculate_two_db_total_power, get_lte_band_info
# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
application = app
print("---> Entered into app.py ")
CORS(app, resources={r"/calculate": {"origins": ["http://localhost:5000", "http://127.0.0.1:5500", "http://127.0.0.1:*", "http://192.168.1.7:5000", "http://192.168.1.7:5000", "http://192.168.*:*", "*"]}})  # Allow all origins for testing

# Serve the index.html file at the root URL and calculator URLs
@app.route('/')
@app.route('/calculator/<calc_id>')
def serve_calculator(calc_id=None):
    """
    Serve the index.html file when the root URL or a calculator URL is accessed.
    The calc_id parameter is optional and used for client-side routing.
    """
    try:
        logger.debug(f"Serving index.html for route: /{calc_id or ''} from {request.remote_addr}")
        return send_file('index.html')
    except FileNotFoundError:
        logger.error("index.html not found")
        return jsonify({'error': 'index.html not found'}), 404

# Serve static files (CSS, JS, HTML snippets, and assets)
@app.route('/<path:filename>')
def serve_static(filename):
    """
    Serve static files like CSS, JS, HTML snippets, and assets from the current directory or subdirectories.
    """
    if filename == 'favicon.ico':
        response = make_response('')
        response.status_code = 204
        return response
    try:
        # Construct the full path relative to app.root_path
        file_path = os.path.join(app.root_path, filename)
        # If file not found, check the calculator subdirectory
        if not os.path.isfile(file_path):
            if filename in ['calculator_styles.css', 'calculators.js', 'calculator_core.js', 'calculator_logs.html', 'calculator_welcome.html']:
                file_path = os.path.join(app.root_path, 'calculator', filename)
        if not os.path.isfile(file_path):
            logger.error(f"Static file not found: {filename}")
            return jsonify({'error': f'{filename} not found'}), 404
        logger.debug(f"Serving static file: {filename} from {request.remote_addr} at {file_path}")
        return send_file(file_path)
    except FileNotFoundError:
        logger.error(f"Static file not found: {filename}")
        return jsonify({'error': f'{filename} not found'}), 404

@app.route('/calculate', methods=['POST'])
def calculate():
    """
    Handle calculator requests from the front-end.
    Expects a JSON payload with 'calculator' and 'data' (dictionary of inputs).
    Returns the result and logs as JSON.
    """
    logger.debug(f"Received POST request to /calculate from {request.remote_addr} with data: {request.get_data()}")
    data = request.get_json()
    if not data:
        logger.error("No JSON data provided")
        return jsonify({'result': 'Error: No JSON data provided', 'logs': ['Error: No JSON data']}), 400
    calculator = data.get('calculator')
    input_data = data.get('data', {})  # Use 'data' instead of 'numbers' for dictionary

    if calculator == 'CONV-EARFCN-FREQ':
        result, logs = earfcn_to_dl_freq(list(input_data.values()) if input_data else [])  # Convert to list if needed
        logger.debug(f"CONV-EARFCN-FREQ result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})
    
    elif calculator == 'el1-tx-power':
        result, logs = el1_tx_power_cal(input_data)  # Pass the dictionary directly
        logger.debug(f"el1-tx-power result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})
    
    elif calculator == 'el1-rx-cal':
        result, logs = el1_rx_cal(input_data)  # Pass the dictionary directly
        logger.debug(f"el1-rx result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})
    
    
    elif calculator == 'lte-dl-tput-cal':
        result, logs = lte_dl_tput_calculations(list(input_data.values()) if input_data else [])  # Convert to list if needed
        logger.debug(f"lte-dl-tput-cal result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})
    
    elif calculator == 'CONV-TE_SFN-UE_SFN':
        result, logs = conv_te_sfn_to_ue_sfn(list(input_data.values()) if input_data else [])  # Convert to list if needed
        logger.debug(f"CONV-TE_SFN-UE_SFN result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})

    elif calculator == 'two-db-total-power':
        result, logs = calculate_two_db_total_power(list(input_data.values()) if input_data else [])  # Convert to list if needed
        logger.debug(f"two-db-total-power result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})

    elif calculator == 'GET-BNAD-INFO':
        result, logs = get_lte_band_info(list(input_data.values()) if input_data else [])  # Convert to list if needed
        logger.debug(f"GET-BNAD-INFO result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})
    
    elif calculator == 'weighted-average':
        result, logs = test_api(list(input_data.values()) if input_data else [])  # Convert to list if needed
        logger.debug(f"weighted-average result: {result}, logs: {logs}")
        return jsonify({'result': result, 'logs': logs})

    elif calculator == 'old_weighted-average':
        try:
            num_subjects = int(list(input_data.values())[0]) if input_data else 0
            if num_subjects not in [2, 3, 4]:
                return jsonify({'result': 'Error: Number of subjects must be 2, 3, or 4', 'logs': ['Error: Invalid number of subjects']}), 400
        except (ValueError, IndexError):
            return jsonify({'result': 'Error: Invalid number of subjects', 'logs': ['Error: Number of subjects must be an integer (2, 3, or 4)']}), 400

        scores = []
        weights = []
        logs = []
        values = list(input_data.values()) if input_data else []
        for i in range(num_subjects):
            try:
                score = float(values[2 * i + 1])
                if score < 0:
                    return jsonify({'result': 'Error: Scores must be non-negative', 'logs': ['Error: Scores must be non-negative']}), 400
                scores.append(score)
                weight_flag = values[2 * i + 2].lower()
                if weight_flag not in ['true', 'false']:
                    return jsonify({'result': 'Error: Invalid weight flag', 'logs': ['Error: Weight flags must be "true" or "false"']}), 400
                weight = 2 if weight_flag == 'true' else 1
                weights.append(weight)
                logs.append(f'Subject {i+1}: Score = {score}, Weight = {weight}')
            except (ValueError, IndexError):
                return jsonify({'result': 'Error: Invalid input', 'logs': ['Error: Scores must be numeric, weights must be provided']}), 400

        weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
        total_weight = sum(weights)
        if total_weight == 0:
            return jsonify({'result': 'Error: Total weight cannot be zero', 'logs': ['Error: Total weight cannot be zero']}), 400
        weighted_avg = weighted_sum / total_weight
        weighted_avg = round(weighted_avg, 2)
        logs.append(f'Weighted Sum = {weighted_sum}')
        logs.append(f'Total Weight = {total_weight}')
        logs.append(f'Weighted Average = {weighted_avg}')

        return jsonify({'result': f'{weighted_avg}', 'logs': logs})
    
    else:
        logger.error(f"Unknown calculator: {calculator}")
        return jsonify({'result': 'Error: Unknown calculator', 'logs': ['Error: Unknown calculator']}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)