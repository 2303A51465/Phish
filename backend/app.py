import os
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from phishing_detector import analyze_url_ml

FRONTEND_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path='')
DATABASE_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'url_history.db')

# Ensure database directory exists and create the table if missing.
def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS URL_History (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                date_checked TEXT NOT NULL
            )
            '''
        )
        conn.commit()

# Save every checked URL result into the SQLite database.
def store_result(url, status, risk_score):
    timestamp = datetime.utcnow().isoformat() + 'Z'
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            'INSERT INTO URL_History (url, status, risk_score, date_checked) VALUES (?, ?, ?, ?)',
            (url, status, risk_score, timestamp)
        )
        conn.commit()

# Load the last 20 checked URLs.
def get_history(limit=20):
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.execute(
            'SELECT id, url, status, risk_score, date_checked FROM URL_History ORDER BY id DESC LIMIT ?',
            (limit,)
        )
        return [
            {
                'id': row[0],
                'url': row[1],
                'status': row[2],
                'risk_score': row[3],
                'date_checked': row[4],
            }
            for row in cursor.fetchall()
        ]

# Delete a single history record by ID.
def delete_record_by_id(record_id):
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute('DELETE FROM URL_History WHERE id = ?', (record_id,))
        conn.commit()

# Delete all history records.
def delete_all_records():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute('DELETE FROM URL_History')
        conn.commit()

# Validate the URL structure and return a normalized version.
def validate_url(value):
    if not isinstance(value, str) or not value.strip():
        return None

    url = value.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        return parsed.geturl()
    except Exception:
        return None

# Machine Learning-based URL analysis using trained RandomForest classifier
def analyze_url(url):
    """
    Analyze a URL using the ML-based phishing detector.
    Returns analysis results with status, risk_score, and reasons.
    """
    return analyze_url_ml(url)


@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get('url', '')
    normalized_url = validate_url(raw_url)
    if not normalized_url:
        return jsonify({'message': 'Invalid URL format. Please enter a valid URL.'}), 400

    analysis = analyze_url(normalized_url)
    store_result(normalized_url, analysis['status'], analysis['risk_score'])
    return jsonify(analysis)

@app.route('/history', methods=['GET'])
def history():
    rows = get_history()
    return jsonify({'history': rows})

@app.route('/delete_history/<int:record_id>', methods=['DELETE'])
def delete_history(record_id):
    try:
        delete_record_by_id(record_id)
        return jsonify({'message': 'Record deleted successfully'})
    except Exception as e:
        return jsonify({'message': f'Error deleting record: {str(e)}'}), 500

@app.route('/delete_all_history', methods=['DELETE'])
def delete_all_history():
    try:
        delete_all_records()
        return jsonify({'message': 'All history deleted'})
    except Exception as e:
        return jsonify({'message': f'Error clearing history: {str(e)}'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5002, debug=True)
