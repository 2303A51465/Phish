# Phishing URL Detection Web App

A beginner-friendly full-stack project using:
- Frontend: HTML, CSS, JavaScript
- Backend: Python + Flask
- Database: SQLite

## Project Structure

- `frontend/` - static UI files (`index.html`, `styles.css`, `script.js`)
- `backend/app.py` - Flask server and URL analysis logic
- `database/schema.sql` - SQLite table schema and sample query
- `requirements.txt` - Python dependencies

## Features

- Enter a URL and click **Check URL**
- Rule-based phishing detection using URL length, `@`, IP usage, suspicious words, HTTPS, and structure checks
- Displays status, risk score, and reasons
- Stores every checked URL in SQLite history
- Shows recent history table and progress bar
- Simple responsive design with animations and loading spinner

## Setup Instructions

1. Open a terminal in the project folder:
   ```powershell
   cd "c:\Users\Shree priya\OneDrive\Desktop\Phish"
   ```

2. Create a Python virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Run the Flask backend:
   ```powershell
   python backend\app.py
   ```

5. Open your browser and visit:
   ```text
   http://127.0.0.1:5002
   ```

## Notes

- The backend automatically creates `database/url_history.db` when first run.
- The frontend sends requests to `/check_url` and `/history`.

## Database Schema

The SQLite schema is defined in `database/schema.sql`:

```sql
CREATE TABLE IF NOT EXISTS URL_History (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    date_checked TEXT NOT NULL
);
```
