-- SQLite schema for phishing URL history
CREATE TABLE IF NOT EXISTS URL_History (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    date_checked TEXT NOT NULL
);

-- Query to fetch the latest history rows
SELECT url, status, risk_score, date_checked
FROM URL_History
ORDER BY id DESC
LIMIT 20;
