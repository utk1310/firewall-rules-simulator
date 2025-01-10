from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

@app.route("/")
def index():
    conn = sqlite3.connect('../logs/firewall_logs.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs")
    logs = cursor.fetchall()
    conn.close()
    return render_template('index.html', logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
