import os
import time
import uuid
import threading
import requests
import pandas as pd
from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__)

# -------------------------------
# Folders for uploads & outputs
# -------------------------------
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# -------------------------------
# In-memory job tracker
# -------------------------------
jobs = {}

# -------------------------------
# VirusTotal lookup
# -------------------------------
def query_vt(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=20)

        if r.status_code == 200:
            data = r.json()
            return data["data"]["attributes"]["sha256"]

        elif r.status_code == 404:
            return "NOT_FOUND"

        elif r.status_code == 429:
            time.sleep(15)
            return query_vt(hash_value, api_key)

        else:
            return "ERROR"

    except Exception as e:
        return "ERROR"

# -------------------------------
# Background file processing
# -------------------------------
def process_file(job_id, filepath, api_key):
    try:
        jobs[job_id]["status"] = "processing"

        # Read input file
        if filepath.endswith(".xlsx"):
            df = pd.read_excel(filepath)
            hashes = df.iloc[:, 0].astype(str).tolist()
        else:
            df = pd.read_csv(filepath)
            # If first row has column name like "hashes" or "final_hashes"
            if df.columns[0].lower() in ["hashes", "final_hashes"]:
                hashes = df.iloc[:, 0].astype(str).tolist()
            else:
                hashes = df.iloc[:, 0].astype(str).tolist()

        results = []
        total = len(hashes)

        for i, h in enumerate(hashes):
            sha256 = query_vt(h.strip(), api_key)
            results.append(sha256)
            jobs[job_id]["progress"] = int((i + 1) / total * 100)
            time.sleep(15)  # Free VT API rate limit

        # Save output
        out_df = pd.DataFrame({
            "Input Hash": hashes,
            "SHA256": results
        })
        output_path = os.path.join(OUTPUT_FOLDER, f"{job_id}.xlsx")
        out_df.to_excel(output_path, index=False)

        jobs[job_id]["status"] = "done"
        jobs[job_id]["file"] = output_path

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)

# -------------------------------
# Routes
# -------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    api_key = request.form.get("apikey")
    file = request.files.get("file")

    if not api_key or not file:
        return jsonify({"error": "Missing API key or file"}), 400

    job_id = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    jobs[job_id] = {"status": "queued", "progress": 0, "file": None}

    # Start background thread
    thread = threading.Thread(
        target=process_file,
        args=(job_id, filepath, api_key),
        daemon=True
    )
    thread.start()

    return jsonify({"job_id": job_id})

@app.route("/status/<job_id>")
def status(job_id):
    return jsonify(jobs.get(job_id, {}))

@app.route("/download/<job_id>")
def download(job_id):
    path = jobs[job_id].get("file")
    if path and os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

# -------------------------------
# Run for Render
# -------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
