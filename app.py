import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from core.sast_analyzer import SASTScanner

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

scanner = SASTScanner("rules.yaml")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan-file", methods=["POST"])
def scan_uploaded_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Scan the uploaded file
    findings = scanner.scan_file(filepath)

    # Cleanup uploaded file after scan
    if os.path.exists(filepath):
        os.remove(filepath)

    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    medium = sum(1 for f in findings if f['severity'] == 'MEDIUM')

    score = max(0, 100 - (critical * 30 + high * 15 + medium * 5))

    return jsonify({
        "filename": filename,
        "score": score,
        "findings": findings,
        "total": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium
    })

if __name__ == "__main__":
    app.run(debug=True, port=5001)