from flask import Flask, render_template, request, redirect, url_for
from scanner import run_scan
import os

app = Flask(__name__)

os.makedirs("reports", exist_ok=True)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("index.html", error="Please enter a URL.")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    results = run_scan(url)
    return render_template("result.html", url=url, results=results)


@app.route("/report")
def report():
    try:
        with open("reports/scan_report.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        content = "No report generated yet. Run a scan first."
    return render_template("report.html", content=content)


if __name__ == "__main__":
    app.run(debug=True)
