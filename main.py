from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/characters")
def characters():
    return render_template("characters.html")


@app.route("/police")
def police():
    return render_template("police.html")


@app.route("/justice")
def justice():
    return render_template("justice.html")


@app.route("/health")
def health():
    return render_template("health.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
