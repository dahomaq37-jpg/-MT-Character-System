import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "mt-secret-key")

DATABASE = "mt_characters.db"


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS characters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            second_name TEXT NOT NULL,
            country TEXT NOT NULL,
            nationality TEXT NOT NULL,
            birth_date TEXT NOT NULL
        )
    """)

    db.commit()
    db.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/characters")
def characters():
    db = get_db()

    characters = db.execute("""
        SELECT *
        FROM characters
        ORDER BY id DESC
    """).fetchall()

    db.close()

    return render_template(
        "characters.html",
        characters=characters
    )


@app.route("/characters/register", methods=["GET", "POST"])
def register_character():

    if request.method == "POST":

        first_name = request.form.get("first_name", "").strip()
        second_name = request.form.get("second_name", "").strip()
        country = request.form.get("country", "").strip()
        nationality = request.form.get("nationality", "").strip()
        birth_date = request.form.get("birth_date", "").strip()

        if not all([
            first_name,
            second_name,
            country,
            nationality,
            birth_date
        ]):
            flash("فضلاً عبّ جميع البيانات")
            return redirect(url_for("register_character"))

        db = get_db()

        db.execute("""
            INSERT INTO characters
            (first_name, second_name, country, nationality, birth_date)
            VALUES (?, ?, ?, ?, ?)
        """, (
            first_name,
            second_name,
            country,
            nationality,
            birth_date
        ))

        db.commit()
        db.close()

        return redirect(url_for("characters"))

    return render_template("register_character.html")


@app.route("/police")
def police():
    return render_template("police.html")


@app.route("/justice")
def justice():
    return render_template("justice.html")


@app.route("/health")
def health():
    return render_template("health.html")


init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
