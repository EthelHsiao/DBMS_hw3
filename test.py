from flask import Flask, render_template, request, redirect, flash, session
import mysql.connector
import hashlib  # 用於 SHA-256 雜湊

# Flask App Initialization
app = Flask(__name__)
app.secret_key = "your_secret_key"  # 替換為更安全的密鑰

# Database Configuration
db_config = {
    'host': 'localhost',  # MySQL 主機
    'user': 'your_user',  # MySQL 使用者名稱
    'password': 'your_password',  # MySQL 密碼
    'database': 'hw3'  # 資料庫名稱
}

# Database Connection
def get_db_connection():
    """建立並返回 MySQL 資料庫連線"""
    return mysql.connector.connect(**db_config)

# 密碼雜湊函數 (SHA-256)
def hash_password(password):
    """將提供的密碼進行 SHA-256 雜湊處理"""
    hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed

# Login Page
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)  # 雜湊密碼

        conn = get_db_connection()
        cursor = conn.cursor()

        # 使用參數化查詢避免 SQL Injection
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result and result[0] == hashed_password:
            session['username'] = username
            flash("Login successful!", "success")
            return redirect("/welcome")
        else:
            flash("Invalid username or password.", "danger")

        cursor.close()
        conn.close()

    return render_template("login.html")

# Signup Page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)  # 雜湊密碼

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # 插入新使用者資料
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, hashed_password)
            )
            conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect("/")
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "danger")
        finally:
            cursor.close()
            conn.close()

    return render_template("signup.html")

# Welcome Page
@app.route("/welcome")
def welcome():
    if 'username' not in session:
        return redirect("/")
    return render_template("welcome.html")

# Logout
@app.route("/logout")
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
