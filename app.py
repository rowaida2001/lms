import os
import base64
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash  # ✅ استيراد التشفير

app = Flask(__name__)
app.secret_key = "your_secret_key"

UPLOAD_FOLDER = "static/user_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_user_by_email(email):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    return user

def insert_user(fullname, email, password, photo_path=None):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (fullname, email, password, photo_path) VALUES (?, ?, ?, ?)",
            (fullname, email, password, photo_path)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

@app.route('/')
def home():
    if 'email' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user = get_user_by_email(email)
    if user and check_password_hash(user[3], password):  # ✅ التحقق من الباسورد
        session['email'] = email
        return redirect(url_for('dashboard'))

    return render_template('login.html', error="Invalid credentials")

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('home'))
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')  # ✅ تأكيد الباسورد
        photo_data = request.form.get('photo_data')

        if get_user_by_email(email):
            return render_template('register.html', error="Email already exists.")

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match.")  # ✅ تحقق من التطابق

        hashed_password = generate_password_hash(password)  # ✅ تشفير كلمة السر

        photo_path = None
        if photo_data:
            try:
                photo_data = photo_data.split(',')[1]
                image_bytes = base64.b64decode(photo_data)
                photo_path = os.path.join(UPLOAD_FOLDER, f"{email}.jpg")
                with open(photo_path, 'wb') as f:
                    f.write(image_bytes)
            except Exception as e:
                return render_template('register.html', error="Photo could not be saved.")

        success = insert_user(fullname, email, hashed_password, photo_path)
        if success:
            return redirect(url_for('home'))
        else:
            return render_template('register.html', error="Registration failed.")

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '').lower()

    if 'hello' in user_message or 'hi' in user_message:
        reply = "welcome"
    elif 'your name' in user_message:
        reply = "I'm your assistant chatbot 🤖."
    elif 'help' in user_message:
        reply = "You can ask me anything about the system!"
    else:
        reply = "Sorry, I didn't understand that."

    return jsonify({'reply': reply})

if __name__ == '__main__':
    app.run(debug=True)


