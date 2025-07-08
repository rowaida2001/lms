import os
import base64
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash  

app = Flask(__name__)
app.secret_key = "your_secret_key"

UPLOAD_FOLDER = "static/user_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==========================
# Database Setup Functions
# ==========================
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fullname TEXT,
                    email TEXT UNIQUE,
                    password TEXT,
                    photo_path TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS courses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    name TEXT,
                    description TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    conn.commit()
    conn.close()

init_db()

# ==========================
# Helper Functions
# ==========================
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

def insert_course(user_id, course_name, course_description):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute(
            "INSERT INTO courses (user_id, name, description) VALUES (?, ?, ?)",
            (user_id, course_name, course_description)
        )
        conn.commit()
        return True
    except Exception as e:
        print("Error inserting course:", e)
        return False
    finally:
        conn.close()

def get_courses_by_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT name, description FROM courses WHERE user_id = ?", (user_id,))
    courses = c.fetchall()
    conn.close()
    return courses

# ==========================
# Routes
# ==========================
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
    if user and check_password_hash(user[3], password):  
        session['email'] = email
        return redirect(url_for('dashboard'))

    return render_template('login.html', error="Invalid credentials")

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('home'))

    user = get_user_by_email(session['email'])
    user_id = user[0]  
    courses = get_courses_by_user(user_id)

    return render_template('dashboard.html', courses=[{'name': c[0], 'description': c[1]} for c in courses])

@app.route('/create_course', methods=['GET', 'POST'])
def create_course():
    if 'email' not in session:
        return redirect(url_for('home'))

    user = get_user_by_email(session['email'])
    user_id = user[0]

    if request.method == 'POST':
        course_name = request.form.get('course_name')
        course_description = request.form.get('course_description', '')
        if course_name:
            insert_course(user_id, course_name, course_description)
            return redirect(url_for('dashboard'))

    return render_template('create_course.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')  
        photo_data = request.form.get('photo_data')

        if get_user_by_email(email):
            return render_template('register.html', error="Email already exists.")

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match.")  

        hashed_password = generate_password_hash(password) 

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

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '').lower()
    print(f"[Chat] Received message: {user_message}")  # debug

    if 'hello' in user_message or 'hi' in user_message:
        reply = "welcome"
    elif 'your name' in user_message:
        reply = "I'm your assistant chatbot 🤖."
    elif 'help' in user_message:
        reply = "You can ask me anything about the system!"
    else:
        reply = "Sorry, I didn't understand that."

    print(f"[Chat] Replying with: {reply}")  # debug
    return jsonify({'reply': reply})

# ==========================
# Run App
# ==========================
if __name__ == '__main__':
    app.run(debug=True)


