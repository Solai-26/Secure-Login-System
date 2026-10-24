from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management'
bcrypt = Bcrypt(app)

# In-memory User Database (For Demo)
users_db = {}

# HTML Templates
HTML_LAYOUT = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login System</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); width: 320px; }
        h2 { text-align: center; margin-bottom: 20px; color: #333; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 10px; }
        button:hover { background-color: #0056b3; }
        .message { color: red; font-size: 14px; margin-bottom: 10px; text-align: center; }
        .success { color: green; font-size: 14px; margin-bottom: 10px; text-align: center; }
        a { color: #007bff; text-decoration: none; display: block; text-align: center; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {{ content | safe }}
    </div>
</body>
</html>
"""

REGISTER_FORM = """
<h2>Register</h2>
<form method="POST" action="/register">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password (Min 6 chars)" required><br>
    <button type="submit">Sign Up</button>
</form>
<a href="/login">Already have an account? Login</a>
"""

LOGIN_FORM = """
<h2>Login</h2>
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <button type="submit">Login</button>
</form>
<a href="/register">Don't have an account? Register</a>
"""

DASHBOARD = """
<h2>Welcome, {{ username }}! 🎉</h2>
<p style="text-align:center;">You are securely logged in using hashed passwords (bcrypt).</p>
<a href="/logout"><button style="background-color:#dc3545;">Logout</button></a>
"""

@app.route('/')
def home():
    if 'username' in session:
        return render_template_string(HTML_LAYOUT, content=DASHBOARD.replace("{{ username }}", session['username']))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Input Validation (Sanitization against basic SQLi/Script injections)
        if not re.match("^[a-zA-Z0-9_]+$", username):
            flash("Username can only contain letters, numbers, and underscores!", "message")
            return render_template_string(HTML_LAYOUT, content=REGISTER_FORM)

        if len(password) < 6:
            flash("Password must be at least 6 characters long!", "message")
            return render_template_string(HTML_LAYOUT, content=REGISTER_FORM)

        if username in users_db:
            flash("Username already exists! Choose another.", "message")
            return render_template_string(HTML_LAYOUT, content=REGISTER_FORM)

        # Hash Password using Bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_db[username] = hashed_password

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template_string(HTML_LAYOUT, content=REGISTER_FORM)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Validate Credentials
        if username in users_db and bcrypt.check_password_hash(users_db[username], password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash("Invalid Username or Password!", "message")

    return render_template_string(HTML_LAYOUT, content=LOGIN_FORM)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)