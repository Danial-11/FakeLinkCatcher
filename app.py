import os
import re
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = os.urandom(24)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    results = db.relationship('LinkResult', backref='user', lazy=True)

class LinkResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    is_fake = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create tables in the database
def initialize_database():
    with app.app_context():
        db.create_all()

initialize_database()

def is_fake_link(url):
    # Check if the URL matches a simple regular expression for a valid URL structure
    regex = re.compile(
        r'^(https?://)?'  # Optional http or https
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+' # Domain name with at least one subdomain
        r'[A-Za-z]{2,6}'  # Top-level domain
    )
    if not regex.match(url):
        return True  # The URL structure is invalid

    # Check against a list of known fake TLDs
    known_fake_tlds = ['.xyz', '.top', '.gq', '.tk']
    if any(url.endswith(tld) for tld in known_fake_tlds):
        return True  # The URL ends with a known fake TLD

    # Attempt to access the URL and check the HTTP status code
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        if response.status_code != 200:
            return True  # The URL is not accessible
    except requests.RequestException:
        return True  # The URL is not accessible

    return False



@app.route('/', methods=['GET', 'POST'])  # Map the root URL to the login page
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('link_checker'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password,
                        first_name=first_name, last_name=last_name)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/link_checker')
def link_checker():
    # Make sure the user is logged in before accessing the link checker
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('link_checker.html')

@app.route('/check_link', methods=['POST'])
def check_link():
    # Check if the user is logged in
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    url = request.json.get('url')
    is_fake = is_fake_link(url)

    # Add the new result to the database
    new_result = LinkResult(url=url, is_fake=is_fake, user_id=session['user_id'])
    db.session.add(new_result)
    db.session.commit()

    return jsonify({"url": url, "is_fake": is_fake})



@app.route('/result')
def result_page():
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    results = LinkResult.query.filter_by(user_id=user_id).all()
    return render_template('result.html', results=results)







# Configure mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Enter your email address
app.config['MAIL_PASSWORD'] = 'your_password'  # Enter your email password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        msg = Message(subject,
                      sender=email,
                      recipients=['your_email@gmail.com'])  # Replace with your email

        msg.body = f"From: {name}\nEmail: {email}\n\n{message}"

        try:
            mail.send(msg)
            return render_template('success.html')
        except Exception as e:
            return str(e)

    return render_template('contact.html')


if __name__ == '__main__':
    app.run(debug=True)
