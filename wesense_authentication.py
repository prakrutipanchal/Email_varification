import os
from flask import Flask, request, jsonify, url_for, render_template, session
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime, timezone

client = MongoClient("mongodb+srv://prakrutipanchal2005:prakruti_2005@cluster0.pvtqygk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['wesense']
collection = db['wesense_authentication']

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAIL_DEFAULT_SENDER'] = 'prakrutipanchal2005@gmail.com'
app.config['MAIL_USERNAME'] = 'prakrutipanchal2005@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

bcrypt = Bcrypt(app)
mail = Mail(app)


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_confirmation_token(email):
    return serializer.dumps(email, salt="email-confirmation-extraSecurity")


def send_confirmation_token(user):
    token = generate_confirmation_token(user['email'])
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = 'Please confirm your account!'
    msg = Message(subject, recipients=[user['email']], html=html)
    mail.send(msg)


@app.get('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirmation-extraSecurity', max_age=3600)
    except Exception as e:
        return jsonify({"Message": "Your confirmation link is invalid or has expired."}), 400

    user = collection.find_one({"email": email})
    if user and not user['confirmed']:
        collection.update_one({"email": email}, {"$set": {"confirmed": True, "confirmed_on": datetime.now(timezone.utc)}})
        return jsonify({"Message": "Account activated successfully! You can log in now."}), 200
    elif user and user['confirmed']:
        return jsonify({"Message": "Account already activated!"}), 200
    else:
        return jsonify({"Message": "Invalid credentials! Please register again."}), 400

@app.post('/register_user')
def register_user():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    
    existing_user = collection.find_one({
        "$or": [
            {"username": data.get('username')},
            {"email": data.get("email")}
        ]
    })

    if existing_user:
        return jsonify({"Message": "User with this username or email already exists!"}), 400

    user = {
        'username': data.get('username'),
        'password': hashed_password,
        'email': data.get('email'),
        "confirmed": False,
        "confirmed_on": None,
        "created_at": datetime.now(timezone.utc)
    }

    collection.insert_one(user)
    send_confirmation_token(user)

    return jsonify({"Message": "User registered successfully, please check your mail to confirm your account!"}), 201

if __name__ == '__main__':
    app.run(debug=True)