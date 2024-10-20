import os
from flask import Flask, request, jsonify, session, url_for, render_template
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from bson import ObjectId

client = MongoClient('mongodb+srv://prakrutipanchal2005:prakruti_2005@cluster0.pvtqygk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client['Example_deploy']
collection = db["Example_deploy_table"]

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Ksuradcen239s_23ms'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'gdhHksm9e4j2_0'
app.config['MAIL_USERNAME'] = 'prakrutipanchal2005@gmail.com'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'prakrutipanchal2005@gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

key = Fernet.generate_key()
cipher = Fernet(key)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
mail = Mail(app)

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


class MongoUser(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.confirmed = user_data['confirmed']

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    try:
        user = collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return MongoUser(user)
    except:
        return None 


def generate_confirmation_token(email):
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def send_confirmation_token(user):
    token = generate_confirmation_token(user['email'])
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = "Please activate your account!!"
    msg = Message(subject, recipients=[user['email']], html=html)
    mail.send(msg)

@app.post('/register_user')
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    user = {
        "username": data.get('username'),
        "password": hashed_password,  # Store hashed password
        "email": data.get('email'),
        "confirmed": False,
        "confirmed_on": None,
        "passwords": []
    }
    collection.insert_one(user)
    send_confirmation_token(user)
    return jsonify({"Message": "User registered successfully! Please check your email to verify your account."})


@app.post('/login_user')
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"Message": "Username and password are required!"}), 400

    user = collection.find_one({"username": data.get('username')})

    if not user:
        return jsonify({"Message": "Invalid username!"}), 400

    if bcrypt.check_password_hash(user['password'], data.get('password')):
        if user['confirmed']:
            mongo_user = MongoUser(user)  
            login_user(mongo_user) 
            return jsonify({"Message": f"{user['username']} logged in successfully!"})
        else:
            return jsonify({"Message": "Email not confirmed. Please check your email to confirm your account."})
    else:
        return jsonify({"Message": "Incorrect password!"}), 400


@app.get('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        return jsonify({"Message": "Token expired! Kindly register again."})

    user = collection.find_one({"email": email})
    if user and not user['confirmed']:
        collection.update_one(
            {"email": email},
            {"$set": {"confirmed": True, "confirmed_on": datetime.now(timezone.utc)}}
        )
        return jsonify({"Message": "Account activated successfully! You can now log in."})
    elif user and user['confirmed']:
        return jsonify({"Message": "Account already activated!"})
    else:
        return jsonify({"Message": "Invalid credentials! Please register again."})

@app.put('/update_user_email')
@login_required
def update_email():
    data = request.get_json()
    new_email = data.get('email')
    
    if collection.find_one({"email": new_email}):
        return jsonify({"Message": "This email is already in use!"})
    
    collection.update_one(
        {"username": current_user.username},
        {"$set": {"email": new_email}}
    )
    return jsonify({"Message": "Email updated successfully!"})

@app.put('/update_user_password')
@login_required
def update_user_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    user = collection.find_one({"email": current_user.email})
    
    if not bcrypt.check_password_hash(user['password'], current_password):
        return jsonify({"Message": "Invalid current password!"})
    
    new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    collection.update_one(
        {"email": current_user.email},
        {"$set": {"password": new_hashed_password}}
    )
    return jsonify({"Message": "Password changed successfully!"})

@app.post('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    return jsonify({"Message": f"{username} logged out successfully!"}), 200

# ----------------------------------------------------------------------------------

@app.route('/add_data', methods=['POST'])
@login_required
def add_data():
    data = request.get_json()
    if not data.get('title') or not data.get('password'):
        return jsonify({"Message": "Title and password are required!"}), 400
    
    encrypted_password = encrypt(data.get('password'))
    
    new_entry = {
        "title": data.get('title'),
        "password": encrypted_password,
        "notes": data.get('notes', ""),
        "added_on": datetime.now(timezone.utc)
    }
    
    result = collection.update_one(
        {"_id": ObjectId(current_user.id)},  
        {"$push": {"passwords": new_entry}}
    )
    
    if result.modified_count > 0:
        return jsonify({"Message": "Data added successfully!"})
    else:
        return jsonify({"Message": "Failed to add data!"}), 500

@app.put('/update_password/<user_id>/<title>')
@login_required
def update_password(user_id, title):
    data = request.get_json()
    new_title_password = data.get('password')

    if not new_title_password:
        return jsonify({"message": "No data to update"}), 400

    encrypted_password = encrypt(new_title_password)
    update = collection.update_one(
        {"_id": ObjectId(user_id), "passwords.title": title},
        {"$set": {"passwords.$.password": encrypted_password}}
    )
    if update.matched_count == 0:
        return jsonify({"message": "Title not found"}), 404

    return jsonify({"message": "Password details updated successfully"}), 200


@app.put('/update_notes/<user_id>/<title>')
@login_required
def update_notes(user_id, title):
    data = request.get_json()
    new_title_notes = data.get('notes')

    if not new_title_notes:
        return jsonify({"message": "No data to update"}), 400

    update = collection.update_one(
        {"_id": ObjectId(user_id), "passwords.title": title},
        {"$set": {"passwords.$.notes": new_title_notes}}
    )
    if update.matched_count == 0:
        return jsonify({"message": "Title not found"}), 404

    return jsonify({"message": "notes details updated successfully"}), 200


@app.delete('/delete_data/<user_id>/<title>')
@login_required
def delete_data(user_id, title):
    delete = collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$pull": {"passwords": {"title": title}}}
        )

    if delete.matched_count == 0:
        return jsonify({"message": "Title not found"}), 404
    return jsonify({"message": "data deleted successfully"}), 200

@app.get('/get_all_data/<user_id>')
@login_required
def get_all_data(user_id):
    user_data = collection.find_one(
        {"_id": ObjectId(user_id)},
        {"passwords": 1, "_id": 0} 
    )

    if not user_data:
        return jsonify({"message": "User not found"}), 404

    for password_entry in user_data.get('passwords', []):
        encrypted_password = password_entry.get('password')
        if encrypted_password:
            password_entry['password'] = decrypt(encrypted_password)

    return jsonify(user_data), 200

if __name__ == '__main__':
     app.run(host='0.0.0.0', port=10000)
