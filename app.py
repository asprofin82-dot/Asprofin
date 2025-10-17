from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    account = db.relationship('Account', backref='user', uselist=False)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        phone_number = request.form.get('phone_number')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))
        new_user = User(email=email, password=generate_password_hash(password, method='pbkdf2:sha256'), phone_number=phone_number)
        db.session.add(new_user)
        db.session.commit()
        new_account = Account(user_id=new_user.id)
        db.session.add(new_account)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup screen.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template('home screen.html', balance=user.account.balance)

@app.route('/add_money', methods=['GET', 'POST'])
def add_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        user = db.session.get(User, session['user_id'])
        user.account.balance += amount
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_money.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        recipient_email = request.form.get('recipient_email')
        amount = float(request.form.get('amount'))
        sender = db.session.get(User, session['user_id'])
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:
            flash('Recipient not found')
            return redirect(url_for('transfer'))
        if sender.account.balance < amount:
            flash('Insufficient funds')
            return redirect(url_for('transfer'))
        sender.account.balance -= amount
        recipient.account.balance += amount
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('transfer.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)