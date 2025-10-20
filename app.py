from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random

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
    verified = db.Column(db.Boolean, default=False)
    full_name = db.Column(db.String(100))
    date_of_birth = db.Column(db.String(100))
    account = db.relationship('Account', backref='user', uselist=False)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Gift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    message = db.Column(db.String(200))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_gifts')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_gifts')

class Crypto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='cryptos')

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_holder = db.Column(db.String(100), nullable=False)
    card_number = db.Column(db.String(20), nullable=False, unique=True)
    exp_date = db.Column(db.String(10), nullable=False)
    cvv = db.Column(db.String(4), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='cards')

class LinkedAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String(100), nullable=False)
    account_holder = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='linked_accounts')

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    goal_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='vaults')

class Pocket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='pockets')

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticker = db.Column(db.String(10), nullable=False)
    shares = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='stocks')

class NetWorth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    value = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='net_worth_history')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('walkthrough'))

@app.route('/walkthrough')
def walkthrough():
    return render_template('Walkthrough Screen.html')

@app.route('/launch')
def launch():
    return render_template('Launch screen.html')

@app.route('/gifts', methods=['GET', 'POST'])
def gifts():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])

    if request.method == 'POST':
        recipient_email = request.form.get('recipient_email')
        amount = float(request.form.get('amount'))
        message = request.form.get('message')

        recipient = User.query.filter_by(email=recipient_email).first()

        if not recipient:
            flash('Recipient not found')
            return redirect(url_for('gifts'))

        if user.account.balance < amount:
            flash('Insufficient funds')
            return redirect(url_for('gifts'))

        new_gift = Gift(sender_id=user.id, recipient_id=recipient.id, amount=amount, message=message)
        user.account.balance -= amount
        recipient.account.balance += amount

        db.session.add(new_gift)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('gifts screen.html', received_gifts=user.received_gifts)

@app.route('/crypto')
def crypto():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template('crypto screen.html', cryptos=user.cryptos)

@app.route('/buy_crypto', methods=['GET', 'POST'])
def buy_crypto():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        crypto_name = request.form.get('crypto_name')
        amount = float(request.form.get('amount'))
        user = db.session.get(User, session['user_id'])

        # In a real app, you'd have more complex logic for buying crypto
        # For simplicity, we'll just add the crypto to the user's holdings

        existing_crypto = Crypto.query.filter_by(user_id=user.id, name=crypto_name).first()

        if existing_crypto:
            existing_crypto.amount += amount
        else:
            new_crypto = Crypto(name=crypto_name, amount=amount, user_id=user.id)
            db.session.add(new_crypto)

        db.session.commit()

        return redirect(url_for('crypto'))

    return render_template('Buy crypto screen.html')

@app.route('/atm')
def atm():
    return render_template('ATM screen.html')

@app.route('/account_details')
def account_details():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template('account details screen.html', user=user)

@app.route('/order_cards', methods=['GET', 'POST'])
def order_cards():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        card_holder = request.form.get('card_holder')
        # In a real app, you'd have more complex logic for generating card numbers
        card_number = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        exp_date = '12/28'
        cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])

        new_card = Card(card_holder=card_holder, card_number=card_number, exp_date=exp_date, cvv=cvv, user_id=session['user_id'])
        db.session.add(new_card)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('order cards screen.html')

@app.route('/add_account', methods=['GET', 'POST'])
def add_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        bank_name = request.form.get('bank_name')
        account_holder = request.form.get('account_holder')
        account_number = request.form.get('account_number')

        new_linked_account = LinkedAccount(bank_name=bank_name, account_holder=account_holder, account_number=account_number, user_id=session['user_id'])
        db.session.add(new_linked_account)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('add account screen.html')

@app.route('/lounges')
def lounges():
    return render_template('lounges screen.html')

@app.route('/exchange', methods=['GET', 'POST'])
def exchange():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # In a real app, you'd use an API to get exchange rates
        # For simplicity, we'll just pretend to do the exchange
        flash('Exchange successful!')
        return redirect(url_for('home'))
    return render_template('exchange screen.html')

@app.route('/vaults', methods=['GET', 'POST'])
def vaults():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        name = request.form.get('name')
        goal_amount = float(request.form.get('goal_amount'))
        new_vault = Vault(name=name, goal_amount=goal_amount, user_id=user.id)
        db.session.add(new_vault)
        db.session.commit()
        return redirect(url_for('vaults'))
    return render_template('vaults screen.html', vaults=user.vaults)

@app.route('/pockets', methods=['GET', 'POST'])
def pockets():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        name = request.form.get('name')
        balance = float(request.form.get('balance'))
        if user.account.balance < balance:
            flash('Insufficient funds')
            return redirect(url_for('pockets'))
        user.account.balance -= balance
        new_pocket = Pocket(name=name, balance=balance, user_id=user.id)
        db.session.add(new_pocket)
        db.session.commit()
        return redirect(url_for('pockets'))
    return render_template('pockets screen.html', pockets=user.pockets)

@app.route('/salary')
def salary():
    return render_template('salary screen.html')

@app.route('/widget')
def widget():
    return render_template('Widget screen.html')

@app.route('/shops')
def shops():
    return render_template('shops screen.html')

@app.route('/insurance')
def insurance():
    return render_template('insurance screen.html')

@app.route('/stocks', methods=['GET', 'POST'])
def stocks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        ticker = request.form.get('ticker')
        shares = float(request.form.get('shares'))
        new_stock = Stock(ticker=ticker, shares=shares, user_id=user.id)
        db.session.add(new_stock)
        db.session.commit()
        return redirect(url_for('stocks'))
    return render_template('stocks screen.html', stocks=user.stocks)

@app.route('/net_worth')
def net_worth():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    # In a real app, you'd calculate the net worth based on all assets
    net_worth_value = user.account.balance
    return render_template('net worth screen.html', net_worth=net_worth_value)

@app.route('/invite_friends')
def invite_friends():
    return render_template('invite friends screen.html')

@app.route('/linked_account')
def linked_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template('linked account screen.html', linked_accounts=user.linked_accounts)

@app.route('/search')
def search():
    return render_template('Search screen.html')

@app.route('/donation', methods=['GET', 'POST'])
def donation():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # In a real app, you'd have logic to process the donation
        flash('Thank you for your donation!')
        return redirect(url_for('home'))
    return render_template('Donation screen.html')

@app.route('/hub')
def hub():
    return render_template('hub screen.html')

@app.route('/account_settings', methods=['GET', 'POST'])
def account_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')

        user.full_name = full_name
        user.email = email
        user.phone_number = phone_number

        db.session.commit()

        flash('Your settings have been updated.')
        return redirect(url_for('account_settings'))

    return render_template('accpunt settings screen.html', user=user)

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
        session['user_id'] = new_user.id
        return redirect(url_for('verify_identity'))
    return render_template('signup screen.html')

@app.route('/verify_identity', methods=['GET', 'POST'])
def verify_identity():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # In a real app, you'd have more complex verification logic
        user = db.session.get(User, session['user_id'])
        user.verified = True
        db.session.commit()
        return redirect(url_for('complete_signup'))
    return render_template('verify identity screen.html')

@app.route('/complete_signup', methods=['GET', 'POST'])
def complete_signup():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        date_of_birth = request.form.get('date_of_birth')
        user = db.session.get(User, session['user_id'])
        user.full_name = full_name
        user.date_of_birth = date_of_birth
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('complete sign up screen.html')

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
    users = User.query.all()
    return render_template('transfer screen.html', users=users)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')