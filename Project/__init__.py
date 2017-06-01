from flask import Flask
from flask import render_template
from flask import redirect
from flask import Flask, render_template, request, redirect, url_for, abort
from sqlalchemy import desc, and_
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import session
from functools import wraps
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, AnyOf
import random
import string
from db_setup import Base, User
import json
import hashlib
import ast


app = Flask(__name__)
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lf_uCMUAAAAALyBJyxLVKfifsAHQ2NplhcLwBF_'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lf_uCMUAAAAAOXeF2owkRPId_t89F3X3g5NZvwi'
engine = create_engine('postgresql://db:dbpass@localhost/db')
#Base.metadata.bind = engine
DBsession = sessionmaker(bind=engine)
session = DBsession() # noqa

onVM = True

if onVM:
    hash_salt = json.loads(
        open('hash_codes.json', 'r').read())['keys']['cookie_salt']
    flask_secret_key = json.loads(
        open('hash_codes.json', 'r').read())['keys']['secret_key']
else:
    HASH_CODE_FILE = '/hash_codes.json'
    hash_salt = json.loads(
        open(HASH_CODE_FILE, 'r').read())['keys']['cookie_salt']
    flask_secret_key = json.loads(
        open(HASH_CODE_FILE, 'r').read())['keys']['secret_key']

MAIN_METHOD_HEADER = 'public class SecureWebsite{\n\n'
TEST_CODE_HEADER = '''
public class SecureWebsite{\n
public static void main(String[] args){\n
'''


def hash_cookie(user):
    hash_text = hashlib.sha512(user.username + hash_salt).hexdigest()
    cookie_text = '%s|%s' % (user.username, hash_text)
    return cookie_text


def setCookie(user):
    cookie_value = hash_cookie(user)
    response = app.make_response(redirect(url_for('main')))
    response.set_cookie('user_id', value=cookie_value)
    return response


def check_for_user():
    cookie_value = request.cookies.get('user_id')
    if cookie_value:
        params = cookie_value.split('|')
        if hashlib.sha512(params[0] + hash_salt).hexdigest() == params[1]:
            user = session.query(User).filter(
                User.username == params[0]).first()
            if user:
                return user


def check_password(password, user):
    hashed_pass = hashlib.sha512(password + user.salt).hexdigest()
    if hashed_pass == user.password:
        return True
    else:
        return False


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = check_for_user()
        if not user:
            return redirect(url_for('login'))
        return f(user, *args, **kwargs)
    return wrapper

def make_salt():
    salt = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(7))
    return salt

def validate_captcha(self, form):
    recaptcha_challenge_field = self.request.get("recaptcha_challenge_field")
    recaptcha_response_field = self.request.get("recaptcha_response_field")
    remote_ip = self.request.remote_addr
    recaptcha_private_key = '6LftuyMUAAAAAPIovqeviDzisoPIbVuZfP3h0xeP' # put recaptcha private key here

    recaptcha_post_data = {"privatekey":  recaptcha_private_key,
        "remoteip": remote_ip,
        "challenge": recaptcha_challenge_field,
        "response": recaptcha_response_field}
    response = urlfetch.fetch(url='http://www.google.com/recaptcha/api/verify', payload=urlencode(recaptcha_post_data), method="POST")
    captcha_ok = True if response.content.split("\n")[0] == "true" else False
    if not captcha_ok:
      form.captcha.errors.append("Invalid captcha values, please try again")
    return captcha_ok

# class LoginForm(FlaskForm):
#     def check_username(password, username, user):
#         username = user.username
#         password = user.password
        
@app.route('/')
@login_required
def hello():
    posts = db.session.query(User).all()
    return render_template('index.html', posts=posts)

@app.route('/home')
def home():
    page_title = 'This is the title that was passed to the page'
    creator_name = 'Paul'
    return render_template('home.html', page_title = page_title, creator_name = creator_name)
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    recaptcha = RecaptchaField()
    # login = LoginForm()
    if request.method == 'GET':
        user = check_for_user()
        if user:
            return redirect(url_for('main'))
        else:
            return render_template('login.html')
    else:
        username = request.form['username']
        password = request.form['password']

        user = session.query(User).filter(User.username == username).first()
        if user:
            hashed_password = hashlib.sha512(password + user.salt).hexdigest()
            if user.password == hashed_password:
                return setCookie(user)

        error = 'Invalid username and/or password'
        return render_template('login.html', username=username, error=error, form=form)

@app.route('/logout')
def logout():
    response = app.make_response(redirect(url_for('main')))
    cookie_value = ''
    response.set_cookie('user_id', value=cookie_value)
    return response
    


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        params = {}
        return render_template('signup.html', params=params)
    else:
        print(request.form.items())
        params = {}
        params['f_name'] = request.form['f_name']
        params['l_name'] = request.form['l_name']
        params['username'] = request.form['username'].strip()
        password = request.form['password']
        verify = request.form['verify']
        params['email'] = request.form['email']

        if (not params['f_name'] or not params['l_name'] or not
                params['username']):
            params['message'] = 'Please enter your first name, last name, ' \
                'and a username.'
            return render_template('signup.html',
                                   params=params)

        userQuery = session.query(User).filter(
            User.username == params['username']).first()
        if userQuery:
            params['message'] = 'That username is already in use. ' \
                'Please choose a different one.'
            return render_template('signup.html', params=params)
        if not password:
            params['message'] = 'Please enter a valid password'
            return render_template('signup.html', params=params)
        if password != verify:
            params['message'] = 'Your passwords did not match. ' \
                'Please try again.'
            return render_template('signup.html', params=params)

        if not params['email']:
            params['message'] = 'Please enter a valid email address.'
            return render_template('signup.html', params=params)
        salt = make_salt()
        hashed_password = hashlib.sha512(password + salt).hexdigest()
        user = User(f_name=params['f_name'], l_name=params['l_name'], email=params['email'], username=params['username'],password=hashed_password, salt=salt, admin=False)
        session.add(user)
        session.commit()
        if(user.id == 1):
            user.admin = True
            session.commit()
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key = flask_secret_key
    app.debug = onVM
    app.run(host='0.0.0.0', port=5000)