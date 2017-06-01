from flask import Flask
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import session
from flask import flash
from flask import g
from functools import wraps
import sqlite3

app = Flask(__name__)

app.config['SECRET_KEY'] = 'dfjnwopn'
app.database = "sample.db"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return decorated_function

@app.route('/')
@login_required
def hello():
    # return '<h2>Hello, World! This is a new sentence!</h2>' 
    g.db = connect_db()
    cur = g.db.execute('select * from posts')
    posts = [dict(title=row[0], description=row[1]) for row in cur.fetchall()]
    g.db.close()
    return render_template('index.html', posts=posts)

@app.route('/home')
def home():
    page_title = 'This is the title that was passed to the page'
    creator_name = 'Paul'
    return render_template('home.html', page_title = page_title, creator_name = creator_name)
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            session['logged_in'] = True
            flash('you were just logged in')
            return redirect(url_for('home'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('you were just logged out')
    return redirect(url_for('home'))

def connect_db():
    return sqlite3.connect(app.database)
    


@app.route('/signup')
def signup():
    return render_template('signup') 

if __name__=='__main__':
    app.run(debug=True)