import re
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, make_response
from datetime import datetime
from flask import flash
from flask_mail import Mail,Message
from flask_recaptcha import ReCaptcha
from random import *
import sqlite3

app = Flask(__name__)


mail = Mail(app)
con = sqlite3.connect('blog.db', check_same_thread=False)

cur = con.cursor()
app.secret_key="xmlwq2e3udgs"

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'studydsscw2@gmail.com'
app.config["MAIL_PASSWORD"] = 'Secureweb!2021'
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config['RECAPTCHA_SITE_KEY'] = '6LduyckcAAAAAEqcFeg7XRxVR1AASJhJt8DHL9T8'
app.config['RECAPTCHA_SECRET_KEY'] = '6LduyckcAAAAALmPi39r6H1gbE163025NttXmdJ7'

recaptcha =  ReCaptcha(app)
mail = Mail(app)
otp = randint(000000,999999)


@app.route('/')
def home():
    session['attempt'] = 3
    return render_template('home.html')


@app.route('/index')
def index():
    cookies = request.cookies
    usr = cookies.get('Auto log off')
    userid = session["userid"]
    print(usr)
    if usr:
        user_id = userid
        print("in Index "+ str(user_id))
        post_query = "SELECT * FROM blogpost WHERE user_id=? ORDER BY date_posted DESC"
        posts = cur.execute(post_query,(user_id,)).fetchall()
        resp = make_response(render_template('index.html', posts=posts))
        resp.headers.set("Content-Security-Policy", "script-src http://127.0.0.1:5000")

        return resp
    else:

        return redirect('/login')

@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/validate_register', methods=['POST'])
def validate_register():
    email = request.form.get('email')
    password = request.form.get('password')

    validations = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,10}$"
    pat = re.compile(validations)
    mat = re.search(pat, password)
    if mat:
        verify = cur.execute("SELECT * FROM user WHERE email=?", (email,)).fetchone()
        print(verify)
        if verify:
            flash('User already exist')
            return redirect('/register')
        else:
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            query = "INSERT INTO user (email, password) VALUES (?,?)"
            cur.execute(query,(email, hashed_password))
            con.commit()
            return redirect('/')
    else:
        flash('Please enter a strong password')
        return redirect('register')


@app.route('/validate_login', methods=['POST'])
def validate_login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = cur.execute("SELECT id, email, password FROM user WHERE email=?", (email,)).fetchone()
    if user:
        if len(password) <= 10:
            if recaptcha.verify():
                password = hashlib.sha256(password.encode('utf-8')).hexdigest()
                if user[2] == password:
                    message = Message('OTP', sender = 'studydsscw2@gmail.com', recipients=[email])
                    message.body ='Your Login OTP is : {}'.format(str(otp))
                    mail.send(message)
                    my_user_id = user[0]
                    return redirect(url_for('email_verification', my_user_id=my_user_id))
                else:
                    attempt = session.get('attempt')
                    attempt -= 1
                    session['attempt'] = attempt
                    if attempt <= 0:
                        flash("Account is locked out due to invalid login attempts" )
                        return render_template('login.html',attempt=attempt)
                    flash("Wrong credentials!!, last %s attempts left " % session.get('attempt'))
                    return redirect('/login')
        else:
            attempt = session.get('attempt')
            attempt -= 1
            session['attempt'] = attempt
            if attempt <= 0:
                flash("Account is locked out due to invalid login attempts")
                return render_template('login.html', attempt=attempt)
            flash("Please Enter a password less than equals 10 characters, last %s attempt left" % session.get('attempt'))
            return redirect('/login')
    else:
        flash("Invalid Input")
        return redirect("/login")



@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/post/<int:post_id>')
def post(post_id):

    post = cur.execute("SELECT * FROM blogpost WHERE id=?", (post_id,)).fetchone()
    return render_template('post.html', post=post)


@app.route('/add')
def add():
    return render_template('add.html')


@app.route('/delete')
def delete():
    posts = cur.execute("SELECT * FROM blogpost ORDER BY date_posted DESC").fetchall()
    return render_template('delete.html',posts=posts)


@app.route('/addpost', methods=['POST'])
def addpost():
    add_user_id = session['user']
    title = request.form['title']
    subtitle = request.form['subtitle']
    author = request.form['author']
    content = request.form['content']
    date_posted = datetime.now()

    query1 = """INSERT INTO blogpost (title, subtitle, author, date_posted, content, user_id) VALUES (?,?,?,?,?,?)"""
    cur.execute(query1,( title, subtitle, author, date_posted, content,add_user_id) )
    con.commit()

    return redirect(url_for('index'))


@app.route('/deletepost', methods=['DELETE','POST'])
def deletepost():
    post_id = request.form.get("post_id")
    sql = "DELETE FROM blogpost WHERE id=?"
    cur.execute(sql, (post_id,))
    con.commit()
    
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    res = make_response(redirect('/login'))
    res.delete_cookie('Auto log off')
    return res


@app.route('/email_verification/<my_user_id>')
def email_verification(my_user_id):
    print("in email verification " + str(my_user_id))
    return render_template('emailVerification.html',my_user_id=my_user_id)


@app.route('/validate_email/<my_user_id>',methods=['POST'])
def validate_email(my_user_id):
    print("in validaste email " + str(my_user_id))
    user_otp = request.form['otp']
    if otp == int(user_otp):
        res = make_response(redirect('/index'))
        session['userid'] = my_user_id

        res.set_cookie("Auto log off",
                       value = "log off",
                       # max_age =20,
                       httponly=True
                       )
        res.headers.set("Content-Security-Policy", "script-src http://127.0.0.1:5000")
        return res

    else:
        flash("Please Enter Valid OTP")
        return redirect('/email_verification/<my_user_id>')


@app.route('/alert')
def alert():
    return


if __name__ == '__main__':
    app.run(debug=True)