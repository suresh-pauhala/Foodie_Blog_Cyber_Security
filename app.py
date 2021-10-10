import re
import base64
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
from flask import flash
from flask_mail import Mail,Message
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import new

from random import *
import sqlite3
app = Flask(__name__)
mail = Mail(app)
con = sqlite3.connect('blog.db', check_same_thread=False)
cur = con.cursor()
app.secret_key="xmlwq2e3udgs"
# cur.execute('''CREATE TABLE blogpost
#                (id integer primary key, title text, subtitle text, author text, date_posted datetime, content text, user_id integer )''')

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'pauhalasuresh@gmail.com'
app.config["MAIL_PASSWORD"] = 'priyancyd123'
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
mail = Mail(app)
otp = randint(000000,999999)



@app.route('/')
def home():
    session['attempt'] = 3
    return render_template('home.html')


@app.route('/index')
def index():
    if 'user' in session:
    # cur.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")

    # posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).all()
    # return render_template('index.html', posts=posts)
        user_id = session['user']
        print("in Index "+ str(user_id))
        post_query = "SELECT * FROM blogpost WHERE user_id=? ORDER BY date_posted DESC"
        posts = cur.execute(post_query,(user_id,)).fetchall()
        return render_template('index.html', posts=posts)
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

            query = "INSERT INTO user (email, password) VALUES (?,?)"
            cur.execute(query,(email, password))
            con.commit()
            return redirect('/index')
    else:
        flash('Please enter a strong password')
        return redirect('register')


@app.route('/validate_login', methods=['POST'])
def validate_login():
    email = request.form.get('email')
    password = request.form.get('password')
    new_key = "asc34dfjkirf345j"
    new_key = str.encode(new_key)
    password = str.encode(password)


    encrypt_password = encrypt(new_key, password)
    print("encrypted password is "+encrypt_password)

    decrypt_password = decrypt(new_key, encrypt_password)

    print("decrypted password is " +decrypt_password)

    print(len(password))
    user = cur.execute("SELECT id, email, password FROM user WHERE email=?", (email,)).fetchone()
    if len(password) <= 10:
        print("in login" + str(user[0]))
        if user[2] == password:
            message = Message('OTP', sender = 'pauhalasuresh@gmail.com', recipients=[email])
            message.body ='Your OTP is : {}'.format(str(otp))
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



@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/post/<int:post_id>')
def post(post_id):
    # post = Blogpost.query.filter_by(id=post_id).one()
    # return render_template('post.html', post=post)
    post = cur.execute("SELECT * FROM blogpost WHERE id=?", (post_id,)).fetchone()
    return render_template('post.html', post=post)


@app.route('/add')
def add():
    return render_template('add.html')


@app.route('/delete')
def delete():
    # posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).all()
    posts = cur.execute("SELECT * FROM blogpost ORDER BY date_posted DESC").fetchall()

    # return render_template('delete.html', posts=posts)
    # return render_template('delete.html')
    return render_template('delete.html',posts=posts)


@app.route('/addpost', methods=['POST'])
def addpost():
    add_user_id = session['user']
    title = request.form['title']
    subtitle = request.form['subtitle']
    author = request.form['author']
    content = request.form['content']
    date_posted = datetime.now()

    # post = Blogpost(title=title, subtitle=subtitle, author=author, content=content, date_posted=datetime.now())
    # cur.execute("INSERT INTO blogpost VALUES (title,'BUY','RHAT',100,35.14)")
    query1 = """INSERT INTO blogpost (title, subtitle, author, date_posted, content, user_id) VALUES (?,?,?,?,?,?)"""
    cur.execute(query1,( title, subtitle, author, date_posted, content,add_user_id) )
    con.commit()
    # db.session.add(post)
    # db.session.commit()

    return redirect(url_for('index'))


@app.route('/deletepost', methods=['DELETE','POST'])
def deletepost():
    post_id = request.form.get("post_id")
    sql = "DELETE FROM blogpost WHERE id=?"
    cur.execute(sql, (post_id,))
    con.commit()
    # post = Blogpost.query.filter_by(id=post_id).first()

    # db.session.delete(post)
    # db.session.commit()
    
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/login')


@app.route('/email_verification/<my_user_id>')
def email_verification(my_user_id):
    print("in email verification " + str(my_user_id))
    return render_template('emailVerification.html',my_user_id=my_user_id)


@app.route('/validate_email/<my_user_id>',methods=['POST'])
def validate_email(my_user_id):
    print("in validaste email " + str(my_user_id))
    user_otp = request.form['otp']
    if otp == int(user_otp):
        session['user'] =  my_user_id
        return redirect('/index')
    else:
        flash("Please Enter Valid OTP")
        return redirect('/email_verification/<my_user_id>')


def encrypt(key, source, encode=True):
    # key = SHA256.new(key).digest
    iv = new().read(AES.block_size)
    obj = AES.new(key, AES.MODE_EAX,iv)
    padding =AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = obj.encrypt(source)
    return base64.b64encode(data).decode("utf-8") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64encode(source.encode("utf-8"))
    # key = SHA256.new(key).digest()
    IV =source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_EAX,IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    print(padding)
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")
    return data[:-padding]


if __name__ == '__main__':
    app.run(debug=True)