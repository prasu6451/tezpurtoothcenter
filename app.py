from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from flask_mail import *
import random
import os
import datetime
from werkzeug.utils import secure_filename
from yolo_model import run_yolo_analysis




app = Flask(__name__)

#DB Config
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'TezpurToothCenter'
app.secret_key = 'secret_key'

mysql = MySQL(app)

# mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = '587'
app.config['MAIL_USERNAME'] = 'prasuryakakati97072@gmail.com'
app.config['MAIL_PASSWORD'] = 'pauezqqroblohybg'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
class EmailVerifyForm(FlaskForm):
    otp = StringField("Enter OTP", validators=[DataRequired()])
    submit = SubmitField("Verify")


@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data 
        email = form.email.data 
        password = form.password.data
        session['email'] = email
        hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        #store data into database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already registered. Please log in or use a different email.")
            return redirect(url_for('register'))
        else :
            cursor.execute("INSERT INTO users (name, email, password, verified) VALUES (%s,%s,%s, %s)", (name, email, hash_password.decode('utf-8'), False))
            mysql.connection.commit()
            cursor.close()
        
        # email verification
        global otp
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        msg = Message('Email Verification', sender = 'prasuryakakati97072@gmail.com', recipients = [email])
        msg.body = "Hi"+name+"\nYour email OTP is : "+ str(otp)

        mail.send(msg)
        return render_template('email_verify.html', email=email, form=EmailVerifyForm())

        #return redirect(url_for('email_verify'))

    return render_template('register.html', form=form)

@app.route('/email_verify', methods=['GET', 'POST'])
def email_verify():
    form = EmailVerifyForm()
    if form.validate_on_submit():
        user_otp = form.otp.data
        email = session.get('email')
        if 'otp' in session and int(user_otp) == session['otp']:
            flash("Email verified successfully!", "success")
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET verified = TRUE WHERE email = %s", (email,))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM users WHERE email = %s AND verified = FALSE", (email,))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('register'))
    
    return render_template('email_verify.html', form=form)     


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data 
        password = form.password.data

        #store data into database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            annotated_img = session.pop('annotated_img', None)
            detections = session.pop('detections', None)
            return render_template('dashboard.html', user=user, annotated_img=annotated_img, detections=detections)

    return redirect(url_for('login'))


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'img' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))

    file = request.files['img']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_folder = os.path.join('static/uploads', str(session['user_id']))
        os.makedirs(user_folder, exist_ok=True)

        filepath = os.path.join(user_folder, filename)
        file.save(filepath)

        # ---- Run YOLO Analysis ----
        result_img_path, detections = run_yolo_analysis(filepath)

        # Store result in DB
        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO reports (user_id, image_path, detection_result) 
            VALUES (%s, %s, %s)
        """, (
            session['user_id'], 
            result_img_path, 
            str(detections)
        ))
        mysql.connection.commit()
        cursor.close()

        # Save to session to show on dashboard
        session['annotated_img'] = result_img_path
        session['detections'] = detections

        return redirect(url_for('dashboard'))

    flash('File type not allowed')
    return redirect(url_for('dashboard'))


@app.route('/reports')
def reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, image_path, detection_result, created_at 
        FROM reports 
        WHERE user_id = %s 
        ORDER BY created_at DESC
    """, (user_id,))
    report_data = cursor.fetchall()
    cursor.close()

    return render_template('reports.html', reports=report_data)



@app.route('/logout')
def logout():
    # Clear the user session
    session.pop('user_id', None)  # Remove only user_id
    # Or clear everything:
    # session.clear()
    return redirect(url_for('login'))  # Redirect to login page

   

if __name__ == '__main__':
    app.run(debug=True, host='192.168.29.110')