import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import date, datetime, timedelta
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify, make_response
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, RequestResetForm, ResetPasswordForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import jwt
from functools import wraps
from flask_wtf.csrf import CSRFError
from flask_wtf.csrf import CSRFProtect

# Set up logger configuration
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
current_year = date.today().strftime('%Y')
current_month = date.today().strftime('%m')
year_month_dir = os.path.join(logs_dir, current_year, current_month)
os.makedirs(year_month_dir, exist_ok=True)
log_file = os.path.join(year_month_dir, f'{date.today()}.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# JWT token generation for access, refresh, email verification, and password reset
def generate_access_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def generate_refresh_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def generate_verification_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def generate_reset_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Token required decorator for protecting routes
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'x-access-token' not in request.cookies:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            access_token = request.cookies.get('x-access-token')
            jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Function to send verification email
def send_verification_email(user):
    token = generate_verification_token(user.id)
    verification_link = url_for('verify_email', token=token, _external=True)
    msg = Message('Email Verification', sender='noreply@demo.com', recipients=[user.email])
    msg.html = render_template('verification_email.html', user=user, verification_link=verification_link)
    mail.send(msg)

# Hello World route
@app.route("/")
def hello_world():
    return jsonify(message="Hello, World!")

# Home route
@app.route("/")
@app.route("/home")
def home():
    try:
        page = request.args.get('page', 1, type=int)
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
        post_list = []
        for post in posts.items:
            post_list.append({
                'id': post.id,
                'title': post.title,
                'content': post.content,
                'author': post.author.username,
                'date_posted': post.date_posted.strftime('%Y-%m-%d %H:%M:%S')
            })
        return jsonify({'posts': post_list})
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}")
        abort(500)

# About route
@app.route("/about")
def about():
    return render_template('about.html', title='About')

# Registration route
@app.route("/register", methods=['POST'])
def register():
    data = request.get_json()
    form = RegistrationForm(data=data)
    if form.validate():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password).decode('utf-8')
            user = User(username=form.username, email=form.email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            # Save the new password to the password history
            user.update_password_history(form.password)
            send_verification_email(user)
            return jsonify({'message': 'User registered successfully. Please check your email for verification instructions.'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Email verification route
@app.route("/verify_email/<token>", methods=['GET'])
def verify_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = data['identity']
        user = User.query.get(user_id)
        if user:
            user.verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully. You can now log in.'}), 200
        else:
            return jsonify({'message': 'Invalid token'}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Login route
@app.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    form = LoginForm(data=data)
    if form.validate():
        try:
            user = User.query.filter_by(email=form.email).first()
            if user and bcrypt.check_password_hash(user.password, form.password):
                if user.verified:
                    login_user(user)
                    access_token = create_access_token(identity=user.id)
                    response = make_response(jsonify({'message': 'Login successful', 'access_token': access_token}), 200)
                    response.set_cookie('x-access-token', access_token, httponly=True)
                    return response
                else:
                    return jsonify({'message': 'Email not verified'}), 403
            else:
                return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as e:
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    response = make_response(jsonify({'message': 'Logged out successfully'}), 200)
    response.delete_cookie('x-access-token')
    return response

# Account route
@app.route("/account", methods=['GET', 'PUT'])
@login_required
def account():
    if request.method == 'GET':
        return jsonify({
            'username': current_user.username,
            'email': current_user.email,
            'image_file': url_for('static', filename='profile_pics/' + current_user.image_file)
        }), 200
    elif request.method == 'PUT':
        data = request.get_json()
        form = UpdateAccountForm(data=data)
        if form.validate():
            try:
                if form.picture.data:
                    picture_file = save_picture(form.picture.data)
                    current_user.image_file = picture_file
                current_user.username = form.username.data
                current_user.email = form.email.data
                db.session.commit()
                return jsonify({'message': 'Account updated successfully'}), 200
            except Exception as e:
                logger.error(f"Error in account route: {str(e)}")
                db.session.rollback()
                return jsonify({'message': 'An error occurred. Please try again later.'}), 500
        else:
            return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Delete account route
@app.route("/account/delete", methods=['DELETE'])
@login_required
def delete_account():
    try:
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        response = make_response(jsonify({'message': 'Account deleted successfully'}), 200)
        response.delete_cookie('x-access-token')
        return response
    except Exception as e:
        logger.error(f"Error in delete_account route: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'An error occurred. Please try again later.'}), 500

# Posts route
@app.route("/posts", methods=['GET', 'POST'])
@login_required
def posts():
    if request.method == 'GET':
        try:
            posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.date_posted.desc()).all()
            post_list = []
            for post in posts:
                post_list.append({
                    'id': post.id,
                    'title': post.title,
                    'content': post.content,
                    'author': post.author.username,
                    'date_posted': post.date_posted.strftime('%Y-%m-%d %H:%M:%S')
                })
            return jsonify({'posts': post_list}), 200
        except Exception as e:
            logger.error(f"Error in posts GET route: {str(e)}")
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    elif request.method == 'POST':
        data = request.get_json()
        form = PostForm(data=data)
        if form.validate():
            try:
                post = Post(title=form.title.data, content=form.content.data, author=current_user)
                db.session.add(post)
                db.session.commit()
                return jsonify({'message': 'Post created successfully'}), 200
            except Exception as e:
                logger.error(f"Error in posts POST route: {str(e)}")
                db.session.rollback()
                return jsonify({'message': 'An error occurred. Please try again later.'}), 500
        else:
            return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Single post route
@app.route("/posts/<int:post_id>", methods=['GET', 'PUT', 'DELETE'])
@login_required
def post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if request.method == 'GET':
        return jsonify({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'author': post.author.username,
            'date_posted': post.date_posted.strftime('%Y-%m-%d %H:%M:%S')
        }), 200
    elif request.method == 'PUT':
        data = request.get_json()
        form = PostForm(data=data)
        if form.validate():
            try:
                post.title = form.title.data
                post.content = form.content.data
                db.session.commit()
                return jsonify({'message': 'Post updated successfully'}), 200
            except Exception as e:
                logger.error(f"Error in post PUT route: {str(e)}")
                db.session.rollback()
                return jsonify({'message': 'An error occurred. Please try again later.'}), 500
        else:
            return jsonify({'message': 'Validation error', 'errors': form.errors}), 400
    elif request.method == 'DELETE':
        try:
            db.session.delete(post)
            db.session.commit()
            return jsonify({'message': 'Post deleted successfully'}), 200
        except Exception as e:
            logger.error(f"Error in post DELETE route: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500

# Request password reset route
@app.route("/reset_password_request", methods=['POST'])
def reset_password_request():
    data = request.get_json()
    form = RequestResetForm(data=data)
    if form.validate():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            send_password_reset_email(user)
            return jsonify({'message': 'An email has been sent with instructions to reset your password.'}), 200
        except Exception as e:
            logger.error(f"Error in reset_password_request route: {str(e)}")
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Send password reset email
def send_password_reset_email(user):
    token = generate_reset_token(user.id)
    reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.html = render_template('password_reset_email.html', user=user, reset_link=reset_link)
    mail.send(msg)

# Reset password route
@app.route("/reset_password/<token>", methods=['POST'])
def reset_password(token):
    data = request.get_json()
    form = ResetPasswordForm(data=data)
    if form.validate():
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data['identity']
            user = User.query.get(user_id)
            if user:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                return jsonify({'message': 'Your password has been updated successfully.'}), 200
            else:
                return jsonify({'message': 'Invalid token'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400
    
# # Example of disabling CSRF protection for specific routes (if needed)
# @app.route('/unprotected', methods=['POST'])
# @csrf.exempt # type: ignore
# def unprotected_route():
#     return 'No CSRF protection here!'    

# Error handling routes
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'message': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'message': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'message': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal Server Error'}), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'message': 'CSRF token missing or incorrect'}), 400
