import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
# from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm
from libgravatar import Gravatar
from smtplib import SMTP


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

smtp_user = os.environ.get('SMTP_USER')
smtp_password = os.environ.get('SMTP_PASSWORD')
admin_email = os.environ.get('ADMIN_EMAIL')
contact_email = os.environ.get('CONTACT_EMAIL')


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URL', 'sqlite:///posts.db')
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # # created new author_id for creating relationship
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('Users', back_populates="posts")
    comments = relationship('Comments', back_populates='post')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# TODO: Create a User table for all your registered users. 
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    # added new relations i.e. with posts and comments
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comments', back_populates='author')


# Create a Table for Comments
class Comments(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship('Users', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship('BlogPost', back_populates="comments")


with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        registration_email = register_form.email.data
        user = db.session.execute(db.select(Users).where(Users.email == registration_email)).scalar()
        if user:
            flash("Email already registered. Please login instead!")
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8)
            user = Users(
                name=request.form.get('name'),
                email = registration_email,
                password = hashed_password
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('get_all_posts', logged_in=True))
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        entered_email = login_form.email.data
        user = db.session.execute(db.select(Users).where(Users.email == entered_email)).scalar()
        if user:
            entered_password = login_form.password.data
            if check_password_hash(user.password, entered_password):
                login_user(user)
                return redirect(url_for('get_all_posts', logged_in=True))
            else:
                flash("Password Incorrect. Please try again!")
                return redirect(url_for('login'))
        else:
            flash("Email not registered. Kindly check you are registered with us or try again!")
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)
    return wrapper


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form= CommentForm()
    if current_user.is_authenticated:
        gravatar = Gravatar(current_user.email).get_image(default='monsterid')
    else:
        gravatar = url_for('static', filename='/assets/img/default-profile.jpg')
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comments(
                author=current_user,
                text=form.editor.data,
                post=requested_post
            )
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("Only logged in users can comments. Please login first!")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post,
                           logged_in=current_user.is_authenticated, form=form, image=gravatar)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True,
                           logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact", methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')
        print(name, email, phone, message, smtp_user, smtp_password, admin_email, contact_email)
        with SMTP('mail.smtp2go.com') as connection:
            connection.starttls()
            connection.login(user=smtp_user, password=smtp_password)
            message1 = f'Subject:Blogster Contact request received\n\nThank You for contacting us. We have received your request\n\nYour message: {message}\nWe will get back to you ASAP.\n\nTeam Blogster'.encode('utf-8')
            message2 = f"Subject:New Contact Request.\n\nFrom: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}\n".encode('utf-8')
            connection.sendmail(from_addr=admin_email, to_addrs=email, msg=message1)
            connection.sendmail(from_addr=admin_email, to_addrs=contact_email, msg=message2)
        return render_template('contact.html', logged_in=current_user.is_authenticated, msg_sent=True)
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True)
