from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash
from forms import *
from typing import List



app = Flask(__name__)
app.config['SECRET_KEY'] = 'bc26d388cb92dc12ef5aca09e9487f0bfd5a6a7aa778a97a11ebf6c3555d544c'
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    author: Mapped["User"] = relationship(back_populates="posts")
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    comments: Mapped[List["Comment"]] = relationship(back_populates="parent_post")


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=False, nullable=False)
    password: Mapped[str] = mapped_column(String(100), unique=False, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")
    comments: Mapped[List["Comment"]] = relationship(back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped["User"] = relationship(back_populates="comments")
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    parent_post: Mapped["BlogPost"] = relationship(back_populates="comments")
    parent_post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    posted_time : Mapped[str] = mapped_column(Text, nullable=False) # TODO add time function which calculates the time from post being posted



# Authentication Functions
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for("login"))

    
def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous:
            return redirect(url_for('login', next=request.url))
        elif current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return function(*args, **kwargs)
    return decorated_function


def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        user = db.session.execute(db.select(Comment).where(Comment.author_id == current_user.id)).scalar()
        if not current_user.is_authenticated or current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check
    

def hash_password(password: str)->str:
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

with app.app_context():
    db.create_all()


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm(db=db, User=User)
    if register_form.validate_on_submit():
        if db.session.execute(db.select(User).where(User.email == register_form.email.data)).scalar():
            flash("Email already in use")
            return redirect(url_for("register"))
        
        else:
            hashed_password = hash_password(password=register_form.password.data)
            new_user = User(username=register_form.username.data, password=hashed_password, email=register_form.email.data)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form, current_user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm(db=db, User=User)
    if login_form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == login_form.email.data)).scalar()
        login_user(user)
        return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if request.method == "POST":
            if current_user.is_authenticated:
                new_comment = Comment(text=form.body.data,
                                      author=current_user,
                                      author_id=current_user.id, 
                                      parent_post= db.get_or_404(BlogPost, post_id),
                                      parent_post_id=post_id,
                                      posted_time=date.today().strftime("%B %d, %Y"))
                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for("show_post", post_id=post_id))
            else:
                flash("You need to login or register to comment.")
                return redirect(url_for("login"))

    requested_post = db.get_or_404(BlogPost, post_id)
    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


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
            author_id=int(current_user.id),
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


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
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/comment/<int:comment_id>/<int:post_id>")
@only_commenter
def delete_comment(post_id, comment_id):
    post_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'), current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
