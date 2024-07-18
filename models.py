from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, backref
db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    profile_image = db.Column(db.String(300), default='default_profile.png')
    is_admin = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, default=False)
    comments = db.relationship('Comment', backref='author', lazy=True)
    is_banned = db.Column(db.Boolean, default=False)
    liked_comments = db.relationship('CommentLike', back_populates='user', lazy='dynamic', overlaps="comment_likes,liker")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    published_date = db.Column(db.DateTime, default=datetime.utcnow)
    comments = relationship("Comment", backref="news", cascade="all, delete-orphan")
    def __repr__(self):
        return f'<News {self.title}>'

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), nullable=False)
    comment_likes = db.relationship('CommentLike', back_populates='comment', lazy='dynamic', cascade="all, delete-orphan", overlaps="liked_comments,liker")

class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    user = db.relationship('User', backref='comment_likes', lazy=True)
    comment = db.relationship('Comment', backref='comment_likes', lazy=True)
    user = db.relationship('User', back_populates='liked_comments', overlaps="comment_likes,liker")
    comment = db.relationship('Comment', back_populates='comment_likes', overlaps="liked_comments,liker")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    