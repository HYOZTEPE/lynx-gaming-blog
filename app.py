from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_mail import Mail, Message
from functools import wraps
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from models import db, User, News, Comment
from sqlalchemy import func
from werkzeug.utils import secure_filename
import os
import locale
from config import Config
from models import User, News, Comment, CommentLike


locale.setlocale(locale.LC_TIME, 'tr_TR.UTF-8')

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'hasanyigit61'


# Veritabanı yapılandırması
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:hasanyigit61@localhost/lynx'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail yapılandırması
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Gerçek SMTP sunucusunu kullanın
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'lynxgamingmanagement@gmail.com'  # Gerçek e-posta adresinizi kullanın
app.config['MAIL_PASSWORD'] = 'omdyqrtmvvinmhav'  # Gerçek e-posta parolanızı kullanın
app.config['MAIL_DEFAULT_SENDER'] = 'lynxgamingmanagement@gmail.com'  # Gönderici e-posta adresinizi kullanın

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET'])
def index():
    news_items = News.query.order_by(News.published_date.desc()).all()
    return render_template('index.html', news_items=news_items)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Bu email adresi ile kayıtlı kullanıcı bulunamadı.', 'danger')
            return redirect(url_for('login'))

        if user.is_banned:
            flash('Bu hesap banlanmış.', 'danger')
            return redirect(url_for('login'))

        if not user.confirmed:
            flash('Lütfen e-posta adresinizi doğrulayın.', 'warning')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Yanlış şifre.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash('Giriş başarılı!', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Şifreler uyuşmuyor!', 'danger')
            return redirect(url_for('register'))

        user_by_email = User.query.filter_by(email=email).first()
        user_by_username = User.query.filter_by(username=username).first()
        
        if user_by_email:
            if user_by_email.is_banned:
                flash('Bu email adresi banlanmış. Kayıt olamazsınız.', 'danger')
                return redirect(url_for('register'))
            else:
                flash('Bu email adresi zaten kayıtlı.', 'danger')
                return redirect(url_for('register'))
        
        if user_by_username:
            flash('Bu kullanıcı adı zaten alınmış.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            token = s.dumps(email, salt='email-confirm')
            msg = Message('E-posta Onayı', recipients=[email])
            link = url_for('confirm_email', token=token, _external=True)
            msg.body = f'E-posta adresinizi doğrulamak için lütfen şu bağlantıya tıklayın: {link}'
            mail.send(msg)

            flash('Bir onay e-postası gönderildi.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt başarısız: {str(e)}', 'danger')

    return render_template('register.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('Onay bağlantısının süresi dolmuş.', 'danger')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first_or_404()
    user.confirmed = True
    db.session.commit()

    flash('E-posta adresiniz doğrulandı!', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yapıldı.', 'success')
    return redirect(url_for('index'))

@app.route('/news')
def news():
    news_items = News.query.all()
    return render_template('news.html', news_items=news_items)

@app.route('/news/<int:news_id>', methods=['GET', 'POST'])
def news_detail(news_id):
    news_item = News.query.get_or_404(news_id)
    comments = Comment.query.filter_by(news_id=news_id).order_by(Comment.likes.desc()).all()
    
    liked_comments = []
    if current_user.is_authenticated:
        liked_comments = [like.comment_id for like in CommentLike.query.filter_by(user_id=current_user.id).all()]
    
    if request.method == 'POST':
        content = request.form['content']
        comment = Comment(content=content, author=current_user, news_id=news_id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('news_detail', news_id=news_id))

    return render_template('news_detail.html', news_item=news_item, comments=comments, liked_comments=liked_comments)


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    like = CommentLike.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    
    if like:
        # If already liked, remove like
        db.session.delete(like)
        comment.likes -= 1
    else:
        # Add new like
        like = CommentLike(user_id=current_user.id, comment_id=comment_id)
        db.session.add(like)
        comment.likes += 1
    
    db.session.commit()
    return jsonify({'likes': comment.likes})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    print(app.config.get('UPLOAD_FOLDER'))  # Debugging için
    if request.method == 'POST':
        if 'profile_image' in request.files:
            profile_image = request.files['profile_image']
            if profile_image.filename != '':
                filename = secure_filename(profile_image.filename)
                profile_image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_image.save(profile_image_path)
                current_user.profile_image = 'images/' + filename
        if not current_user.profile_image:
            current_user.profile_image = 'images/default_profile.png'
        db.session.commit()
        flash('Profil güncellendi!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if not current_user.check_password(current_password):
            flash('Mevcut şifreniz yanlış.', 'danger')
        elif new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor.', 'danger')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Şifreniz başarıyla güncellendi.', 'success')
            return redirect(url_for('profile'))
    return render_template('change_password.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    search = request.args.get('search')
    if search:
        news_items = News.query.filter(News.title.ilike(f'%{search}%')).all()
    else:
        news_items = News.query.all()

    users = User.query.all()
    return render_template('admin.html', users=users, news_items=news_items)

@app.route('/add_news', methods=['POST'])
def add_news():
    if not current_user.is_admin:
        flash("Bu işlemi gerçekleştirme yetkiniz yok.", "danger")
        return redirect(url_for('admin'))

    title = request.form['title']
    description = request.form['description']
    image = request.files['image']
    
    if image:
        image_filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        image_url = url_for('uploaded_file', filename=image_filename)
    else:
        image_url = None

    news_item = News(title=title, description=description, image_url=image_url)
    db.session.add(news_item)
    db.session.commit()
    flash('Haber başarıyla eklendi!', 'success')
    return redirect(url_for('admin'))


@app.route('/delete_news/<int:news_id>', methods=['POST'])
def delete_news(news_id):
    news_item = News.query.get_or_404(news_id)
    db.session.delete(news_item)
    db.session.commit()
    flash('Haber ve ilgili yorumlar başarıyla silindi.', 'success')
    return redirect(url_for('admin'))

@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user and not current_user.is_admin:
        flash('Bu yorumu düzenleme yetkiniz yok.', 'danger')
        return redirect(url_for('news_detail', news_id=comment.news_id))
    if request.method == 'POST':
        comment.content = request.form.get('content')
        db.session.commit()
        flash('Yorum başarıyla güncellendi!', 'success')
        return redirect(url_for('news_detail', news_id=comment.news_id))
    return render_template('edit_comment.html', comment=comment)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if not comment:
        flash('Yorum bulunamadı.', 'danger')
        return redirect(request.referrer)
    
    if current_user.is_admin or current_user.id == comment.user_id:
        # Yoruma bağlı tüm beğenileri sil
        CommentLike.query.filter_by(comment_id=comment_id).delete()
        
        # Yorumu sil
        db.session.delete(comment)
        db.session.commit()
        flash('Yorum başarıyla silindi.', 'success')
    else:
        flash('Bu yorumu silmek için yetkiniz yok.', 'danger')

    return redirect(request.referrer)




@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not name or not email or not message:
            flash('Lütfen tüm alanları doldurun.', 'danger')
        else:
            msg = Message(
                subject='Yeni İletişim Formu Mesajı',
                sender=email,
                recipients=['lynxgamingmanagement@gmail.com'],
                body=f'Ad: {name}\nEmail: {email}\n\nMesaj:\n{message}'
            )
            mail.send(msg)
            flash('Mesajınız başarıyla gönderildi!', 'success')
            return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/all_news')
def all_news():
    search = request.args.get('search')
    sort_by = request.args.get('sort_by')

    query = News.query

    if search:
        query = query.filter(News.title.ilike(f'%{search}%') | News.description.ilike(f'%{search}%'))

    if sort_by == 'title':
        query = query.order_by(News.title)
    elif sort_by == 'comments':
        query = query.outerjoin(Comment).group_by(News.id).order_by(func.count(Comment.id).desc())
    else:  # Default is to sort by date
        query = query.order_by(News.published_date.desc())

    news_items = query.all()
    return render_template('all_news.html', news_items=news_items)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    search = request.args.get('search')
    filter_by = request.args.get('filter')

    query = User.query

    if search:
        query = query.filter(User.username.ilike(f'%{search}%'))

    if filter_by == 'banned':
        query = query.filter(User.is_banned == True)
    elif filter_by == 'admin':
        query = query.filter(User.is_admin == True)

    users = query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = not user.is_banned
    db.session.commit()
    flash('Kullanıcının durumu değiştirildi.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Bu işlemi yapmak için yetkiniz yok.', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get(user_id)
    if user:
        try:
            # Kullanıcıya ait yorumları ve ilgili kayıtları sil
            comments = Comment.query.filter_by(user_id=user_id).all()
            for comment in comments:
                CommentLike.query.filter_by(comment_id=comment.id).delete()
                db.session.delete(comment)

            # Kullanıcıyı sil
            db.session.delete(user)
            db.session.commit()
            flash('Kullanıcı ve kullanıcıya ait tüm veriler başarıyla silindi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Kullanıcı silinemedi: {str(e)}', 'danger')
    else:
        flash('Kullanıcı bulunamadı.', 'danger')

    return redirect(url_for('admin_users'))



@app.route('/admin/delete_comments/<int:user_id>', methods=['POST'])
@login_required
def delete_user_comments(user_id):
    if not current_user.is_admin:
        flash("Bu işlemi gerçekleştirme yetkiniz yok.", "danger")
        return redirect(url_for('admin_users'))  # Doğru endpoint'i kullanın

    user = User.query.get_or_404(user_id)
    comments = Comment.query.filter_by(user_id=user_id).all()

    for comment in comments:
        db.session.delete(comment)

    db.session.commit()
    flash(f"{user.username} kullanıcısının tüm yorumları silindi.", "success")
    return redirect(url_for('admin_users'))  # Doğru endpoint'i kullanın

@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('Bu işlemi gerçekleştirme yetkiniz yok.', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get(user_id)
    if user:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"{user.username} kullanıcısının adminlik durumu değiştirildi.", 'success')
    else:
        flash('Kullanıcı bulunamadı.', 'danger')

    return redirect(url_for('admin_users'))

@app.route('/edit_news/<int:news_id>', methods=['GET', 'POST'])
def edit_news(news_id):
    if not current_user.is_admin:
        flash("Bu işlemi gerçekleştirme yetkiniz yok.", "danger")
        return redirect(url_for('admin'))

    news_item = News.query.get_or_404(news_id)
    if request.method == 'POST':
        news_item.title = request.form['title']
        news_item.description = request.form['description']
        
        image = request.files['image']
        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            news_item.image_url = url_for('uploaded_file', filename=image_filename)
        
        db.session.commit()
        flash("Haber başarıyla güncellendi.", "success")
        return redirect(url_for('admin'))
        
    return render_template('edit_news.html', news_item=news_item)


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='email-confirm')
            link = url_for('reset_password', token=token, _external=True)
            msg = Message('Şifre Sıfırlama İsteği', recipients=[email])
            msg.body = f'Linke tıklayarak şifrenizi sıfırlayabilirsiniz: {link}'
            mail.send(msg)
            flash('Şifre sıfırlama talimatları e-posta adresinize gönderildi.', 'success')
        else:
            flash('Bu e-posta adresi ile kayıtlı kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>Token süresi dolmuş!</h1>'
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            user = User.query.filter_by(email=email).first()
            if user:
                user.set_password(password)
                db.session.commit()
                flash('Şifreniz başarıyla güncellendi!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Kullanıcı bulunamadı.', 'danger')
        else:
            flash('Şifreler uyuşmuyor.', 'danger')
    
    return render_template('reset_password.html', token=token)

@app.route('/view_user_comments/<int:user_id>', methods=['GET'])
@login_required
def view_user_comments(user_id):
    if not current_user.is_admin:
        flash('Bu işlemi yapmak için yetkiniz yok.', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get(user_id)
    if not user:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('admin_users'))

    comments = Comment.query.filter_by(user_id=user_id).all()
    liked_comments = [comment.id for comment in current_user.liked_comments]
    return render_template('view_user_comments.html', user=user, comments=comments, liked_comments=liked_comments)

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if not current_user.is_admin:
        flash('Bu işlemi yapmak için yetkiniz yok.', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        recipient_emails = request.form.getlist('recipient_emails')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not recipient_emails or not subject or not message:
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return redirect(url_for('send_message'))

        try:
            for email in recipient_emails:
                msg = Message(subject, recipients=[email])
                msg.body = message
                mail.send(msg)
            flash('Mesaj başarıyla gönderildi.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            flash(f'Mesaj gönderilemedi: {str(e)}', 'danger')

    users = User.query.all()
    return render_template('send_message.html', users=users)


@app.route('/message_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def message_user(user_id):
    if not current_user.is_admin:
        flash('Bu işlemi yapmak için yetkiniz yok.', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get(user_id)
    if not user:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not subject or not message:
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return redirect(url_for('message_user', user_id=user_id))

        try:
            msg = Message(subject, recipients=[user.email])
            msg.body = message
            mail.send(msg)
            flash('Mesaj başarıyla gönderildi.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            flash(f'Mesaj gönderilemedi: {str(e)}', 'danger')

    return render_template('message_user.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)




