import os
from app import app, db
from models import User

app.app_context().push()

def make_admin():
    email = input("Admin yapmak istediğiniz kullanıcının e-posta adresi: ")

    # Kullanıcıyı e-posta adresine göre bulun
    user = User.query.filter_by(email=email).first()
    if not user:
        print(f"{email} adresi ile kayıtlı bir kullanıcı bulunamadı.")
        return

    # Kullanıcının admin olup olmadığını kontrol edin
    if user.is_admin:
        print(f"{email} adresi zaten bir admin.")
        return

    # Kullanıcıyı admin yapın
    user.is_admin = True

    try:
        db.session.commit()
        print(f"{user.username} adlı kullanıcıya admin erişimi verildi.")
    except Exception as e:
        db.session.rollback()
        print(f"Hata: {e}")

if __name__ == "__main__":
    make_admin()
