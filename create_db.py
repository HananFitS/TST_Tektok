from app import app, db
from app import Mountain

# Membuat tabel database
with app.app_context():
    db.create_all()  # Membuat tabel jika belum ada
    print("Database and tables created!")

    if not Mountain.query.first():  # Cek apakah tabel Mountain kosong
        gunung1 = Mountain(name="Gunung Ciremai", difficulty="Mudah", is_locked=True)
        gunung2 = Mountain(name="Gunung Gede", difficulty="Sedang", is_locked=True)
        gunung3 = Mountain(name="Gunung Pangrango", difficulty="Sulit", is_locked=True)
        gunung4 = Mountain(name="Gunung Papandayan", difficulty="Mudah", is_locked=False)
        gunung5 = Mountain(name="Gunung Slamet", difficulty="Sulit", is_locked=False)
        # gunung_locked = Mountain(name="Gunung Semeru", difficulty="Sulit", is_locked=True)
        # gunung_normal = Mountain(name="Gunung Merbabu", difficulty="Sedang", is_locked=False)

        db.session.add_all([gunung1, gunung2, gunung3, gunung4, gunung5])
        db.session.commit()
        print("Initial data added!")