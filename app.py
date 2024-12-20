from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Mountain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)  # Level: Mudah, Sedang, Sulit
    votes = db.Column(db.Integer, default=0)  # Total evaluasi dari pengguna
    difficulty_score = db.Column(db.Float, default=0.0)  # Rata-rata skor evaluasi
    is_locked = db.Column(db.Boolean, default=False)  # True jika gunung tidak bisa diupdate

class Evaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mountain_id = db.Column(db.Integer, db.ForeignKey('mountain.id'), nullable=False)
    difficulty_feedback = db.Column(db.String(20), nullable=False)  # Feedback: sesuai/tidak sesuai


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField("register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("Username already exists.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField("login")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

# @app.route('/dashboard', methods=['GET', 'POST'])
# @login_required
# def dashboard():
#     return render_template('dashboard.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Default filter values
    difficulty_filter = request.form.get('difficulty', 'all')
    name_filter = request.form.get('name', '').strip()

    # Query untuk memfilter gunung
    query = Mountain.query
    if difficulty_filter != 'all':
        query = query.filter_by(difficulty=difficulty_filter)
    if name_filter:
        query = query.filter(Mountain.name.ilike(f'%{name_filter}%'))  # Pencarian nama gunung

    mountains = query.all()  # Eksekusi query
    return render_template('dashboard.html', mountains=mountains, selected_difficulty=difficulty_filter)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/mountains')
def mountains():
    mountains = Mountain.query.all()  # Ambil semua data gunung dari database
    return render_template('mountains.html', mountains=mountains)

def update_mountain_difficulty():
    mountains = Mountain.query.all()  # Ambil semua gunung dari database
    for mountain in mountains:
        # Abaikan gunung yang terkunci
        if mountain.is_locked:
            continue

        # Ambil semua feedback untuk gunung ini
        evaluations = Evaluation.query.filter_by(mountain_id=mountain.id).all()

        # Hitung jumlah feedback dan feedback positif
        total_votes = len(evaluations)
        positive_votes = sum(1 for e in evaluations if e.difficulty_feedback == "sesuai")

        # Hitung persentase feedback positif
        if total_votes > 0:
            positive_percentage = positive_votes / total_votes
        else:
            positive_percentage = 0  # Tidak ada feedback

        # Tentukan level kesulitan berdasarkan persentase
        if positive_percentage >= 0.8:
            mountain.difficulty = "Mudah"
        elif positive_percentage >= 0.5:
            mountain.difficulty = "Sedang"
        else:
            mountain.difficulty = "Sulit"

        # Perbarui informasi di database
        mountain.votes = total_votes
        mountain.difficulty_score = positive_percentage
        db.session.commit()



@app.route('/preferences', methods=['GET', 'POST'])
@login_required
def preferences():
    mountains = Mountain.query.all()  # Ambil semua gunung dari database
    if request.method == 'POST':
        for mountain in mountains:
            feedback = request.form.get(f'feedback_{mountain.id}')  # Ambil feedback dari form
            evaluation = Evaluation(
                user_id=current_user.id,
                mountain_id=mountain.id,
                difficulty_feedback=feedback
            )
            db.session.add(evaluation)
        db.session.commit()

        # Perbarui level kesulitan gunung
        update_mountain_difficulty()
        return redirect(url_for('mountains'))

    return render_template('preferences.html', mountains=mountains)


if __name__ == '__main__':
    app.run(debug=True)