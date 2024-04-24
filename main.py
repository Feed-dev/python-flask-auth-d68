from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

# Define the database object globally
db = SQLAlchemy()


# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(1000))


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret-key-goes-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize plugins
    db.init_app(app)

    # Setup login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Create all tables
    with app.app_context():
        db.create_all()

    # Define routes
    @app.route('/')
    def home():
        return render_template("index.html")

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')

            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email address already exists. Please use a different email.', 'error')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful!', 'success')
            login_user(new_user)
            return redirect(url_for('secrets'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash('Invalid email or password.', 'error')
                return redirect(url_for('login'))
        return render_template("login.html")

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('home'))

    @app.route('/secrets')
    @login_required
    def secrets():
        return render_template("secrets.html", name=current_user.name)

    @app.route('/download')
    @login_required
    def download():
        directory = 'static/files'  # Ensure this path is correct and exists
        filename = 'cheat_sheet.pdf'
        try:
            return send_from_directory(directory, filename, as_attachment=True)
        except Exception as e:
            return str(e)  # To display the error if something goes wrong

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
