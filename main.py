import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship


app = Flask(__name__)
app.app_context().push()
login_manager = LoginManager()
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR65'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    lists = relationship("List", back_populates="user")


class List(db.Model):
    __tablename__ = "lists"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    todo_item = db.Column(db.String(200))
    user = relationship("User", back_populates="lists")


# db.create_all()


@app.route("/")
def home():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        try:
            user = User.query.filter_by(email=email).first()
            if check_password_hash(user.password, password) and user:
                login_user(user)
                flash('You were successfully logged in')
                return redirect(url_for("todo"))
            else:
                flash("Sorry but that's the wrong password")
                return redirect(url_for('login'))
        except AttributeError:
            flash("That email does not exist in the database. Please create an account.")
            return redirect(url_for('register'))

    return render_template('login.html', logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        details = {
            "email": request.form["email"],
            "password": request.form["password"],
            "name": request.form["name"],
        }
        user = User.query.filter_by(email=details["email"]).first()
        if user:
            flash("You already have an account with this email. Try logging in.")
            user = None  # added
            return redirect(url_for('login'))
        password = werkzeug.security.generate_password_hash(details["password"], method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=details["email"], password=password, name=details["name"])
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return render_template("list.html", name=details["name"])

    return render_template("register.html", logged_in=current_user.is_authenticated)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/todo', methods=["GET", "POST"])
@login_required
def todo():
    tasks = List.query.filter_by(user_id=current_user.id)
    if request.method == "POST":
        new_item = List(todo_item=request.form["item"], user_id=current_user.id)
        db.session.add(new_item)
        db.session.commit()
    return render_template("list.html", name=current_user.name, tasks=tasks, logged_in=True)


@app.route("/delete/<int:task_id>")
def delete_post(task_id):
    task_to_delete = List.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('todo'))


if __name__ == "__main__":
    app.run(debug=True)

