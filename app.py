from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import BooleanField, FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import Email, EqualTo, InputRequired, Length, NumberRange

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///support.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

with app.app_context():
    db.create_all()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship("InventoryItem", back_populates="owner", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    rack_slot = db.Column(db.String(1), nullable=False)
    level = db.Column(db.Integer, nullable=False)  # 1 (upper) or 2 (lower)
    weight = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    owner = db.relationship("User", back_populates="items")


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=128)])
    remember = BooleanField("Remember me")
    submit = SubmitField("Masuk")


class RegisterForm(FlaskForm):
    full_name = StringField("Nama Lengkap", validators=[InputRequired(), Length(max=120)])
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=80)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[InputRequired(), Length(min=6, max=128)],
    )
    confirm_password = PasswordField(
        "Konfirmasi Password",
        validators=[InputRequired(), EqualTo("password", message="Password tidak sama")],
    )
    submit = SubmitField("Daftar")


class ItemForm(FlaskForm):
    name = StringField("Nama Barang", validators=[InputRequired(), Length(max=150)])
    rack_slot = SelectField(
        "Slot Rak",
        choices=[
            ("A", "Rack 1 - Slot A"),
            ("B", "Rack 1 - Slot B"),
            ("C", "Rack 2 - Slot C"),
            ("D", "Rack 2 - Slot D"),
            ("E", "Rack 3 - Slot E"),
            ("F", "Rack 3 - Slot F"),
        ],
        validators=[InputRequired()],
    )
    level = SelectField(
        "Posisi",
        coerce=int,
        choices=[(1, "Posisi Atas"), (2, "Posisi Bawah")],
        validators=[InputRequired()],
    )
    weight = FloatField(
        "Berat (Kg)",
        validators=[InputRequired(), NumberRange(min=0.0, message="Berat harus lebih dari 0")],
    )
    submit = SubmitField("Tambah Barang")


class ProfileForm(FlaskForm):
    full_name = StringField("Nama Lengkap", validators=[InputRequired(), Length(max=120)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=120)])
    submit = SubmitField("Simpan Perubahan")

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(func.lower(User.email) == func.lower(form.email.data)).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Selamat datang kembali!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        flash("Email atau password salah", "danger")
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (func.lower(User.email) == func.lower(form.email.data))
            | (func.lower(User.username) == func.lower(form.username.data))
        ).first()
        if existing_user:
            flash("Email atau username sudah terdaftar", "warning")
        else:
            user = User(
                full_name=form.full_name.data,
                username=form.username.data,
                email=form.email.data,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registrasi berhasil, silakan login", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Anda telah keluar", "info")
    return redirect(url_for("login"))


def _build_layout(items: List[InventoryItem]) -> Dict:
    layout = {
        1: {"slots": {"A": {1: None, 2: None}, "B": {1: None, 2: None}}, "total": 0.0},
        2: {"slots": {"C": {1: None, 2: None}, "D": {1: None, 2: None}}, "total": 0.0},
        3: {"slots": {"E": {1: None, 2: None}, "F": {1: None, 2: None}}, "total": 0.0},
    }
    rack_lookup = {"A": 1, "B": 1, "C": 2, "D": 2, "E": 3, "F": 3}

    total_weight = 0.0
    total_positions = 0
    for item in items:
        rack = rack_lookup.get(item.rack_slot)
        if rack is None:
            continue
        layout[rack]["slots"][item.rack_slot][item.level] = item
        layout[rack]["total"] += item.weight
        total_weight += item.weight

    filled_positions = 0
    for rack in layout.values():
        for slot_levels in rack["slots"].values():
            total_positions += len(slot_levels)
            for level_item in slot_levels.values():
                if level_item is not None:
                    filled_positions += 1

    layout_summary = {
        "racks": layout,
        "total_weight": total_weight,
        "total_items": len(items),
        "filled_positions": filled_positions,
        "total_positions": total_positions,
    }
    return layout_summary


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = ItemForm()
    if form.validate_on_submit():
        existing_item = InventoryItem.query.filter_by(
            user_id=current_user.id,
            rack_slot=form.rack_slot.data,
            level=form.level.data,
        ).first()

        if existing_item:
            existing_item.name = form.name.data
            existing_item.weight = form.weight.data
            existing_item.created_at = datetime.utcnow()
            flash("Slot diperbarui dengan barang baru", "info")
        else:
            item = InventoryItem(
                name=form.name.data,
                rack_slot=form.rack_slot.data,
                level=form.level.data,
                weight=form.weight.data,
                owner=current_user,
            )
            db.session.add(item)
            flash("Barang berhasil ditambahkan", "success")
        db.session.commit()
        return redirect(url_for("dashboard"))

    items = (
        InventoryItem.query.filter_by(user_id=current_user.id)
        .order_by(InventoryItem.created_at.desc())
        .all()
    )
    layout = _build_layout(items)

    return render_template("dashboard.html", form=form, items=items, layout=layout)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm(full_name=current_user.full_name, email=current_user.email)
    if form.validate_on_submit():
        email_exists = (
            User.query.filter(func.lower(User.email) == func.lower(form.email.data), User.id != current_user.id)
            .first()
            is not None
        )
        if email_exists:
            flash("Email sudah digunakan pengguna lain", "warning")
        else:
            current_user.full_name = form.full_name.data
            current_user.email = form.email.data
            db.session.commit()
            flash("Profil berhasil diperbarui", "success")
            return redirect(url_for("profile"))
    stats = _build_layout(current_user.items)
    return render_template("profile.html", form=form, stats=stats)


if __name__ == "__main__":
    app.run(debug=True)
