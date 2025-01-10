from datetime import datetime
from yourpackage import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    totp_secret = db.Column(db.String(16), nullable=True)
    notes = db.relationship('Note', backref='author', lazy=True)  # Relacja z modelem Note

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

note_shares = db.Table('note_shares',
    db.Column('note_id', db.Integer, db.ForeignKey('note.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.String(44), nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    signature = db.Column(db.String(256), nullable=False)  # Dodane pole na podpis
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with = db.relationship('User', secondary=note_shares, lazy='subquery',
        backref=db.backref('shared_notes', lazy=True))

    def __repr__(self):
        return f"Note('{self.title}', '{self.date_posted}')"

    def clean_content(self):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul', 'h1',
                        'h2', 'h3', 'h4', 'h5', 'img']
        allowed_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt']
        }
        self.content = bleach.clean(self.content, tags=allowed_tags, attributes=allowed_attributes)