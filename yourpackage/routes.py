from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from yourpackage import app, db, bcrypt
from yourpackage.forms import RegistrationForm, LoginForm, NoteForm
from yourpackage.models import User, Note
from yourpackage.utils import generate_key, encrypt_content, decrypt_content, sign_content

@app.route("/")
@app.route("/home")
def home():
    tab = request.args.get('tab', 'private')
    if not current_user.is_authenticated:
        # If user is not authenticated, only show public notes
        notes = Note.query.filter_by(is_public=True).all()
        tab = 'public'  # Force the tab to be 'public' for unauthenticated users
    else:
        if tab == 'private':
            notes = Note.query.filter_by(author=current_user).all()
        elif tab == 'public':
            notes = Note.query.filter_by(is_public=True).all()
        elif tab == 'shared':
            notes = Note.query.filter(Note.shared_with.any(id=current_user.id)).all()
        else:
            notes = []
    return render_template('home.html', notes=notes, tab=tab)

@app.route("/about")
def about():
    return render_template('about.html', title='About')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/note/new/<string:note_type>", methods=['GET', 'POST'])
@login_required
def new_note(note_type):
    form = NoteForm()
    if form.validate_on_submit():
        if form.is_encrypted.data:
            key = generate_key()
            encrypted_content = encrypt_content(form.content.data, key)
            note = Note(title=form.title.data, content=encrypted_content, author=current_user, is_encrypted=True,
                        encryption_key=key.decode(), is_public=(note_type == 'public'),
                        signature=sign_content(encrypted_content, current_user))
        else:
            note = Note(title=form.title.data, content=form.content.data, author=current_user, is_encrypted=False,
                        is_public=(note_type == 'public'), signature=sign_content(form.content.data, current_user))

        if note_type == 'shared':
            usernames = [username.strip() for username in form.share_with.data.split(',')]
            for username in usernames:
                user_to_share = User.query.filter_by(username=username).first()
                if user_to_share:
                    note.shared_with.append(user_to_share)
                else:
                    flash(f'User {username} not found.', 'danger')
                    return render_template('create_note.html', title='New Note', form=form, legend='New Note')

        db.session.add(note)
        db.session.commit()
        flash('Your note has been created!', 'success')
        return redirect(url_for('home', tab=note_type))
    return render_template('create_note.html', title='New Note', form=form, legend='New Note')


@app.route("/note/<int:note_id>/update", methods=['GET', 'POST'])
@login_required
def update_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    form = NoteForm()
    if form.validate_on_submit():
        if form.is_encrypted.data:
            key = generate_key()
            encrypted_content = encrypt_content(form.content.data, key)
            note.title = form.title.data
            note.content = encrypted_content
            note.is_encrypted = True
            note.encryption_key = key.decode()
            note.signature = sign_content(encrypted_content, current_user)
        else:
            note.title = form.title.data
            note.content = form.content.data
            note.is_encrypted = False
            note.encryption_key = None
            note.signature = sign_content(form.content.data, current_user)

        if note.is_public:
            note.shared_with = []  # Clear shared users for public notes
        elif 'shared' in request.path:
            share_with_username = form.share_with.data
            user_to_share = User.query.filter_by(username=share_with_username).first()
            if user_to_share:
                note.shared_with.append(user_to_share)
            else:
                flash(f'User {share_with_username} not found.', 'danger')
                return render_template('create_note.html', title='Update Note', form=form, legend='Update Note')

        db.session.commit()
        flash('Your note has been updated!', 'success')
        return redirect(url_for('note', note_id=note.id))
    elif request.method == 'GET':
        form.title.data = note.title
        form.content.data = note.content if not note.is_encrypted else decrypt_content(note.content,
                                                                                       note.encryption_key.encode())
        form.is_encrypted.data = note.is_encrypted
        if 'shared' in request.path and note.shared_with:
            form.share_with.data = note.shared_with[0].username  # Show the first shared user's username

    return render_template('create_note.html', title='Update Note', form=form, legend='Update Note')

@app.route("/note/<int:note_id>")
@login_required
def note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user and current_user not in note.shared_with and not note.is_public:
        abort(403)
    if note.is_encrypted:
        content = decrypt_content(note.content, note.encryption_key.encode())
    else:
        content = note.content
    shared_with_usernames = [user.username for user in note.shared_with]
    return render_template('note.html', title=note.title, note=note, content=content, shared_with_usernames=shared_with_usernames)

@app.route("/note/<int:note_id>/delete", methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash('Your note has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/note/<int:note_id>/share", methods=['GET', 'POST'])
@login_required
def share_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    if request.method == 'POST':
        shared_with_username = request.form.get('username')
        user_to_share = User.query.filter_by(username=shared_with_username).first()
        if user_to_share:
            note.shared_with.append(user_to_share)
            db.session.commit()
            flash(f'Note shared with {shared_with_username}!', 'success')
        else:
            flash('User not found', 'danger')
        return redirect(url_for('note', note_id=note.id))
    return render_template('share_note.html', title='Share Note', note=note)

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404