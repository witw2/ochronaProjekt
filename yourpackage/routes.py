from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from yourpackage import app, db, bcrypt
from yourpackage.forms import RegistrationForm, LoginForm, NoteForm, DecryptNoteForm, EmptyForm
from yourpackage.models import User, Note, note_shares
from yourpackage.utils import encrypt_content_with_password, decrypt_content_with_password, sign_content, verify_totp, simple_encrypt, simple_decrypt
import time
import pyotp
import bleach
import base64
import qrcode
from io import BytesIO

login_attempts = {}

def clean_content(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul', 'h1', 'h2', 'h3', 'h4', 'h5', 'img','div','br']
    allowed_attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt']
    }
    return bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes)

@app.route("/")
@app.route("/home")
def home():
    tab = request.args.get('tab', 'private')
    if not current_user.is_authenticated:
        notes = Note.query.filter_by(is_public=True).all()
        tab = 'public'
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

@app.route("/about", methods=['GET', 'POST'])
@login_required
def about():
    user = current_user
    form = EmptyForm()
    return render_template('about.html', title='About', user=user, form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    qr_code_data = None
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        user.totp_secret = pyotp.random_base32()
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! Please scan the QR code with your TOTP app.', 'success')

        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(user.email, issuer_name="YourAppName")
        img = qrcode.make(totp_uri)
        stream = BytesIO()
        img.save(stream, 'PNG')
        stream.seek(0)
        qr_code_data = base64.b64encode(stream.getvalue()).decode('utf-8')

    return render_template('register.html', title='Register', form=form, qr_code_data=qr_code_data)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        email = form.email.data
        if email not in login_attempts:
            login_attempts[email] = {'attempts': 0, 'last_attempt_time': time.time()}
        attempts = login_attempts[email]['attempts']
        last_attempt_time = login_attempts[email]['last_attempt_time']

        if attempts >= 5 and time.time() - last_attempt_time < 300:
            remaining_time = int(300 - (time.time() - last_attempt_time))
            form.email.errors.append('Too many login attempts. Please try again in ' + str(remaining_time) + ' seconds.')
        elif user and bcrypt.check_password_hash(user.password, form.password.data):
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(form.totp.data):
                login_attempts[email] = {'attempts': 0, 'last_attempt_time': time.time()}
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                time.sleep(0.5)
                form.totp.errors.append('Invalid TOTP. Please try again.')
        else:
            time.sleep(0.5)
            form.email.errors.append('Login Unsuccessful. Please check email and password')
            login_attempts[email]['attempts'] += 1
            login_attempts[email]['last_attempt_time'] = time.time()
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
        cleaned_content = clean_content(form.content.data)
        is_public = (note_type == 'public')
        if form.is_encrypted.data:
            password = form.password.data
            encrypted_content = encrypt_content_with_password(cleaned_content, password)
        else:
            encrypted_content = simple_encrypt(cleaned_content)

        note = Note(title=form.title.data, content=encrypted_content, author=current_user,
                    is_encrypted=form.is_encrypted.data, is_public=is_public,
                    signature=sign_content(encrypted_content, current_user))

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

    if note.is_encrypted:
        flash('Encrypted notes cannot be edited.', 'warning')
        return redirect(url_for('note', note_id=note_id))

    form = NoteForm()
    if form.validate_on_submit():
        cleaned_content = clean_content(form.content.data)
        if form.is_encrypted.data:
            password = form.password.data
            encrypted_content = encrypt_content_with_password(cleaned_content, password)
        else:
            encrypted_content = simple_encrypt(cleaned_content)

        note.title = form.title.data
        note.content = encrypted_content
        note.is_encrypted = form.is_encrypted.data
        note.signature = sign_content(encrypted_content, current_user)

        if note.is_public:
            note.shared_with = []
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
        if note.is_encrypted:
            flash('Please enter the password to decrypt the note.', 'info')
            return redirect(url_for('decrypt_note', note_id=note.id))
        else:
            form.content.data = simple_decrypt(note.content)
        form.is_encrypted.data = note.is_encrypted
        if note.shared_with:
            form.share_with.data = ', '.join([user.username for user in note.shared_with])

    return render_template('create_note.html', title='Update Note', form=form, legend='Update Note')

@app.route("/note/<int:note_id>/decrypt", methods=['GET', 'POST'])
@login_required
def decrypt_note(note_id):
    note = Note.query.get_or_404(note_id)
    form = DecryptNoteForm()
    shared_with_usernames = [user.username for user in note.shared_with]

    if form.validate_on_submit():
        if form.submit.data:
            password = form.password.data
            try:
                decrypted_content = decrypt_content_with_password(note.content, password)
                flash('Note has been decrypted.', 'success')
                return render_template('decrypted_note.html', title=note.title, note=note, content=decrypted_content, shared_with_usernames=shared_with_usernames, form=form)
            except ValueError:
                flash('Incorrect password. Please try again.', 'danger')
        elif form.delete_submit.data:
            if note.author != current_user:
                flash('You do not have permission to delete this note.', 'danger')
            else:
                totp_code = form.totp.data
                if verify_totp(current_user, totp_code):
                    db.session.execute(note_shares.delete().where(note_shares.c.note_id == note_id))
                    db.session.delete(note)
                    db.session.commit()
                    flash('Note has been deleted.', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Invalid TOTP code. Please try again.', 'danger')

    return render_template('decrypt_note.html', form=form, note=note, note_id=note_id)

@app.route("/note/<int:note_id>")
@login_required
def note(note_id):
    note = Note.query.get_or_404(note_id)
    form = EmptyForm()
    shared_with_usernames = [user.username for user in note.shared_with]
    if note.author != current_user and current_user not in note.shared_with and not note.is_public:
        abort(403)
    if note.is_encrypted:
        flash('Please enter the password to decrypt the note.', 'info')
        return redirect(url_for('decrypt_note', note_id=note.id))
    content = simple_decrypt(note.content)
    return render_template('note.html', title=note.title, note=note, content=content, shared_with_usernames=shared_with_usernames, form=form)

@app.route("/note/<int:note_id>/delete", methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)

    try:
        db.session.execute(note_shares.delete().where(note_shares.c.note_id == note.id))
        db.session.commit()
        db.session.delete(note)
        db.session.commit()
        flash('Your note has been deleted!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the note. Please try again.', 'danger')
        print(f"Error: {e}")

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

@app.route("/delete_all_notes", methods=['POST'])
@login_required
def delete_all_notes():
    password = request.form['password']
    totp_code = request.form['totp']
    if bcrypt.check_password_hash(current_user.password, password) and verify_totp(current_user, totp_code):
        notes = Note.query.filter_by(author=current_user).all()
        for note in notes:
            db.session.execute(note_shares.delete().where(note_shares.c.note_id == note.id))
        Note.query.filter_by(author=current_user).delete()
        db.session.commit()
        flash('All your notes have been deleted!', 'success')
    else:
        flash('Invalid password or TOTP code. Please try again.', 'danger')
    return redirect(url_for('about'))

@app.route("/delete_account", methods=['POST'])
@login_required
def delete_account():
    password = request.form['password']
    totp_code = request.form['totp']
    if bcrypt.check_password_hash(current_user.password, password) and verify_totp(current_user, totp_code):
        notes = Note.query.filter_by(author=current_user).all()
        for note in notes:
            db.session.execute(note_shares.delete().where(note_shares.c.note_id == note.id))
        Note.query.filter_by(author=current_user).delete()
        db.session.delete(current_user)
        db.session.commit()
        flash('Your account has been deleted!', 'success')
        return redirect(url_for('home'))
    else:
        flash('Invalid password or TOTP code. Please try again.', 'danger')
    return redirect(url_for('about'))