from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Regexp, Length, Email, EqualTo, ValidationError
from yourpackage.models import User

class RegistrationForm(FlaskForm):

    username = StringField('Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(min=2, max=20, message='Username must be between 2 and 20 characters')
        ])
    email = StringField('Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Invalid email address')
        ])
    password = PasswordField('Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, message='Password must be at least 8 characters long'),
            Regexp(r'(?=.*[A-Z])', message='Password must contain at least one uppercase letter'),
            Regexp(r'(?=.*[a-z])', message='Password must contain at least one lowercase letter'),
            Regexp(r'(?=.*\d)', message='Password must contain at least one digit'),
            Regexp(r'(?=.*[@$!%*?&#])', message='Password must contain at least one special character')
        ])
    confirm_password = PasswordField('Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ])
    submit = SubmitField('Sign Up')
    '''
    username = StringField('Username')
    email = StringField('Email')
    password = PasswordField('Password')
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Sign Up')
    '''
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Invalid email address')
        ])
    password = PasswordField('Password',
        validators=[
            DataRequired(message='Password is required')
        ])
    totp = StringField('TOTP',
        validators=[
            DataRequired(message='TOTP is required')
        ])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    is_encrypted = BooleanField('Encrypt Note')
    password = PasswordField('Encryption Password')
    share_with = StringField('Share with (comma separated usernames)')
    submit = SubmitField('Post')


from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField

class DecryptNoteForm(FlaskForm):
    password = PasswordField('Encryption Password')
    totp = StringField('TOTP Code')
    submit = SubmitField('Decrypt Note')
    delete_submit = SubmitField('Delete Note')