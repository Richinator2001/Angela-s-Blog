from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

#WTForm
class RegisterForm(FlaskForm):
    username = StringField("Enter Username:", validators=[DataRequired()])
    email = StringField("Enter Email Address:", validators=[DataRequired(), Email()])
    password = PasswordField("Enter your Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    email = StringField('Enter Email Address:', validators=[DataRequired(), Email()])
    password = PasswordField('Enter your Password:', validators=[DataRequired()])
    submit = SubmitField("Submit")

class CommentForm(FlaskForm):
    comment = CKEditorField('Add yor Comment:', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')