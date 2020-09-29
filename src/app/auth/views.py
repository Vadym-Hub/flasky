from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, \
    current_user
from .. import db
from . import auth
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm


@auth.before_app_request
def before_request():
    """
    Декоратор before_app_request перехватит запрос
    при выполнении всех трех условий
    """
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint \
            and request.blueprint != 'auth' \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    """Фильтрует подтвержденные аккаунты"""
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Вход в аккаунт"""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Неверный email или password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    """Выход из аккаунта"""
    logout_user()
    flash('Вы вышли с аккаунта.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация аккаунта"""
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Подтвердите ваш аккаунт',
                   'auth/email/confirm', user=user, token=token)
        flash('Письмо с подтверждением было отправлено на ваш email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    """Подтверждение аккаунта"""
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('Вы подтвердили свою аккаунт. Спасибо!')
    else:
        flash('Ссылка для подтверждения недействительна или срок ее действия истек.')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    """Отправка email для подтверждения аккаунта"""
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Подтвердите свой аккаунт',
               'auth/email/confirm', user=current_user, token=token)
    flash('Вам было отправлено новое письмо с подтверждением по email.')
    return redirect(url_for('main.index'))
