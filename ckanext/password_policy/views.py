
import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for
from six import text_type

import ckan.lib.authenticator as authenticator
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.logic as logic
import ckan.model as model
import ckan.plugins.toolkit as tk
import ckanext.password_policy.helpers as helper
from ckan.common import config, login_user, logout_user
from ckan.views.user import EditView, PerformResetView, RegisterView
from flask_login import current_user, login_required, login_user, logout_user

log = logging.getLogger(__name__)


custom_user = Blueprint('custom_user', __name__, url_prefix='/user')


def me():
    return h.redirect_to(
        config.get('ckan.route_after_login', 'dashboard.index'))


@logic.schema.validator_args
def custom_user_schema(unicode_safe, user_both_passwords_entered,
                       user_passwords_match, user_custom_password_validator):
    schema = logic.schema.user_new_form_schema()

    schema['password1'] = [unicode_safe, user_both_passwords_entered,
                           user_custom_password_validator,
                           user_passwords_match]
    schema['password2'] = [text_type]

    return schema


@logic.schema.validator_args
def custom_user_edit_form_schema(
        ignore_missing, unicode_safe, user_custom_password_validator,
        user_passwords_match):
    schema = logic.schema.default_user_schema()

    schema['password1'] = [ignore_missing, unicode_safe,
                           user_custom_password_validator,
                           user_passwords_match]
    schema['password2'] = [ignore_missing, unicode_safe]

    return schema


class RegisterView_(RegisterView):
    def _prepare(self):
        context = {
            'model': model,
            'session': model.Session,
            'user': current_user.name if current_user.is_authenticated else None,
            'auth_user_obj': getattr(current_user, 'user', None),
            'schema': custom_user_schema(),
            'save': 'save' in request.form
        }
        try:
            logic.check_access('user_create', context)
        except logic.NotAuthorized:
            tk.base.abort(403, tk._('Unauthorized to register as a user.'))
        return context


class EditView_(EditView):

    def _prepare(self, id):
        context = {
            'save': 'save' in request.form,
            'schema': custom_user_edit_form_schema(),
            'model': model,
            'session': model.Session,
            'user': current_user.name if current_user.is_authenticated else None,
            'auth_user_obj': getattr(current_user, 'user', None)
        }
        if not id:
            if current_user.is_authenticated:
                id = current_user.id
            else:
                base.abort(400, tk._('No user specified'))
        data_dict = {'id': id}
        try:
            logic.check_access('user_update', context, data_dict)
        except logic.NotAuthorized:
            base.abort(403, tk._('Unauthorized to edit a user.'))
        return context, id


class PerformResetView_(PerformResetView):

    def _get_form_password(self):
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if not password1 or not password2:
            msg = tk._('You must provide a password')
            raise ValueError(msg)

        password_length = helper.get_password_length()

        valid_pass = helper.custom_password_check(password1)
        if not valid_pass['password_ok']:
            raise ValueError(helper.requirements_message(password_length))
        elif password1 != password2:
            raise ValueError(
                tk._('The passwords you entered'
                    ' do not match.'))
        return password1

@custom_user.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.datasets'))

    if request.method == 'POST':
        username = request.form.get('login')
        password = request.form.get('password')

        if helper.user_locked_out(username):
            flash(helper.lockout_message(), 'error')
            return redirect(url_for('custom_user.locked'))

        identity = {
            u"login": username,
            u"password": password
        }

        user_obj = authenticator.ckan_authenticator(identity)

        if user_obj:
            login_user(user_obj)
            helper.clear_login_count(username)
            return redirect(
                request.args.get('next') or url_for('dashboard.datasets'))
        else:
            helper.increment_user_login_count(username)
            flash(tk._('Login failed. Bad username or password.'), 'error')

            if helper.user_locked_out(username):
                return redirect(url_for('custom_user.locked'))

    return render_template('user/login.html')


@custom_user.route('/locked')
def locked():
    alert = helper.lockout_message()
    return render_template('user/locked.html', alert=alert)


@custom_user.route('/logout')
@login_required
def logout():
    helper.clear_login_count(current_user.name)
    logout_user()
    return redirect(url_for('custom_user.login'))


@custom_user.route('/reset_login/<username>', methods=['POST'])
def reset_login(username):
    log.info("Re-enabling login for user {}".format(username))
    helper.clear_login_count(username)
    flash(tk._('User login re-enabled'), 'success')
    return redirect(url_for('user.read', id=username))


custom_user.add_url_rule('/register', view_func=RegisterView_.as_view('register'))
_edit_view = EditView_.as_view('edit')
custom_user.add_url_rule('/edit', view_func=_edit_view)
custom_user.add_url_rule('/edit/<id>', view_func=_edit_view)
custom_user.add_url_rule('/reset/<id>', view_func=PerformResetView_.as_view('perform_reset'))


def get_blueprints():
    return [custom_user]
