from ckan.views.user import (
    RegisterView, EditView, PerformResetView,
    rotate_token, next_page_or_default
    )
import ckan.logic as logic
import ckan.plugins as plugins
import ckan.lib.base as base
import ckan.lib.authenticator as authenticator
from flask import Blueprint
import ckan.model as model
import ckan.plugins.toolkit as tk
import ckan.lib.helpers as h
import ckanext.password_policy.helpers as helper
from typing import Any, Optional, Union
from ckan.common import (
    _, config, g, current_user, login_user, request
)
from ckan.types import Context, Response, Validator


custom_user = Blueprint(u'custom_user', __name__, url_prefix=u'/user')


def me():
    return h.redirect_to(
        config.get(u'ckan.route_after_login', u'dashboard.index'))


@logic.schema.validator_args
def custom_user_schema(unicode_safe, user_both_passwords_entered,
                       user_passwords_match, user_custom_password_validator):
    schema = logic.schema.user_new_form_schema()

    schema['password1'] = [unicode_safe, user_both_passwords_entered,
                           user_custom_password_validator,
                           user_passwords_match]
    schema['password2'] = []

    return schema


@logic.schema.validator_args
def custom_user_edit_form_schema(
        ignore_missing: Validator, unicode_safe: Validator,
        not_empty: Validator, user_id_or_name_exists: Validator,
        user_custom_password_validator: Validator,
        user_passwords_match: Validator):
    schema = logic.schema.default_user_schema()

    schema["id"] = [not_empty, user_id_or_name_exists, unicode_safe]
    schema['password'] = [ignore_missing]
    schema['password1'] = [ignore_missing, unicode_safe,
                           user_custom_password_validator,
                           user_passwords_match]
    schema['password2'] = [ignore_missing, unicode_safe]

    return schema


class RegisterView_(RegisterView):
    def _prepare(self):
        context = {
            u'model': model,
            u'session': model.Session,
            u'user': g.user,
            u'auth_user_obj': g.userobj,
            u'schema': custom_user_schema(),
            u'save': u'save' in request.form
        }
        try:
            logic.check_access(u'user_create', context)
        except logic.NotAuthorized:
            tk.base.abort(403, tk._(u'Unauthorized to register as a user.'))
        return context


class EditView_(EditView):

    def _prepare(self, id: Optional[str]) -> tuple[Context, str]:
        context: Context = {
            u'save': u'save' in request.form,
            u'schema': custom_user_edit_form_schema(),
            u'user': current_user.name,
            u'auth_user_obj': current_user
        }
        if id is None:
            if current_user.is_authenticated:
                id = current_user.id
            else:
                base.abort(400, _(u'No user specified'))
        assert id
        data_dict = {u'id': id}

        try:
            logic.check_access(u'user_update', context, data_dict)
        except logic.NotAuthorized:
            base.abort(403, _(u'Unauthorized to edit a user.'))
        return context, id


class PerformResetView_(PerformResetView):

    def _get_form_password(self):
        password1 = request.form.get(u'password1')
        password2 = request.form.get(u'password2')

        password_length = config.get('ckanext.password_policy.password_length', 12)

        valid_pass = helper.custom_password_check(password1)
        if valid_pass['password_ok'] is False:
            raise ValueError(
                _(f"u'Your password must be {password_length} characters or '"
                  u'longer and contain uppercase, lowercase, '
                  u'digit and special character'))
        elif password1 != password2:
            raise ValueError(
                _(u'The passwords you entered'
                    u' do not match.'))
        return password1
        msg = _(u'You must provide a password')
        raise ValueError(msg)


def _get_repoze_handler(handler_name):
    u'''Returns the URL that repoze.who will respond to and perform a
    login or logout.'''
    return getattr(request.environ[u'repoze.who.plugins'][u'friendlyform'],
                   handler_name)


def custom_login() -> Union[Response, str]:
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        response = item.login()
        if response:
            return response

    extra_vars: dict[str, Any] = {}

    if current_user.is_authenticated:
        return base.render("user/logout_first.html", extra_vars)

    if request.method == "POST":
        username_or_email = request.form.get("login")
        password = request.form.get("password")
        _remember = request.form.get("remember")

        identity = {
            u"login": username_or_email,
            u"password": password
        }

        allowed_failes_logins = int(config.get('ckanext.password_policy.failed_logins', 3))
        user_obj = authenticator.ckan_authenticator(identity)

        if user_obj and (helper.user_login_count(user_obj.name) < allowed_failes_logins):
            next = request.args.get('next', request.args.get('came_from'))
            if _remember:
                from datetime import timedelta
                duration_time = timedelta(milliseconds=int(_remember))
                login_user(user_obj, remember=True, duration=duration_time)
                rotate_token()
                return next_page_or_default(next)
            else:
                login_user(user_obj)
                rotate_token()
                return next_page_or_default(next)
        else:
            user_redis = model.User.by_name(username_or_email)
            if not user_redis:
                user_redis = model.User.by_email(username_or_email)

            if user_redis:
                login_counter = helper.user_login_count(user_redis.name)
            else:
                login_counter = 0

            if login_counter < allowed_failes_logins:
                if config.get('ckan.recaptcha.privatekey'):
                    err = _(u"Login failed. Bad username or password or CAPTCHA.")
                else:
                    err = _(u"Login failed. Bad username or password.")
                h.flash_error(err)
                return base.render("user/login.html", extra_vars)
            else:
                return base.render("user/locked.html", extra_vars)

    return base.render("user/login.html", extra_vars)


def logged_in():
    # redirect if needed
    came_from = request.params.get(u'came_from', u'')
    if h.url_is_local(came_from):
        return h.redirect_to(str(came_from))
    if g.user:
        return me()
    else:

        err = _(u'Login failed. Bad username or password')
        h.flash_error(err)
        return custom_login()


def locked_user():

    alert = helper.lockout_time()

    extra_vars = {}
    extra_vars['alert'] = alert
    return base.render(u'user/locked.html', extra_vars)


def logout():
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        if g.user:
            helper.clear_login_count(g.user)
        response = item.logout()
        if response:
            return response

    url = h.url_for(u'user.logged_out_page')
    return h.redirect_to(
        _get_repoze_handler(u'logout_handler_path') + u'?came_from=' + url,
        parse_url=True)


custom_user.add_url_rule(
    u'/register', view_func=RegisterView_.as_view(str(u'register')))

_edit_view = EditView_.as_view(str(u'edit'))
custom_user.add_url_rule(u'/edit', view_func=_edit_view)
custom_user.add_url_rule(u'/edit/<id>', view_func=_edit_view)

custom_user.add_url_rule(
    u'/reset/<id>', view_func=PerformResetView_.as_view(str(u'perform_reset')))

custom_user.add_url_rule("/login", view_func=custom_login, methods=("GET", "POST"))
custom_user.add_url_rule(u'/logged_in', view_func=logged_in, methods=("GET", "POST"))

custom_user.add_url_rule(u'/locked', view_func=locked_user, methods=("GET", "POST"))
custom_user.add_url_rule(u'/_logout', view_func=logout)


def get_blueprints():
    return [custom_user]
