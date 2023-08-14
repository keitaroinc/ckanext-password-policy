from ckan.views.user import RegisterView, EditView
import ckan.logic as logic
import ckan.plugins as plugins
import ckan.lib.base as base
from flask import Blueprint
import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan.common import _, config, g, request
import ckan.lib.helpers as h


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

    return schema


@logic.schema.validator_args
def custom_user_edit_form_schema(
        ignore_missing, unicode_safe, user_custom_password_validator,
        user_passwords_match):
    schema = logic.schema.default_user_schema()

    schema['password1'] = [ignore_missing, unicode_safe,
                           user_custom_password_validator,
                           user_passwords_match]

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
    
    def _prepare(self, id):
        context = {
            u'save': u'save' in request.form,
            u'schema': custom_user_edit_form_schema(),
            u'model': model,
            u'session': model.Session,
            u'user': g.user,
            u'auth_user_obj': g.userobj
        }
        if id is None:
            if g.userobj:
                id = g.userobj.id
            else:
                base.abort(400, _(u'No user specified'))
        data_dict = {u'id': id}

        try:
            logic.check_access(u'user_update', context, data_dict)
        except logic.NotAuthorized:
            base.abort(403, _(u'Unauthorized to edit a user.'))
        return context, id


def _get_repoze_handler(handler_name):
    u'''Returns the URL that repoze.who will respond to and perform a
    login or logout.'''
    return getattr(request.environ[u'repoze.who.plugins'][u'friendlyform'],
                   handler_name)


def custom_login():
    # Do any plugin login stuff
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        response = item.login()
        if response:
            return response

    extra_vars = {}
    if g.user:
        return base.render(u'user/logout_first.html', extra_vars)

    came_from = request.params.get(u'came_from')
    if not came_from:
        came_from = h.url_for(u'user.logged_in')
    g.login_handler = h.url_for(
        _get_repoze_handler(u'login_handler_path'), came_from=came_from)
    return base.render(u'user/login.html', extra_vars)


def logged_in():
    # redirect if needed
    came_from = request.params.get(u'came_from', u'')
    if h.url_is_local(came_from):
        return h.redirect_to(str(came_from))

    if g.user:
        return me()
    else:
        err = _(u'Login failed. Bad username or password overwriten.')
        h.flash_error(err)
        return custom_login()


custom_user.add_url_rule(
    u'/register', view_func=RegisterView_.as_view(str(u'register')))

_edit_view = EditView_.as_view(str(u'edit'))
custom_user.add_url_rule(u'/edit', view_func=_edit_view)
custom_user.add_url_rule(u'/edit/<id>', view_func=_edit_view)

custom_user.add_url_rule("/login", view_func=custom_login, methods=("GET", "POST"))
custom_user.add_url_rule(u'/logged_in', view_func=logged_in)


def get_blueprints():
    return [custom_user]
