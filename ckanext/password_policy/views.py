from ckan.views.user import RegisterView, EditView, PerformResetView
# from ckan.lib.repoze_plugins.friendly_form import FriendlyFormPlugin
import ckan.logic as logic
import ckan.plugins as plugins
import ckan.lib.base as base
from flask import Blueprint
import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan.common import _, config, g, request
import ckan.lib.helpers as h
import ckanext.password_policy.helpers as helper
# from webob import Request
# from webob.exc import HTTPFound, HTTPUnauthorized
from six import text_type
from six.moves.urllib.parse import urlencode
# try:
#     from webob.multidict import MultiDict
# except ImportError:
#     from webob import UnicodeMultiDict as MultiDict


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


class PerformResetView_(PerformResetView):
        
    def _get_form_password(self):
        password1 = request.form.get(u'password1')
        password2 = request.form.get(u'password2')

        password_length = config.get('ckanext.password_policy.password_length')
       
        valid_pass = helper.custom_password_check(password1)
        if valid_pass['password_ok']==False:
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


# class FriendlyFormPlugin_(FriendlyFormPlugin):

#     def identify(self, environ):
#         u'''
#         Override the parent's identifier to introduce a login counter
#         (possibly along with a post-login page) and load the login counter into
#         the ``environ``.

#         '''
#         allowed_failes_logins = int(config.get('ckanext.password_policy.failed_logins', 3))
#         request = Request(environ, charset=self.charset)

#         path_info = environ[u'PATH_INFO']
#         script_name = environ.get(u'SCRIPT_NAME') or u'/'
#         query = request.GET
#         if path_info == self.login_handler_path:
#             # We are on the URL where repoze.who processes authentication. #
#             # Let's append the login counter to the query string of the
#             # 'came_from' URL. It will be used by the challenge below if
#             # authorization is denied for this request.
#             form = dict(request.POST)
#             form.update(query)
#             try:
#                 login = form[u'login']
#                 password = form[u'password']
#             except KeyError:
#                 credentials = None
#             else:
#                 if request.charset == u'us-ascii':
#                     credentials = {
#                         u'login': str(login),
#                         u'password': str(password),
#                     }
#                 else:
#                     credentials = {u'login': login, u'password': password}

#             try:
#                 credentials[u'max_age'] = form[u'remember']
#             except KeyError:
#                 pass
#             if helper.user_login_count(login) < allowed_failes_logins:
#                 referer = environ.get(u'HTTP_REFERER', script_name)
#                 destination = form.get(u'came_from', referer)

#                 if self.post_login_url:
#                     # There's a post-login page, so we have to replace the
#                     # destination with it.
#                     destination = self._get_full_path(self.post_login_url,
#                                                     environ)
#                     if u'came_from' in query:
#                         # There's a referrer URL defined, so we have to pass it to
#                         # the post-login page as a GET variable.
#                         destination = self._insert_qs_variable(destination,
#                                                             u'came_from',
#                                                             query[u'came_from'])
#                 failed_logins = self._get_logins(environ, True)
#                 new_dest = self._set_logins_in_url(destination, failed_logins)

#                 environ[u'repoze.who.application'] = HTTPFound(location=new_dest)
#                 return credentials
#             else:
#                 new_dest = 'user/locked'
#                 environ[u'repoze.who.application'] = HTTPFound(location=new_dest)
#                 extra_vars = {}
#                 return extra_vars
                   
#         elif path_info == self.logout_handler_path:
#             #    We are on the URL where repoze.who logs the user out.    #
#             r = Request(environ)
#             params = dict(list(r.GET.items()) + list(r.POST.items()))
#             form = MultiDict(params)
#             form.update(query)
#             referer = environ.get(u'HTTP_REFERER', script_name)
#             came_from = form.get(u'came_from', referer)
#             # set in environ for self.challenge() to find later
#             environ[u'came_from'] = came_from
#             environ[u'repoze.who.application'] = HTTPUnauthorized()
#             return None

#         elif path_info == self.login_form_url or self._get_logins(environ):
#             #  We are on the URL that displays the from OR any other page  #
#             #   where the login counter is included in the query string.   #
#             # So let's load the counter into the environ and then hide it from
#             # the query string (it will cause problems in frameworks like TG2,
#             # where this unexpected variable would be passed to the controller)
#             environ[u'repoze.who.logins'] = self._get_logins(environ, True)
#             # Hiding the GET variable in the environ:
#             if self.login_counter_name in query:
#                 del query[self.login_counter_name]
#                 environ[u'QUERY_STRING'] = urlencode(query, doseq=True)
        

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
