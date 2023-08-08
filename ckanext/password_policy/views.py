from ckan.views.user import RegisterView
import ckan.logic as logic
from flask import Blueprint
import ckan.model as model
from ckan.common import g, request
import ckan.plugins.toolkit as tk



custom_user = Blueprint(u'custom_user', __name__, url_prefix=u'/user')

@logic.schema.validator_args
def custom_user_schema(unicode_safe, user_both_passwords_entered, user_passwords_match, user_custom_password_validator):
    schema = logic.schema.user_new_form_schema()
     
    schema['password1'] = [unicode_safe, user_both_passwords_entered,
                            user_custom_password_validator, user_passwords_match]

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

custom_user.add_url_rule(
    u'/register', view_func=RegisterView_.as_view(str(u'register')))

def get_blueprints():
    return [custom_user]


                                                      