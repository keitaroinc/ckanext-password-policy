from ckan.views.user import RegisterView, EditView
import ckan.logic as logic
import ckan.lib.base as base
from flask import Blueprint
import ckan.model as model
from ckan.common import g, request
import ckan.plugins.toolkit as tk


custom_user = Blueprint(u'custom_user', __name__, url_prefix=u'/user')



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


custom_user.add_url_rule(
    u'/register', view_func=RegisterView_.as_view(str(u'register')))

_edit_view = EditView_.as_view(str(u'edit'))
custom_user.add_url_rule(u'/edit', view_func=_edit_view)
custom_user.add_url_rule(u'/edit/<id>', view_func=_edit_view)


def get_blueprints():
    return [custom_user]
