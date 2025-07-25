from six import string_types

import ckan.lib.navl.dictization_functions as df
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
import ckanext.password_policy.helpers as h
import ckanext.password_policy.views as views
from ckan.model import User as CKANModelUser
from flask_login import LoginManager, UserMixin

Missing = df.Missing
missing = df.missing


def user_custom_password_validator(key, data, errors, context):
    value = data[key]
    username = data.get(("name",))
    user_fullname = data.get(("fullname",))

    valid_pass = h.custom_password_check(value, username, user_fullname)
    password_length = h.get_password_length(username)

    if isinstance(value, Missing):
        pass
    elif not isinstance(value, string_types):
        errors[("password",)].append(tk._("Passwords must be strings"))
    elif value == "":
        pass
    elif not valid_pass["password_ok"]:
        errors[("password",)].append(h.requirements_message(password_length))


# Wrapper class for flask-login
class CKANUser(UserMixin):
    def __init__(self, user: CKANModelUser):
        self.id = str(user.id)
        self.name = user.name
        self.email = user.email
        self.sysadmin = user.sysadmin


class PasswordPolicyPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.ITemplateHelpers)

    # IConfigurer

    def update_config(self, config_):
        # Templates and static
        tk.add_template_directory(config_, "templates")
        tk.add_public_directory(config_, "public")
        tk.add_resource("assets", "password_policy")

        # Initialize Flask-Login
        login_manager = LoginManager()
        app = config_.get("app") or tk.config.get("flask_app")
        if app:
            login_manager.init_app(app)
            login_manager.login_view = "password_policy.login"

            @login_manager.user_loader
            def load_user(user_id):
                user = CKANModelUser.get(user_id)
                if user:
                    return CKANUser(user)
                return None

    def get_validators(self):
        return {"user_custom_password_validator": user_custom_password_validator}

    def get_blueprint(self):
        return views.get_blueprints()

    def get_helpers(self):
        return {
            "get_user_login_count": h.get_user_login_count,
            "lockout_message": h.lockout_message,
            "requirements_message": h.requirements_message,
            "user_locked_out": h.user_locked_out,
        }
