import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckanext.password_policy.views as views
import ckan.lib.navl.dictization_functions as df
import ckanext.password_policy.helpers as h
from six import string_types
from ckan.common import _, config


Missing = df.Missing
missing = df.missing

password_length = int(config.get('ckanext.password_policy.password_length', 12))


def user_custom_password_validator(key, data, errors, context):
    value = data[key]
    valid_pass = h.custom_password_check(value)

    if isinstance(value, Missing):
        pass
    elif not isinstance(value, string_types):
        errors[('password',)].append(_('Passwords must be strings'))
    elif value == '':
        pass
    elif not valid_pass['password_ok']:
        errors[('password',)].append('Your password must be 12 characters or longer and contain uppercase, lowercase, digit and special character')

     
class PasswordPolicyPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer) 
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic',
            'password_policy')
        
    def get_validators(self):
        return {'user_custom_password_validator': user_custom_password_validator}
    
    def get_blueprint(self):
        return views.get_blueprints()


