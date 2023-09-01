# CKAN password policy 

CKAN extension that adds password policy for all the users. With this extension You can set up minimum password length and password complexity (password must consist capital and small letters, number and special characters). A user lock on defined time period after x number of failed logins is also implemented


## Requirements

Compatibility with core CKAN versions:

| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.6 and earlier | not tested    |
| 2.7             | not tested    |
| 2.8             | not tested    |
| 2.9             | Yes    |



## Installation

To install ckanext-password-policy:

1. Activate your CKAN virtual environment, for example:

     . /usr/lib/ckan/default/bin/activate

2. Clone the source and install it on the virtualenv

   ``` 
    git clone https://github.com/Keitaro/ckanext-password-policy.git
    cd ckanext-password-policy
    pip install -e .
    pip install -r requirements.txt
   ``` 

3. Add `password_policy` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

     sudo service apache2 reload


## Config settings

1. The following setting needs to be done in who.ini
	
   	```
	[plugin:friendlyform]
	use = ckanext.password_policy.views:FriendlyFormPlugin_
  	```


2. These are the settings for production.ini

   	```
	Minimum length of the user password. Default is 12
	ckan.password_policy.password_length = 12

	Number of failed logins before the user is locked. Default is 3
 	ckan.password_policy.failed_logins = 3

	Time after the locked user is allowed to log in again in seconds. Default is 600 
	ckan.password_policy.user_locked_time = 600
	```



## Developer installation

To install ckanext-password-policy for development, activate your CKAN virtualenv and
do:

    git clone https://github.com/Keitaro/ckanext-password-policy.git
    cd ckanext-password-policy
    python setup.py develop
    pip install -r dev-requirements.txt


## Tests

To run the tests, do:

    pytest --ckan-ini=test.ini


## Releasing a new version of ckanext-password-policy

If ckanext-password-policy should be available on PyPI you can follow these steps to publish a new version:

1. Update the version number in the `setup.py` file. See [PEP 440](http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers) for how to choose version numbers.

2. Make sure you have the latest version of necessary packages:

    pip install --upgrade setuptools wheel twine

3. Create a source and binary distributions of the new version:

       python setup.py sdist bdist_wheel && twine check dist/*

   Fix any errors you get.

4. Upload the source distribution to PyPI:

       twine upload dist/*

5. Commit any outstanding changes:

       git commit -a
       git push

6. Tag the new release of the project on GitHub with the version number from
   the `setup.py` file. For example if the version number in `setup.py` is
   0.0.1 then do:

       git tag 0.0.1
       git push --tags

## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
