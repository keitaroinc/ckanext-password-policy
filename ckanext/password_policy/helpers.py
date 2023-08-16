import re
from ckan.lib.redis import connect_to_redis
import ckan.plugins.toolkit as tk


def user_login_count(username):
    redis_conn = connect_to_redis()
    user_cached = redis_conn.get(username)
    if user_cached == None:
        print('user will be cached in redis')
        redis_conn.set(username, 1, ex=600)
    else:
        print('user allready cached in redis, incrementing')
        redis_conn.incr(username)

    failed_logins_count = int(redis_conn.get(username))
    print(failed_logins_count)

    return failed_logins_count


# def user_login_count(username):
#     redis_conn = connect_to_redis()
#     user_cached = redis_conn.get(username)
#     if user_cached == None:
#         print('user will be cached in redis')
#         redis_conn.set(username, 1, ex=600)
#     else:
#         print('user allready cached in redis, incrementing')
#         redis_conn.incr(username)

#     failed_logins_count = int(redis_conn.get(username))
#     print(failed_logins_count)
#     if failed_logins_count < 3:
#         return failed_logins_count
#     else:
#         return tk.redirect_to("password_policy.locked")

def custom_password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        12 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 12

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }