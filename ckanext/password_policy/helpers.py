import re
from ckan.lib.redis import connect_to_redis
from ckan.common import config


def user_login_count(username):
    redis_conn = connect_to_redis()
    user_cached = redis_conn.get(username)
    if user_cached == None:
        expiry = config.get('ckan.password_policy.user_locked_time', 600)
        # user will be cached in redis with count 1
        redis_conn.set(username, 1, ex=expiry)
    else:
        # user allready cached in redis, incrementing login count
        redis_conn.incr(username)

    failed_logins_count = int(redis_conn.get(username))
    print(failed_logins_count)

    return failed_logins_count


def clear_login_count(username):

    redis_conn = connect_to_redis()
    redis_conn.delete(username)
    return None


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
    password_length = int(config.get('ckan.password_policy.password_length', 12))
    # calculating the length
    length_error = len(password) < password_length

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