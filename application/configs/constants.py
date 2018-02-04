import sys

IS_TEST = 'test' in sys.argv

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

HTTP_SCHEME = 'http'
HTTPS_SCHEME = 'https'
SCHEME = HTTPS_SCHEME

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': PROJECT_NAME,
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',
        'PORT': '3306',
        'OPTIONS': {
            'charset': 'utf8',
            'init_command': 'SET default_storage_engine=INNODB',
        },
        'TEST': {
            'CHARSET': 'utf8',
            'COLLATION': 'utf8_general_ci'
        }
    }
}

if IS_TEST:
    for db_name in DATABASES:
        DATABASES[db_name] = {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:'
        }
