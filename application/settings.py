from split_settings.tools import optional, include

PROJECT_NAME = 'enigma'

include(
    'configs/constants.py',
    optional('configs/local_constants.py'),

    'configs/settings.py',
    optional('configs/local_settings.py'),
)
