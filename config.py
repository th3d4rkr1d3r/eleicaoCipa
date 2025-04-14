import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'uma_chave_secreta_aleatoria_muito_longa')
    DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///eleicao_cipa.db')
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', 'outra_chave_secreta_aleatoria_csrf')
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 12
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
        },
        'handlers': {
            'file': {
                'class': 'logging.FileHandler',
                'filename': 'eleicao_cipa.log',
                'formatter': 'standard'
            },
        },
        'root': {
            'handlers': ['file'],
            'level': 'INFO',
        }
    }