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

    # Configurações do SQL Server
    SQL_SERVER = os.getenv('SQL_SERVER', '172.16.136.55')
    SQL_DATABASE = os.getenv('SQL_DATABASE', 'DW_GMO')
    SQL_USERNAME = os.getenv('SQL_USERNAME', 'BI_GMO')
    SQL_PASSWORD = os.getenv('SQL_PASSWORD', 'GMOBI#2022')
    SQL_DRIVER = os.getenv('SQL_DRIVER', 'ODBC Driver 17 for SQL Server')

    # String de conexão para o SQL Server
    SQL_SERVER_URI = f"mssql+pyodbc://{SQL_USERNAME}:{SQL_PASSWORD}@{SQL_SERVER}/{SQL_DATABASE}?driver={SQL_DRIVER.replace(' ', '+')}"

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