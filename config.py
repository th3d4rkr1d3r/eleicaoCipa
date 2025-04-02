import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'chave_secreta_padrao')
    DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///instance/eleicao_cipa.db')