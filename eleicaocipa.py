from flask import Flask, render_template, request, redirect, flash, url_for, session, abort, send_file, jsonify, make_response, Response
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from functools import wraps
import sqlite3
import os
import threading
import hashlib
import io
import csv
from playsound import playsound
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
from config import Config
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired
import pytz
from helpers import converter_para_brasil, formatar_data_brasil
import time
from werkzeug.utils import secure_filename
import getpass
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

fuso_brasil = pytz.timezone('America/Sao_Paulo')
data_local = datetime.now(fuso_brasil)

# Configuração da conexão com o SQL Server
SQL_SERVER_ENGINE = create_engine(Config.SQL_SERVER_URI)
SQL_Session = sessionmaker(bind=SQL_SERVER_ENGINE)

# Inicialização do aplicativo Flask
app = Flask(__name__)
app.config.from_object(Config)

# Configurações de upload
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'candidatos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Configure o logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuração do fuso horário
TZ_BRASIL = pytz.timezone('America/Sao_Paulo')


def to_brasil_time(utc_dt):
    """Converte datetime UTC para horário de Brasília"""
    if utc_dt is None:
        return None
    if isinstance(utc_dt, str):
        utc_dt = datetime.strptime(utc_dt, '%Y-%m-%d %H:%M:%S')
    if utc_dt.tzinfo is None:
        utc_dt = pytz.utc.localize(utc_dt)
    return utc_dt.astimezone(TZ_BRASIL)


def format_brasil_datetime(dt):
    """Formata datetime no padrão brasileiro"""
    if dt is None:
        return "N/A"
    return dt.strftime('%d/%m/%Y %H:%M')


# Extensões
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Configuração de logging
handler = RotatingFileHandler('eleicao_cipa.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {
        'options': '-c timezone=America/Sao_Paulo'
    }
}


# Forms
class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')


class EleicaoForm(FlaskForm):
    titulo = StringField('Título', validators=[DataRequired()])
    descricao = TextAreaField('Descrição')
    data_inicio = StringField('Data de Início', validators=[DataRequired()])
    data_fim = StringField('Data de Término', validators=[DataRequired()])
    submit = SubmitField('Salvar')


class FilialForm(FlaskForm):
    nome = StringField('Nome da Filial', validators=[DataRequired()])
    eleicao_id = SelectField('Eleição', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Salvar')


# Modelos
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    nivel = db.Column(db.String(20), nullable=False, default='user')
    ativo = db.Column(db.Boolean, default=True)
    ultimo_login = db.Column(db.DateTime)
    tentativas_login = db.Column(db.Integer, default=0)
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Usuario {self.username}>'


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    expiracao = db.Column(db.DateTime, nullable=False)
    usado = db.Column(db.Boolean, default=False)
    usuario = db.relationship('Usuario', backref='tokens_reset')


class Eleicao(db.Model):
    __tablename__ = 'eleicoes'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text)
    data_inicio = db.Column(db.DateTime, nullable=False)
    data_fim = db.Column(db.DateTime, nullable=False)
    ativa = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())

    filiais = db.relationship('Filial', backref='eleicao', lazy=True)

    def __repr__(self):
        return f'<Eleicao {self.titulo}>'


class Filial(db.Model):
    __tablename__ = 'filiais'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    eleicao_id = db.Column(db.Integer, db.ForeignKey('eleicoes.id'), nullable=False)  # Esta linha é crucial
    ativa = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Filial {self.nome}>'


class Candidato(db.Model):
    __tablename__ = 'candidatos'
    id = db.Column(db.Integer, primary_key=True)
    filial_id_seq = db.Column(db.Integer, nullable=False, default=1)
    nome = db.Column(db.String(100), nullable=False)
    filial_id = db.Column(db.Integer, db.ForeignKey('filiais.id'), nullable=False)
    eleicao_id = db.Column(db.Integer, db.ForeignKey('eleicoes.id'), nullable=False)
    ativa = db.Column(db.Boolean, default=True)
    foto = db.Column(db.String(255))
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())
    filial = db.relationship('Filial', backref='candidatos')
    eleicao = db.relationship('Eleicao', backref='candidatos')

    __table_args__ = (
        db.UniqueConstraint('filial_id', 'filial_id_seq', 'eleicao_id', name='_filial_id_seq_eleicao_uc'),
    )

    def __repr__(self):
        return f'<Candidato {self.nome} (Filial ID: {self.filial_id}, Seq: {self.filial_id_seq}, Eleição: {self.eleicao_id})>'

    @classmethod
    def proximo_id_filial(cls, filial_id, eleicao_id):
        """Retorna o próximo ID sequencial para a filial e eleição especificadas"""
        max_id = db.session.query(db.func.max(cls.filial_id_seq)).filter_by(filial_id=filial_id,
                                                                            eleicao_id=eleicao_id).scalar()
        return 1 if max_id is None else max_id + 1


class Voto(db.Model):
    __tablename__ = 'votos'
    id = db.Column(db.Integer, primary_key=True)
    cpf = db.Column(db.String(11), nullable=False)
    nome = db.Column(db.String(100), nullable=False)  # Novo campo
    filial_id = db.Column(db.Integer, db.ForeignKey('filiais.id'), nullable=False)
    candidato_id = db.Column(db.Integer, db.ForeignKey('candidatos.id'), nullable=False)
    eleicao_id = db.Column(db.Integer, db.ForeignKey('eleicoes.id'), nullable=False)
    data_voto = db.Column(db.DateTime, default=db.func.current_timestamp())
    filial = db.relationship('Filial', backref='votos')
    candidato = db.relationship('Candidato', backref='votos')
    eleicao = db.relationship('Eleicao', backref='votos')

    __table_args__ = (
        db.UniqueConstraint('cpf', 'eleicao_id', name='_cpf_eleicao_uc'),
    )

    def __repr__(self):
        return f'<Voto {self.cpf} (Eleição: {self.eleicao_id})>'


class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    acao = db.Column(db.String(255), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True)
    ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    url = db.Column(db.String(255))
    data = db.Column(db.DateTime, default=db.func.current_timestamp())
    usuario = db.relationship('Usuario', backref='logs')

    def __repr__(self):
        return f'<Log {self.acao}>'


# Funções auxiliares
def registrar_log(acao, usuario_id=None):
    try:
        log = Log(
            acao=acao,
            usuario_id=usuario_id,
            ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            url=request.url
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Erro ao registrar log: {str(e)}")


def tocar_som():
    try:
        caminho_som = os.path.join(app.static_folder, "urna.mp3")
        if os.path.exists(caminho_som):
            threading.Thread(target=playsound, args=(caminho_som,)).start()
    except Exception as e:
        app.logger.error(f"Erro ao reproduzir som: {str(e)}")


def validar_cpf(cpf):
    cpf = ''.join(filter(str.isdigit, cpf))
    if len(cpf) != 11:
        return (False, "CPF deve conter 11 dígitos")
    if all(d == cpf[0] for d in cpf):
        return (False, "CPF inválido (números repetidos)")

    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digito1 = (soma * 10) % 11
    digito1 = digito1 if digito1 < 10 else 0
    if digito1 != int(cpf[9]):
        return (False, "CPF inválido (dígito verificador incorreto)")

    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digito2 = (soma * 10) % 11
    digito2 = digito2 if digito2 < 10 else 0
    if digito2 != int(cpf[10]):
        return (False, "CPF inválido (dígito verificador incorreto)")

    return (True, "CPF válido")


def verificar_cpf_funcionario(cpf, filial_nome):
    """Verifica se o CPF existe na tabela de funcionários e pertence à filial correta"""
    try:
        session = SQL_Session()

        # Extrai apenas o nome principal da filial (antes do '-') para comparação
        filial_base = filial_nome.split('-')[0].strip().upper()

        # Determinar o grupo da filial selecionada
        if filial_base.startswith('GMO'):
            grupo_filial = 'GMO'
        elif filial_base.startswith('PAC'):
            grupo_filial = 'PAC'
        elif filial_base.startswith('POLY'):
            grupo_filial = 'POLY'
        else:
            grupo_filial = None

        query = text("""
        SELECT RA_CIC, RA_NOME, RA_FILIAL 
        FROM VIW_CIPA_CPF 
        WHERE RA_CIC = :cpf
        """)

        result = session.execute(query, {'cpf': cpf}).fetchone()
        session.close()

        if not result:
            return False, "CPF não encontrado"

        # Determinar o grupo do funcionário
        funcionario_filial = result.RA_FILIAL.strip().upper()
        if funcionario_filial.startswith('GMO'):
            grupo_funcionario = 'GMO'
        elif funcionario_filial.startswith('PAC'):
            grupo_funcionario = 'PAC'
        elif funcionario_filial.startswith('POLY'):
            grupo_funcionario = 'POLY'
        else:
            grupo_funcionario = None

        # Verificar se os grupos são compatíveis
        if grupo_filial and grupo_funcionario and grupo_filial == grupo_funcionario:
            return True, result.RA_NOME
        else:
            return False, f"Funcionário pertence a {grupo_funcionario} e não pode votar em {grupo_filial}"

    except Exception as e:
        app.logger.error(f"Erro ao verificar CPF no banco de dados: {str(e)}")
        return False, f"Erro ao verificar CPF: {str(e)}"


# Decorators
def login_required(level="user"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                registrar_log("Tentativa de acesso não autenticada")
                return redirect(url_for('login', next=request.url))

            usuario = Usuario.query.get(session['user_id'])
            if not usuario or not usuario.ativo:
                session.clear()
                registrar_log("Tentativa de acesso com usuário inativo")
                flash("Sua conta está desativada", "danger")
                return redirect(url_for('login'))

            access_levels = ["admin", "operador", "user"]
            if access_levels.index(usuario.nivel) > access_levels.index(level):
                registrar_log(f"Tentativa de acesso não autorizado - Nível necessário: {level}", usuario.id)
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Rotas
@app.route('/')
def index():
    try:
        # Obter todas eleições ativas (dentro do período válido)
        agora = datetime.now(fuso_brasil)
        eleicoes_ativas = Eleicao.query.filter(
            Eleicao.ativa == True,
            Eleicao.data_inicio <= agora,
            Eleicao.data_fim >= agora
        ).order_by(Eleicao.data_inicio.desc()).all()

        if not eleicoes_ativas:
            flash("Não há eleições ativas no momento", "info")
            return render_template("index.html",
                               filiais=[],
                               candidatos=[],
                               eleicoes_ativas=[],
                               eleicao_ativa=None)

        # Verificar se há parâmetro de eleição na URL
        eleicao_id = request.args.get('eleicao')
        if eleicao_id:
            try:
                eleicao_id = int(eleicao_id)
                eleicao_ativa = next((e for e in eleicoes_ativas if e.id == eleicao_id), eleicoes_ativas[0])
            except ValueError:
                eleicao_ativa = eleicoes_ativas[0]
        else:
            eleicao_ativa = eleicoes_ativas[0]

        # Consulta para filiais ativas da eleição selecionada
        filiais = Filial.query.filter_by(
            eleicao_id=eleicao_ativa.id,
            ativa=True
        ).order_by(Filial.nome).all()

        # Consulta para candidatos ativos da eleição selecionada
        candidatos = Candidato.query.filter(
            Candidato.ativa == True,
            Candidato.eleicao_id == eleicao_ativa.id
        ).join(Filial).filter(
            Filial.ativa == True
        ).order_by(Filial.nome, Candidato.filial_id_seq).all()

        return render_template("index.html",
                           filiais=filiais,
                           candidatos=candidatos,
                           eleicao_ativa=eleicao_ativa,
                           eleicoes_ativas=eleicoes_ativas)

    except Exception as e:
        app.logger.error(f"Erro na página inicial: {str(e)}", exc_info=True)
        flash("Erro ao carregar a página de votação", "danger")
        return render_template("index.html",
                           filiais=[],
                           candidatos=[],
                           eleicoes_ativas=[],
                           eleicao_ativa=None)


@app.route('/votar', methods=['POST'])
@csrf.exempt
def votar():
    cpf = request.form["cpf"].strip()
    nome = request.form["nome"].strip()
    filial_id = request.form["filial"].strip()
    candidato_id = request.form["candidato"].strip()
    eleicao_id = request.form.get("eleicao_id", "").strip()

    if not all([cpf, nome, filial_id, candidato_id, eleicao_id]):
        flash("Todos os campos são obrigatórios!", "danger")
        return redirect(url_for("index"))
        # Obter o nome da filial selecionada
    filial = Filial.query.get(filial_id)
    if not filial:
        flash("Filial inválida!", "danger")
        return redirect(url_for("index"))

    # Verificar se o CPF é de um funcionário do grupo correto
    cpf_cadastrado, mensagem = verificar_cpf_funcionario(cpf, filial.nome)
    if not cpf_cadastrado:
        flash(f"Erro: {mensagem}", "danger")
        return redirect(url_for("index"))

    # Validação do CPF
    cpf_valido, mensagem = validar_cpf(cpf)
    if not cpf_valido:
        flash(f"Erro: {mensagem}", "danger")
        return redirect(url_for("index"))

    # Obter o nome da filial selecionada
    filial = Filial.query.get(filial_id)
    if not filial:
        flash("Filial inválida!", "danger")
        return redirect(url_for("index"))

    # Verificar se o CPF é de um funcionário da filial
    cpf_cadastrado, mensagem = verificar_cpf_funcionario(cpf, filial.nome)
    if not cpf_cadastrado:
        flash(f"Erro: {mensagem}", "danger")
        return redirect(url_for("index"))

    try:
        # Verificar se o CPF já votou nesta eleição
        if Voto.query.filter_by(cpf=cpf, eleicao_id=eleicao_id).first():
            flash("Este CPF já votou nesta eleição! Cada pessoa pode votar apenas uma vez por eleição.", "warning")
            return redirect(url_for("index"))

        novo_voto = Voto(
            cpf=cpf,
            nome=nome,
            filial_id=filial_id,
            candidato_id=candidato_id,
            eleicao_id=eleicao_id,
            data_voto=datetime.utcnow()  # Usar UTC para armazenamento interno
        )

        db.session.add(novo_voto)
        db.session.commit()

        registrar_log(f"Voto registrado na eleição {eleicao_id}", session.get('user_id'))
        flash("Voto registrado com sucesso!", "success")
        tocar_som()
    except Exception as e:
        db.session.rollback()
        registrar_log(f"Erro ao registrar voto: {str(e)}")
        flash(f"Erro ao registrar voto: {str(e)}", "danger")

    return redirect(url_for("index"))


@app.route('/resultados')
@login_required(level="user")
def resultados():
    def converter_para_brasil(dt):
        """Converte datetime UTC para horário de Brasília"""
        if dt is None:
            return None
        if isinstance(dt, str):
            dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        return dt.astimezone(pytz.timezone('America/Sao_Paulo'))

    def formatar_data_brasil(dt):
        """Formata datetime no padrão brasileiro"""
        if dt is None:
            return "N/A"
        return dt.strftime('%d/%m/%Y %H:%M')

    eleicao_id = request.args.get('eleicao', '')
    filial_filtro = request.args.get('filial', 'Todas Filiais')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    # Obter todas as eleições para o dropdown
    eleicoes = Eleicao.query.order_by(Eleicao.data_inicio.desc()).all()

    if not eleicao_id and eleicoes:
        eleicao_id = eleicoes[0].id

    # Query principal incluindo a foto do candidato
    query = db.session.query(
        Candidato.nome,
        Candidato.foto,
        db.func.count(Voto.id).label('votos'),
        db.func.max(Voto.data_voto).label('ultimo_voto')
    ).join(Voto, Voto.candidato_id == Candidato.id
           ).join(Filial, Voto.filial_id == Filial.id
                  ).join(Eleicao, Voto.eleicao_id == Eleicao.id)

    # Aplicar filtros
    if eleicao_id:
        query = query.filter(Eleicao.id == eleicao_id)
    if filial_filtro != 'Todas Filiais':
        query = query.filter(Filial.nome == filial_filtro)
    if data_inicio:
        query = query.filter(db.func.date(Voto.data_voto) >= data_inicio)
    if data_fim:
        query = query.filter(db.func.date(Voto.data_voto) <= data_fim)

    resultados_raw = query.group_by(Candidato.nome, Candidato.foto).order_by(db.desc('votos')).all()

    resultados = []
    for nome, foto, votos, ultimo_voto in resultados_raw:
        dt_brasil = converter_para_brasil(ultimo_voto)
        resultados.append((
            nome,
            votos,
            formatar_data_brasil(dt_brasil),
            foto
        ))

    # Query para detalhes dos votos - mantenha como estava originalmente
    detalhes_query = db.session.query(
        Voto.id,
        Voto.cpf,
        Voto.nome,
        Filial.nome.label('filial'),
        Candidato.nome.label('candidato'),
        Voto.data_voto
    ).join(Candidato, Voto.candidato_id == Candidato.id
           ).join(Filial, Voto.filial_id == Filial.id
                  ).join(Eleicao, Voto.eleicao_id == Eleicao.id)

    # Aplicar filtros
    if eleicao_id:
        detalhes_query = detalhes_query.filter(Eleicao.id == eleicao_id)
    if filial_filtro != 'Todas Filiais':
        detalhes_query = detalhes_query.filter(Filial.nome == filial_filtro)
    if data_inicio:
        detalhes_query = detalhes_query.filter(db.func.date(Voto.data_voto) >= data_inicio)
    if data_fim:
        detalhes_query = detalhes_query.filter(db.func.date(Voto.data_voto) <= data_fim)

    # Processar detalhes dos votos (mantenha como tuplas)
    detalhes_votos = []
    for voto_id, cpf, nome, filial, candidato, data_voto in detalhes_query.order_by(Voto.data_voto.desc()).all():
        # Converter explicitamente para o fuso do Brasil
        if data_voto.tzinfo is None:
            data_voto = pytz.utc.localize(data_voto)  # Assumir UTC se não tiver timezone
        dt_brasil = data_voto.astimezone(pytz.timezone('America/Sao_Paulo'))

        detalhes_votos.append((
            cpf,
            nome,
            filial,
            candidato,
            formatar_data_brasil(dt_brasil),
            voto_id
        ))

    # Calcular total de votos
    total_query = db.session.query(db.func.count(Voto.id)).join(Eleicao, Voto.eleicao_id == Eleicao.id)
    if eleicao_id:
        total_query = total_query.filter(Eleicao.id == eleicao_id)
    if filial_filtro != 'Todas Filiais':
        total_query = total_query.join(Filial, Voto.filial_id == Filial.id).filter(Filial.nome == filial_filtro)
    if data_inicio:
        total_query = total_query.filter(db.func.date(Voto.data_voto) >= data_inicio)
    if data_fim:
        total_query = total_query.filter(db.func.date(Voto.data_voto) <= data_fim)

    total_votos = total_query.scalar() or 0

    # Obter lista de filiais para o dropdown
    filiais = [f[0] for f in db.session.query(Filial.nome).filter_by(eleicao_id=eleicao_id).all()] if eleicao_id else []

    return render_template(
        "resultados.html",
        resultados=resultados,  # Dados agregados
        detalhes_votos=detalhes_votos,  # Dados detalhados
        filiais=filiais,
        eleicoes=eleicoes,
        eleicao_selecionada=int(eleicao_id) if eleicao_id else None,
        total_votos=total_votos,
        filial_filtro=filial_filtro,
        data_inicio=data_inicio or '',
        data_fim=data_fim or ''
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        usuario = Usuario.query.filter_by(username=username).first()

        if usuario and bcrypt.check_password_hash(usuario.password_hash, password):
            session['user_id'] = usuario.id
            session['user_level'] = usuario.nivel
            registrar_log("Login realizado", usuario.id)
            flash('Login realizado com sucesso!', 'success')

            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin'))

        flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    if 'user_id' in session:
        registrar_log("Logout realizado", session['user_id'])
    session.clear()
    flash("Você foi desconectado com sucesso.", "info")
    return redirect(url_for('login'))


@app.route('/admin')
@login_required(level="admin")
def admin():
    try:
        # Obter parâmetros de filtro
        eleicao_id = request.args.get('eleicao_id', type=int)
        filial_id = request.args.get('filial_id', type=int)
        candidato_id = request.args.get('candidato_id', type=int)
        data_inicio = request.args.get('data_inicio')
        data_fim = request.args.get('data_fim')

        # Construir consulta base com filtros
        query_votos = Voto.query
        if eleicao_id:
            query_votos = query_votos.filter_by(eleicao_id=eleicao_id)
        if filial_id:
            query_votos = query_votos.filter_by(filial_id=filial_id)
        if candidato_id:
            query_votos = query_votos.filter_by(candidato_id=candidato_id)
        if data_inicio:
            query_votos = query_votos.filter(Voto.data_voto >= datetime.strptime(data_inicio, '%d/%m/%Y'))
        if data_fim:
            query_votos = query_votos.filter(
                Voto.data_voto <= datetime.strptime(data_fim + ' 23:59:59', '%d/%m/%Y %H:%M:%S'))

        # Estatísticas básicas com filtros aplicados
        total_votos = query_votos.count()

        # Eleições ativas (dentro do período válido)
        agora = datetime.now(fuso_brasil)
        eleicoes_ativas = Eleicao.query.filter(
            Eleicao.ativa == True,
            Eleicao.data_inicio <= agora,
            Eleicao.data_fim >= agora
        ).count()

        # Total de candidatos ativos
        query_candidatos = Candidato.query.filter_by(ativa=True)
        if eleicao_id:
            query_candidatos = query_candidatos.filter_by(eleicao_id=eleicao_id)
        if filial_id:
            query_candidatos = query_candidatos.filter_by(filial_id=filial_id)
        total_candidatos = query_candidatos.count()

        # Total de filiais ativas
        query_filiais = Filial.query.filter_by(ativa=True)
        if eleicao_id:
            query_filiais = query_filiais.filter_by(eleicao_id=eleicao_id)
        total_filiais = query_filiais.count()

        # Top 10 candidatos
        top_candidatos = db.session.query(
            Candidato.nome,
            db.func.count(Voto.id).label('total')
        ).join(Voto).group_by(Candidato.nome)

        if eleicao_id:
            top_candidatos = top_candidatos.filter(Voto.eleicao_id == eleicao_id)
        if filial_id:
            top_candidatos = top_candidatos.filter(Voto.filial_id == filial_id)
        if candidato_id:
            top_candidatos = top_candidatos.filter(Voto.candidato_id == candidato_id)
        if data_inicio:
            top_candidatos = top_candidatos.filter(Voto.data_voto >= datetime.strptime(data_inicio, '%d/%m/%Y'))
        if data_fim:
            top_candidatos = top_candidatos.filter(
                Voto.data_voto <= datetime.strptime(data_fim + ' 23:59:59', '%d/%m/%Y %H:%M:%S'))

        top_candidatos = top_candidatos.order_by(db.desc('total')).limit(10).all()

        # Votos por filial
        votos_filial = db.session.query(
            Filial.nome,
            db.func.count(Voto.id).label('total')
        ).join(Voto).group_by(Filial.nome)

        if eleicao_id:
            votos_filial = votos_filial.filter(Voto.eleicao_id == eleicao_id)
        if filial_id:
            votos_filial = votos_filial.filter(Voto.filial_id == filial_id)
        if candidato_id:
            votos_filial = votos_filial.filter(Voto.candidato_id == candidato_id)
        if data_inicio:
            votos_filial = votos_filial.filter(Voto.data_voto >= datetime.strptime(data_inicio, '%d/%m/%Y'))
        if data_fim:
            votos_filial = votos_filial.filter(
                Voto.data_voto <= datetime.strptime(data_fim + ' 23:59:59', '%d/%m/%Y %H:%M:%S'))

        votos_filial = votos_filial.all()

        # Timeline de votos (últimas 24 horas)
        timeline = db.session.query(
            db.func.strftime('%H:00', Voto.data_voto).label('hora'),
            db.func.count(Voto.id).label('total')
        ).filter(
            Voto.data_voto >= datetime.now() - timedelta(hours=24)
        )

        if eleicao_id:
            timeline = timeline.filter(Voto.eleicao_id == eleicao_id)
        if filial_id:
            timeline = timeline.filter(Voto.filial_id == filial_id)
        if candidato_id:
            timeline = timeline.filter(Voto.candidato_id == candidato_id)

        timeline = timeline.group_by('hora').order_by('hora').all()

        # Heatmap por hora do dia
        heatmap = db.session.query(
            db.func.strftime('%H', Voto.data_voto).label('hora'),
            db.func.count(Voto.id).label('total')
        )

        if eleicao_id:
            heatmap = heatmap.filter(Voto.eleicao_id == eleicao_id)
        if filial_id:
            heatmap = heatmap.filter(Voto.filial_id == filial_id)
        if candidato_id:
            heatmap = heatmap.filter(Voto.candidato_id == candidato_id)
        if data_inicio:
            heatmap = heatmap.filter(Voto.data_voto >= datetime.strptime(data_inicio, '%d/%m/%Y'))
        if data_fim:
            heatmap = heatmap.filter(
                Voto.data_voto <= datetime.strptime(data_fim + ' 23:59:59', '%d/%m/%Y %H:%M:%S'))

        heatmap = heatmap.group_by('hora').order_by('hora').all()

        # Preencher horas faltantes no heatmap
        heatmap_data = [0] * 24
        for hora, total in heatmap:
            heatmap_data[int(hora)] = total

        # Últimos votos (com conversão de fuso horário)
        ultimos_votos = query_votos.order_by(Voto.data_voto.desc()).limit(10).all()
        ultimos_votos_convertidos = []
        for voto in ultimos_votos:
            if voto.data_voto.tzinfo is None:
                voto.data_voto = pytz.utc.localize(voto.data_voto)
            voto_convertido = {
                'data_voto': voto.data_voto.astimezone(fuso_brasil),
                'filial': voto.filial,
                'candidato': voto.candidato
            }
            ultimos_votos_convertidos.append(voto_convertido)

        # Filiais com maior participação
        filiais_participacao = db.session.query(
            Filial.nome,
            db.func.count(Voto.id).label('total_votos')
        ).join(Voto).group_by(Filial.nome)

        if eleicao_id:
            filiais_participacao = filiais_participacao.filter(Voto.eleicao_id == eleicao_id)
        if candidato_id:
            filiais_participacao = filiais_participacao.filter(Voto.candidato_id == candidato_id)
        if data_inicio:
            filiais_participacao = filiais_participacao.filter(
                Voto.data_voto >= datetime.strptime(data_inicio, '%d/%m/%Y'))
        if data_fim:
            filiais_participacao = filiais_participacao.filter(
                Voto.data_voto <= datetime.strptime(data_fim + ' 23:59:59', '%d/%m/%Y %H:%M:%S'))

        filiais_participacao = filiais_participacao.order_by(db.desc('total_votos')).limit(5).all()

        # Percentual de participação (meta fixa de 1000 votos)
        meta_votos = 1000
        percentual_participacao = min(100, round((total_votos / meta_votos) * 100, 2)) if meta_votos > 0 else 0

        # Votos por hora (média)
        votos_por_hora = round(total_votos / 24, 1) if total_votos > 0 else 0

        # Votos por dia (média)
        dias_eleicao = 1  # Valor padrão para evitar divisão por zero
        if eleicao_id:
            eleicao = Eleicao.query.get(eleicao_id)
            if eleicao:
                dias_eleicao = (eleicao.data_fim - eleicao.data_inicio).days or 1
        votos_por_dia = round(total_votos / dias_eleicao, 1) if total_votos > 0 else 0

        # Calcular máximos para as barras de progresso
        max_votos_hora_result = db.session.query(
            db.func.count(Voto.id)
        ).filter(
            db.func.strftime('%H', Voto.data_voto) == db.func.strftime('%H', datetime.now())
        ).scalar() or 1

        max_votos_hora = max(max_votos_hora_result, 1)

        max_votos_dia_result = db.session.query(
            db.func.count(Voto.id)
        ).filter(
            db.func.date(Voto.data_voto) == db.func.date(datetime.now())
        ).scalar() or 1

        max_votos_dia = max(max_votos_dia_result, 1)

        # Obter todas eleições, filiais e candidatos para os dropdowns
        todas_eleicoes = Eleicao.query.order_by(Eleicao.data_inicio.desc()).all()
        todas_filiais = Filial.query.order_by(Filial.nome).all()
        todos_candidatos = Candidato.query.order_by(Candidato.nome).all()

        return render_template(
            "admin.html",
            total_filiais=total_filiais,
            total_candidatos=total_candidatos,
            total_votos=total_votos,
            eleicoes_ativas=eleicoes_ativas,
            candidatos_top_labels=[c[0] for c in top_candidatos],
            candidatos_top_data=[c[1] for c in top_candidatos],
            filiais_labels=[f[0] for f in votos_filial],
            filiais_data=[f[1] for f in votos_filial],
            timeline_labels=[t[0] for t in timeline],
            timeline_data=[t[1] for t in timeline],
            heatmap_data=heatmap_data,
            ultimos_votos=ultimos_votos_convertidos,  # Usando os votos convertidos
            filiais_participacao=filiais_participacao,
            percentual_participacao=percentual_participacao,
            votos_por_hora=votos_por_hora,
            votos_por_dia=votos_por_dia,
            max_votos_hora=max_votos_hora,
            max_votos_dia=max_votos_dia,
            todas_eleicoes=todas_eleicoes,
            todas_filiais=todas_filiais,
            todos_candidatos=todos_candidatos,
            filtro_eleicao=eleicao_id,
            filtro_filial=filial_id,
            filtro_candidato=candidato_id,
            filtro_data_inicio=data_inicio or '',
            filtro_data_fim=data_fim or ''
        )

    except Exception as e:
        app.logger.error(f"Erro no painel admin: {str(e)}", exc_info=True)
        registrar_log(f"Erro no painel admin: {str(e)}", session.get('user_id'))
        flash(f"Ocorreu um erro ao carregar o painel administrativo. Detalhes: {str(e)}", "danger")
        return redirect(url_for('admin'))


@app.route('/admin/timeline')
@login_required(level="admin")
def admin_timeline():
    try:
        range_hours = request.args.get('range', '24', type=str)
        eleicao_id = request.args.get('eleicao_id', type=int)
        filial_id = request.args.get('filial_id', type=int)
        candidato_id = request.args.get('candidato_id', type=int)
        data_inicio = request.args.get('data_inicio')
        data_fim = request.args.get('data_fim')

        # Converter range para horas
        if range_hours == '24':
            hours = 24
        elif range_hours == '72':
            hours = 72
        else:  # 168 horas (7 dias)
            hours = 168

        # Construir consulta com filtros
        query = db.session.query(
            db.func.strftime('%Y-%m-%d %H:00', Voto.data_voto).label('hora'),
            db.func.count(Voto.id).label('total')
        ).filter(
            Voto.data_voto >= datetime.now() - timedelta(hours=hours)
        )

        if eleicao_id:
            query = query.filter(Voto.eleicao_id == eleicao_id)
        if filial_id:
            query = query.filter(Voto.filial_id == filial_id)
        if candidato_id:
            query = query.filter(Voto.candidato_id == candidato_id)
        if data_inicio:
            query = query.filter(Voto.data_voto >= datetime.strptime(data_inicio, '%d/%m/%Y'))
        if data_fim:
            query = query.filter(Voto.data_voto <= datetime.strptime(data_fim + ' 23:59:59', '%d/%m/%Y %H:%M:%S'))

        timeline = query.group_by('hora').order_by('hora').all()

        # Formatar para o gráfico
        labels = [t[0] for t in timeline]
        data = [t[1] for t in timeline]

        return jsonify({
            'labels': labels,
            'data': data
        })

    except Exception as e:
        app.logger.error(f"Erro na timeline: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route("/admin/resetar_votos", methods=['POST'])
@login_required(level="admin")
def resetar_votos():
    if request.method == 'POST':
        try:
            eleicao_id = request.form.get('eleicao_id')

            if eleicao_id:
                # Resetar votos apenas para uma eleição específica
                num_votos = db.session.query(Voto).filter_by(eleicao_id=eleicao_id).count()
                db.session.query(Voto).filter_by(eleicao_id=eleicao_id).delete()
                eleicao = Eleicao.query.get(eleicao_id)
                registrar_log(f"Reset de votos concluído - {num_votos} votos removidos da eleição {eleicao.titulo}",
                              session['user_id'])
                flash(f"Todos os {num_votos} votos da eleição {eleicao.titulo} foram resetados com sucesso!", "success")
            else:
                # Resetar todos os votos
                num_votos = db.session.query(Voto).count()
                db.session.query(Voto).delete()
                registrar_log(f"Reset de todos os votos concluído - {num_votos} votos removidos", session['user_id'])
                flash(f"Todos os {num_votos} votos foram resetados com sucesso!", "success")

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            registrar_log(f"Falha ao resetar votos: {str(e)}", session.get('user_id'))
            flash(f"Erro ao resetar votos: {str(e)}", "danger")

        return redirect(url_for('admin'))


@app.route("/admin/filiais", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_filiais():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    form = FilialForm()

    # Preencher as opções de eleição
    form.eleicao_id.choices = [(e.id, e.titulo) for e in Eleicao.query.order_by(Eleicao.titulo).all()]

    if request.method == 'POST':
        if form.validate_on_submit():
            nome = form.nome.data.strip().upper()
            eleicao_id = form.eleicao_id.data

            try:
                # Verificar se já existe filial com esse nome para a mesma eleição
                if Filial.query.filter_by(nome=nome, eleicao_id=eleicao_id).first():
                    flash("Já existe uma filial com este nome para esta eleição!", "danger")
                else:
                    filial = Filial(nome=nome, eleicao_id=eleicao_id)
                    db.session.add(filial)
                    db.session.commit()
                    registrar_log(f"Filial {nome} adicionada para eleição {eleicao_id}", session['user_id'])
                    flash(f"Filial {nome} adicionada com sucesso!", "success")
                    return redirect(url_for('gerenciar_filiais', page=page))
            except Exception as e:
                db.session.rollback()
                registrar_log(f"Erro ao adicionar filial: {str(e)}", session['user_id'])
                flash(f"Erro ao adicionar filial: {str(e)}", "danger")

        elif 'toggle_filial' in request.form:
            filial_id = request.form['toggle_filial']
            filial = Filial.query.get(filial_id)
            if filial:
                filial.ativa = not filial.ativa
                db.session.commit()
                registrar_log(f"Status da filial {filial.nome} alterado para {'Ativa' if filial.ativa else 'Inativa'}",
                              session['user_id'])
                flash("Status da filial atualizado com sucesso!", "success")
                return redirect(url_for('gerenciar_filiais', page=page))

        elif 'excluir_filial' in request.form:
            filial_id = request.form['excluir_filial']
            filial = Filial.query.get(filial_id)
            if filial:
                try:
                    # Verificar se há candidatos ou votos associados
                    if Candidato.query.filter_by(filial_id=filial_id).count() > 0 or Voto.query.filter_by(
                            filial_id=filial_id).count() > 0:
                        flash("Não é possível excluir - filial possui candidatos ou votos associados!", "warning")
                    else:
                        db.session.delete(filial)
                        db.session.commit()
                        registrar_log(f"Filial {filial.nome} excluída", session['user_id'])
                        flash("Filial excluída com sucesso!", "success")
                    return redirect(url_for('gerenciar_filiais', page=page))
                except Exception as e:
                    db.session.rollback()
                    registrar_log(f"Erro ao excluir filial: {str(e)}", session['user_id'])
                    flash(f"Erro ao excluir filial: {str(e)}", "danger")

        return redirect(url_for('gerenciar_filiais', page=page))

    # Query para filiais com paginação
    query = db.session.query(
        Filial.id,
        Filial.nome,
        Filial.ativa,
        Eleicao.titulo.label('eleicao_nome'),
        db.func.strftime('%d/%m/%Y %H:%M', Filial.data_criacao).label('data_criacao')
    ).join(Eleicao).order_by(Eleicao.titulo, Filial.nome)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    filiais = pagination.items

    total_ativas = sum(1 for f in filiais if f[2])  # Índice 2 = ativa
    total_inativas = sum(1 for f in filiais if not f[2])

    return render_template(
        "admin_filiais.html",
        filiais=filiais,
        form=form,
        total_ativas=total_ativas,
        total_inativas=total_inativas,
        pagination=pagination
    )


@app.route("/admin/eleicoes", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_eleicoes():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    form = EleicaoForm()

    if form.validate_on_submit():
        try:
            data_inicio = datetime.strptime(form.data_inicio.data, '%Y-%m-%dT%H:%M')
            data_fim = datetime.strptime(form.data_fim.data, '%Y-%m-%dT%H:%M')

            # Verificar se é uma edição
            eleicao_id = request.form.get('eleicao_id')
            if eleicao_id:
                eleicao = Eleicao.query.get(eleicao_id)
                if eleicao:
                    eleicao.titulo = form.titulo.data
                    eleicao.descricao = form.descricao.data
                    eleicao.data_inicio = data_inicio
                    eleicao.data_fim = data_fim
                    registrar_log(f"Eleição {form.titulo.data} atualizada", session['user_id'])
                    flash("Eleição atualizada com sucesso!", "success")
                else:
                    flash("Eleição não encontrada", "danger")
            else:
                # Nova eleição
                eleicao = Eleicao(
                    titulo=form.titulo.data,
                    descricao=form.descricao.data,
                    data_inicio=data_inicio,
                    data_fim=data_fim
                )
                db.session.add(eleicao)
                registrar_log(f"Eleição {form.titulo.data} criada", session['user_id'])
                flash("Eleição criada com sucesso!", "success")

            db.session.commit()
            return redirect(url_for('gerenciar_eleicoes'))
        except Exception as e:
            db.session.rollback()
            registrar_log(f"Erro ao salvar eleição: {str(e)}", session['user_id'])
            flash(f"Erro ao salvar eleição: {str(e)}", "danger")

    elif request.method == 'POST':
        if 'toggle_eleicao' in request.form:
            eleicao_id = request.form['toggle_eleicao']
            eleicao = Eleicao.query.get(eleicao_id)
            if eleicao:
                eleicao.ativa = not eleicao.ativa
                db.session.commit()
                registrar_log(
                    f"Status da eleição {eleicao.titulo} alterado para {'Ativa' if eleicao.ativa else 'Inativa'}",
                    session['user_id'])
                flash("Status da eleição atualizado com sucesso!", "success")
                return redirect(url_for('gerenciar_eleicoes', page=page))

        elif 'excluir_eleicao' in request.form:
            eleicao_id = request.form['excluir_eleicao']
            eleicao = Eleicao.query.get(eleicao_id)
            if eleicao:
                try:
                    if Voto.query.filter_by(eleicao_id=eleicao.id).count() > 0:
                        flash("Não é possível excluir - eleição possui votos associados!", "warning")
                    else:
                        db.session.delete(eleicao)
                        db.session.commit()
                        registrar_log(f"Eleição {eleicao.titulo} excluída", session['user_id'])
                        flash("Eleição excluída com sucesso!", "success")
                    return redirect(url_for('gerenciar_eleicoes', page=page))
                except Exception as e:
                    db.session.rollback()
                    registrar_log(f"Erro ao excluir eleição: {str(e)}", session['user_id'])
                    flash(f"Erro ao excluir eleição: {str(e)}", "danger")


        elif 'editar_eleicao' in request.form:

            eleicao_id = request.form['editar_eleicao']

            eleicao = Eleicao.query.get(eleicao_id)

            if eleicao:
                form.titulo.data = eleicao.titulo

                form.descricao.data = eleicao.descricao

                form.data_inicio.data = eleicao.data_inicio.strftime('%Y-%m-%dT%H:%M')

                form.data_fim.data = eleicao.data_fim.strftime('%Y-%m-%dT%H:%M')

                # REFAZ a query que popula eleicoes, pagination e totais

                query = db.session.query(

                    Eleicao.id,

                    Eleicao.titulo,

                    Eleicao.descricao,

                    Eleicao.ativa,

                    db.func.strftime('%d/%m/%Y %H:%M', Eleicao.data_inicio).label('data_inicio'),

                    db.func.strftime('%d/%m/%Y %H:%M', Eleicao.data_fim).label('data_fim'),

                    db.func.strftime('%d/%m/%Y %H:%M', Eleicao.data_criacao).label('data_criacao')

                ).order_by(Eleicao.data_inicio.desc())

                pagination = query.paginate(page=page, per_page=per_page, error_out=False)

                eleicoes = pagination.items

                total_ativas = sum(1 for e in eleicoes if e[3])  # Índice 3 = ativa

                total_inativas = sum(1 for e in eleicoes if not e[3])

                return render_template(

                    "admin_eleicoes.html",

                    eleicoes=eleicoes,

                    form=form,

                    total_ativas=total_ativas,

                    total_inativas=total_inativas,

                    pagination=pagination,

                    eleicao_editando=eleicao

                )

    # Query para eleições com paginação
    query = db.session.query(
        Eleicao.id,
        Eleicao.titulo,
        Eleicao.descricao,
        Eleicao.ativa,
        db.func.strftime('%d/%m/%Y %H:%M', Eleicao.data_inicio).label('data_inicio'),
        db.func.strftime('%d/%m/%Y %H:%M', Eleicao.data_fim).label('data_fim'),
        db.func.strftime('%d/%m/%Y %H:%M', Eleicao.data_criacao).label('data_criacao')
    ).order_by(Eleicao.data_inicio.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    eleicoes = pagination.items

    total_ativas = sum(1 for e in eleicoes if e[3])  # Índice 3 = ativa
    total_inativas = sum(1 for e in eleicoes if not e[3])

    return render_template(
        "admin_eleicoes.html",
        eleicoes=eleicoes,
        form=form,
        total_ativas=total_ativas,
        total_inativas=total_inativas,
        pagination=pagination,
        eleicao_editando=None  # Ou o objeto eleição quando estiver editando
    )


@app.route("/admin/candidatos", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_candidatos():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if request.method == 'POST':
        if 'nome_candidato' in request.form:
            nome = request.form['nome_candidato'].strip()
            filial_id = request.form['filial_candidato']
            eleicao_id = request.form['eleicao_candidato']
            foto = None

            # Obter o próximo ID sequencial para a filial e eleição
            novo_id = Candidato.proximo_id_filial(filial_id, eleicao_id)

            # Processar upload de foto
            if 'foto_candidato' in request.files:
                file = request.files['foto_candidato']
                if file and allowed_file(file.filename):
                    try:
                        if file.content_length > 2 * 1024 * 1024:
                            flash("Arquivo muito grande (tamanho máximo: 2MB)", "danger")
                            return redirect(url_for('gerenciar_candidatos'))

                        ext = file.filename.rsplit('.', 1)[1].lower()
                        filename = f"cand_{filial_id}_{eleicao_id}_{novo_id}.{ext}"
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                        file.save(filepath)
                        foto = filename

                    except Exception as upload_error:
                        app.logger.error(f"Erro no upload: {str(upload_error)}")
                        flash("Erro ao processar a imagem do candidato", "danger")
                        return redirect(url_for('gerenciar_candidatos'))

                elif file.filename != '':
                    flash("Formato de arquivo não permitido (use JPG, PNG)", "danger")
                    return redirect(url_for('gerenciar_candidatos'))

            try:
                candidato = Candidato(
                    nome=nome,
                    filial_id=filial_id,
                    eleicao_id=eleicao_id,
                    filial_id_seq=novo_id,
                    foto=foto
                )
                db.session.add(candidato)
                db.session.commit()

                registrar_log(f"Candidato {nome} adicionado (ID Filial: {novo_id})", session['user_id'])
                flash(f"Candidato {nome} cadastrado com sucesso! (ID: {novo_id})", "success")
                return redirect(url_for('gerenciar_candidatos'))

            except Exception as e:
                db.session.rollback()
                if foto and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], foto)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], foto))

                registrar_log(f"Erro ao adicionar candidato: {str(e)}", session['user_id'])
                flash(f"Erro ao cadastrar candidato: {str(e)}", "danger")
                return redirect(url_for('gerenciar_candidatos'))

        elif 'toggle_candidato' in request.form:
            candidato_id = request.form['toggle_candidato']
            candidato = Candidato.query.get(candidato_id)
            if candidato:
                candidato.ativa = not candidato.ativa
                db.session.commit()
                registrar_log(
                    f"Status do candidato {candidato.nome} (ID Filial: {candidato.filial_id_seq}) alterado para {'Ativo' if candidato.ativa else 'Inativo'}",
                    session['user_id'])
                flash("Status do candidato atualizado com sucesso!", "success")
                return redirect(url_for('gerenciar_candidatos'))

        elif 'excluir_candidato' in request.form:
            candidato_id = request.form['excluir_candidato']
            candidato = Candidato.query.get(candidato_id)
            if candidato:
                try:
                    if Voto.query.filter_by(candidato_id=candidato.id).count() > 0:
                        flash("Não é possível excluir - candidato possui votos associados!", "warning")
                    else:
                        if candidato.foto and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto)):
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto))

                        db.session.delete(candidato)
                        db.session.commit()
                        registrar_log(f"Candidato {candidato.nome} (ID Filial: {candidato.filial_id_seq}) excluído",
                                      session['user_id'])
                        flash("Candidato excluído com sucesso!", "success")
                    return redirect(url_for('gerenciar_candidatos'))
                except Exception as e:
                    db.session.rollback()
                    registrar_log(f"Erro ao excluir candidato: {str(e)}", session['user_id'])
                    flash(f"Erro ao excluir candidato: {str(e)}", "danger")
                    return redirect(url_for('gerenciar_candidatos'))

        elif 'editar_candidato' in request.form:
            candidato_id = request.form['editar_candidato']
            candidato = Candidato.query.get(candidato_id)

            if candidato:
                try:
                    candidato.nome = request.form.get('editar_nome', candidato.nome)
                    novo_filial_id = request.form.get('editar_filial', candidato.filial_id)
                    novo_eleicao_id = request.form.get('editar_eleicao', candidato.eleicao_id)

                    # Se mudou de filial ou eleição, reatribuir o ID sequencial
                    if novo_filial_id != candidato.filial_id or novo_eleicao_id != candidato.eleicao_id:
                        max_id = db.session.query(db.func.max(Candidato.filial_id_seq)) \
                                     .filter_by(filial_id=novo_filial_id, eleicao_id=novo_eleicao_id) \
                                     .scalar() or 0
                        candidato.filial_id_seq = max_id + 1
                        candidato.filial_id = novo_filial_id
                        candidato.eleicao_id = novo_eleicao_id

                    if 'remover_foto' in request.form:
                        if candidato.foto and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto)):
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto))
                        candidato.foto = None

                    if 'nova_foto' in request.files:
                        file = request.files['nova_foto']
                        if file and allowed_file(file.filename):
                            if candidato.foto and os.path.exists(
                                    os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto)):
                                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto))

                            filename = secure_filename(
                                f"cand_{candidato.filial_id}_{candidato.eleicao_id}_{candidato.filial_id_seq}.{file.filename.rsplit('.', 1)[1].lower()}")
                            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                            candidato.foto = filename

                    db.session.commit()
                    registrar_log(f"Candidato {candidato.nome} (ID Filial: {candidato.filial_id_seq}) atualizado",
                                  session['user_id'])
                    flash("Candidato atualizado com sucesso!", "success")
                    return redirect(url_for('gerenciar_candidatos'))

                except Exception as e:
                    db.session.rollback()
                    registrar_log(f"Erro ao atualizar candidato: {str(e)}", session['user_id'])
                    flash(f"Erro ao atualizar candidato: {str(e)}", "danger")
                    return redirect(url_for('gerenciar_candidatos'))

    # Query para candidatos com paginação (com joins explícitos)
    query = db.session.query(
        Candidato.id,
        Candidato.nome,
        Filial.nome.label('filial'),
        Eleicao.titulo.label('eleicao'),
        Candidato.ativa,
        Candidato.foto,
        Candidato.filial_id_seq,
        Filial.id.label('filial_id'),
        Eleicao.id.label('eleicao_id'),
        db.func.strftime('%d/%m/%Y %H:%M', Candidato.data_criacao).label('data_formatada')
    ).join(Filial, Candidato.filial_id == Filial.id
    ).join(Eleicao, Candidato.eleicao_id == Eleicao.id
    ).order_by(Eleicao.titulo, Filial.nome, Candidato.filial_id_seq)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    candidatos = pagination.items

    filiais = Filial.query.filter_by(ativa=True).order_by(Filial.nome).all()
    eleicoes = Eleicao.query.order_by(Eleicao.titulo).all()
    total_ativas = sum(1 for c in candidatos if c[4])  # Índice 4 = ativa
    total_inativas = sum(1 for c in candidatos if not c[4])

    return render_template(
        "admin_candidatos.html",
        candidatos=candidatos,
        filiais=filiais,
        eleicoes=eleicoes,
        total_ativas=total_ativas,
        total_inativas=total_inativas,
        pagination=pagination
    )


@app.route("/admin/logs")
@login_required(level="admin")
def visualizar_logs():
    try:
        logs_raw = db.session.execute(
            db.select(
                Log.acao,
                Log.data,
                Log.ip,
                Log.user_agent,
                Usuario.username
            )
            .join(Usuario, Log.usuario_id == Usuario.id, isouter=True)
            .order_by(Log.data.desc())
        ).all()

        logs = []
        for registro in logs_raw:
            try:
                dt_brasil = converter_para_brasil(registro.data)
                logs.append({
                    'acao': registro.acao,
                    'data': formatar_data_brasil(dt_brasil),
                    'ip': registro.ip or 'N/A',
                    'user_agent': registro.user_agent[:75] + '...' if registro.user_agent else 'N/A',
                    'username': registro.username or 'Sistema'
                })
            except Exception as e:
                app.logger.error(f"Erro ao processar registro: {str(e)}")
                continue

        if not logs:
            flash("Nenhum registro de log encontrado", "info")

        return render_template("admin_logs.html", logs=logs)

    except Exception as e:
        app.logger.error(f"Erro grave ao acessar logs: {str(e)}", exc_info=True)
        flash("Falha crítica ao carregar os logs. Verifique o arquivo de log para detalhes.", "danger")
        return redirect(url_for('admin'))


@app.route('/admin/exportar/<tipo>')
@login_required(level="admin")
def exportar_dados(tipo):
    if tipo == 'votos':
        try:
            # 1. Obtenha os parâmetros
            eleicao_id = request.args.get('eleicao', '')

            # 2. Construa a query de forma segura
            query = db.session.query(
                Voto.cpf,
                Voto.nome,
                Filial.nome.label('filial'),
                Candidato.nome.label('candidato'),
                Voto.data_voto,  # Pega o datetime bruto
                Eleicao.titulo.label('eleicao')
            ).join(Candidato, Voto.candidato_id == Candidato.id) \
                .join(Filial, Voto.filial_id == Filial.id) \
                .join(Eleicao, Voto.eleicao_id == Eleicao.id)

            if eleicao_id:
                query = query.filter(Eleicao.id == eleicao_id)

            dados = query.all()

            # 3. Crie um gerador de CSV em memória
            def gerar_csv():
                buffer = io.StringIO()
                buffer.write('\ufeff')  # BOM para UTF-8
                writer = csv.writer(buffer, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

                # Escreva cabeçalho
                writer.writerow(['CPF', 'Nome Eleitor', 'Filial', 'Candidato', 'Data/Hora (Brasília)', 'Eleição'])

                # Escreva dados
                for cpf, nome, filial, candidato, data_voto, eleicao in dados:
                    # Converter para fuso de Brasília
                    if data_voto:
                        if data_voto.tzinfo is None:
                            data_voto = pytz.utc.localize(data_voto)
                        data_brasil = data_voto.astimezone(pytz.timezone('America/Sao_Paulo'))
                        data_str = data_brasil.strftime('%d/%m/%Y %H:%M')
                    else:
                        data_str = ''
                    writer.writerow([cpf, nome, filial, candidato, data_str, eleicao])

                buffer.seek(0)
                yield buffer.getvalue()
                buffer.close()

            # 4. Retorne a resposta com os headers corretos
            response = Response(
                gerar_csv(),
                mimetype='text/csv; charset=utf-8',
                headers={
                    "Content-Disposition": "attachment; filename=votos_cipa.csv",
                    "Content-Type": "text/csv; charset=utf-8"
                }
            )
            return response

        except Exception as e:
            app.logger.error(f"ERRO NA EXPORTAÇÃO: {str(e)}")
            flash("Falha ao gerar arquivo CSV. Verifique os logs.", "danger")
            return redirect(url_for('resultados'))

    abort(404)


@app.route('/recuperar-senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        usuario = Usuario.query.filter_by(username=email).first()

        if usuario:
            token = hashlib.sha256(f"{email}{datetime.now()}".encode()).hexdigest()
            expiracao = datetime.now() + timedelta(hours=1)

            reset_token = PasswordResetToken(
                token=token,
                usuario_id=usuario.id,
                expiracao=expiracao
            )
            db.session.add(reset_token)
            db.session.commit()

            reset_link = url_for('redefinir_senha', token=token, _external=True)
            app.logger.info(f"Link de recuperação para {email}: {reset_link}")

        flash("Se o e-mail estiver cadastrado, você receberá um link para redefinir sua senha.", "info")
        return redirect(url_for('login'))

    return render_template('recuperar_senha.html')


@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    reset_token = PasswordResetToken.query.filter_by(token=token, usado=False).first()

    if not reset_token or reset_token.expiracao < datetime.now():
        flash("Link inválido ou expirado", "danger")
        return redirect(url_for('recuperar_senha'))

    if request.method == 'POST':
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if nova_senha != confirmar_senha:
            flash("As senhas não coincidem", "danger")
            return redirect(url_for('redefinir_senha', token=token))

        reset_token.usuario.password_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
        reset_token.usado = True
        db.session.commit()

        flash("Senha redefinida com sucesso! Faça login com sua nova senha.", "success")
        return redirect(url_for('login'))

    return render_template('redefinir_senha.html', token=token)


@app.route('/admin/usuarios')
@login_required(level="admin")
def gerenciar_usuarios():
    usuarios = Usuario.query.order_by(Usuario.username).all()
    return render_template('admin_usuarios.html', usuarios=usuarios)


@app.route('/api/filiais/<int:eleicao_id>')
def get_filiais_por_eleicao(eleicao_id):
    try:
        # Busca filiais que têm candidatos na eleição especificada
        filiais = db.session.query(
            Filial.id,
            Filial.nome
        ).filter_by(
            eleicao_id=eleicao_id,
            ativa=True
        ).order_by(Filial.nome).all()

        return jsonify([{'id': f[0], 'nome': f[1]} for f in filiais])
    except Exception as e:
        app.logger.error(f"Erro ao buscar filiais: {str(e)}")
        return jsonify([])


@app.route('/anular_voto/<int:voto_id>', methods=['POST'])
@login_required(level="admin")
def anular_voto(voto_id):
    try:
        voto = Voto.query.get_or_404(voto_id)

        # Registrar log antes de deletar
        registrar_log(f"Voto anulado - CPF: {voto.cpf}, Candidato: {voto.candidato.nome}", session['user_id'])

        db.session.delete(voto)
        db.session.commit()

        flash("Voto anulado com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        registrar_log(f"Erro ao anular voto: {str(e)}", session['user_id'])
        flash(f"Erro ao anular voto: {str(e)}", "danger")

    return redirect(request.referrer or url_for('resultados'))


# Comandos CLI
@app.cli.command('create-admin')
def create_admin():
    """Cria um usuário admin"""
    username = input("Nome de usuário: ")
    password = getpass.getpass("Senha: ")  # Isso ocultará a senha durante a digitação

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

    admin = Usuario(
        username=username,
        password_hash=hashed_pw,
        nivel='admin',
        ativo=True
    )

    db.session.add(admin)
    db.session.commit()
    print(f"Admin {username} criado com sucesso!")


if __name__ == "__main__":
    app.run(debug=True)