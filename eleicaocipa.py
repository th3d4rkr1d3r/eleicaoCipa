from flask import Flask, render_template, request, redirect, flash, url_for, session, abort, send_file
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
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import pytz
from datetime import datetime, timedelta
from helpers import converter_para_brasil, formatar_data_brasil
import logging
import os
import time
from werkzeug.utils import secure_filename

# Inicialização do aplicativo Flask
app = Flask(__name__)
app.config.from_object(Config)



# Configurações de upload
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'candidatos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Cria a pasta se não existir

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

# Login Form
class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

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

class Filial(db.Model):
    __tablename__ = 'filiais'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    ativa = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Filial {self.nome}>'

class Candidato(db.Model):
    __tablename__ = 'candidatos'
    id = db.Column(db.Integer, primary_key=True)  # ID global (mantido para relações)
    filial_id_seq = db.Column(db.Integer, nullable=False, default=1)  # ID específico da filial
    nome = db.Column(db.String(100), nullable=False)
    filial_id = db.Column(db.Integer, db.ForeignKey('filiais.id'), nullable=False)
    ativa = db.Column(db.Boolean, default=True)
    foto = db.Column(db.String(255))  # Armazena o caminho da imagem
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())
    filial = db.relationship('Filial', backref='candidatos')

    __table_args__ = (
        db.UniqueConstraint('filial_id', 'filial_id_seq', name='_filial_id_seq_uc'),
    )

    def __repr__(self):
        return f'<Candidato {self.nome} (Filial ID: {self.filial_id}, Seq: {self.filial_id_seq})>'

    @classmethod
    def proximo_id_filial(cls, filial_id):
        """Retorna o próximo ID sequencial para a filial especificada"""
        max_id = db.session.query(db.func.max(cls.filial_id_seq)).filter_by(filial_id=filial_id).scalar()
        return 1 if max_id is None else max_id + 1

class Voto(db.Model):
    __tablename__ = 'votos'
    id = db.Column(db.Integer, primary_key=True)
    cpf = db.Column(db.String(11), nullable=False)
    filial_id = db.Column(db.Integer, db.ForeignKey('filiais.id'), nullable=False)
    candidato_id = db.Column(db.Integer, db.ForeignKey('candidatos.id'), nullable=False)
    data_voto = db.Column(db.DateTime, default=db.func.current_timestamp())
    filial = db.relationship('Filial', backref='votos')
    candidato = db.relationship('Candidato', backref='votos')

    def __repr__(self):
        return f'<Voto {self.cpf}>'

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
        # Consulta para filiais ativas
        filiais = db.session.query(
            Filial.id,
            Filial.nome
        ).filter_by(ativa=True).order_by(Filial.nome).all()

        # Consulta para candidatos ativos com suas filiais (também ativas)
        candidatos = db.session.query(
            Candidato.id,
            Candidato.nome,
            Filial.nome.label('filial_nome'),
            Candidato.foto,
            Candidato.filial_id_seq,
            Filial.id.label('filial_id')  # Adicionando o ID da filial para referência
        ).join(Filial).filter(
            Candidato.ativa == True,
            Filial.ativa == True
        ).order_by(Filial.nome, Candidato.filial_id_seq).all()

        # Log para debug (remova depois de testar)
        app.logger.info(f"Filiais carregadas: {len(filiais)}")
        app.logger.info(f"Candidatos carregados: {len(candidatos)}")
        for filial in filiais:
            app.logger.info(f"Filial: {filial.nome} (ID: {filial.id})")
        for cand in candidatos:
            app.logger.info(f"Candidato: {cand.nome} - Filial: {cand.filial_nome} (ID Filial: {cand.filial_id})")

        return render_template("index.html",
                            filiais=filiais,
                            candidatos=candidatos)

    except Exception as e:
        app.logger.error(f"Erro na página inicial: {str(e)}", exc_info=True)
        flash("Erro ao carregar a página de votação", "danger")
        # Retorna listas vazias para evitar erros no template
        return render_template("index.html", filiais=[], candidatos=[])

@app.route('/votar', methods=['POST'])
@csrf.exempt  # Isenta CSRF para esta rota específica se necessário
def votar():
    cpf = request.form["cpf"].strip()
    filial_id = request.form["filial"].strip()
    candidato_id = request.form["candidato"].strip()

    if not all([cpf, filial_id, candidato_id]):
        flash("Todos os campos são obrigatórios!", "danger")
        return redirect(url_for("index"))

    cpf_valido, mensagem = validar_cpf(cpf)
    if not cpf_valido:
        flash(f"Erro: {mensagem}", "danger")
        return redirect(url_for("index"))

    try:
        if Voto.query.filter_by(cpf=cpf).first():
            flash("Este CPF já votou! Cada pessoa pode votar apenas uma vez.", "warning")
            return redirect(url_for("index"))

        novo_voto = Voto(
            cpf=cpf,
            filial_id=filial_id,
            candidato_id=candidato_id
        )
        db.session.add(novo_voto)
        db.session.commit()

        registrar_log("Voto registrado", session.get('user_id'))
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

    filial_filtro = request.args.get('filial', 'Todas Filiais')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    # Query principal incluindo a foto do candidato
    query = db.session.query(
        Candidato.nome,
        Candidato.foto,  # Adicionado a foto aqui
        db.func.count(Voto.id).label('votos'),
        db.func.max(Voto.data_voto).label('ultimo_voto')
    ).join(Voto, Voto.candidato_id == Candidato.id
          ).join(Filial, Voto.filial_id == Filial.id)

    # Aplicar filtros
    if filial_filtro != 'Todas Filiais':
        query = query.filter(Filial.nome == filial_filtro)
    if data_inicio:
        query = query.filter(db.func.date(Voto.data_voto) >= data_inicio)
    if data_fim:
        query = query.filter(db.func.date(Voto.data_voto) <= data_fim)

    resultados_raw = query.group_by(Candidato.nome, Candidato.foto).order_by(db.desc('votos')).all()

    # Processar resultados incluindo a foto
    resultados = []
    for nome, foto, votos, ultimo_voto in resultados_raw:
        dt_brasil = converter_para_brasil(ultimo_voto)
        resultados.append((
            nome,
            votos,
            formatar_data_brasil(dt_brasil),
            foto  # Incluindo a foto na tupla
        ))

    # Query para detalhes dos votos
    detalhes_query = db.session.query(
        Voto.cpf,
        Filial.nome,
        Candidato.nome,
        Voto.data_voto
    ).join(Candidato, Voto.candidato_id == Candidato.id
          ).join(Filial, Voto.filial_id == Filial.id)

    # Aplicar os mesmos filtros
    if filial_filtro != 'Todas Filiais':
        detalhes_query = detalhes_query.filter(Filial.nome == filial_filtro)
    if data_inicio:
        detalhes_query = detalhes_query.filter(db.func.date(Voto.data_voto) >= data_inicio)
    if data_fim:
        detalhes_query = detalhes_query.filter(db.func.date(Voto.data_voto) <= data_fim)

    detalhes_raw = detalhes_query.order_by(Voto.data_voto.desc()).all()

    # Processar detalhes dos votos
    detalhes_votos = []
    for cpf, filial, candidato, data_voto in detalhes_raw:
        dt_brasil = converter_para_brasil(data_voto)
        detalhes_votos.append((
            cpf[:3] + '.***.***-**',  # Mascarar CPF
            filial,
            candidato,
            formatar_data_brasil(dt_brasil)
        ))

    # Calcular total de votos
    total_query = db.session.query(db.func.count(Voto.id))
    if filial_filtro != 'Todas Filiais':
        total_query = total_query.join(Filial, Voto.filial_id == Filial.id).filter(Filial.nome == filial_filtro)
    if data_inicio:
        total_query = total_query.filter(db.func.date(Voto.data_voto) >= data_inicio)
    if data_fim:
        total_query = total_query.filter(db.func.date(Voto.data_voto) <= data_fim)

    total_votos = total_query.scalar() or 0

    # Obter lista de filiais para o dropdown
    filiais = [f[0] for f in db.session.query(Filial.nome).all()]

    return render_template(
        "resultados.html",
        resultados=resultados,
        detalhes_votos=detalhes_votos,
        filiais=filiais,
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

@app.route("/admin")
@login_required(level="admin")
def admin():
    try:
        # Estatísticas totais
        total_filiais = Filial.query.count()
        total_candidatos = Candidato.query.filter_by(ativa=True).count()
        total_votos = Voto.query.count()

        # Query para filiais (id, nome, status)
        filiais = db.session.query(
            Filial.id,
            Filial.nome,
            Filial.ativa
        ).order_by(Filial.nome).all()

        # Query para candidatos (id, nome, filial, status)
        candidatos = db.session.query(
            Candidato.id,
            Candidato.nome,
            Filial.nome.label('filial_nome'),
            Candidato.ativa
        ).join(Filial, Candidato.filial_id == Filial.id
        ).order_by(Filial.nome, Candidato.nome).all()

        # Registrar acesso ao painel
        registrar_log("Acessou painel administrativo", session['user_id'])

        return render_template(
            "admin.html",
            total_filiais=total_filiais,
            total_candidatos=total_candidatos,
            total_votos=total_votos,
            filiais=filiais,
            candidatos=candidatos
        )

    except Exception as e:
        app.logger.error(f"Erro no painel admin: {str(e)}")
        registrar_log(f"Erro no painel admin: {str(e)}", session.get('user_id'))
        flash("Ocorreu um erro ao carregar o painel administrativo", "danger")
        return redirect(url_for('index'))

@app.route("/admin/resetar_votos", methods=['POST'])
@login_required(level="admin")
def resetar_votos():
    if request.method == 'POST':
        try:
            # Verificação CSRF correta (usando o método verificado do Flask-WTF)
            csrf.protect()  # Isso valida automaticamente o token CSRF
            
            usuario = Usuario.query.get(session['user_id'])
            registrar_log("Iniciou reset de votos", usuario.id)
            
            # Resetar votos
            num_votos = db.session.query(Voto).count()
            db.session.query(Voto).delete()
            db.session.commit()
            
            registrar_log(f"Reset de votos concluído - {num_votos} votos removidos", usuario.id)
            flash(f"Todos os {num_votos} votos foram resetados com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            registrar_log(f"Falha ao resetar votos: {str(e)}", session.get('user_id'))
            flash(f"Erro ao resetar votos: {str(e)}", "danger")
        
        return redirect(url_for('admin'))
@app.route("/admin/filiais", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_filiais():
    # Configuração da paginação
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Número de itens por página

    if request.method == 'POST':
        if 'nome_filial' in request.form:
            nome = request.form['nome_filial'].strip().upper()
            try:
                filial = Filial(nome=nome)
                db.session.add(filial)
                db.session.commit()
                registrar_log(f"Filial {nome} adicionada", session['user_id'])
                flash(f"Filial {nome} adicionada com sucesso!", "success")
                return redirect(url_for('gerenciar_filiais', page=page))
            except Exception as e:
                db.session.rollback()
                registrar_log(f"Erro ao adicionar filial: {str(e)}", session['user_id'])
                flash("Esta filial já existe ou houve um erro!", "danger")
        
        elif 'toggle_filial' in request.form:
            filial_id = request.form['toggle_filial']
            filial = Filial.query.get(filial_id)
            if filial:
                filial.ativa = not filial.ativa
                db.session.commit()
                registrar_log(f"Status da filial {filial.nome} alterado para {'Ativa' if filial.ativa else 'Inativa'}", session['user_id'])
                flash("Status da filial atualizado com sucesso!", "success")
                return redirect(url_for('gerenciar_filiais', page=page))
        
        elif 'excluir_filial' in request.form:
            filial_id = request.form['excluir_filial']
            filial = Filial.query.get(filial_id)
            if filial:
                try:
                    db.session.delete(filial)
                    db.session.commit()
                    registrar_log(f"Filial {filial.nome} excluída", session['user_id'])
                    flash("Filial excluída com sucesso!", "success")
                    return redirect(url_for('gerenciar_filiais', page=page))
                except Exception as e:
                    db.session.rollback()
                    registrar_log(f"Erro ao excluir filial: {str(e)}", session['user_id'])
                    flash("Não é possível excluir - filial possui candidatos ou votos associados!", "danger")
        
        return redirect(url_for('gerenciar_filiais', page=page))

    # Query para filiais com paginação
    query = db.session.query(
        Filial.id,
        Filial.nome,
        Filial.ativa,
        db.func.strftime('%d/%m/%Y %H:%M', Filial.data_criacao).label('data_criacao')
    ).order_by(Filial.nome)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    filiais = pagination.items

    total_ativas = sum(1 for f in filiais if f[2])  # Índice 2 = ativa
    total_inativas = sum(1 for f in filiais if not f[2])

    return render_template("admin_filiais.html",
                         filiais=filiais,
                         total_ativas=total_ativas,
                         total_inativas=total_inativas,
                         pagination=pagination)


@app.route("/admin/candidatos", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_candidatos():
    # Configuração da paginação
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if request.method == 'POST':
        if 'nome_candidato' in request.form:
            nome = request.form['nome_candidato'].strip()
            filial_id = request.form['filial_candidato']
            foto = None
            
            # Obter o próximo ID sequencial para a filial
            max_id = db.session.query(db.func.max(Candidato.filial_id_seq))\
                      .filter_by(filial_id=filial_id)\
                      .scalar() or 0  # Retorna 0 se não houver candidatos
            novo_id = max_id + 1

            # Processar upload de foto
            if 'foto_candidato' in request.files:
                file = request.files['foto_candidato']
                if file and allowed_file(file.filename):
                    try:
                        if file.content_length > 2 * 1024 * 1024:
                            flash("Arquivo muito grande (tamanho máximo: 2MB)", "danger")
                            return redirect(url_for('gerenciar_candidatos'))
                        
                        ext = file.filename.rsplit('.', 1)[1].lower()
                        filename = f"cand_{filial_id}_{novo_id}.{ext}"
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
                        registrar_log(f"Candidato {candidato.nome} (ID Filial: {candidato.filial_id_seq}) excluído", session['user_id'])
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
                    
                    # Se mudou de filial, reatribuir o ID sequencial
                    if novo_filial_id != candidato.filial_id:
                        max_id = db.session.query(db.func.max(Candidato.filial_id_seq))\
                                  .filter_by(filial_id=novo_filial_id)\
                                  .scalar() or 0
                        candidato.filial_id_seq = max_id + 1
                        candidato.filial_id = novo_filial_id
                    
                    if 'remover_foto' in request.form:
                        if candidato.foto and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto)):
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto))
                        candidato.foto = None
                    
                    if 'nova_foto' in request.files:
                        file = request.files['nova_foto']
                        if file and allowed_file(file.filename):
                            if candidato.foto and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto)):
                                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidato.foto))
                            
                            filename = secure_filename(f"cand_{candidato.filial_id}_{candidato.filial_id_seq}.{file.filename.rsplit('.', 1)[1].lower()}")
                            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                            candidato.foto = filename
                    
                    db.session.commit()
                    registrar_log(f"Candidato {candidato.nome} (ID Filial: {candidato.filial_id_seq}) atualizado", session['user_id'])
                    flash("Candidato atualizado com sucesso!", "success")
                    return redirect(url_for('gerenciar_candidatos'))
                
                except Exception as e:
                    db.session.rollback()
                    registrar_log(f"Erro ao atualizar candidato: {str(e)}", session['user_id'])
                    flash(f"Erro ao atualizar candidato: {str(e)}", "danger")
                    return redirect(url_for('gerenciar_candidatos'))

    # Query para candidatos com paginação (incluindo filial_id_seq)
    query = db.session.query(
        Candidato.id,
        Candidato.nome,
        Filial.nome.label('filial'),
        Candidato.ativa,
        Candidato.foto,
        Candidato.filial_id_seq,
        Filial.id.label('filial_id'),
        db.func.strftime('%d/%m/%Y %H:%M', Candidato.data_criacao).label('data_formatada')
    ).join(Filial).order_by(Filial.nome, Candidato.filial_id_seq)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    candidatos = pagination.items

    filiais = Filial.query.filter_by(ativa=True).order_by(Filial.nome).all()
    total_ativas = sum(1 for c in candidatos if c[3])  # Índice 3 = ativa
    total_inativas = sum(1 for c in candidatos if not c[3])

    return render_template(
        "admin_candidatos.html",
        candidatos=candidatos,
        filiais=filiais,
        total_ativas=total_ativas,
        total_inativas=total_inativas,
        pagination=pagination
    )

@app.route("/admin/logs")
@login_required(level="admin")
def visualizar_logs():
    try:
        # Consulta segura com tratamento de erros
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

        # Processamento dos dados
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
        votos = db.session.query(
            Voto.cpf,
            Filial.nome,
            Candidato.nome,
            db.func.strftime('%d/%m/%Y %H:%M', Voto.data_voto).label('data_voto')
        ).join(Candidato).join(Filial).order_by(Voto.data_voto.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['CPF', 'Filial', 'Candidato', 'Data/Hora'])
        writer.writerows(votos)

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name='votos_cipa.csv'
        )
    
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

# Comandos CLI
@app.cli.command('create-admin')
def create_admin():
    """Cria um usuário admin"""
    username = input("Nome de usuário: ")
    password = input("Senha: ")
    
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = Usuario(username=username, password_hash=hashed_pw, nivel='admin')
    
    db.session.add(admin)
    db.session.commit()
    print(f"Usuário admin '{username}' criado com sucesso!")

    app.cli.add_command(create_admin)

if __name__ == "__main__":
    app.run(debug=True)