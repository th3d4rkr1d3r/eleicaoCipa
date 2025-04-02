from flask import Flask, render_template, request, redirect, flash, url_for
import sqlite3
import os
import threading
import hashlib
from playsound import playsound
from functools import wraps
from flask import session, redirect, url_for, abort

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_super_forte_aqui'

# Credenciais de acesso (em produção, use um banco de dados com senhas criptografadas!)
USUARIOS = {
    "admin": "cipa2024",
    "comissao": "eleicao123"
}

# Configuração das filiais
FILIAIS = ["ITAJAI", "NAVEGANTES", "RECIFE", "VITORIA", "GOIANIA", "SAO JOSE DOS PINHAIS"]



def login_required(level="user"):
    """Decorator para verificar se o usuário está logado e tem o nível necessário"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login', next=request.url))

            # Verifica o nível de acesso
            conn = sqlite3.connect("eleicao_cipa.db")
            cursor = conn.cursor()
            cursor.execute("SELECT nivel FROM usuarios WHERE id = ?", (session['user_id'],))
            user_level = cursor.fetchone()[0]
            conn.close()

            # Hierarquia de níveis: admin > operador > user
            access_levels = ["admin", "operador", "user"]
            if access_levels.index(user_level) > access_levels.index(level):
                abort(403)  # Acesso proibido

            return f(*args, **kwargs)

        return decorated_function

    return decorator

def criar_banco():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS filiais (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           nome TEXT UNIQUE,
                           ativa BOOLEAN DEFAULT 1)''')

    # Atualizar a tabela se ela já existia
    try:
        cursor.execute("ALTER TABLE filiais ADD COLUMN ativa BOOLEAN DEFAULT 1")
    except sqlite3.OperationalError:
        pass  # Coluna já existe
    try:
        cursor.execute("ALTER TABLE candidatos ADD COLUMN ativa BOOLEAN DEFAULT 1")
    except sqlite3.OperationalError:
        pass  # Coluna já existe
    # Tabela de candidatos
    cursor.execute('''CREATE TABLE IF NOT EXISTS candidatos (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        nome TEXT,
                        filial_id INTEGER,
                        FOREIGN KEY (filial_id) REFERENCES filiais(id))''')

    # Tabela de votos (já existente)
    cursor.execute('''CREATE TABLE IF NOT EXISTS votos (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cpf TEXT UNIQUE,
                        filial_id INTEGER,
                        candidato_id INTEGER,
                        data_voto TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (filial_id) REFERENCES filiais(id),
                        FOREIGN KEY (candidato_id) REFERENCES candidatos(id))''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                            id INTEGER PRIMARY KEY,
                            username TEXT UNIQUE,
                            password_hash TEXT,
                            nivel TEXT)''')

    # Cria usuário admin padrão se não existir
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        senha_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("INSERT INTO usuarios (username, password_hash, nivel) VALUES (?, ?, ?)",
                       ("admin", senha_hash, "admin"))

    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          acao TEXT,
                          usuario_id INTEGER,
                          data TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    conn.commit()
    conn.close()


def tocar_som():
    """Reproduz o som da urna eletrônica"""
    try:
        caminho_som = os.path.join(app.static_folder, "urna.mp3")
        if os.path.exists(caminho_som):
            threading.Thread(target=playsound, args=(caminho_som,)).start()
    except Exception as e:
        app.logger.error(f"Erro ao reproduzir som: {str(e)}")


def validar_cpf(cpf):
    """Validação completa de CPF com mensagens específicas"""
    cpf = ''.join(filter(str.isdigit, cpf))

    if len(cpf) != 11:
        return (False, "CPF deve conter 11 dígitos")

    if all(d == cpf[0] for d in cpf):
        return (False, "CPF inválido (números repetidos)")

    # Cálculo do primeiro dígito verificador
    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digito1 = (soma * 10) % 11
    digito1 = digito1 if digito1 < 10 else 0

    if digito1 != int(cpf[9]):
        return (False, "CPF inválido (dígito verificador incorreto)")

    # Cálculo do segundo dígito verificador
    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digito2 = (soma * 10) % 11
    digito2 = digito2 if digito2 < 10 else 0

    if digito2 != int(cpf[10]):
        return (False, "CPF inválido (dígito verificador incorreto)")

    return (True, "CPF válido")


# Sistema de autenticação básica
def requer_autenticacao(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username in USUARIOS and USUARIOS[auth.username] == auth.password):
            return (
                '<h1>Acesso não autorizado</h1>'
                '<p>Você precisa de credenciais válidas para acessar os resultados</p>',
                401,
                {'WWW-Authenticate': 'Basic realm="Resultados CIPA"'}
            )
        return f(*args, **kwargs)

    return decorador


@app.route("/")
def index():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    # Certifique-se que esta query está EXATAMENTE assim
    cursor.execute("SELECT id, nome FROM filiais WHERE ativa = 1 ORDER BY nome")
    filiais = cursor.fetchall()

    cursor.execute('''SELECT c.id, c.nome, f.nome 
                      FROM candidatos c
                      JOIN filiais f ON c.filial_id = f.id
                      WHERE f.ativa = 1
                      ORDER BY f.nome, c.nome''')
    candidatos = cursor.fetchall()

    conn.close()

    # Adicione este print para debug (verá no terminal do Flask)
    print("Filiais carregadas do banco:", filiais)

    return render_template("index.html",
                           filiais=filiais,
                           candidatos=candidatos)


@app.route("/votar", methods=["POST"])
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

    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM votos WHERE cpf = ?", (cpf,))
        if cursor.fetchone()[0] > 0:
            flash("Este CPF já votou! Cada pessoa pode votar apenas uma vez.", "warning")
            return redirect(url_for("index"))

        cursor.execute(
            "INSERT INTO votos (cpf, filial_id, candidato_id) VALUES (?, ?, ?)",
            (cpf, filial_id, candidato_id)  # Corrigido aqui
        )
        conn.commit()
        flash("Voto registrado com sucesso!", "success")
        tocar_som()

    except sqlite3.Error as e:
        flash(f"Erro ao registrar voto: {str(e)}", "danger")
    finally:
        conn.close()

    return redirect(url_for("index"))


@app.route("/resultados")
@login_required(level="user")
def resultados():
    filial_filtro = request.args.get('filial', 'Todas Filiais')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    # Query para resultados
    query = """SELECT c.nome, COUNT(*) as votos, 
               strftime('%d/%m/%Y %H:%M', datetime(v.data_voto, 'localtime')) as data_formatada
               FROM votos v
               JOIN candidatos c ON v.candidato_id = c.id
               JOIN filiais f ON v.filial_id = f.id
               WHERE 1=1"""
    params = []

    if filial_filtro != 'Todas Filiais':
        query += " AND f.nome = ?"
        params.append(filial_filtro)

    if data_inicio:
        query += " AND date(v.data_voto) >= ?"
        params.append(data_inicio)

    if data_fim:
        query += " AND date(v.data_voto) <= ?"
        params.append(data_fim)

    query += " GROUP BY c.nome ORDER BY votos DESC"
    cursor.execute(query, params)
    resultados = cursor.fetchall()

    # Query para detalhes dos votos
    detalhes_query = """SELECT v.cpf, f.nome, c.nome, 
                       strftime('%d/%m/%Y %H:%M', datetime(v.data_voto, 'localtime')) as data_formatada
                       FROM votos v
                       JOIN candidatos c ON v.candidato_id = c.id
                       JOIN filiais f ON v.filial_id = f.id
                       WHERE 1=1"""
    detalhes_params = []

    if filial_filtro != 'Todas Filiais':
        detalhes_query += " AND f.nome = ?"
        detalhes_params.append(filial_filtro)

    if data_inicio:
        detalhes_query += " AND date(v.data_voto) >= ?"
        detalhes_params.append(data_inicio)

    if data_fim:
        detalhes_query += " AND date(v.data_voto) <= ?"
        detalhes_params.append(data_fim)

    cursor.execute(detalhes_query, detalhes_params)
    detalhes_votos = cursor.fetchall()

    # Query para total de votos (COM FILTRO)
    total_query = "SELECT COUNT(*) FROM votos v JOIN filiais f ON v.filial_id = f.id WHERE 1=1"
    total_params = []

    if filial_filtro != 'Todas Filiais':
        total_query += " AND f.nome = ?"
        total_params.append(filial_filtro)

    if data_inicio:
        total_query += " AND date(v.data_voto) >= ?"
        total_params.append(data_inicio)

    if data_fim:
        total_query += " AND date(v.data_voto) <= ?"
        total_params.append(data_fim)

    cursor.execute(total_query, total_params)
    total_votos = cursor.fetchone()[0] or 0

    # Obter lista de filiais para o dropdown
    cursor.execute("SELECT nome FROM filiais")
    filiais = [f[0] for f in cursor.fetchall()]

    conn.close()

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("eleicao_cipa.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, nivel FROM usuarios WHERE username = ? AND password_hash = ?",
                       (username, hashlib.sha256(password.encode()).hexdigest()))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['user_level'] = user[1]
            flash("Login realizado com sucesso!", "success")

            # Redireciona para a URL original ou para o admin
            next_url = request.args.get('next', url_for('admin'))
            return redirect(next_url)
        else:
            flash("Usuário ou senha incorretos", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Você foi desconectado com sucesso.", "info")
    return redirect(url_for('login'))


@app.route("/admin")
@login_required(level="admin")
def admin():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    # Obter estatísticas básicas
    cursor.execute("SELECT COUNT(*) FROM filiais")
    total_filiais = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM candidatos WHERE ativa = 1")  # Só conta candidatos ativos
    total_candidatos = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM votos")
    total_votos = cursor.fetchone()[0] or 0

    # Obter lista de filiais para exibir (com status)
    cursor.execute("SELECT id, nome, ativa FROM filiais ORDER BY nome")
    filiais = cursor.fetchall()

    # Obter lista de candidatos para exibir (com status e nome da filial)
    cursor.execute('''SELECT c.id, c.nome, f.nome, c.ativa
                      FROM candidatos c
                      JOIN filiais f ON c.filial_id = f.id
                      ORDER BY f.nome, c.nome''')
    candidatos = cursor.fetchall()

    conn.close()

    return render_template("admin.html",
                         total_filiais=total_filiais,
                         total_candidatos=total_candidatos,
                         total_votos=total_votos,
                         filiais=filiais,
                         candidatos=candidatos)


# Exemplo de como implementar logs (adicione na rota resetar_votos)
@app.route("/admin/resetar_votos", methods=['POST'])
@login_required(level="admin")
def resetar_votos():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    try:
        # Obter nome do usuário atual para o log
        cursor.execute("SELECT username FROM usuarios WHERE id = ?", (session['user_id'],))
        username = cursor.fetchone()[0]

        # Registrar log com hora local
        from datetime import datetime
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO logs (acao, usuario_id, data) VALUES (?, ?, ?)",
                       (f"Reset de votos realizado por {username}", session['user_id'], now))

        # Resetar votos
        cursor.execute("DELETE FROM votos")
        conn.commit()
        flash("Todos os votos foram resetados com sucesso!", "success")
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Erro ao resetar votos: {str(e)}", "danger")
    finally:
        conn.close()

    return redirect(url_for('admin'))

@app.route("/admin/filiais", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_filiais():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    # Verifica se a coluna data_criacao existe, se não, cria
    try:
        cursor.execute("ALTER TABLE filiais ADD COLUMN data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Coluna já existe

    if request.method == 'POST':
        # Adicionar nova filial
        if 'nome_filial' in request.form:
            nome = request.form['nome_filial'].strip().upper()
            try:
                cursor.execute(
                    "INSERT INTO filiais (nome, ativa, data_criacao) VALUES (?, 1, CURRENT_TIMESTAMP)",
                    (nome,)
                )
                conn.commit()
                flash(f"Filial {nome} adicionada com sucesso!", "success")
            except sqlite3.IntegrityError:
                flash("Esta filial já existe!", "danger")
            return redirect(url_for('gerenciar_filiais'))

        # Toggle status da filial
        elif 'toggle_filial' in request.form:
            filial_id = request.form['toggle_filial']
            cursor.execute("UPDATE filiais SET ativa = NOT ativa WHERE id = ?", (filial_id,))
            conn.commit()
            flash("Status da filial atualizado com sucesso!", "success")
            return redirect(url_for('gerenciar_filiais'))

        # Excluir filial
        elif 'excluir_filial' in request.form:
            filial_id = request.form['excluir_filial']
            try:
                cursor.execute("DELETE FROM filiais WHERE id = ?", (filial_id,))
                conn.commit()
                flash("Filial excluída com sucesso!", "success")
            except sqlite3.IntegrityError as e:
                flash("Não é possível excluir - filial possui candidatos associados!", "danger")
            return redirect(url_for('gerenciar_filiais'))

    # Consulta atualizada para incluir data_criacao
    cursor.execute("""
        SELECT id, nome, ativa, 
               strftime('%d/%m/%Y %H:%M', datetime(data_criacao, 'localtime')) 
        FROM filiais 
        ORDER BY nome
    """)
    filiais = cursor.fetchall()

    conn.close()

    return render_template("admin_filiais.html",
                           filiais=filiais,
                           total_ativas=sum(1 for f in filiais if f[2]),
                           total_inativas=sum(1 for f in filiais if not f[2]))


@app.route("/admin/candidatos", methods=['GET', 'POST'])
@login_required(level="admin")
def gerenciar_candidatos():
    conn = None
    try:
        conn = sqlite3.connect("eleicao_cipa.db")
        cursor = conn.cursor()

        # 1. GARANTIR ESTRUTURA DO BANCO DE DADOS
        # Verifica e cria colunas ausentes com tratamento de erro
        columns_to_add = [
            ("ativa", "BOOLEAN DEFAULT 1"),
            ("data_criacao", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        ]

        for column, definition in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE candidatos ADD COLUMN {column} {definition}")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Coluna já existe

        # 2. PROCESSAR FORMULÁRIOS (POST)
        if request.method == 'POST':
            # Adicionar novo candidato
            if 'nome_candidato' in request.form:
                nome = request.form['nome_candidato'].strip()
                filial_id = request.form['filial_candidato']

                try:
                    cursor.execute(
                        "INSERT INTO candidatos (nome, filial_id, ativa) VALUES (?, ?, 1)",
                        (nome, filial_id)
                    )
                    conn.commit()
                    flash(f"Candidato {nome} adicionado com sucesso!", "success")
                except sqlite3.IntegrityError as e:
                    flash(f"Erro ao adicionar candidato: {str(e)}", "danger")

                return redirect(url_for('gerenciar_candidatos'))

            # Alternar status do candidato
            elif 'toggle_candidato' in request.form:
                candidato_id = request.form['toggle_candidato']
                try:
                    cursor.execute(
                        "UPDATE candidatos SET ativa = NOT ativa WHERE id = ?",
                        (candidato_id,)
                    )
                    conn.commit()
                    flash("Status do candidato atualizado com sucesso!", "success")
                except sqlite3.Error as e:
                    flash(f"Erro ao atualizar status: {str(e)}", "danger")

                return redirect(url_for('gerenciar_candidatos'))

            # Excluir candidato
            elif 'excluir_candidato' in request.form:
                candidato_id = request.form['excluir_candidato']
                try:
                    # Verifica se o candidato tem votos associados
                    cursor.execute(
                        "SELECT COUNT(*) FROM votos WHERE candidato_id = ?",
                        (candidato_id,)
                    )
                    if cursor.fetchone()[0] > 0:
                        flash("Não é possível excluir - candidato possui votos associados!", "warning")
                    else:
                        cursor.execute(
                            "DELETE FROM candidatos WHERE id = ?",
                            (candidato_id,)
                        )
                        conn.commit()
                        flash("Candidato excluído com sucesso!", "success")
                except sqlite3.Error as e:
                    flash(f"Erro ao excluir candidato: {str(e)}", "danger")

                return redirect(url_for('gerenciar_candidatos'))

        # 3. CONSULTA SEGURA DOS DADOS
        # Consulta principal com tratamento para coluna data_criacao
        cursor.execute("""
            SELECT 
                c.id, 
                c.nome, 
                f.nome AS filial, 
                c.ativa,
                COALESCE(
                    strftime('%d/%m/%Y %H:%M', datetime(c.data_criacao, 'localtime')),
                    'N/A'
                ) AS data_formatada
            FROM 
                candidatos c
            JOIN 
                filiais f ON c.filial_id = f.id
            ORDER BY 
                f.nome, c.nome
        """)
        candidatos = cursor.fetchall()

        # Filiais ativas para dropdown
        cursor.execute("""
            SELECT id, nome 
            FROM filiais 
            WHERE ativa = 1 
            ORDER BY nome
        """)
        filiais = cursor.fetchall()

        # Estatísticas
        total_ativas = sum(1 for c in candidatos if c[3])  # índice 3 = ativa
        total_inativas = sum(1 for c in candidatos if not c[3])

    except sqlite3.Error as e:
        flash(f"Erro no banco de dados: {str(e)}", "danger")
        candidatos = []
        filiais = []
        total_ativas = 0
        total_inativas = 0
    finally:
        if conn:
            conn.close()

    # 4. RENDERIZAÇÃO DO TEMPLATE
    return render_template(
        "admin_candidatos.html",
        candidatos=candidatos,
        filiais=filiais,
        total_ativas=total_ativas,
        total_inativas=total_inativas
    )


@app.route("/admin/logs")
@login_required(level="admin")
def visualizar_logs():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()

    cursor.execute('''SELECT l.acao, u.username, 
                     strftime('%d/%m/%Y %H:%M', l.data, 'localtime') as data_local
                     FROM logs l
                     JOIN usuarios u ON l.usuario_id = u.id
                     ORDER BY l.data DESC''')
    logs = cursor.fetchall()

    conn.close()
    return render_template("admin_logs.html", logs=logs)

def criar_usuario_admin():
    conn = sqlite3.connect("eleicao_cipa.db")
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM usuarios WHERE username = 'admin'")
        senha_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute(
            "INSERT OR REPLACE INTO usuarios (username, password_hash, nivel) VALUES (?, ?, ?)",
            ("admin", senha_hash, "admin")
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao criar usuário admin: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    criar_banco()
    criar_usuario_admin()  # Adicione esta linha
    app.run(debug=True)