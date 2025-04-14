📝 Descrição
Sistema completo para gerenciamento de eleições da CIPA (Comissão Interna de Prevenção de Acidentes), com módulos para:

🗳️ Votação eletrônica segura

🏢 Gerenciamento de filiais

👥 Cadastro de candidatos

📊 Apuração de resultados em tempo real

📜 Registro de logs de atividades

✨ Funcionalidades
Principais
* Sistema de votação com validação de CPF

* Painel administrativo completo

* Gerenciamento de candidatos com upload de fotos

* Filtros avançados para resultados (por filial e período)

* Reset seguro de votos (com confirmação)

Segurança
* Autenticação de usuários com níveis de acesso

* Proteção CSRF em formulários

* Hash de senhas com bcrypt

* Rate limiting para prevenção de ataques

🛠️ Tecnologias
Backend:

* Python 3

* Flask

* Flask-SQLAlchemy

* Flask-Migrate

* Flask-WTF

* Bcrypt

* Frontend:

* Bootstrap 5

* AdminLTE 3

* Font Awesome

* Chart.js

* Banco de Dados:

* SQLite (padrão)

🚀 Uso
Acesse a votação: http://localhost:5000

Painel admin: http://localhost:5000/admin

Login padrão: (criado via comando create-admin)

📂 Estrutura de Arquivos
Copy
eleicao-cipa/
├── static/              # Arquivos estáticos
│   ├── css/             # Estilos customizados
│   └── uploads/         # Fotos de candidatos
├── templates/           # Templates HTML
├── eleicaocipa.py       # Aplicação principal
├── config.py            # Configurações
├── requirements.txt     # Dependências
└── migrations/          # Migrações do banco de dados
📄 Licença
Este projeto está sob a licença MIT. Consulte o arquivo LICENSE para mais detalhes.

Desenvolvido por Gabriel Raasch