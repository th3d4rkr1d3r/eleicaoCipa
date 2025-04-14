from eleicaocipa import db, app
from sqlalchemy import text

def add_column():
    with app.app_context():
        try:
            # Forma correta para SQLAlchemy 2.x
            with db.engine.connect() as connection:
                # Verifica se a coluna já existe
                result = connection.execute(
                    text("PRAGMA table_info(candidatos);")
                ).fetchall()
                
                columns = [row[1] for row in result]  # Nomes das colunas
                
                if 'filial_id_seq' not in columns:
                    # Adiciona a coluna se não existir
                    connection.execute(
                        text("ALTER TABLE candidatos ADD COLUMN filial_id_seq INTEGER DEFAULT 1")
                    )
                    connection.commit()
                    print("✅ Coluna filial_id_seq adicionada com sucesso!")
                else:
                    print("ℹ️ Coluna filial_id_seq já existe na tabela")
                    
        except Exception as e:
            print(f"❌ Erro ao adicionar coluna: {e}")
            raise

if __name__ == "__main__":
    add_column()