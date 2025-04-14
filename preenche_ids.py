from eleicaocipa import db, app, Candidato
from collections import defaultdict

def populate_ids():
    with app.app_context():
        try:
            # Para cada filial, atualize os IDs sequenciais
            filiais_ids = defaultdict(int)
            
            # Obtém todos os candidatos ordenados por filial e ID
            candidatos = Candidato.query.order_by(Candidato.filial_id, Candidato.id).all()
            
            for candidato in candidatos:
                filiais_ids[candidato.filial_id] += 1
                candidato.filial_id_seq = filiais_ids[candidato.filial_id]
            
            db.session.commit()
            print("✅ IDs sequenciais por filial atualizados com sucesso!")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Erro ao atualizar IDs: {e}")
            raise

if __name__ == "__main__":
    populate_ids()