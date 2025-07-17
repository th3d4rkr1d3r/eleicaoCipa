from eleicaocipa import app, db, Voto

with app.app_context():
    for voto in Voto.query.all():
        cpf_numeros = ''.join(filter(str.isdigit, voto.cpf or ''))
        if cpf_numeros and cpf_numeros != voto.cpf:
            voto.cpf = cpf_numeros
    db.session.commit()
print('CPFs corrigidos!')