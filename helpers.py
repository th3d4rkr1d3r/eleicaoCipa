import pytz
from datetime import datetime
from flask import current_app

TZ_BRASIL = pytz.timezone('America/Sao_Paulo')


def converter_para_brasil(dt):
    """Converte datetime para o fuso horário do Brasil com tratamento robusto"""
    try:
        if dt is None:
            current_app.logger.warning("Data None recebida para conversão")
            return None

        if isinstance(dt, str):
            try:
                dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f' if '.' in dt else '%Y-%m-%d %H:%M:%S')
            except ValueError:
                current_app.logger.error(f"Formato de data inválido: {dt}")
                return None

        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)

        return dt.astimezone(TZ_BRASIL)

    except Exception as e:
        current_app.logger.error(f"Erro na conversão de horário: {str(e)}")
        return None


def formatar_data_brasil(dt):
    """Formata datetime com tratamento de erros"""
    try:
        if dt is None:
            return "Data inválida"
        return dt.strftime('%d/%m/%Y %H:%M')
    except Exception as e:
        current_app.logger.error(f"Erro ao formatar data: {str(e)}")
        return "Formato inválido"