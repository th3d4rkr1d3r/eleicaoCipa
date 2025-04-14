import os

def listar_estrutura(caminho='.', prefixo=''):
    for item in sorted(os.listdir(caminho)):
        caminho_completo = os.path.join(caminho, item)
        if os.path.isdir(caminho_completo):
            print(f"{prefixo}📁 {item}/")
            listar_estrutura(caminho_completo, prefixo + '    ')
        else:
            print(f"{prefixo}📄 {item}")

# Executar na raiz do projeto
listar_estrutura('.')
