# Servidor e cliente - Protocolo cliente-servidor (1ª entrega)

API REST em Python/FastAPI (servidor) e página HTML/JavaScript (cliente) que seguem o
protocolo `protocolo-cliente-servidor.yaml` (v1.3.1). Os dados do servidor ficam em memória
e somem ao reiniciá-lo.

## Conteúdo do pacote
- `servidor/main.py` - servidor
- `servidor/requirements.txt` - lista das bibliotecas
- `servidor/libs/` - bibliotecas já baixadas (para instalar sem internet)
- `cliente/index.html` - cliente
- `README.md` - este arquivo

## Requisitos
Python 3.9 ou superior (testado com Python 3.11).

## 1. Instalar as bibliotecas
Abra o terminal dentro da pasta `servidor` e use:

Com internet:
```
python -m pip install -r requirements.txt
```
Sem internet (usa a pasta `libs/`):
```
python -m pip install --no-index --find-links libs -r requirements.txt
```
(As bibliotecas da pasta `libs/` foram baixadas para Windows 64 bits com Python 3.11; em outro sistema ou outra versão do Python, use a instalação com internet.)

## 2. Iniciar o servidor
Ainda dentro da pasta `servidor`:
```
python main.py
```
O programa pergunta `Porta do servidor [8000]:`. Digite a porta e tecle Enter (Enter vazio = 8000).
Aparece `Application startup complete` quando está pronto. Para parar: `Ctrl+C`.
O servidor escuta em todas as interfaces (0.0.0.0); se outro computador for acessá-lo,
libere a porta no firewall do Windows.

## 3. Usar o cliente
Abra o arquivo `cliente/index.html` no navegador (dois cliques).
1. No topo, digite o **IP** e a **Porta** do servidor (ex.: `127.0.0.1` e `8000`).
2. **Cadastro**: nome (3 a 50), e-mail (5 a 30), senha (6 a 20, só letras e números).
3. **Login**: depois dele aparecem as opções:
   - Buscar meus dados
   - Atualizar tudo (PUT) ou parcial (PATCH)
   - Apagar minha conta
   - Logout

O cliente funciona com o servidor de qualquer outro aluno que siga o protocolo,
bastando trocar IP e porta.

## Rotas (prefixo /api/v1)
POST /sessions · DELETE /sessions/{id} · POST /users · GET, PUT, PATCH, DELETE /users/{id}

Documentação interativa do servidor: `http://IP:PORTA/docs`

## Decisões não definidas no protocolo
- Id de usuário: inteiro incremental. Id de sessão: UUID.
- Logout de sessão inexistente ou de outro usuário responde 403 (o 403 vem antes do 404).

## Administrador e produtos (protocolo v1.4.0)
- Ao iniciar, o servidor cria um **usuário ADM padrão**: e-mail `admin@admin.com`, senha `admin123`
  (podem ser trocados com as variáveis `ADMIN_EMAIL` e `ADMIN_SENHA`). Cadastros pela API sempre criam usuário comum.
- ADM: lista (`GET /users`), lê, atualiza e apaga qualquer usuário; cadastra, atualiza e remove produtos.
- Usuário comum e ADM: listam e consultam produtos (`GET /products`, `GET /products/{id}`).
- O terminal do servidor mostra a **lista de usuários logados**, atualizada a cada login, logout ou remoção de usuário.
- No cliente, as opções de administração só aparecem para o ADM.