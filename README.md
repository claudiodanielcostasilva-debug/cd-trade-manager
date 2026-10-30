# CD Trade Manager — com banco de dados

Contas, login e dados (trades, parametros, lancamentos) ficam salvos no servidor.

## Como rodar no seu PC

1. Instale o Node.js (https://nodejs.org/) versao 18+

2. Abra o terminal na pasta cd-trade-server e rode:

   npm install
   npm start

3. Abra no navegador: http://localhost:3000

Se a porta 3000 estiver ocupada:

   PORT=3456 npm start

## O que foi criado

- API Node.js (Express)
- Banco em arquivo data/db.json (usuarios, sessoes, dados de cada conta)
- Senhas com hash bcrypt (nunca em texto puro)
- Frontend conectado a API (login, registro, salvar trades no servidor)

## Rotas da API

- POST /api/register  body: nome, login, senha
- POST /api/login     body: login, senha
- POST /api/logout    header Authorization Bearer token
- GET  /api/me
- POST /api/change-password  body: senhaAtual, senhaNova
- GET  /api/data
- PUT  /api/data      body: params, trades, operacoes

## Publicar na internet

Use Railway, Render ou Fly.io: envie a pasta, comando npm start.
Mantenha a pasta data persistente para nao perder contas ao reiniciar.
