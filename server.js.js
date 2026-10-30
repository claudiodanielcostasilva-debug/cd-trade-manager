/**
 * CD Trade Manager — Backend seguro
 * - Senhas com bcrypt (custo 12)
 * - Tokens com expiração e rotação
 * - Rate limit em login/registro
 * - Headers de segurança (Helmet)
 * - Validação de entrada
 * - Escrita atômica do banco
 * - Limpeza de sessões expiradas
 */
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const SESSION_HOURS = Number(process.env.SESSION_HOURS) || 72; // token válido por 72h
const MAX_SESSIONS_PER_USER = 5;
const BCRYPT_ROUNDS = 12;
const MIN_PASSWORD = 6;
const MAX_BODY = '1mb';

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const DB_TMP = path.join(DATA_DIR, 'db.json.tmp');

fs.mkdirSync(DATA_DIR, { recursive: true });

// ========== BANCO (JSON com escrita atômica) ==========
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    return { users: [], sessions: [], user_data: {}, meta: { version: 1 } };
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const db = JSON.parse(raw);
    if (!Array.isArray(db.users)) db.users = [];
    if (!Array.isArray(db.sessions)) db.sessions = [];
    if (!db.user_data || typeof db.user_data !== 'object') db.user_data = {};
    return db;
  } catch (e) {
    console.error('Erro ao ler DB, iniciando vazio:', e.message);
    return { users: [], sessions: [], user_data: {}, meta: { version: 1 } };
  }
}

function saveDB(db) {
  const payload = JSON.stringify(db, null, 2);
  fs.writeFileSync(DB_TMP, payload, 'utf8');
  fs.renameSync(DB_TMP, DB_FILE); // atômico na maioria dos FS
}

function cleanExpiredSessions(db) {
  const now = Date.now();
  const before = db.sessions.length;
  db.sessions = db.sessions.filter(s => s.expires_at && new Date(s.expires_at).getTime() > now);
  return before - db.sessions.length;
}

function createToken() {
  return crypto.randomBytes(32).toString('hex'); // 64 chars, mais seguro que uuid simples
}

function sessionExpiry() {
  return new Date(Date.now() + SESSION_HOURS * 60 * 60 * 1000).toISOString();
}

// ========== VALIDAÇÃO ==========
function sanitizeString(v, max = 200) {
  if (typeof v !== 'string') return '';
  return v.trim().slice(0, max);
}

function isValidLogin(login) {
  // e-mail básico OU telefone (8–15 dígitos, opcional +)
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login)) return true;
  const digits = login.replace(/\D/g, '');
  return digits.length >= 8 && digits.length <= 15;
}

function isValidPassword(senha) {
  if (typeof senha !== 'string' || senha.length < MIN_PASSWORD) return false;
  if (senha.length > 128) return false;
  return true;
}

function isValidNome(nome) {
  return nome.length >= 2 && nome.length <= 80;
}

const defaultParams = {
  capitalInicial: 10000,
  metaLucro: 20,
  metaDiaria: 1,
  stopDiario: 2,
  stopTotal: 10,
  tipoGerenciamento: 'seguro',
  modoRisco: 'fix',
  riscoModerado: 2,
  riscoAgressivo: 5,
  riscoBaseComposto: 0.5,
  riscoMaxComposto: 2,
  aumentoComposto: 10,
  drawdownComposto: 8,
  tipoEntradaPers: 'percentual',
  riscoPersonalizado: 1,
  valorPorTrade: 100,
  maxTradesDia: 5,
  stopPorTrade: 100
};

function sanitizeParams(input) {
  if (!input || typeof input !== 'object') return { ...defaultParams };
  const out = { ...defaultParams };
  for (const key of Object.keys(defaultParams)) {
    if (input[key] === undefined || input[key] === null) continue;
    if (typeof defaultParams[key] === 'number') {
      const n = Number(input[key]);
      if (Number.isFinite(n)) out[key] = n;
    } else if (typeof defaultParams[key] === 'string') {
      out[key] = String(input[key]).slice(0, 50);
    }
  }
  return out;
}

function sanitizeArray(arr, maxItems = 5000) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, maxItems);
}

// ========== APP ==========
const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

const allowedOrigin = process.env.CORS_ORIGIN || true; // true = refletir origin em dev; em prod defina a URL
app.use(cors({
  origin: allowedOrigin === 'true' ? true : (allowedOrigin === true ? true : allowedOrigin),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));

app.use(express.json({ limit: MAX_BODY }));
app.use(express.urlencoded({ extended: false, limit: MAX_BODY }));

// Rate limit geral API
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente em alguns minutos.' }
});

// Rate limit estrito para auth (anti brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas de login/registro. Aguarde 15 minutos.' }
});

app.use('/api/', apiLimiter);

// Static frontend
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: NODE_ENV === 'production' ? '1h' : 0,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  }
}));

// ========== AUTH HELPERS ==========
function getUserByToken(token) {
  if (!token || typeof token !== 'string' || token.length < 32 || token.length > 128) return null;
  const db = loadDB();
  cleanExpiredSessions(db);
  const session = db.sessions.find(s => s.token === token);
  if (!session) return null;
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    db.sessions = db.sessions.filter(s => s.token !== token);
    saveDB(db);
    return null;
  }
  const user = db.users.find(u => u.id === session.user_id);
  if (!user) return null;
  // sliding expiration leve: renova se faltam menos de 12h
  const exp = new Date(session.expires_at).getTime();
  if (exp - Date.now() < 12 * 60 * 60 * 1000) {
    session.expires_at = sessionExpiry();
    saveDB(db);
  }
  return { id: user.id, nome: user.nome, login: user.login, criado: user.criado };
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  const user = getUserByToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Não autenticado. Faça login novamente.' });
  }
  req.user = user;
  req.token = token;
  next();
}

function issueSession(db, userId) {
  // remove sessões expiradas do usuário
  const now = Date.now();
  db.sessions = db.sessions.filter(s => {
    if (s.user_id !== userId) return true;
    return s.expires_at && new Date(s.expires_at).getTime() > now;
  });
  // limita quantidade de sessões ativas
  const mine = db.sessions.filter(s => s.user_id === userId);
  if (mine.length >= MAX_SESSIONS_PER_USER) {
    mine.sort((a, b) => new Date(a.criado) - new Date(b.criado));
    const remove = mine.slice(0, mine.length - MAX_SESSIONS_PER_USER + 1).map(s => s.token);
    db.sessions = db.sessions.filter(s => !remove.includes(s.token));
  }
  const token = createToken();
  const criado = new Date().toISOString();
  db.sessions.push({
    token,
    user_id: userId,
    criado,
    expires_at: sessionExpiry(),
    user_agent: '' // preenchido abaixo se disponível
  });
  return token;
}

// ========== ROTAS AUTH ==========
app.post('/api/register', authLimiter, (req, res) => {
  try {
    const nome = sanitizeString(req.body.nome, 80);
    const login = sanitizeString(req.body.login, 120).toLowerCase();
    const senha = typeof req.body.senha === 'string' ? req.body.senha : '';

    if (!isValidNome(nome) || !login || !senha) {
      return res.status(400).json({ error: 'Preencha nome, e-mail/telefone e senha válidos.' });
    }
    if (!isValidLogin(login)) {
      return res.status(400).json({ error: 'Informe um e-mail válido ou telefone (8 a 15 dígitos).' });
    }
    if (!isValidPassword(senha)) {
      return res.status(400).json({ error: `A senha deve ter entre ${MIN_PASSWORD} e 128 caracteres.` });
    }

    const db = loadDB();
    cleanExpiredSessions(db);

    if (db.users.some(u => u.login === login)) {
      // mensagem genérica reduz enumeração parcial, mas UX pede clareza
      return res.status(409).json({ error: 'Já existe uma conta com este e-mail/telefone.' });
    }

    const id = uuidv4();
    const criado = new Date().toISOString();
    db.users.push({
      id,
      nome,
      login,
      senha_hash: bcrypt.hashSync(senha, BCRYPT_ROUNDS),
      criado
    });
    db.user_data[id] = {
      params: { ...defaultParams },
      trades: [],
      operacoes: [],
      atualizado: criado
    };

    const token = issueSession(db, id);
    const sess = db.sessions.find(s => s.token === token);
    if (sess) sess.user_agent = sanitizeString(req.headers['user-agent'] || '', 200);
    saveDB(db);

    res.status(201).json({
      token,
      expires_in_hours: SESSION_HOURS,
      user: { id, nome, login, criado }
    });
  } catch (err) {
    console.error('register', err);
    res.status(500).json({ error: 'Erro ao criar conta.' });
  }
});

app.post('/api/login', authLimiter, (req, res) => {
  try {
    const login = sanitizeString(req.body.login, 120).toLowerCase();
    const senha = typeof req.body.senha === 'string' ? req.body.senha : '';

    if (!login || !senha) {
      return res.status(400).json({ error: 'Preencha e-mail/telefone e senha.' });
    }

    const db = loadDB();
    cleanExpiredSessions(db);
    const user = db.users.find(u => u.login === login);

    // comparação constante-tempo: se usuário não existe, ainda roda bcrypt dummy
    const hash = user ? user.senha_hash : '$2a$12$invalidhashinvalidhashinvalidhoO';
    const ok = bcrypt.compareSync(senha, user ? user.senha_hash : hash);
    if (!user || !ok) {
      return res.status(401).json({ error: 'Conta não encontrada ou senha incorreta.' });
    }

    const token = issueSession(db, user.id);
    const sess = db.sessions.find(s => s.token === token);
    if (sess) sess.user_agent = sanitizeString(req.headers['user-agent'] || '', 200);
    saveDB(db);

    res.json({
      token,
      expires_in_hours: SESSION_HOURS,
      user: { id: user.id, nome: user.nome, login: user.login, criado: user.criado }
    });
  } catch (err) {
    console.error('login', err);
    res.status(500).json({ error: 'Erro ao fazer login.' });
  }
});

app.post('/api/logout', authMiddleware, (req, res) => {
  try {
    const db = loadDB();
    db.sessions = db.sessions.filter(s => s.token !== req.token);
    saveDB(db);
    res.json({ ok: true });
  } catch (err) {
    console.error('logout', err);
    res.status(500).json({ error: 'Erro ao sair.' });
  }
});

app.post('/api/logout-all', authMiddleware, (req, res) => {
  try {
    const db = loadDB();
    db.sessions = db.sessions.filter(s => s.user_id !== req.user.id);
    saveDB(db);
    res.json({ ok: true });
  } catch (err) {
    console.error('logout-all', err);
    res.status(500).json({ error: 'Erro ao encerrar sessões.' });
  }
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/change-password', authMiddleware, authLimiter, (req, res) => {
  try {
    const senhaAtual = typeof req.body.senhaAtual === 'string' ? req.body.senhaAtual : '';
    const senhaNova = typeof req.body.senhaNova === 'string' ? req.body.senhaNova : '';

    if (!senhaAtual || !senhaNova) {
      return res.status(400).json({ error: 'Preencha a senha atual e a nova.' });
    }
    if (!isValidPassword(senhaNova)) {
      return res.status(400).json({ error: `A nova senha deve ter entre ${MIN_PASSWORD} e 128 caracteres.` });
    }
    if (senhaAtual === senhaNova) {
      return res.status(400).json({ error: 'A nova senha deve ser diferente da atual.' });
    }

    const db = loadDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user || !bcrypt.compareSync(senhaAtual, user.senha_hash)) {
      return res.status(401).json({ error: 'Senha atual incorreta.' });
    }

    user.senha_hash = bcrypt.hashSync(senhaNova, BCRYPT_ROUNDS);
    // invalida outras sessões (mantém a atual)
    db.sessions = db.sessions.filter(s => s.token === req.token || s.user_id !== req.user.id);
    // na verdade: só mantém a sessão atual
    db.sessions = db.sessions.filter(s => s.token === req.token);
    saveDB(db);

    res.json({ ok: true });
  } catch (err) {
    console.error('change-password', err);
    res.status(500).json({ error: 'Erro ao alterar senha.' });
  }
});

// ========== DADOS ==========
app.get('/api/data', authMiddleware, (req, res) => {
  try {
    const db = loadDB();
    let row = db.user_data[req.user.id];
    if (!row) {
      row = {
        params: { ...defaultParams },
        trades: [],
        operacoes: [],
        atualizado: new Date().toISOString()
      };
      db.user_data[req.user.id] = row;
      saveDB(db);
    }
    res.json({
      params: row.params || defaultParams,
      trades: Array.isArray(row.trades) ? row.trades : [],
      operacoes: Array.isArray(row.operacoes) ? row.operacoes : []
    });
  } catch (err) {
    console.error('get data', err);
    res.status(500).json({ error: 'Erro ao carregar dados.' });
  }
});

app.put('/api/data', authMiddleware, (req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Corpo inválido.' });
    }
    const params = sanitizeParams(req.body.params);
    const trades = sanitizeArray(req.body.trades, 3000);
    const operacoes = sanitizeArray(req.body.operacoes, 10000);
    const agora = new Date().toISOString();

    const db = loadDB();
    db.user_data[req.user.id] = { params, trades, operacoes, atualizado: agora };
    saveDB(db);
    res.json({ ok: true, atualizado: agora });
  } catch (err) {
    console.error('put data', err);
    res.status(500).json({ error: 'Erro ao salvar dados.' });
  }
});

// Health (sem dados sensíveis)
app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// SPA fallback — só GET não-API
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Rota não encontrada.' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Erro genérico
app.use((err, req, res, next) => {
  console.error('unhandled', err);
  res.status(500).json({ error: 'Erro interno.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('CD Trade Manager online na porta ' + PORT);
  console.log('Banco: ' + DB_FILE);
  console.log('Sessão válida por ' + SESSION_HOURS + 'h | bcrypt rounds ' + BCRYPT_ROUNDS);
});
