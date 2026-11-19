// src/index.js
// API do site de classificados de servicos
// Cloudflare Workers + D1 (registros) + R2 (fotos)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

const L = {
  tituloMin: 3,
  tituloMax: 120,
  descricaoMin: 10,
  descricaoMax: 2000,
  autorMax: 60,
  fotosMax: 5,
  fotoBytesMax: 900 * 1024,
  postsHoraIp: 10,
  tokenHoras: 8,
};

const STATUS_VALIDOS = ['pendente', 'aprovada', 'rejeitada'];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      if (path.startsWith('/media/')) return servirMidia(request, env);

      if (path === '/api/health') return json({ ok: true });

      if (path === '/api/posts' && method === 'GET') return listarPublicos(request, env);
      if (path === '/api/posts' && method === 'POST') return criarPost(request, env);
      if (path === '/api/reports' && method === 'POST') return criarDenuncia(request, env);

      if (path === '/api/admin/login' && method === 'POST') return login(request, env);

      if (path.startsWith('/api/admin/')) {
        const sessao = await exigirAuth(request, env);
        if (!sessao) return erro('Nao autorizado.', 401);

        if (path === '/api/admin/posts' && method === 'GET') return adminListar(request, env, url);
        if (path === '/api/admin/stats' && method === 'GET') return adminStats(env);
        if (path === '/api/admin/reports' && method === 'GET') return adminDenuncias(request, env);

        const rota = /^\/api\/admin\/posts\/([A-Za-z0-9-]+)$/.exec(path);
        if (rota && method === 'PATCH') return adminAtualizar(request, env, rota[1]);
        if (rota && method === 'DELETE') return adminRemover(env, rota[1]);
      }

      return erro('Rota nao encontrada.', 404);
    } catch (e) {
      return erro('Erro interno: ' + (e && e.message ? e.message : 'desconhecido'), 500);
    }
  },
};

/* ---------------- utilidades ---------------- */

function json(dados, status = 200) {
  return new Response(JSON.stringify(dados), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
}

function erro(mensagem, status = 400) {
  return json({ erro: mensagem }, status);
}

const uid = () => crypto.randomUUID();
const agora = () => new Date().toISOString();

async function sha256Hex(texto) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(texto));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function b64url(bytes) {
  const s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlTexto(texto) {
  const bytes = new TextEncoder().encode(texto);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function textoB64url(txt) {
  const base = txt.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(base);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function assinar(env, payload) {
  const segredo = env.TOKEN_SECRET || env.ADMIN_PASSWORD || 'segredo-nao-configurado';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(segredo),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return b64url(sig);
}

async function criarToken(env, usuario) {
  const payload = b64urlTexto(
    JSON.stringify({
      u: usuario,
      exp: Math.floor(Date.now() / 1000) + L.tokenHoras * 3600,
    })
  );
  return payload + '.' + (await assinar(env, payload));
}

async function verificarToken(env, token) {
  if (!token || !token.includes('.')) return null;
  const partes = token.split('.');
  if (partes.length !== 2) return null;
  const [payload, sig] = partes;
  const esperado = await assinar(env, payload);
  if (sig !== esperado) return null;
  try {
    const dados = JSON.parse(textoB64url(payload));
    if (!dados.exp || dados.exp < Math.floor(Date.now() / 1000)) return null;
    return dados;
  } catch {
    return null;
  }
}

async function exigirAuth(request, env) {
  const h = request.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : null;
  return await verificarToken(env, token);
}

function mapPost(row, request) {
  const origin = new URL(request.url).origin;
  let keys = [];
  try {
    keys = JSON.parse(row.fotos || '[]');
  } catch {
    keys = [];
  }
  return {
    id: row.id,
    titulo: row.titulo,
    descricao: row.descricao,
    valor: row.valor === null || row.valor === undefined ? null : Number(row.valor),
    valorTexto: row.valor_texto,
    contatoTipo: row.contato_tipo,
    contato: row.contato,
    autor: row.autor,
    fotos: keys.map((k) => (/^https?:\/\//.test(k) ? k : origin + '/media/' + k)),
    status: row.status,
    criadoEm: row.criado_em,
    aprovadoEm: row.aprovado_em,
  };
}

function validarContato(tipo, valor) {
  const v = String(valor || '').trim();
  if (tipo === 'telefone') {
    const d = v.replace(/\D/g, '');
    if (d.length < 10 || d.length > 11) return 'Telefone deve ter DDD e 10 ou 11 digitos.';
    return null;
  }
  if (tipo === 'email') {
    if (v.length > 80) return 'E-mail muito longo.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) return 'E-mail invalido.';
    return null;
  }
  if (tipo === 'instagram') {
    if (!/^[A-Za-z0-9._]{1,30}$/.test(v.replace(/^@/, ''))) return 'Usuario do Instagram invalido.';
    return null;
  }
  return 'Tipo de contato invalido.';
}

function parseDataUrl(dataUrl) {
  const m = /^data:(image\/(?:png|jpeg|jpg|webp|gif));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl));
  if (!m) return null;
  const mime = m[1] === 'image/jpg' ? 'image/jpeg' : m[1];
  const bin = atob(m[2]);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return { mime, bytes };
}

/* ---------------- midia (R2) ---------------- */

async function servirMidia(request, env) {
  const key = decodeURIComponent(new URL(request.url).pathname.replace('/media/', ''));
  if (!key || key.includes('..') || key.startsWith('/')) {
    return new Response('Nao encontrado', { status: 404, headers: CORS });
  }

  const obj = await env.BUCKET.get(key);
  if (!obj) return new Response('Nao encontrado', { status: 404, headers: CORS });

  const headers = new Headers(CORS);
  obj.writeHttpMetadata(headers);
  headers.set('etag', obj.httpEtag);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  return new Response(obj.body, { headers });
}

/* ---------------- rotas publicas ---------------- */

async function listarPublicos(request, env) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM posts WHERE status = ? ORDER BY COALESCE(aprovado_em, criado_em) DESC LIMIT 100'
  )
    .bind('aprovada')
    .all();

  return json({ posts: (results || []).map((r) => mapPost(r, request)) });
}

async function criarPost(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return erro('Corpo da requisicao invalido.');
  }

  const titulo = String(body.titulo || '').trim();
  const descricao = String(body.descricao || '').trim();
  const autor = String(body.autor || '').trim();
  const contatoTipo = String(body.contatoTipo || '').trim();
  const contato = String(body.contato || '').trim();
  const valor = body.valor === null || body.valor === undefined || body.valor === '' ? null : Number(body.valor);

  if (titulo.length < L.tituloMin) return erro('Titulo muito curto.');
  if (titulo.length > L.tituloMax) return erro('Titulo muito longo.');
  if (descricao.length < L.descricaoMin) return erro('Descricao muito curta.');
  if (descricao.length > L.descricaoMax) return erro('Descricao muito longa.');
  if (!autor || autor.length > L.autorMax) return erro('Informe um nome valido.');
  if (valor !== null && (!Number.isFinite(valor) || valor < 0)) return erro('Valor invalido.');

  const problemaContato = validarContato(contatoTipo, contato);
  if (problemaContato) return erro(problemaContato);

  const ip = request.headers.get('CF-Connecting-IP') || 'desconhecido';
  const ipHash = await sha256Hex(ip + '|' + (env.ADMIN_PASSWORD || 'sal'));
  const umaHoraAtras = new Date(Date.now() - 3600000).toISOString();

  const contagem = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM posts WHERE ip_hash = ? AND criado_em > ?'
  )
    .bind(ipHash, umaHoraAtras)
    .first();

  if (contagem && contagem.n >= L.postsHoraIp) {
    return erro('Muitas publicacoes em pouco tempo. Tente novamente mais tarde.', 429);
  }

  const fotosEntrada = Array.isArray(body.fotos) ? body.fotos.slice(0, L.fotosMax) : [];
  const keys = [];

  for (const foto of fotosEntrada) {
    const parsed = parseDataUrl(foto);
    if (!parsed) return erro('Formato de foto invalido.');
    if (parsed.bytes.length > L.fotoBytesMax) return erro('Uma das fotos e grande demais.');

    const ext = parsed.mime === 'image/jpeg' ? 'jpg' : parsed.mime.split('/')[1];
    const key = 'posts/' + uid() + '.' + ext;
    await env.BUCKET.put(key, parsed.bytes, { httpMetadata: { contentType: parsed.mime } });
    keys.push(key);
  }

  const id = uid();
  const valorTexto =
    valor === null
      ? 'A combinar'
      : 'R$ ' + valor.toFixed(2).replace('.', ',').replace(/\B(?=(\d{3})+(?!\d))/g, '.');

  await env.DB.prepare(
    'INSERT INTO posts (id, titulo, descricao, valor, valor_texto, contato_tipo, contato, autor, fotos, status, ip_hash, criado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
  )
    .bind(
      id,
      titulo,
      descricao,
      valor,
      valorTexto,
      contatoTipo,
      contato,
      autor,
      JSON.stringify(keys),
      'pendente',
      ipHash,
      agora()
    )
    .run();

  return json(
    {
      post: {
        id,
        titulo,
        descricao,
        valor,
        valorTexto,
        contatoTipo,
        contato,
        autor,
        fotos: keys,
        status: 'pendente',
        criadoEm: agora(),
        aprovadoEm: null,
      },
    },
    201
  );
}

async function criarDenuncia(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return erro('Corpo da requisicao invalido.');
  }

  const postId = String(body.postId || '').trim();
  const motivo = String(body.motivo || 'Outro').trim().slice(0, 200);

  if (!postId) return erro('Anuncio nao informado.');

  const existe = await env.DB.prepare('SELECT id FROM posts WHERE id = ?').bind(postId).first();
  if (!existe) return erro('Anuncio nao encontrado.', 404);

  await env.DB.prepare('INSERT INTO reports (id, post_id, motivo, criado_em) VALUES (?,?,?,?)')
    .bind(uid(), postId, motivo, agora())
    .run();

  return json({ ok: true }, 201);
}

/* ---------------- admin ---------------- */

async function login(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return erro('Corpo da requisicao invalido.');
  }

  const senha = String(body.senha || '');
  const usuario = String(body.usuario || 'admin').trim() || 'admin';

  if (!senha) return erro('Informe a senha.');

  const total = await env.DB.prepare('SELECT COUNT(*) AS n FROM admins').first();
  const existentes = total ? total.n : 0;

  if (existentes === 0) {
    if (!env.ADMIN_PASSWORD) {
      return erro('Senha do administrador nao configurada no servidor.', 500);
    }
    if (senha !== env.ADMIN_PASSWORD) return erro('Senha incorreta.', 401);

    await env.DB.prepare('INSERT INTO admins (usuario, senha_hash, criado_em) VALUES (?,?,?)')
      .bind(usuario, await sha256Hex(senha), agora())
      .run();

    return json({ token: await criarToken(env, usuario), usuario });
  }

  const adm = await env.DB.prepare('SELECT * FROM admins WHERE usuario = ?').bind(usuario).first();
  if (!adm) return erro('Senha incorreta.', 401);
  if (adm.senha_hash !== (await sha256Hex(senha))) return erro('Senha incorreta.', 401);

  return json({ token: await criarToken(env, usuario), usuario });
}

async function adminListar(request, env, url) {
  const status = url.searchParams.get('status') || 'pendente';
  if (!STATUS_VALIDOS.includes(status)) return erro('Status invalido.');

  const { results } = await env.DB.prepare(
    'SELECT * FROM posts WHERE status = ? ORDER BY criado_em DESC LIMIT 200'
  )
    .bind(status)
    .all();

  return json({ posts: (results || []).map((r) => mapPost(r, request)) });
}

async function adminStats(env) {
  const { results } = await env.DB.prepare(
    'SELECT status, COUNT(*) AS n FROM posts GROUP BY status'
  ).all();

  const stats = { pendente: 0, aprovada: 0, rejeitada: 0 };
  for (const r of results || []) {
    if (r.status in stats) stats[r.status] = r.n;
  }

  const den = await env.DB.prepare('SELECT COUNT(*) AS n FROM reports').first();
  stats.denuncias = den ? den.n : 0;

  return json({ stats });
}

async function adminAtualizar(request, env, id) {
  let body;
  try {
    body = await request.json();
  } catch {
    return erro('Corpo da requisicao invalido.');
  }

  const status = String(body.status || '');
  if (!STATUS_VALIDOS.includes(status)) return erro('Status invalido.');

  const existe = await env.DB.prepare('SELECT id FROM posts WHERE id = ?').bind(id).first();
  if (!existe) return erro('Anuncio nao encontrado.', 404);

  const aprovadoEm = status === 'aprovada' ? agora() : null;

  await env.DB.prepare('UPDATE posts SET status = ?, aprovado_em = ? WHERE id = ?')
    .bind(status, aprovadoEm, id)
    .run();

  return json({ ok: true, id, status });
}

async function adminRemover(env, id) {
  const row = await env.DB.prepare('SELECT fotos FROM posts WHERE id = ?').bind(id).first();
  if (!row) return erro('Anuncio nao encontrado.', 404);

  let keys = [];
  try {
    keys = JSON.parse(row.fotos || '[]');
  } catch {
    keys = [];
  }

  for (const key of keys) {
    if (!/^https?:\/\//.test(key)) {
      try {
        await env.BUCKET.delete(key);
      } catch {
        /* arquivo ja ausente */
      }
    }
  }

  await env.DB.prepare('DELETE FROM reports WHERE post_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();

  return json({ ok: true });
}

async function adminDenuncias(request, env) {
  const { results } = await env.DB.prepare(
    'SELECT r.id AS denuncia_id, r.motivo, r.criado_em, p.id AS post_id, p.titulo, p.autor, p.status, p.fotos FROM reports r LEFT JOIN posts p ON p.id = r.post_id ORDER BY r.criado_em DESC LIMIT 200'
  ).all();

  const origin = new URL(request.url).origin;

  return json({
    denuncias: (results || []).map((r) => {
      let keys = [];
      try {
        keys = JSON.parse(r.fotos || '[]');
      } catch {
        keys = [];
      }
      return {
        id: r.denuncia_id,
        motivo: r.motivo,
        criadoEm: r.criado_em,
        postId: r.post_id,
        titulo: r.titulo,
        autor: r.autor,
        status: r.status,
        fotos: keys.map((k) => (/^https?:\/\//.test(k) ? k : origin + '/media/' + k)),
      };
    }),
  });
}
