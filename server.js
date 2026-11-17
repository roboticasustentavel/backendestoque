'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 3000);
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

function requiredEnv(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
  }

  return value;
}

const supabase = createClient(
  requiredEnv('SUPABASE_URL'),
  requiredEnv('SUPABASE_SERVICE_ROLE_KEY'),
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);

const JWT_SECRET = requiredEnv('JWT_SECRET');

if (JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET deve possuir pelo menos 32 caracteres.');
}

// ========================================
// CONFIGURAÇÕES DE SEGURANÇA
// ========================================

app.disable('x-powered-by');
app.set('trust proxy', 1);

function fail(res, status, message, error = null) {
  return res.status(status).json({
    success: false,
    message,
    ...(error ? { error } : {})
  });
}

function send(res, status, message, data = null) {
  return res.status(status).json({
    success: true,
    message,
    data
  });
}

app.use((req, res, next) => {
  if (
    isProduction &&
    req.headers['x-forwarded-proto'] !== 'https'
  ) {
    return fail(res, 403, 'Conexão HTTPS obrigatória.');
  }

  next();
});

app.use(helmet());

const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || !isProduction || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origem não permitida pelo CORS.'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
  maxAge: 600
}));

app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// ========================================
// RATE LIMIT
// ========================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Muitas tentativas de login. Tente novamente mais tarde.'
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

app.use('/api', apiLimiter);

// ========================================
// TRATAMENTO DE ERROS ASSÍNCRONOS
// ========================================

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ========================================
// VALIDAÇÃO
// ========================================

function validate(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);

    if (!result.success) {
      return fail(
        res,
        400,
        'Dados inválidos.',
        result.error.issues.map(i => ({
          campo: i.path.join('.'),
          mensagem: i.message
        }))
      );
    }

    req[source] = result.data;
    next();
  };
}

const uuidSchema = z.string().uuid();

const productCreateSchema = z.object({
  nome: z.string().trim().min(2).max(100),
  categoria: z.string().trim().max(80).optional().default('Insumos'),
  quantidade: z.number().finite().min(0).max(100000000).optional().default(0),
  unidade: z.enum(['kg', 'litros', 'unidades']),
  estoque_minimo: z.number().finite().min(0).max(100000000).default(0)
}).strict();

const productUpdateSchema = z.object({
  nome: z.string().trim().min(2).max(100).optional(),
  categoria: z.string().trim().max(80).optional(),
  unidade: z.enum(['kg', 'litros', 'unidades']).optional(),
  estoque_minimo: z.number().finite().min(0).max(100000000).optional()
}).strict().refine(
  v => Object.keys(v).length > 0,
  'Informe ao menos um campo para atualizar.'
);

const movementSchema = z.object({
  produto_id: z.string().uuid(),
  quantidade: z.number().finite().positive().max(100000000),
  fornecedor: z.string().trim().max(150).optional().nullable(),
  motivo: z.string().trim().max(250).optional().nullable(),
  observacao: z.string().trim().max(1000).optional().nullable()
}).strict();

const loginSchema = z.object({
  email: z.string().trim().email().max(254).transform(v => v.toLowerCase()),
  senha: z.string().min(1).max(200)
}).strict();

const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).max(100000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20)
});

// ========================================
// MIDDLEWARE DE AUTENTICAÇÃO JWT
// ========================================

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');

    if (scheme !== 'Bearer' || !token) {
      return fail(res, 401, 'Autenticação necessária.');
    }

    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'padaria-api',
      audience: 'padaria-client'
    });

    if (!payload.sub || !payload.jti) {
      return fail(res, 401, 'Token inválido.');
    }

    const { data: revoked, error } = await supabase
      .from('tokens_revogados')
      .select('jti')
      .eq('jti', payload.jti)
      .maybeSingle();

    if (error) throw error;

    if (revoked) {
      return fail(res, 401, 'Token revogado.');
    }

    const { data: user, error: userError } = await supabase
      .from('usuarios')
      .select('id,email,ativo')
      .eq('id', payload.sub)
      .maybeSingle();

    if (userError) throw userError;

    if (!user || !user.ativo) {
      return fail(res, 401, 'Usuário não autorizado.');
    }

    req.user = {
      id: user.id,
      email: user.email,
      jti: payload.jti,
      exp: payload.exp
    };

    req.token = token;

    next();

  } catch (err) {
    if (
      err.name === 'JsonWebTokenError' ||
      err.name === 'TokenExpiredError'
    ) {
      return fail(res, 401, 'Token inválido ou expirado.');
    }

    next(err);
  }
}

// ========================================
// SEED ADMINISTRATIVO
// ========================================

async function seedAdmin() {
  const email = (
    process.env.SEED_ADMIN_EMAIL ||
    'alvaro@padaria.com.br'
  ).toLowerCase();

  const password = requiredEnv('SEED_ADMIN_PASSWORD');

  if (password.length < 12) {
    throw new Error(
      'SEED_ADMIN_PASSWORD deve possuir pelo menos 12 caracteres.'
    );
  }

  const password_hash = await bcrypt.hash(password, 12);

  const { error } = await supabase
    .from('usuarios')
    .upsert(
      {
        email,
        password_hash,
        ativo: true
      },
      { onConflict: 'email' }
    );

  if (error) throw error;

  console.log(`Usuário administrador inicializado: ${email}`);
}

if (process.argv.includes('--seed-admin')) {
  seedAdmin()
    .then(() => process.exit(0))
    .catch(err => {
      console.error('Falha ao inicializar administrador:', err.message);
      process.exit(1);
    });
} else {// ========================================
// AUTENTICAÇÃO
// ========================================

app.post(
  '/api/auth/login',
  loginLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const { email, senha } = req.body;

    const { data: user, error } = await supabase
      .from('usuarios')
      .select('id,email,password_hash,ativo')
      .eq('email', email)
      .maybeSingle();

    if (error) throw error;

    const valid =
      user &&
      user.ativo &&
      await bcrypt.compare(senha, user.password_hash);

    if (!valid) {
      return fail(res, 401, 'E-mail ou senha inválidos.');
    }

    const jti = randomUUID();

    const token = jwt.sign(
      { sub: user.id, jti },
      JWT_SECRET,
      {
        algorithm: 'HS256',
        expiresIn: JWT_EXPIRES_IN,
        issuer: 'padaria-api',
        audience: 'padaria-client'
      }
    );

    return send(res, 200, 'Login realizado com sucesso.', {
      token,
      tipo: 'Bearer',
      expires_in: JWT_EXPIRES_IN,
      usuario: {
        id: user.id,
        email: user.email
      }
    });
  })
);

// ========================================
// PROTEÇÃO DAS ROTAS
// ========================================

app.use('/api', (req, res, next) => {
  if (req.path === '/auth/login') {
    return next();
  }

  return authenticate(req, res, next);
});

// ========================================
// LOGOUT
// ========================================

app.post(
  '/api/auth/logout',
  asyncHandler(async (req, res) => {
    const expiresAt = new Date(req.user.exp * 1000).toISOString();

    const { error } = await supabase
      .from('tokens_revogados')
      .upsert(
        {
          jti: req.user.jti,
          usuario_id: req.user.id,
          expira_em: expiresAt
        },
        { onConflict: 'jti' }
      );

    if (error) throw error;

    return send(res, 200, 'Logout realizado. Token revogado.');
  })
);

// ========================================
// VALIDAR TOKEN
// ========================================

app.get('/api/auth/me', (req, res) => {
  return send(res, 200, 'Token válido.', {
    usuario: {
      id: req.user.id,
      email: req.user.email
    }
  });
});

// ========================================
// PRODUTOS
// ========================================

// LISTAR PRODUTOS

app.get(
  '/api/produtos',
  asyncHandler(async (req, res) => {
    const parsed = paginationSchema.safeParse(req.query);

    if (!parsed.success) {
      return fail(res, 400, 'Parâmetros de paginação inválidos.');
    }

    const { page, limit } = parsed.data;

    const from = (page - 1) * limit;
    const to = from + limit - 1;

    const { data, error, count } = await supabase
      .from('produtos')
      .select('*', { count: 'exact' })
      .order('nome')
      .range(from, to);

    if (error) throw error;

    return res.json({
      success: true,
      message: 'Produtos listados.',
      data,
      pagination: {
        page,
        limit,
        total: count,
        pages: Math.ceil((count || 0) / limit)
      }
    });
  })
);

// CONSULTAR PRODUTO

app.get(
  '/api/produtos/:id',
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      return fail(res, 400, 'ID inválido.');
    }

    const { data, error } = await supabase
      .from('produtos')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return fail(res, 404, 'Produto não encontrado.');
    }

    return send(res, 200, 'Produto encontrado.', data);
  })
);

// CADASTRAR PRODUTO

app.post(
  '/api/produtos',
  validate(productCreateSchema),
  asyncHandler(async (req, res) => {
    const payload = {
      ...req.body,
      nome: req.body.nome.trim()
    };

    const { data, error } = await supabase
      .from('produtos')
      .insert(payload)
      .select('*')
      .single();

    if (error?.code === '23505') {
      return fail(res, 409, 'Já existe um produto com esse nome.');
    }

    if (error) throw error;

    return send(res, 201, 'Produto cadastrado.', data);
  })
);

// ATUALIZAR PRODUTO

app.put(
  '/api/produtos/:id',
  validate(productUpdateSchema),
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      return fail(res, 400, 'ID inválido.');
    }

    const { data, error } = await supabase
      .from('produtos')
      .update(req.body)
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();

    if (error?.code === '23505') {
      return fail(res, 409, 'Já existe um produto com esse nome.');
    }

    if (error) throw error;

    if (!data) {
      return fail(res, 404, 'Produto não encontrado.');
    }

    return send(res, 200, 'Produto atualizado.', data);
  })
);

// EXCLUIR PRODUTO

app.delete(
  '/api/produtos/:id',
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      return fail(res, 400, 'ID inválido.');
    }

    const { error, count } = await supabase
      .from('produtos')
      .delete({ count: 'exact' })
      .eq('id', req.params.id);

    if (error?.code === '23503') {
      return fail(
        res,
        409,
        'Produto possui histórico e não pode ser excluído.'
      );
    }

    if (error) throw error;

    if (!count) {
      return fail(res, 404, 'Produto não encontrado.');
    }

    return send(res, 200, 'Produto excluído.');
  })
);

// ========================================
// ENTRADA DE ESTOQUE
// ========================================

app.post(
  '/api/estoque/entrada',
  validate(movementSchema),
  asyncHandler(async (req, res) => {
    const {
      produto_id,
      quantidade,
      fornecedor,
      observacao
    } = req.body;

    const { data, error } = await supabase.rpc(
      'registrar_movimentacao_estoque',
      {
        p_produto_id: produto_id,
        p_tipo: 'entrada',
        p_quantidade: quantidade,
        p_usuario_id: req.user.id,
        p_fornecedor: fornecedor || null,
        p_motivo: null,
        p_observacao: observacao || null
      }
    );

    if (error) {
      if (error.code === 'P0002') {
        return fail(res, 404, 'Produto não encontrado.');
      }

      throw error;
    }

    return send(res, 201, 'Entrada registrada.', data);
  })
);

// ========================================
// SAÍDA DE ESTOQUE
// ========================================

app.post(
  '/api/estoque/saida',
  validate(movementSchema),
  asyncHandler(async (req, res) => {
    const {
      produto_id,
      quantidade,
      motivo,
      observacao
    } = req.body;

    if (!motivo) {
      return fail(res, 400, 'Informe o motivo da saída.');
    }

    const { data, error } = await supabase.rpc(
      'registrar_movimentacao_estoque',
      {
        p_produto_id: produto_id,
        p_tipo: 'saida',
        p_quantidade: quantidade,
        p_usuario_id: req.user.id,
        p_fornecedor: null,
        p_motivo: motivo,
        p_observacao: observacao || null
      }
    );

    if (error) {
      if (error.code === 'P0002') {
        return fail(res, 404, 'Produto não encontrado.');
      }

      if (error.code === 'P0001') {
        return fail(
          res,
          409,
          'Estoque insuficiente para realizar esta saída.'
        );
      }

      throw error;
    }

    return send(res, 201, 'Saída registrada.', data);
  })
);

// ========================================
// HISTÓRICO DE MOVIMENTAÇÕES
// ========================================

app.get(
  '/api/estoque/historico',
  asyncHandler(async (req, res) => {
    const querySchema = paginationSchema.extend({
      produto_id: z.string().uuid().optional(),
      tipo: z.enum(['entrada', 'saida']).optional(),
      inicio: z.string().datetime({ offset: true }).optional(),
      fim: z.string().datetime({ offset: true }).optional()
    });

    const parsed = querySchema.safeParse(req.query);

    if (!parsed.success) {
      return fail(res, 400, 'Filtros inválidos.', parsed.error.issues);
    }

    const {
      page,
      limit,
      produto_id,
      tipo,
      inicio,
      fim
    } = parsed.data;

    const from = (page - 1) * limit;

    let query = supabase
      .from('movimentacoes')
      .select('*, produtos(id,nome,unidade)', { count: 'exact' })
      .order('criado_em', { ascending: false })
      .range(from, from + limit - 1);

    if (produto_id) query = query.eq('produto_id', produto_id);
    if (tipo) query = query.eq('tipo', tipo);
    if (inicio) query = query.gte('criado_em', inicio);
    if (fim) query = query.lte('criado_em', fim);

    const { data, error, count } = await query;

    if (error) throw error;

    return res.json({
      success: true,
      message: 'Histórico consultado.',
      data,
      pagination: {
        page,
        limit,
        total: count,
        pages: Math.ceil((count || 0) / limit)
      }
    });
  })
);
// ========================================
// PRODUTOS COM ESTOQUE BAIXO
// ========================================

app.get(
  '/api/estoque/baixo',
  asyncHandler(async (req, res) => {
    const { data, error } = await supabase.rpc(
      'listar_produtos_estoque_baixo'
    );

    if (error) throw error;

    return send(
      res,
      200,
      'Produtos abaixo do estoque mínimo.',
      data
    );
  })
);

// ========================================
// PRODUTOS COM ESTOQUE ZERADO
// ========================================

app.get(
  '/api/estoque/zerado',
  asyncHandler(async (req, res) => {
    const { data, error } = await supabase
      .from('produtos')
      .select('*')
      .eq('quantidade', 0)
      .order('nome');

    if (error) throw error;

    return send(
      res,
      200,
      'Produtos sem estoque.',
      data
    );
  })
);

// ========================================
// DASHBOARD
// ========================================

app.get(
  '/api/dashboard',
  asyncHandler(async (req, res) => {
    const [
      products,
      low,
      zero,
      movements,
      sumResult
    ] = await Promise.all([
      supabase
        .from('produtos')
        .select('id', { count: 'exact', head: true }),

      supabase.rpc('listar_produtos_estoque_baixo'),

      supabase
        .from('produtos')
        .select('id', { count: 'exact', head: true })
        .eq('quantidade', 0),

      supabase
        .from('movimentacoes')
        .select('*,produtos(nome,unidade)')
        .order('criado_em', { ascending: false })
        .limit(10),

      supabase
        .from('produtos')
        .select('quantidade')
    ]);

    for (const result of [
      products,
      low,
      zero,
      movements,
      sumResult
    ]) {
      if (result.error) throw result.error;
    }

    const totalQuantidade = (sumResult.data || [])
      .reduce((sum, p) => sum + Number(p.quantidade), 0);

    return send(res, 200, 'Dashboard carregado.', {
      total_produtos: products.count || 0,
      total_itens_estoque: totalQuantidade,
      produtos_estoque_baixo: (low.data || []).length,
      produtos_sem_estoque: zero.count || 0,
      ultimas_movimentacoes: movements.data || []
    });
  })
);

} // Fim do bloco de inicialização normal

// ========================================
// HEALTH CHECK
// ========================================

app.get('/health', (req, res) => {
  return send(res, 200, 'API operacional.', {
    status: 'ok'
  });
});

// ========================================
// ROTA NÃO ENCONTRADA
// ========================================

app.use((req, res) => {
  return fail(res, 404, 'Rota não encontrada.');
});

// ========================================
// TRATAMENTO GLOBAL DE ERROS
// ========================================

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err.message === 'Origem não permitida pelo CORS.') {
    return fail(res, 403, 'Origem não permitida.');
  }

  if (err.type === 'entity.parse.failed') {
    return fail(res, 400, 'JSON inválido.');
  }

  console.error('Erro interno da API:', {
    name: err.name || 'Error',
    code: err.code || 'INTERNAL'
  });

  return fail(
    res,
    500,
    'Erro interno ao processar a solicitação.'
  );
});

// ========================================
// INICIALIZAÇÃO
// ========================================

// Local: npm start
// Vercel: utiliza module.exports

if (require.main === module && !process.argv.includes('--seed-admin')) {
  app.listen(PORT, () => {
    console.log(`API disponível na porta ${PORT}`);
  });
}

module.exports = app;
