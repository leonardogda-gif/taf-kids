const API_VERSION = "3.3.1";
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000;

const ALLOWED_ORIGINS = new Set([
  "https://leonardogda-gif.github.io"
]);

function corsHeaders(request) {
  const origin = request?.headers?.get("Origin") || "";
  const localDev = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
  const allowed = ALLOWED_ORIGINS.has(origin) || localDev;
  return {
    ...(allowed && origin ? { "Access-Control-Allow-Origin": origin, "Vary": "Origin" } : {}),
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
  };
}

function json(data, status = 200, request = null) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...corsHeaders(request),
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    },
  });
}

function cleanSlug(value = "") {
  return String(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function normalizeEmail(value = "") {
  return String(value).trim().toLowerCase();
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);

  return bytesToBase64(data)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return [
    "pbkdf2_sha256",
    PBKDF2_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(new Uint8Array(derived)),
  ].join("$");
}

async function verifyPassword(password, storedHash) {
  try {
    const [algorithm, iterationsText, salt64, expected64] =
      String(storedHash || "").split("$");

    if (algorithm !== "pbkdf2_sha256") return false;

    const iterations = Number(iterationsText);
    if (!iterations || !salt64 || !expected64) return false;

    const salt = base64ToBytes(salt64);
    const expected = base64ToBytes(expected64);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const derived = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations,
          hash: "SHA-256",
        },
        keyMaterial,
        expected.length * 8
      )
    );

    if (derived.length !== expected.length) return false;

    let difference = 0;

    for (let i = 0; i < derived.length; i++) {
      difference |= derived[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

function getBearerToken(request) {
  const authorization = request.headers.get("Authorization") || "";

  if (!authorization.toLowerCase().startsWith("bearer ")) {
    return null;
  }

  return authorization.slice(7).trim();
}

async function getAuthenticatedUser(request, env) {
  const token = getBearerToken(request);
  if (!token) return null;

  const tokenHash = await sha256(token);

  const session = await env.DB.prepare(`
    SELECT
      s.id AS session_id,
      s.user_id,
      s.expires_at,
      u.name,
      u.email,
      u.phone,
      u.avatar_url,
      u.platform_role,
      u.status
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND s.revoked_at IS NULL
      AND datetime(s.expires_at) > datetime('now')
      AND u.status = 'active'
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session) return null;

  return {
    token,
    tokenHash,
    session,
  };
}

async function getUserChurches(env, userId) {
  const memberships = await env.DB.prepare(`
    SELECT
      cu.id AS church_user_id,
      cu.church_id,
      cu.status AS membership_status,
      c.name AS church_name,
      c.slug,
      c.status AS church_status,
      cb.display_name,
      cb.logo_url,
      cb.primary_color,
      cb.secondary_color,
      cb.accent_color
    FROM church_users cu
    JOIN churches c ON c.id = cu.church_id
    LEFT JOIN church_branding cb ON cb.church_id = c.id
    WHERE cu.user_id = ?
      AND cu.status = 'active'
    ORDER BY c.name
  `).bind(userId).all();

  const churches = [];

  for (const membership of memberships.results || []) {
    const rolesResult = await env.DB.prepare(`
      SELECT role
      FROM church_user_roles
      WHERE church_user_id = ?
      ORDER BY role
    `).bind(membership.church_user_id).all();

    churches.push({
      id: membership.church_id,
      name: membership.church_name,
      slug: membership.slug,
      status: membership.church_status,
      membership_status: membership.membership_status,
      branding: {
        display_name: membership.display_name,
        logo_url: membership.logo_url,
        primary_color: membership.primary_color,
        secondary_color: membership.secondary_color,
        accent_color: membership.accent_color,
      },
      roles: (rolesResult.results || []).map(r => r.role),
    });
  }

  return churches;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function getAuthorizedChurch(env, userId, requestedChurchId = null) {
  const params = [userId];
  let churchFilter = "";

  if (requestedChurchId) {
    churchFilter = " AND cu.church_id = ?";
    params.push(requestedChurchId);
  }

  const membership = await env.DB.prepare(`
    SELECT
      cu.id AS church_user_id,
      cu.church_id,
      c.name AS church_name,
      c.slug,
      c.status AS church_status
    FROM church_users cu
    JOIN churches c ON c.id = cu.church_id
    WHERE cu.user_id = ?
      AND cu.status = 'active'
      AND c.status = 'active'
      ${churchFilter}
    ORDER BY c.name
    LIMIT 1
  `).bind(...params).first();

  if (!membership) return null;

  const rolesResult = await env.DB.prepare(`
    SELECT role
    FROM church_user_roles
    WHERE church_user_id = ?
    ORDER BY role
  `).bind(membership.church_user_id).all();

  return {
    ...membership,
    roles: (rolesResult.results || []).map(r => r.role),
  };
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ""));
}
function isDateYmd(value) {
  const s=String(value||"");
  if(!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y,m,d]=s.split("-").map(Number);
  const dt=new Date(Date.UTC(y,m-1,d));
  return dt.getUTCFullYear()===y && dt.getUTCMonth()===m-1 && dt.getUTCDate()===d;
}
function isTimeHm(value) {
  return value == null || value === "" || /^([01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$/.test(String(value));
}
function validTimezone(value) {
  try { new Intl.DateTimeFormat("en-US",{timeZone:String(value)}).format(new Date()); return true; } catch { return false; }
}
function todayInTimezone(timezone) {
  const parts=new Intl.DateTimeFormat("en-CA",{timeZone:timezone||"America/Sao_Paulo",year:"numeric",month:"2-digit",day:"2-digit"}).formatToParts(new Date());
  const o=Object.fromEntries(parts.map(p=>[p.type,p.value]));
  return `${o.year}-${o.month}-${o.day}`;
}
async function requireAuth(request, env) {
  const auth=await getAuthenticatedUser(request,env);
  if(!auth) return {error:json({ok:false,error:"unauthorized",message:"Sessão inválida ou expirada."},401,request)};
  return {auth};
}
async function requireSuperAdmin(request, env) {
  const r=await requireAuth(request,env); if(r.error) return r;
  if(r.auth.session.platform_role!=="super_admin") return {error:json({ok:false,error:"super_admin_required",message:"Acesso exclusivo do Super ADM."},403,request)};
  return r;
}
async function requireChurchAdmin(request, env, churchId) {
  const r=await requireAuth(request,env); if(r.error) return r;
  if(!churchId || !isUuid(churchId)) return {error:json({ok:false,error:"church_id_required",message:"Informe uma igreja válida."},400,request)};
  const church=await getAuthorizedChurch(env,r.auth.session.user_id,churchId);
  if(!church || !church.roles.includes("admin")) return {error:json({ok:false,error:"admin_required",message:"Acesso de administrador necessário."},403,request)};
  return {...r,church};
}
async function requireChurchRole(request, env, churchId, allowedRoles=[]) {
  const r=await requireAuth(request,env); if(r.error) return r;
  if(!churchId || !isUuid(churchId)) return {error:json({ok:false,error:"church_id_required",message:"Informe uma igreja válida."},400,request)};
  const church=await getAuthorizedChurch(env,r.auth.session.user_id,churchId);
  if(!church || !church.roles.some(role=>allowedRoles.includes(role))) return {error:json({ok:false,error:"role_required",message:"Sua função não permite esta operação."},403,request)};
  return {...r,church};
}

async function audit(env,{churchId=null,userId=null,context="system",action,entityType=null,entityId=null,before=null,after=null,metadata=null}) {
  await env.DB.prepare(`INSERT INTO audit_log(id,church_id,actor_user_id,actor_context,action,entity_type,entity_id,before_json,after_json,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)`)
    .bind(crypto.randomUUID(),churchId,userId,context,action,entityType,entityId,before?JSON.stringify(before):null,after?JSON.stringify(after):null,metadata?JSON.stringify(metadata):null).run();
}
async function assertChurchUsable(env, churchId) {
  const church=await env.DB.prepare(`SELECT id,status FROM churches WHERE id=?`).bind(churchId).first();
  if(!church || church.status!=="active") return {ok:false,reason:"church_inactive"};
  const sub=await env.DB.prepare(`SELECT status FROM subscriptions WHERE church_id=? ORDER BY created_at DESC LIMIT 1`).bind(churchId).first();
  if(sub && ["limited","cancelled","expired"].includes(sub.status)) return {ok:false,reason:"subscription_limited",status:sub.status};
  return {ok:true,status:sub?.status||null};
}
async function loginRateState(env,email) {
  const row=await env.DB.prepare(`SELECT COUNT(*) total FROM audit_log WHERE action='LOGIN_FAILED' AND entity_type='login_email' AND entity_id=? AND datetime(created_at)>=datetime('now','-15 minutes')`).bind(email).first();
  return Number(row?.total||0);
}

// =====================================================
// v3.3 — helpers: configurações da igreja e totem
// =====================================================

async function getChurchSettings(env, churchId) {
  const row = await env.DB.prepare(`SELECT * FROM church_settings WHERE church_id=?`).bind(churchId).first();
  if (row) return row;
  // Ainda sem linha salva: devolve os padrões (não grava nada até o ADM salvar de fato).
  return {
    church_id: churchId,
    checkin_reception_required: 1, checkin_allow_visitors: 1,
    checkout_require_qr: 1, checkout_allow_exception: 1,
    labels_enabled: 1, labels_per_child: 2, labels_auto_print: 1,
    feature_totem: 0, feature_calls: 1, feature_support: 1,
    feature_offering: 0, feature_devotionals: 1,
  };
}

async function getAuthenticatedDevice(request, env) {
  const token = request.headers.get("X-Kiosk-Token") || "";
  if (!token) return null;
  const tokenHash = await sha256(token);
  const device = await env.DB.prepare(`
    SELECT id, church_id, name, status
    FROM kiosk_devices
    WHERE token_hash=? AND status='active'
    LIMIT 1
  `).bind(tokenHash).first();
  if (!device) return null;
  await env.DB.prepare(`UPDATE kiosk_devices SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?`).bind(device.id).run();
  return device;
}

async function requireDevice(request, env) {
  const device = await getAuthenticatedDevice(request, env);
  if (!device) return {error: json({ok:false,error:"device_unauthorized",message:"Totem não autenticado ou revogado."},401,request)};
  return {device};
}

async function kioskRateState(env, deviceId) {
  const row = await env.DB.prepare(`SELECT COUNT(*) total FROM audit_log WHERE action='KIOSK_IDENTIFY_FAILED' AND entity_type='kiosk_device' AND entity_id=? AND datetime(created_at)>=datetime('now','-15 minutes')`).bind(deviceId).first();
  return Number(row?.total||0);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      const headers = corsHeaders(request);
      const origin = request.headers.get("Origin") || "";
      if (origin && !headers["Access-Control-Allow-Origin"]) {
        return new Response(null, { status: 403, headers });
      }
      return new Response(null, {
        status: 204,
        headers,
      });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {

      // =====================================================
      // HEALTH
      // =====================================================

      if (path === "/api/health" && request.method === "GET") {
        if (!env.DB) {
          return json({
            ok: false,
            app: "Taf Kids",
            api: "taf-kids-api",
            version: API_VERSION,
            database: "binding_missing",
          }, 500, request);
        }

        const tables = await env.DB.prepare(`
          SELECT COUNT(*) AS total
          FROM sqlite_master
          WHERE type = 'table'
            AND name NOT LIKE 'sqlite_%'
            AND name != '_cf_KV'
        `).first();

        const churches = await env.DB.prepare(`
          SELECT COUNT(*) AS total FROM churches
        `).first();

        const users = await env.DB.prepare(`
          SELECT COUNT(*) AS total FROM users
        `).first();

        return json({
          ok: true,
          app: "Taf Kids",
          api: "taf-kids-api",
          version: API_VERSION,
          database: "connected",
          schema: "v2",
          data: {
            taf_kids_tables: Number(tables?.total || 0),
            churches: Number(churches?.total || 0),
            users: Number(users?.total || 0),
          },
        }, 200, request);
      }

      // Bootstrap público removido na v2.5.
      // Igrejas e administradores passam a ser geridos por rotas autenticadas do Super ADM.

      // =====================================================
      // LOGIN
      // =====================================================

      if (path === "/api/auth/login" && request.method === "POST") {
        const body=await readJson(request);
        if(!body) return json({ok:false,error:"invalid_json",message:"JSON inválido."},400,request);
        const email=normalizeEmail(body.email||""),password=String(body.password||"");
        if(!email||!password) return json({ok:false,error:"missing_credentials",message:"Informe e-mail e senha."},400,request);
        if(await loginRateState(env,email)>=8) return json({ok:false,error:"too_many_attempts",message:"Muitas tentativas. Aguarde alguns minutos e tente novamente."},429,request);

        const user=await env.DB.prepare(`SELECT id,name,email,phone,password_hash,platform_role,status FROM users WHERE email=? LIMIT 1`).bind(email).first();
        const valid=!!(user&&user.status==="active"&&user.password_hash&&await verifyPassword(password,user.password_hash));
        if(!valid){
          await audit(env,{context:"login",action:"LOGIN_FAILED",entityType:"login_email",entityId:email});
          return json({ok:false,error:"invalid_credentials",message:"E-mail ou senha inválidos."},401,request);
        }

        const rawToken=randomToken(32),tokenHash=await sha256(rawToken),sessionId=crypto.randomUUID();
        const expiresAt=new Date(Date.now()+SESSION_DAYS*24*60*60*1000).toISOString();
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO sessions(id,user_id,token_hash,expires_at,user_agent) VALUES(?,?,?,?,?)`).bind(sessionId,user.id,tokenHash,expiresAt,request.headers.get("User-Agent")),
          env.DB.prepare(`UPDATE users SET last_login_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(user.id),
          env.DB.prepare(`INSERT INTO audit_log(id,actor_user_id,actor_context,action,entity_type,entity_id) VALUES(?,?,'login','LOGIN_SUCCESS','user',?)`).bind(crypto.randomUUID(),user.id,user.id)
        ]);
        const churches=await getUserChurches(env,user.id);
        return json({ok:true,message:"Login realizado com sucesso.",token:rawToken,expires_at:expiresAt,user:{id:user.id,name:user.name,email:user.email,phone:user.phone,platform_role:user.platform_role},churches},200,request);
      }

      // =====================================================
      // v3.3 — RECUPERAÇÃO DE SENHA
      // Resposta sempre genérica: nunca revela se o e-mail existe.
      // =====================================================

      if (path === "/api/auth/forgot-password" && request.method === "POST") {
        const body = await readJson(request);
        const email = normalizeEmail(body?.email || "");
        const generic = {ok:true, message:"Se este e-mail existir em nossa base, você receberá um link para redefinir a senha."};
        if (!email) return json(generic, 200, request);

        const user = await env.DB.prepare(`SELECT id,name,email,status FROM users WHERE email=? LIMIT 1`).bind(email).first();

        if (user && user.status === "active") {
          const recent = await env.DB.prepare(`
            SELECT COUNT(*) total FROM password_reset_tokens
            WHERE user_id=? AND datetime(created_at)>=datetime('now','-15 minutes')
          `).bind(user.id).first();
          if (Number(recent?.total||0) < 5) {
            const rawToken = randomToken(32), tokenHash = await sha256(rawToken), id = crypto.randomUUID();
            const expiresAt = new Date(Date.now() + 30*60*1000).toISOString();
            await env.DB.prepare(`INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)`).bind(id,user.id,tokenHash,expiresAt).run();
            await audit(env,{userId:user.id,context:"login",action:"PASSWORD_RESET_REQUESTED",entityType:"user",entityId:user.id});

            // TODO: plugar um provedor de e-mail real (ex.: Resend, Postmark) e enviar resetLink.
            // Por enquanto só registramos no log do Worker — sem provedor configurado,
            // nenhum e-mail é enviado de verdade ainda.
            const resetLink = `https://leonardogda-gif.github.io/?reset_token=${rawToken}`;
            console.log("PASSWORD RESET LINK (configure um provedor de e-mail):", email, resetLink);
          }
        }

        return json(generic, 200, request);
      }

      if (path === "/api/auth/reset-password" && request.method === "POST") {
        const body = await readJson(request);
        const token = String(body?.token || ""), newPassword = String(body?.new_password || "");
        if (!token || newPassword.length < 8) return json({ok:false,message:"Informe o link recebido e uma senha com ao menos 8 caracteres."},400,request);

        const tokenHash = await sha256(token);
        const row = await env.DB.prepare(`
          SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash=? LIMIT 1
        `).bind(tokenHash).first();

        if (!row || row.used_at || new Date(row.expires_at) < new Date()) {
          return json({ok:false,error:"invalid_token",message:"Link inválido ou expirado. Solicite um novo."},400,request);
        }

        const hash = await hashPassword(newPassword);
        await env.DB.batch([
          env.DB.prepare(`UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(hash,row.user_id),
          env.DB.prepare(`UPDATE password_reset_tokens SET used_at=CURRENT_TIMESTAMP WHERE id=?`).bind(row.id),
          env.DB.prepare(`UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL`).bind(row.user_id),
        ]);
        await audit(env,{userId:row.user_id,context:"login",action:"PASSWORD_RESET_COMPLETED",entityType:"user",entityId:row.user_id});

        return json({ok:true,message:"Senha redefinida. Faça login com sua nova senha."},200,request);
      }

      // =====================================================
      // USUARIO ATUAL
      // =====================================================

      if (path === "/api/me" && request.method === "GET") {
        const auth = await getAuthenticatedUser(request, env);

        if (!auth) {
          return json({
            ok: false,
            error: "unauthorized",
            message: "Sessão inválida ou expirada.",
          }, 401, request);
        }

        const s = auth.session;
        const churches = await getUserChurches(env, s.user_id);

        return json({
          ok: true,
          user: {
            id: s.user_id,
            name: s.name,
            email: s.email,
            phone: s.phone,
            avatar_url: s.avatar_url,
            platform_role: s.platform_role,
          },
          churches,
          session: {
            expires_at: s.expires_at,
          },
        }, 200, request);
      }



      // =====================================================
      // COMPATIBILIDADE DO SCHEMA — v3.3.1
      // =====================================================
      if(path==="/api/super/schema-check"&&request.method==="GET"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;
        const expected={
          users:["id","name","email","password_hash","platform_role","status"],
          churches:["id","name","slug","timezone","status"],
          church_users:["id","church_id","user_id","status"],
          church_user_roles:["id","church_user_id","role"],
          rooms:["id","church_id","name","active"],
          services:["id","church_id","name","service_date","starts_at","ends_at","status","allocation_mode"],
          service_rooms:["id","service_id","room_id","active"],
          service_templates:["id","church_id","name","recurrence_rule","starts_at_local","allocation_mode","active"],
          schedules:["id","church_id","service_id","name","status"],
          schedule_assignments:["id","schedule_id","user_id","role","service_room_id","status","responded_at"],
          families:["id","church_id","family_name","status"],
          guardians:["id","church_id","family_id","name","status"],
          children:["id","church_id","first_name","last_name","birth_date","status"],
          child_guardians:["id","child_id","guardian_id","relationship","active"],
          checkins:["id","church_id","service_id","child_id","service_room_id","checkin_method","public_code","status","checked_in_at"],
          sessions:["id","user_id","token_hash","expires_at"],
          audit_log:["id","action","created_at"],
          subscriptions:["id","church_id","status"],
          parent_calls:["id","church_id","service_id","status"],
          church_settings:["church_id"],
          kiosk_devices:["id","church_id","token_hash","status"],
          support_requests:["id","church_id","service_id","status"],
          password_reset_tokens:["id","user_id","token_hash","expires_at","used_at"],
          devotionals:["id","church_id","title","status"],
          offerings:["id","church_id","service_id","amount_cents"],
          announcements:["id","title","message","status"],
          announcement_reads:["id","announcement_id","user_id"]
        };
        const missing_tables=[],missing_columns=[],checked={};
        for(const [table,cols] of Object.entries(expected)){
          const exists=await env.DB.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).bind(table).first();
          if(!exists){missing_tables.push(table);continue}
          const info=await env.DB.prepare(`PRAGMA table_info(${table})`).all();
          const actual=(info.results||[]).map(x=>x.name);checked[table]=actual.length;
          for(const col of cols)if(!actual.includes(col))missing_columns.push(`${table}.${col}`);
        }
        return json({ok:missing_tables.length===0&&missing_columns.length===0,version:API_VERSION,checked,missing_tables,missing_columns,message:missing_tables.length||missing_columns.length?"Schema precisa de ajuste antes do teste amplo.":"Schema compatível com os módulos da v3.3.1."},200,request);
      }

      // =====================================================
      // SUPER ADM - BOOTSTRAP E PAINEL DA PLATAFORMA
      // =====================================================

      if (path === "/api/super/churches/create" && request.method === "POST") {
        const gate=await requireSuperAdmin(request,env); if(gate.error) return gate.error;
        const x=await readJson(request); if(!x) return json({ok:false,message:"JSON inválido."},400,request);
        const name=String(x.name||"").trim(),slug=cleanSlug(x.slug||name),email=x.email?normalizeEmail(x.email):null,phone=x.phone?String(x.phone).trim():null;
        const timezone=String(x.timezone||"America/Sao_Paulo");
        if(!name||!slug||!validTimezone(timezone)) return json({ok:false,message:"Nome, identificador ou fuso horário inválido."},400,request);
        if(await env.DB.prepare(`SELECT id FROM churches WHERE slug=?`).bind(slug).first()) return json({ok:false,message:"Este identificador já está em uso."},409,request);
        const id=crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO churches(id,name,slug,document,email,phone,timezone,status) VALUES(?,?,?,?,?,?,?,'active')`).bind(id,name,slug,x.document?String(x.document).trim():null,email,phone,timezone),
          env.DB.prepare(`INSERT INTO church_settings(church_id) VALUES(?)`).bind(id),
          env.DB.prepare(`INSERT INTO church_branding(church_id,display_name) VALUES(?,?)`).bind(id,name)
        ]);
        await audit(env,{churchId:id,userId:gate.auth.session.user_id,context:"super_admin",action:"CHURCH_CREATED",entityType:"church",entityId:id,after:{name,slug,timezone}});
        return json({ok:true,id,message:"Igreja criada."},201,request);
      }

      if (path === "/api/super/church/admin" && request.method === "POST") {
        const gate=await requireSuperAdmin(request,env); if(gate.error) return gate.error;
        const x=await readJson(request); if(!x||!isUuid(x.church_id)) return json({ok:false,message:"Igreja inválida."},400,request);
        const church=await env.DB.prepare(`SELECT id,name FROM churches WHERE id=? AND status!='archived'`).bind(x.church_id).first();
        if(!church) return json({ok:false,message:"Igreja não encontrada."},404,request);
        const name=String(x.name||"").trim(),email=normalizeEmail(x.email||""),password=String(x.password||"");
        if(!name||!email||password.length<8) return json({ok:false,message:"Nome, e-mail e senha de pelo menos 8 caracteres são obrigatórios."},400,request);
        let user=await env.DB.prepare(`SELECT id FROM users WHERE email=?`).bind(email).first();
        let userId=user?.id;
        if(!userId){ userId=crypto.randomUUID(); const hash=await hashPassword(password); await env.DB.prepare(`INSERT INTO users(id,name,email,phone,password_hash,status) VALUES(?,?,?,?,?,'active')`).bind(userId,name,email,x.phone?String(x.phone).trim():null,hash).run(); }
        let membership=await env.DB.prepare(`SELECT id FROM church_users WHERE church_id=? AND user_id=?`).bind(church.id,userId).first();
        let churchUserId=membership?.id;
        if(!churchUserId){churchUserId=crypto.randomUUID();await env.DB.prepare(`INSERT INTO church_users(id,church_id,user_id,status,invited_by,joined_at) VALUES(?,?,?,'active',?,CURRENT_TIMESTAMP)`).bind(churchUserId,church.id,userId,gate.auth.session.user_id).run();}
        await env.DB.prepare(`INSERT OR IGNORE INTO church_user_roles(id,church_user_id,role) VALUES(?,?,'admin')`).bind(crypto.randomUUID(),churchUserId).run();
        await audit(env,{churchId:church.id,userId:gate.auth.session.user_id,context:"super_admin",action:"CHURCH_ADMIN_GRANTED",entityType:"user",entityId:userId,after:{email}});
        return json({ok:true,message:"Administrador vinculado à igreja."},201,request);
      }

      if (path === "/api/super/dashboard" && request.method === "GET") {
        const auth = await getAuthenticatedUser(request, env);
        if (!auth) return json({ ok:false, error:"unauthorized", message:"Sessão inválida ou expirada." }, 401, request);
        if (auth.session.platform_role !== "super_admin") {
          return json({ ok:false, error:"super_admin_required", message:"Acesso exclusivo do Super ADM." }, 403, request);
        }

        const [churches, users, children, checkins, activeSubscriptions] = await Promise.all([
          env.DB.prepare(`SELECT COUNT(*) AS total FROM churches WHERE status != 'archived'`).first(),
          env.DB.prepare(`SELECT COUNT(*) AS total FROM users WHERE status = 'active'`).first(),
          env.DB.prepare(`SELECT COUNT(*) AS total FROM children WHERE status = 'active'`).first(),
          env.DB.prepare(`SELECT COUNT(*) AS total FROM checkins`).first(),
          env.DB.prepare(`
            SELECT COUNT(*) AS total FROM subscriptions
            WHERE status IN ('trial','active','grace')
          `).first()
        ]);

        const recentChurches = await env.DB.prepare(`
          SELECT
            c.id, c.name, c.slug, c.status, c.email, c.phone, c.created_at,
            COALESCE((
              SELECT COUNT(*) FROM children ch
              WHERE ch.church_id = c.id AND ch.status = 'active'
            ),0) AS children_count,
            COALESCE((
              SELECT COUNT(*) FROM church_users cu
              WHERE cu.church_id = c.id AND cu.status = 'active'
            ),0) AS users_count,
            (
              SELECT s.status FROM subscriptions s
              WHERE s.church_id = c.id
              ORDER BY s.created_at DESC LIMIT 1
            ) AS subscription_status
          FROM churches c
          WHERE c.status != 'archived'
          ORDER BY c.created_at DESC
          LIMIT 10
        `).all();

        return json({
          ok:true,
          summary:{
            churches:Number(churches?.total||0),
            users:Number(users?.total||0),
            children:Number(children?.total||0),
            checkins:Number(checkins?.total||0),
            active_subscriptions:Number(activeSubscriptions?.total||0)
          },
          churches: recentChurches.results || []
        }, 200, request);
      }

      if (path === "/api/super/churches" && request.method === "GET") {
        const auth = await getAuthenticatedUser(request, env);
        if (!auth) return json({ ok:false, error:"unauthorized", message:"Sessão inválida ou expirada." }, 401, request);
        if (auth.session.platform_role !== "super_admin") {
          return json({ ok:false, error:"super_admin_required", message:"Acesso exclusivo do Super ADM." }, 403, request);
        }

        const result = await env.DB.prepare(`
          SELECT
            c.id, c.name, c.slug, c.status, c.email, c.phone, c.timezone, c.created_at,
            COALESCE((SELECT COUNT(*) FROM children ch WHERE ch.church_id=c.id AND ch.status='active'),0) AS children_count,
            COALESCE((SELECT COUNT(*) FROM church_users cu WHERE cu.church_id=c.id AND cu.status='active'),0) AS users_count,
            (SELECT s.status FROM subscriptions s WHERE s.church_id=c.id ORDER BY s.created_at DESC LIMIT 1) AS subscription_status,
            (SELECT s.subscription_type FROM subscriptions s WHERE s.church_id=c.id ORDER BY s.created_at DESC LIMIT 1) AS subscription_type
          FROM churches c
          WHERE c.status != 'archived'
          ORDER BY c.name
        `).all();

        return json({ ok:true, churches:result.results || [] }, 200, request);
      }


      // =====================================================
      // V2.5 - GESTAO REAL ENDURECIDA
      // =====================================================
      if(path==="/api/super/church"&&request.method==="GET"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;
        const id=url.searchParams.get("id");if(!isUuid(id))return json({ok:false,message:"Igreja inválida."},400,request);
        const church=await env.DB.prepare(`SELECT * FROM churches WHERE id=?`).bind(id).first();if(!church)return json({ok:false,message:"Igreja não encontrada."},404,request);
        const admins=await env.DB.prepare(`SELECT u.name,u.email,u.phone FROM church_users cu JOIN users u ON u.id=cu.user_id JOIN church_user_roles cr ON cr.church_user_id=cu.id AND cr.role='admin' WHERE cu.church_id=? AND cu.status='active' ORDER BY u.name`).bind(id).all();
        const subscription=await env.DB.prepare(`SELECT * FROM subscriptions WHERE church_id=? ORDER BY created_at DESC LIMIT 1`).bind(id).first();
        const features=await env.DB.prepare(`SELECT feature_key,enabled,reason,valid_until FROM church_features WHERE church_id=? ORDER BY feature_key`).bind(id).all();
        return json({ok:true,church,admins:admins.results||[],subscription:subscription||null,features:features.results||[]},200,request);
      }
      if(path==="/api/super/church/status"&&request.method==="POST"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;const x=await readJson(request);
        if(!x||!isUuid(x.church_id)||!["active","inactive","suspended"].includes(x.status))return json({ok:false,message:"Dados inválidos."},400,request);
        const before=await env.DB.prepare(`SELECT status FROM churches WHERE id=?`).bind(x.church_id).first();if(!before)return json({ok:false,message:"Igreja não encontrada."},404,request);
        await env.DB.prepare(`UPDATE churches SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(x.status,x.church_id).run();
        await audit(env,{churchId:x.church_id,userId:g.auth.session.user_id,context:"super_admin",action:"CHURCH_STATUS_UPDATED",entityType:"church",entityId:x.church_id,before,after:{status:x.status}});
        return json({ok:true,message:"Status atualizado."},200,request);
      }
      if(path==="/api/super/subscription"&&request.method==="POST"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;const x=await readJson(request);
        if(!x||!isUuid(x.church_id)||!["paid","trial","courtesy","partnership"].includes(x.subscription_type)||!["trial","active","overdue","grace","limited","cancelled","expired"].includes(x.status))return json({ok:false,message:"Dados inválidos."},400,request);
        if(x.current_period_end&&!isDateYmd(x.current_period_end))return json({ok:false,message:"Data final inválida."},400,request);
        const old=await env.DB.prepare(`SELECT * FROM subscriptions WHERE church_id=? ORDER BY created_at DESC LIMIT 1`).bind(x.church_id).first();
        if(old)await env.DB.prepare(`UPDATE subscriptions SET subscription_type=?,status=?,current_period_end=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(x.subscription_type,x.status,x.current_period_end||null,old.id).run();
        else await env.DB.prepare(`INSERT INTO subscriptions(id,church_id,subscription_type,status,starts_at,current_period_end) VALUES(?,?,?,?,CURRENT_TIMESTAMP,?)`).bind(crypto.randomUUID(),x.church_id,x.subscription_type,x.status,x.current_period_end||null).run();
        await audit(env,{churchId:x.church_id,userId:g.auth.session.user_id,context:"super_admin",action:"SUBSCRIPTION_UPDATED",entityType:"subscription",entityId:old?.id||x.church_id,before:old,after:{subscription_type:x.subscription_type,status:x.status,current_period_end:x.current_period_end||null}});
        return json({ok:true,message:"Assinatura atualizada."},200,request);
      }
      if(path==="/api/super/feature"&&request.method==="POST"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;const x=await readJson(request);
        if(!x||!isUuid(x.church_id)||!/^[a-z0-9_.-]{2,60}$/i.test(String(x.feature_key||"")))return json({ok:false,message:"Dados inválidos."},400,request);
        const old=await env.DB.prepare(`SELECT * FROM church_features WHERE church_id=? AND feature_key=?`).bind(x.church_id,x.feature_key).first();
        if(old)await env.DB.prepare(`UPDATE church_features SET enabled=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(x.enabled?1:0,g.auth.session.user_id,old.id).run();
        else await env.DB.prepare(`INSERT INTO church_features(id,church_id,feature_key,enabled,updated_by) VALUES(?,?,?,?,?)`).bind(crypto.randomUUID(),x.church_id,x.feature_key,x.enabled?1:0,g.auth.session.user_id).run();
        await audit(env,{churchId:x.church_id,userId:g.auth.session.user_id,context:"super_admin",action:"FEATURE_UPDATED",entityType:"church_feature",entityId:x.feature_key,before:old,after:{enabled:!!x.enabled}});
        return json({ok:true,message:"Recurso atualizado."},200,request);
      }

      if(path==="/api/admin/rooms"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT * FROM rooms WHERE church_id=? ORDER BY active DESC,name`).bind(g.church.church_id).all();
        return json({ok:true,rooms:q.results||[]},200,request);
      }
      if(path==="/api/admin/rooms"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const usable=await assertChurchUsable(env,g.church.church_id);if(!usable.ok)return json({ok:false,error:usable.reason,message:"A igreja está com acesso administrativo limitado."},403,request);
        const name=String(x?.name||"").trim();if(!name||name.length>80)return json({ok:false,message:"Nome da sala inválido."},400,request);
        if(x.id&&!isUuid(x.id))return json({ok:false,message:"Sala inválida."},400,request);
        const min=x.min_age_months==null?null:Number(x.min_age_months),max=x.max_age_months==null?null:Number(x.max_age_months);
        if((min!=null&&(!Number.isInteger(min)||min<0||min>216))||(max!=null&&(!Number.isInteger(max)||max<0||max>216))||(min!=null&&max!=null&&min>max))return json({ok:false,message:"Faixa etária inválida."},400,request);
        if(!["any","male","female"].includes(x.gender_rule||"any"))return json({ok:false,message:"Regra de gênero inválida."},400,request);
        let id=x.id,old=null;
        if(id){old=await env.DB.prepare(`SELECT * FROM rooms WHERE id=? AND church_id=?`).bind(id,g.church.church_id).first();if(!old)return json({ok:false,message:"Sala não encontrada."},404,request);
          await env.DB.prepare(`UPDATE rooms SET name=?,room_location=?,min_age_months=?,max_age_months=?,gender_rule=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND church_id=?`).bind(name,x.room_location?String(x.room_location).slice(0,120):null,min,max,x.gender_rule||"any",x.active===false?0:1,id,g.church.church_id).run();
        }else{id=crypto.randomUUID();await env.DB.prepare(`INSERT INTO rooms(id,church_id,name,room_location,min_age_months,max_age_months,gender_rule,active) VALUES(?,?,?,?,?,?,?,?)`).bind(id,g.church.church_id,name,x.room_location?String(x.room_location).slice(0,120):null,min,max,x.gender_rule||"any",x.active===false?0:1).run();}
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:old?"ROOM_UPDATED":"ROOM_CREATED",entityType:"room",entityId:id,before:old,after:{name,min_age_months:min,max_age_months:max,gender_rule:x.gender_rule||"any",active:x.active!==false}});
        return json({ok:true,id,message:old?"Sala atualizada.":"Sala criada."},old?200:201,request);
      }
      if(path==="/api/admin/services"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT s.*,(SELECT COUNT(*) FROM service_rooms sr WHERE sr.service_id=s.id AND sr.active=1) room_count FROM services s WHERE s.church_id=? ORDER BY s.service_date DESC,COALESCE(s.starts_at,'') DESC LIMIT 100`).bind(g.church.church_id).all();
        return json({ok:true,services:q.results||[]},200,request);
      }
      if(path==="/api/admin/services"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const usable=await assertChurchUsable(env,g.church.church_id);if(!usable.ok)return json({ok:false,error:usable.reason,message:"A igreja está com acesso administrativo limitado."},403,request);
        const name=String(x?.name||"").trim(),date=String(x?.service_date||""),mode=x?.allocation_mode||"automatic";
        if(!name||name.length>100||!isDateYmd(date)||!isTimeHm(x.starts_at)||!isTimeHm(x.ends_at)||!["automatic","single_room","reception","manual"].includes(mode))return json({ok:false,message:"Dados do culto inválidos."},400,request);
        const roomIds=Array.isArray(x.room_ids)?[...new Set(x.room_ids)]:[];if(roomIds.some(id=>!isUuid(id)))return json({ok:false,message:"Sala inválida."},400,request);
        const id=crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO services(id,church_id,name,service_date,starts_at,ends_at,status,allocation_mode) VALUES(?,?,?,?,?,?,'scheduled',?)`).bind(id,g.church.church_id,name,date,x.starts_at||null,x.ends_at||null,mode).run();
        for(const rid of roomIds){const rr=await env.DB.prepare(`SELECT * FROM rooms WHERE id=? AND church_id=? AND active=1`).bind(rid,g.church.church_id).first();if(rr)await env.DB.prepare(`INSERT INTO service_rooms(id,service_id,room_id,min_age_months,max_age_months,gender_rule,active) VALUES(?,?,?,?,?,?,1)`).bind(crypto.randomUUID(),id,rr.id,rr.min_age_months,rr.max_age_months,rr.gender_rule||"any").run();}
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"SERVICE_CREATED",entityType:"service",entityId:id,after:{name,service_date:date,starts_at:x.starts_at||null,allocation_mode:mode}});
        return json({ok:true,id,message:"Culto criado."},201,request);
      }
      if(path==="/api/admin/service/status"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        if(!isUuid(x?.id)||!["scheduled","open","closed","cancelled"].includes(x.status))return json({ok:false,message:"Dados inválidos."},400,request);
        const old=await env.DB.prepare(`SELECT id,status FROM services WHERE id=? AND church_id=?`).bind(x.id,g.church.church_id).first();if(!old)return json({ok:false,message:"Culto não encontrado."},404,request);
        if(x.status==="open")await env.DB.prepare(`UPDATE services SET status='open',opened_at=COALESCE(opened_at,CURRENT_TIMESTAMP),updated_at=CURRENT_TIMESTAMP WHERE id=? AND church_id=?`).bind(x.id,g.church.church_id).run();
        else if(x.status==="closed")await env.DB.prepare(`UPDATE services SET status='closed',closed_at=CURRENT_TIMESTAMP,closed_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND church_id=?`).bind(g.auth.session.user_id,x.id,g.church.church_id).run();
        else await env.DB.prepare(`UPDATE services SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND church_id=?`).bind(x.status,x.id,g.church.church_id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"SERVICE_STATUS_UPDATED",entityType:"service",entityId:x.id,before:old,after:{status:x.status}});
        return json({ok:true,message:"Status atualizado."},200,request);
      }
      if(path==="/api/admin/schedules"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT sc.id,sc.name,sc.status,s.name service_name,s.service_date,s.starts_at,(SELECT COUNT(*) FROM schedule_assignments sa WHERE sa.schedule_id=sc.id) assignments,(SELECT COUNT(*) FROM schedule_assignments sa WHERE sa.schedule_id=sc.id AND sa.status='confirmed') confirmed FROM schedules sc JOIN services s ON s.id=sc.service_id WHERE sc.church_id=? ORDER BY s.service_date DESC`).bind(g.church.church_id).all();
        return json({ok:true,schedules:q.results||[]},200,request);
      }
      if(path==="/api/admin/schedules"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        if(!isUuid(x?.service_id))return json({ok:false,message:"Culto inválido."},400,request);
        const s=await env.DB.prepare(`SELECT id,name FROM services WHERE id=? AND church_id=?`).bind(x.service_id,g.church.church_id).first();if(!s)return json({ok:false,message:"Culto inválido."},400,request);
        const id=crypto.randomUUID(),name=String(x.name||`Escala - ${s.name}`).trim().slice(0,100);
        try{await env.DB.prepare(`INSERT INTO schedules(id,church_id,service_id,name,status,created_by) VALUES(?,?,?,?, 'draft',?)`).bind(id,g.church.church_id,s.id,name,g.auth.session.user_id).run();}catch{return json({ok:false,message:"Este culto já possui uma escala."},409,request);}
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"SCHEDULE_CREATED",entityType:"schedule",entityId:id,after:{service_id:s.id,name}});
        return json({ok:true,id,message:"Escala criada."},201,request);
      }


      // =====================================================
      // v3.1 — EQUIPE, RECORRÊNCIA, FAMÍLIAS E TESTE OPERACIONAL
      // =====================================================

      if(path==="/api/admin/team"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT cu.id church_user_id,u.id user_id,u.name,u.email,u.phone,cu.status,
          GROUP_CONCAT(cur.role) roles
          FROM church_users cu JOIN users u ON u.id=cu.user_id
          LEFT JOIN church_user_roles cur ON cur.church_user_id=cu.id
          WHERE cu.church_id=? GROUP BY cu.id,u.id,u.name,u.email,u.phone,cu.status ORDER BY u.name`).bind(cid).all();
        return json({ok:true,team:q.results||[]},200,request);
      }
      if(path==="/api/admin/team"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const usable=await assertChurchUsable(env,g.church.church_id);if(!usable.ok)return json({ok:false,message:"A igreja está com acesso administrativo limitado."},403,request);
        const name=String(x?.name||"").trim(),email=String(x?.email||"").trim().toLowerCase(),phone=String(x?.phone||"").trim();
        const roles=[...new Set(Array.isArray(x?.roles)?x.roles:[])].filter(r=>["admin","reception","teacher","assistant"].includes(r));
        if(!name||name.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!roles.length)return json({ok:false,message:"Nome, e-mail e ao menos uma função são obrigatórios."},400,request);
        let user=await env.DB.prepare(`SELECT id,name,email FROM users WHERE email=? COLLATE NOCASE`).bind(email).first(),created=false,tempPassword=null;
        if(!user){tempPassword=String(x?.temporary_password||"");if(tempPassword.length<8)return json({ok:false,message:"Para um novo usuário, informe uma senha temporária com ao menos 8 caracteres."},400,request);
          const uid=crypto.randomUUID(),hash=await hashPassword(tempPassword);await env.DB.prepare(`INSERT INTO users(id,name,email,phone,password_hash,status) VALUES(?,?,?,?,?,'active')`).bind(uid,name,email,phone||null,hash).run();user={id:uid,name,email};created=true;
        }
        let cu=await env.DB.prepare(`SELECT id FROM church_users WHERE church_id=? AND user_id=?`).bind(g.church.church_id,user.id).first();
        if(!cu){cu={id:crypto.randomUUID()};await env.DB.prepare(`INSERT INTO church_users(id,church_id,user_id,status,invited_by,joined_at) VALUES(?,?,?,'active',?,CURRENT_TIMESTAMP)`).bind(cu.id,g.church.church_id,user.id,g.auth.session.user_id).run();}
        await env.DB.prepare(`UPDATE church_users SET status='active',updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(cu.id).run();
        await env.DB.prepare(`DELETE FROM church_user_roles WHERE church_user_id=?`).bind(cu.id).run();
        for(const role of roles)await env.DB.prepare(`INSERT INTO church_user_roles(id,church_user_id,role) VALUES(?,?,?)`).bind(crypto.randomUUID(),cu.id,role).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:created?"TEAM_USER_CREATED":"TEAM_USER_UPDATED",entityType:"user",entityId:user.id,after:{name,email,roles}});
        return json({ok:true,user_id:user.id,created,message:created?"Usuário criado e vinculado.":"Funções atualizadas."},created?201:200,request);
      }

      if(path==="/api/admin/service-series"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const name=String(x?.name||"").trim(),start=String(x?.start_date||""),freq=String(x?.frequency||"weekly"),count=Math.min(52,Math.max(1,Number(x?.occurrences||1)));
        if(!name||!isDateYmd(start)||!["once","weekly","biweekly","monthly"].includes(freq)||!Number.isInteger(count))return json({ok:false,message:"Recorrência inválida."},400,request);
        if(!isTimeHm(x?.starts_at)||!isTimeHm(x?.ends_at))return json({ok:false,message:"Horário inválido."},400,request);
        const roomIds=Array.isArray(x.room_ids)?[...new Set(x.room_ids.filter(isUuid))]:[],mode=["automatic","single_room","reception","manual"].includes(x.allocation_mode)?x.allocation_mode:"automatic";
        const templateId=crypto.randomUUID(),rule=JSON.stringify({frequency:freq,occurrences:count,start_date:start});
        await env.DB.prepare(`INSERT INTO service_templates(id,church_id,name,recurrence_rule,starts_at_local,duration_minutes,allocation_mode,active) VALUES(?,?,?,?,?,NULL,?,1)`).bind(templateId,g.church.church_id,name,rule,x.starts_at||null,mode).run();
        const dates=[];let d=new Date(start+"T12:00:00Z");
        for(let i=0;i<count;i++){dates.push(d.toISOString().slice(0,10));if(freq==="once")break;if(freq==="weekly")d.setUTCDate(d.getUTCDate()+7);else if(freq==="biweekly")d.setUTCDate(d.getUTCDate()+14);else {const day=d.getUTCDate();d.setUTCMonth(d.getUTCMonth()+1);if(d.getUTCDate()!=day)d.setUTCDate(0);}}
        const created=[];
        for(const date of dates){const sid=crypto.randomUUID();await env.DB.prepare(`INSERT INTO services(id,church_id,template_id,name,service_date,starts_at,ends_at,status,allocation_mode) VALUES(?,?,?,?,?,?,?,'scheduled',?)`).bind(sid,g.church.church_id,templateId,name,date,x.starts_at||null,x.ends_at||null,mode).run();
          for(const rid of roomIds){const rr=await env.DB.prepare(`SELECT * FROM rooms WHERE id=? AND church_id=? AND active=1`).bind(rid,g.church.church_id).first();if(rr)await env.DB.prepare(`INSERT INTO service_rooms(id,service_id,room_id,min_age_months,max_age_months,gender_rule,active) VALUES(?,?,?,?,?,?,1)`).bind(crypto.randomUUID(),sid,rid,rr.min_age_months,rr.max_age_months,rr.gender_rule||"any").run();}created.push(sid)}
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"SERVICE_SERIES_CREATED",entityType:"service_template",entityId:templateId,after:{name,frequency:freq,occurrences:created.length}});
        return json({ok:true,template_id:templateId,created:created.length,message:`${created.length} ocorrência(s) criada(s).`},201,request);
      }

      if(path==="/api/admin/schedule/assignments"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),sid=url.searchParams.get("schedule_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        if(!isUuid(sid))return json({ok:false,message:"Escala inválida."},400,request);
        const own=await env.DB.prepare(`SELECT id FROM schedules WHERE id=? AND church_id=?`).bind(sid,cid).first();if(!own)return json({ok:false,message:"Escala não encontrada."},404,request);
        const q=await env.DB.prepare(`SELECT sa.*,u.name user_name,u.email,r.name room_name FROM schedule_assignments sa JOIN users u ON u.id=sa.user_id LEFT JOIN service_rooms sr ON sr.id=sa.service_room_id LEFT JOIN rooms r ON r.id=sr.room_id WHERE sa.schedule_id=? ORDER BY u.name`).bind(sid).all();
        return json({ok:true,assignments:q.results||[]},200,request);
      }
      if(path==="/api/admin/schedule/assignments"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        if(!isUuid(x?.schedule_id)||!isUuid(x?.user_id)||!["admin","reception","teacher","assistant"].includes(x?.role))return json({ok:false,message:"Dados da escala inválidos."},400,request);
        const sc=await env.DB.prepare(`SELECT sc.id,sc.service_id FROM schedules sc WHERE sc.id=? AND sc.church_id=?`).bind(x.schedule_id,g.church.church_id).first();if(!sc)return json({ok:false,message:"Escala não encontrada."},404,request);
        const member=await env.DB.prepare(`SELECT cu.id FROM church_users cu WHERE cu.church_id=? AND cu.user_id=? AND cu.status='active'`).bind(g.church.church_id,x.user_id).first();if(!member)return json({ok:false,message:"Pessoa não pertence à equipe."},400,request);
        let sr=null;if(x.service_room_id){sr=await env.DB.prepare(`SELECT id FROM service_rooms WHERE id=? AND service_id=?`).bind(x.service_room_id,sc.service_id).first();if(!sr)return json({ok:false,message:"Sala não pertence a este culto."},400,request);}
        const id=crypto.randomUUID();try{await env.DB.prepare(`INSERT INTO schedule_assignments(id,schedule_id,user_id,role,service_room_id,status) VALUES(?,?,?,?,?,'pending')`).bind(id,x.schedule_id,x.user_id,x.role,sr?.id||null).run();}catch{return json({ok:false,message:"Essa pessoa já está nessa função/sala."},409,request)}
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"SCHEDULE_ASSIGNMENT_CREATED",entityType:"schedule_assignment",entityId:id,after:{schedule_id:x.schedule_id,user_id:x.user_id,role:x.role}});
        return json({ok:true,id,message:"Pessoa adicionada à escala."},201,request);
      }
      if(path==="/api/schedule/respond"&&request.method==="POST"){
        const x=await readJson(request),g=await requireAuth(request,env);if(g.error)return g.error;
        if(!isUuid(x?.assignment_id)||!["confirmed","declined"].includes(x?.status))return json({ok:false,message:"Resposta inválida."},400,request);
        const a=await env.DB.prepare(`SELECT sa.id,sa.user_id,sc.church_id FROM schedule_assignments sa JOIN schedules sc ON sc.id=sa.schedule_id WHERE sa.id=?`).bind(x.assignment_id).first();
        if(!a||a.user_id!==g.auth.session.user_id)return json({ok:false,message:"Convite não encontrado."},404,request);
        await env.DB.prepare(`UPDATE schedule_assignments SET status=?,responded_at=CURRENT_TIMESTAMP WHERE id=?`).bind(x.status,x.assignment_id).run();
        return json({ok:true,message:"Resposta registrada."},200,request);
      }

      if(path==="/api/admin/families"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT f.id,f.family_name,f.status,
          (SELECT GROUP_CONCAT(g.name, ', ') FROM guardians g WHERE g.family_id=f.id AND g.status='active') guardians,
          (SELECT COUNT(*) FROM children ch JOIN child_guardians cg ON cg.child_id=ch.id JOIN guardians gg ON gg.id=cg.guardian_id WHERE gg.family_id=f.id AND ch.status='active') children_count
          FROM families f WHERE f.church_id=? AND f.status!='archived' ORDER BY COALESCE(f.family_name,''),f.created_at DESC`).bind(cid).all();
        return json({ok:true,families:q.results||[]},200,request);
      }
      if(path==="/api/admin/families"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const guardianName=String(x?.guardian_name||"").trim(),childFirst=String(x?.child_first_name||"").trim(),childLast=String(x?.child_last_name||"").trim(),birth=String(x?.birth_date||"");
        if(!guardianName||!childFirst||(birth&&!isDateYmd(birth)))return json({ok:false,message:"Responsável e nome da criança são obrigatórios."},400,request);
        const fid=crypto.randomUUID(),gid=crypto.randomUUID(),cid=crypto.randomUUID(),familyName=String(x?.family_name||`Família ${childLast||guardianName.split(" ").pop()}`).trim().slice(0,100);
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO families(id,church_id,family_name,status) VALUES(?,?,?,'active')`).bind(fid,g.church.church_id,familyName),
          env.DB.prepare(`INSERT INTO guardians(id,church_id,family_id,name,phone,email,is_legal_guardian,status) VALUES(?,?,?,?,?,?,1,'active')`).bind(gid,g.church.church_id,fid,guardianName,String(x?.phone||"").trim()||null,String(x?.email||"").trim().toLowerCase()||null),
          env.DB.prepare(`INSERT INTO children(id,church_id,first_name,last_name,birth_date,allergies,special_needs,general_notes,image_authorization,status) VALUES(?,?,?,?,?,?,?,?,?,'active')`).bind(cid,g.church.church_id,childFirst,childLast||null,birth||null,String(x?.allergies||"").trim()||null,String(x?.special_needs||"").trim()||null,String(x?.notes||"").trim()||null,x?.image_authorization||"pending"),
          env.DB.prepare(`INSERT INTO child_guardians(id,child_id,guardian_id,relationship,is_primary,active) VALUES(?,?,?,?,1,1)`).bind(crypto.randomUUID(),cid,gid,x?.relationship||"legal_guardian")
        ]);
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"FAMILY_CREATED",entityType:"family",entityId:fid,after:{family_name:familyName}});
        return json({ok:true,family_id:fid,child_id:cid,message:"Família e criança cadastradas."},201,request);
      }

      // =====================================================
      // v3.2 — SALA DO PROFESSOR / AUXILIAR (somente leitura)
      // Nenhuma migration nova: reutiliza schedule_assignments,
      // schedules, services, service_rooms, rooms, checkins, children.
      // =====================================================

      if(path==="/api/teacher/services"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchRole(request,env,cid,["teacher","assistant"]);if(g.error)return g.error;
        // user_id vem exclusivamente do token (g.auth.session.user_id), nunca do request.
        const q=await env.DB.prepare(`
          SELECT sa.id assignment_id, sa.role, sa.status assignment_status, sa.service_room_id,
            s.id service_id, s.name service_name, s.service_date, s.starts_at, s.ends_at, s.status service_status,
            r.name room_name
          FROM schedule_assignments sa
          JOIN schedules sc ON sc.id=sa.schedule_id
          JOIN services s ON s.id=sc.service_id
          LEFT JOIN service_rooms sr ON sr.id=sa.service_room_id
          LEFT JOIN rooms r ON r.id=sr.room_id
          WHERE sc.church_id=? AND sa.user_id=? AND sa.role IN ('teacher','assistant') AND sa.status!='replaced' AND s.status IN ('scheduled','open')
          ORDER BY s.service_date,s.starts_at
        `).bind(cid,g.auth.session.user_id).all();
        return json({ok:true,services:q.results||[]},200,request);
      }

      if(path==="/api/teacher/room"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),serviceId=url.searchParams.get("service_id"),g=await requireChurchRole(request,env,cid,["teacher","assistant"]);if(g.error)return g.error;
        if(!isUuid(serviceId))return json({ok:false,message:"Culto inválido."},400,request);

        const service=await env.DB.prepare(`SELECT id,name,service_date,starts_at,ends_at,status FROM services WHERE id=? AND church_id=?`).bind(serviceId,cid).first();
        if(!service)return json({ok:false,message:"Culto não encontrado."},404,request);

        // A sala nunca vem do request: é sempre derivada da escala do próprio usuário autenticado.
        const myAssignments=await env.DB.prepare(`
          SELECT sa.id,sa.role,sa.status,sa.service_room_id
          FROM schedule_assignments sa
          JOIN schedules sc ON sc.id=sa.schedule_id
          WHERE sc.service_id=? AND sc.church_id=? AND sa.user_id=? AND sa.role IN ('teacher','assistant') AND sa.status!='replaced'
        `).bind(serviceId,cid,g.auth.session.user_id).all();

        const assignments=myAssignments.results||[];
        if(!assignments.length)return json({ok:false,error:"not_assigned",message:"Você não está escalado para este culto."},403,request);

        const roomIds=[...new Set(assignments.map(a=>a.service_room_id).filter(Boolean))];
        const myRole=assignments.some(a=>a.role==="teacher")?"teacher":"assistant";

        let rooms=[],staff=[],children=[];
        if(roomIds.length){
          const placeholders=roomIds.map(()=>"?").join(",");

          const roomsQ=await env.DB.prepare(`
            SELECT sr.id service_room_id, r.name room_name
            FROM service_rooms sr JOIN rooms r ON r.id=sr.room_id
            WHERE sr.id IN (${placeholders})
          `).bind(...roomIds).all();
          rooms=roomsQ.results||[];

          const staffQ=await env.DB.prepare(`
            SELECT sa.role, sa.status, u.name
            FROM schedule_assignments sa
            JOIN schedules sc ON sc.id=sa.schedule_id
            JOIN users u ON u.id=sa.user_id
            WHERE sc.service_id=? AND sa.service_room_id IN (${placeholders}) AND sa.role IN ('teacher','assistant') AND sa.status!='replaced'
            ORDER BY sa.role,u.name
          `).bind(serviceId,...roomIds).all();
          staff=staffQ.results||[];

          const childrenQ=await env.DB.prepare(`
            SELECT ci.id checkin_id, ci.public_code, ci.checked_in_at,
              TRIM(ch.first_name||' '||COALESCE(ch.last_name,'')) name,
              ch.allergies, ch.special_needs
            FROM checkins ci
            JOIN children ch ON ch.id=ci.child_id
            WHERE ci.service_id=? AND ci.service_room_id IN (${placeholders}) AND ci.status='checked_in'
            ORDER BY ci.checked_in_at DESC
          `).bind(serviceId,...roomIds).all();
          children=childrenQ.results||[];
        }

        const settings=await getChurchSettings(env,cid);

        return json({
          ok:true,
          service,
          my_role:myRole,
          rooms,
          staff,
          children,
          children_count:children.length,
          features:{support:!!Number(settings.feature_support),offering:!!Number(settings.feature_offering)}
        },200,request);
      }

      // =====================================================
      // v3.3 — CONFIGURAÇÕES DA IGREJA (item 4)
      // =====================================================

      if(path==="/api/admin/settings"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const settings=await getChurchSettings(env,cid);
        return json({ok:true,settings},200,request);
      }
      if(path==="/api/admin/settings"&&request.method==="PUT"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const before=await getChurchSettings(env,g.church.church_id);
        const bool=v=>v?1:0;
        const next={
          checkin_reception_required:bool(x.checkin_reception_required),
          checkin_allow_visitors:bool(x.checkin_allow_visitors),
          checkout_require_qr:bool(x.checkout_require_qr),
          checkout_allow_exception:bool(x.checkout_allow_exception),
          labels_enabled:bool(x.labels_enabled),
          labels_per_child:Math.min(6,Math.max(1,Number(x.labels_per_child)||2)),
          labels_auto_print:bool(x.labels_auto_print),
          feature_totem:bool(x.feature_totem),
          feature_calls:bool(x.feature_calls),
          feature_support:bool(x.feature_support),
          feature_offering:bool(x.feature_offering),
          feature_devotionals:bool(x.feature_devotionals),
        };
        await env.DB.prepare(`
          INSERT INTO church_settings(church_id,checkin_reception_required,checkin_allow_visitors,checkout_require_qr,checkout_allow_exception,labels_enabled,labels_per_child,labels_auto_print,feature_totem,feature_calls,feature_support,feature_offering,feature_devotionals,updated_by)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(church_id) DO UPDATE SET
            checkin_reception_required=excluded.checkin_reception_required,
            checkin_allow_visitors=excluded.checkin_allow_visitors,
            checkout_require_qr=excluded.checkout_require_qr,
            checkout_allow_exception=excluded.checkout_allow_exception,
            labels_enabled=excluded.labels_enabled,
            labels_per_child=excluded.labels_per_child,
            labels_auto_print=excluded.labels_auto_print,
            feature_totem=excluded.feature_totem,
            feature_calls=excluded.feature_calls,
            feature_support=excluded.feature_support,
            feature_offering=excluded.feature_offering,
            feature_devotionals=excluded.feature_devotionals,
            updated_at=CURRENT_TIMESTAMP,
            updated_by=excluded.updated_by
        `).bind(g.church.church_id,next.checkin_reception_required,next.checkin_allow_visitors,next.checkout_require_qr,next.checkout_allow_exception,next.labels_enabled,next.labels_per_child,next.labels_auto_print,next.feature_totem,next.feature_calls,next.feature_support,next.feature_offering,next.feature_devotionals,g.auth.session.user_id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"SETTINGS_UPDATED",entityType:"church_settings",entityId:g.church.church_id,before,after:next});
        return json({ok:true,settings:await getChurchSettings(env,g.church.church_id),message:"Configurações salvas."},200,request);
      }

      // =====================================================
      // v3.3 — TOTEM (item 5): gestão de dispositivos (ADM) +
      // endpoints públicos do próprio totem, com escopo mínimo.
      // Um token de totem nunca acessa /api/admin/* nem /api/super/*.
      // =====================================================

      if(path==="/api/admin/kiosk-devices"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT id,name,status,last_seen_at,created_at FROM kiosk_devices WHERE church_id=? ORDER BY created_at DESC`).bind(cid).all();
        return json({ok:true,devices:q.results||[]},200,request);
      }
      if(path==="/api/admin/kiosk-devices"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const settings=await getChurchSettings(env,g.church.church_id);
        if(!Number(settings.feature_totem))return json({ok:false,message:"O recurso de Totem está desabilitado nas configurações da igreja."},403,request);
        const name=String(x?.name||"").trim();if(!name||name.length>80)return json({ok:false,message:"Dê um nome ao dispositivo (ex.: “Totem entrada”)."},400,request);
        const id=crypto.randomUUID(),rawToken=randomToken(32),tokenHash=await sha256(rawToken);
        await env.DB.prepare(`INSERT INTO kiosk_devices(id,church_id,name,token_hash,status,created_by) VALUES(?,?,?,?,'active',?)`).bind(id,g.church.church_id,name,tokenHash,g.auth.session.user_id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"KIOSK_DEVICE_CREATED",entityType:"kiosk_device",entityId:id,after:{name}});
        // O token só existe em texto puro aqui, nesta resposta. Depois disso, só o hash fica salvo.
        return json({ok:true,id,device_token:rawToken,message:"Totem criado. Copie o token agora — ele não será mostrado novamente."},201,request);
      }
      if(path==="/api/admin/kiosk-devices/revoke"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        if(!isUuid(x?.id))return json({ok:false,message:"Dispositivo inválido."},400,request);
        const dev=await env.DB.prepare(`SELECT id FROM kiosk_devices WHERE id=? AND church_id=?`).bind(x.id,g.church.church_id).first();if(!dev)return json({ok:false,message:"Totem não encontrado."},404,request);
        await env.DB.prepare(`UPDATE kiosk_devices SET status='revoked',revoked_at=CURRENT_TIMESTAMP,revoked_by=? WHERE id=?`).bind(g.auth.session.user_id,x.id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:"KIOSK_DEVICE_REVOKED",entityType:"kiosk_device",entityId:x.id});
        return json({ok:true,message:"Totem revogado."},200,request);
      }

      if(path==="/api/kiosk/identify"&&request.method==="POST"){
        const gd=await requireDevice(request,env);if(gd.error)return gd.error;
        const x=await readJson(request),phone=String(x?.phone||"").trim();
        if(!phone)return json({ok:false,message:"Informe o telefone do responsável."},400,request);
        if(await kioskRateState(env,gd.device.id)>=20)return json({ok:false,error:"too_many_attempts",message:"Muitas tentativas. Chame a recepção."},429,request);

        // Identifica SOMENTE a família daquele telefone — nunca lista famílias.
        const guardian=await env.DB.prepare(`
          SELECT g.id,g.name,g.family_id FROM guardians g
          WHERE g.church_id=? AND g.phone=? AND g.status='active' LIMIT 1
        `).bind(gd.device.church_id,phone).first();

        if(!guardian){
          await audit(env,{churchId:gd.device.church_id,context:"kiosk",action:"KIOSK_IDENTIFY_FAILED",entityType:"kiosk_device",entityId:gd.device.id,metadata:{phone}});
          return json({ok:false,error:"not_found",message:"Não encontramos um responsável com esse telefone. Procure a recepção."},404,request);
        }

        const children=await env.DB.prepare(`
          SELECT ch.id, TRIM(ch.first_name||' '||COALESCE(ch.last_name,'')) name
          FROM children ch
          JOIN child_guardians cg ON cg.child_id=ch.id
          WHERE cg.guardian_id=? AND cg.active=1 AND ch.status='active'
        `).bind(guardian.id).all();

        return json({ok:true,guardian_name:guardian.name,children:children.results||[]},200,request);
      }

      if(path==="/api/kiosk/services"&&request.method==="GET"){
        const gd=await requireDevice(request,env);if(gd.error)return gd.error;
        const q=await env.DB.prepare(`SELECT id,name,service_date,starts_at FROM services WHERE church_id=? AND status='open' ORDER BY starts_at LIMIT 5`).bind(gd.device.church_id).all();
        return json({ok:true,services:q.results||[]},200,request);
      }

      if(path==="/api/kiosk/checkin"&&request.method==="POST"){
        const gd=await requireDevice(request,env);if(gd.error)return gd.error;
        const x=await readJson(request);
        if(!isUuid(x?.service_id)||!isUuid(x?.child_id))return json({ok:false,message:"Culto/criança inválidos."},400,request);

        const service=await env.DB.prepare(`SELECT id FROM services WHERE id=? AND church_id=? AND status='open'`).bind(x.service_id,gd.device.church_id).first();
        const child=await env.DB.prepare(`SELECT id FROM children WHERE id=? AND church_id=? AND status='active'`).bind(x.child_id,gd.device.church_id).first();
        if(!service||!child)return json({ok:false,message:"Culto ou criança não encontrado."},404,request);

        const id=crypto.randomUUID(),code=String(Math.floor(100+Math.random()*900));
        try{
          await env.DB.prepare(`
            INSERT INTO checkins(id,church_id,service_id,child_id,participation_type,allocation_status,checkin_method,public_code,status)
            VALUES(?,?,?,?,'regular','pending','kiosk',?,'checked_in')
          `).bind(id,gd.device.church_id,x.service_id,x.child_id,code).run();
        }catch{return json({ok:false,message:"Essa criança já possui check-in neste culto."},409,request)}

        await audit(env,{churchId:gd.device.church_id,context:"kiosk",action:"CHECKIN_CREATED",entityType:"checkin",entityId:id,metadata:{device_id:gd.device.id},after:{service_id:x.service_id,child_id:x.child_id}});
        return json({ok:true,id,public_code:code,message:"Check-in realizado. Guarde o código para eventuais chamados."},201,request);
      }

      // =====================================================
      // v3.3 — APOIO / BANHEIRO (item 7)
      // =====================================================

      if(path==="/api/teacher/support"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchRole(request,env,x?.church_id,["teacher","assistant"]);if(g.error)return g.error;
        if(!isUuid(x?.service_id)||!["bathroom","call_guardian","reception_support","other"].includes(x?.type))return json({ok:false,message:"Dados da solicitação inválidos."},400,request);

        // Confere que o próprio usuário está mesmo escalado nessa sala/culto (mesma regra do item 1).
        const mine=await env.DB.prepare(`
          SELECT sa.service_room_id FROM schedule_assignments sa JOIN schedules sc ON sc.id=sa.schedule_id
          WHERE sc.service_id=? AND sc.church_id=? AND sa.user_id=? AND sa.role IN ('teacher','assistant') AND sa.status!='replaced'
        `).bind(x.service_id,g.church.church_id,g.auth.session.user_id).all();
        if(!(mine.results||[]).length)return json({ok:false,error:"not_assigned",message:"Você não está escalado para este culto."},403,request);
        const myRoomId=(mine.results||[]).map(r=>r.service_room_id).filter(Boolean)[0]||null;

        if(x.child_id&&!isUuid(x.child_id))return json({ok:false,message:"Criança inválida."},400,request);
        const id=crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO support_requests(id,church_id,service_id,service_room_id,child_id,type,status,requested_by) VALUES(?,?,?,?,?,?,'waiting',?)`).bind(id,g.church.church_id,x.service_id,myRoomId,x.child_id||null,x.type,g.auth.session.user_id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"teacher",action:"SUPPORT_REQUESTED",entityType:"support_request",entityId:id,after:{type:x.type,service_id:x.service_id}});
        return json({ok:true,id,message:"Solicitação enviada à recepção."},201,request);
      }

      if(path==="/api/reception/support"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchRole(request,env,cid,["admin","reception"]);if(g.error)return g.error;
        const q=await env.DB.prepare(`
          SELECT sr.id,sr.type,sr.status,sr.created_at,sr.accepted_at,
            r.name room_name, TRIM(COALESCE(ch.first_name,'')||' '||COALESCE(ch.last_name,'')) child_name
          FROM support_requests sr
          LEFT JOIN service_rooms svr ON svr.id=sr.service_room_id
          LEFT JOIN rooms r ON r.id=svr.room_id
          LEFT JOIN children ch ON ch.id=sr.child_id
          WHERE sr.church_id=? AND sr.status!='completed'
          ORDER BY CASE sr.status WHEN 'waiting' THEN 1 WHEN 'in_progress' THEN 2 ELSE 3 END, sr.created_at
        `).bind(cid).all();
        return json({ok:true,requests:q.results||[]},200,request);
      }
      if(path==="/api/reception/support/accept"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchRole(request,env,x?.church_id,["admin","reception"]);if(g.error)return g.error;
        if(!isUuid(x?.id))return json({ok:false,message:"Solicitação inválida."},400,request);
        const req_=await env.DB.prepare(`SELECT id,status FROM support_requests WHERE id=? AND church_id=?`).bind(x.id,g.church.church_id).first();if(!req_)return json({ok:false,message:"Não encontrada."},404,request);
        await env.DB.prepare(`UPDATE support_requests SET status='in_progress',accepted_by=?,accepted_at=CURRENT_TIMESTAMP WHERE id=?`).bind(g.auth.session.user_id,x.id).run();
        return json({ok:true,message:"Em atendimento."},200,request);
      }
      if(path==="/api/reception/support/complete"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchRole(request,env,x?.church_id,["admin","reception"]);if(g.error)return g.error;
        if(!isUuid(x?.id))return json({ok:false,message:"Solicitação inválida."},400,request);
        const req_=await env.DB.prepare(`SELECT id,status FROM support_requests WHERE id=? AND church_id=?`).bind(x.id,g.church.church_id).first();if(!req_)return json({ok:false,message:"Não encontrada."},404,request);
        await env.DB.prepare(`UPDATE support_requests SET status='completed',completed_by=?,completed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(g.auth.session.user_id,x.id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"reception",action:"SUPPORT_COMPLETED",entityType:"support_request",entityId:x.id});
        return json({ok:true,message:"Solicitação concluída."},200,request);
      }

      // =====================================================
      // v3.3 — DEVOCIONAIS (item 9)
      // =====================================================

      if(path==="/api/admin/devotionals"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT * FROM devotionals WHERE church_id=? ORDER BY created_at DESC LIMIT 100`).bind(cid).all();
        return json({ok:true,devotionals:q.results||[]},200,request);
      }
      if(path==="/api/admin/devotionals"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchAdmin(request,env,x?.church_id);if(g.error)return g.error;
        const title=String(x?.title||"").trim();if(!title||title.length>150)return json({ok:false,message:"Título é obrigatório."},400,request);
        if(!["draft","published","archived"].includes(x?.status||"draft"))return json({ok:false,message:"Status inválido."},400,request);
        if(x.id&&!isUuid(x.id))return json({ok:false,message:"Devocional inválido."},400,request);
        const fields={
          theme:String(x?.theme||"").trim()||null,
          bible_reference:String(x?.bible_reference||"").trim()||null,
          objective:String(x?.objective||"").trim()||null,
          content:String(x?.content||"").trim()||null,
          activity:String(x?.activity||"").trim()||null,
          questions:String(x?.questions||"").trim()||null,
          materials:String(x?.materials||"").trim()||null,
          status:x?.status||"draft",
          service_id: x.service_id&&isUuid(x.service_id)?x.service_id:null,
        };
        let id=x.id,old=null;
        if(id){
          old=await env.DB.prepare(`SELECT * FROM devotionals WHERE id=? AND church_id=?`).bind(id,g.church.church_id).first();if(!old)return json({ok:false,message:"Devocional não encontrado."},404,request);
          await env.DB.prepare(`UPDATE devotionals SET title=?,theme=?,bible_reference=?,objective=?,content=?,activity=?,questions=?,materials=?,status=?,service_id=?,updated_at=CURRENT_TIMESTAMP,published_at=CASE WHEN ?='published' AND published_at IS NULL THEN CURRENT_TIMESTAMP ELSE published_at END WHERE id=? AND church_id=?`)
            .bind(title,fields.theme,fields.bible_reference,fields.objective,fields.content,fields.activity,fields.questions,fields.materials,fields.status,fields.service_id,fields.status,id,g.church.church_id).run();
        }else{
          id=crypto.randomUUID();
          await env.DB.prepare(`INSERT INTO devotionals(id,church_id,title,theme,bible_reference,objective,content,activity,questions,materials,status,author_id,service_id,published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ?='published' THEN CURRENT_TIMESTAMP ELSE NULL END)`)
            .bind(id,g.church.church_id,title,fields.theme,fields.bible_reference,fields.objective,fields.content,fields.activity,fields.questions,fields.materials,fields.status,g.auth.session.user_id,fields.service_id,fields.status).run();
        }
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"church_admin",action:old?"DEVOTIONAL_UPDATED":"DEVOTIONAL_CREATED",entityType:"devotional",entityId:id,before:old,after:{title,status:fields.status}});
        return json({ok:true,id,message:old?"Devocional atualizado.":"Devocional criado."},old?200:201,request);
      }

      if(path==="/api/teacher/devotionals"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchRole(request,env,cid,["teacher","assistant"]);if(g.error)return g.error;
        const serviceId=url.searchParams.get("service_id");
        const q=await env.DB.prepare(`
          SELECT id,title,theme,bible_reference,objective,content,activity,questions,materials,service_id,published_at
          FROM devotionals
          WHERE church_id=? AND status='published' AND (service_id IS NULL OR service_id=?)
          ORDER BY CASE WHEN service_id=? THEN 0 ELSE 1 END, published_at DESC
          LIMIT 20
        `).bind(cid,serviceId||"",serviceId||"").all();
        return json({ok:true,devotionals:q.results||[]},200,request);
      }

      // =====================================================
      // v3.3 — OFERTA (item 10)
      // =====================================================

      if(path==="/api/teacher/offering"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchRole(request,env,x?.church_id,["teacher","assistant"]);if(g.error)return g.error;
        const settings=await getChurchSettings(env,g.church.church_id);
        if(!Number(settings.feature_offering))return json({ok:false,message:"O registro de oferta está desabilitado nas configurações da igreja."},403,request);
        if(!isUuid(x?.service_id))return json({ok:false,message:"Culto inválido."},400,request);
        const amountCents=Math.round(Number(x?.amount_cents||0));
        if(!Number.isInteger(amountCents)||amountCents<=0)return json({ok:false,message:"Informe um valor válido."},400,request);

        const mine=await env.DB.prepare(`
          SELECT sa.service_room_id FROM schedule_assignments sa JOIN schedules sc ON sc.id=sa.schedule_id
          WHERE sc.service_id=? AND sc.church_id=? AND sa.user_id=? AND sa.role IN ('teacher','assistant') AND sa.status!='replaced'
        `).bind(x.service_id,g.church.church_id,g.auth.session.user_id).all();
        if(!(mine.results||[]).length)return json({ok:false,error:"not_assigned",message:"Você não está escalado para este culto."},403,request);
        const myRoomId=(mine.results||[]).map(r=>r.service_room_id).filter(Boolean)[0]||null;

        const id=crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO offerings(id,church_id,service_id,service_room_id,amount_cents,note,created_by) VALUES(?,?,?,?,?,?,?)`).bind(id,g.church.church_id,x.service_id,myRoomId,amountCents,String(x?.note||"").trim()||null,g.auth.session.user_id).run();
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"teacher",action:"OFFERING_REGISTERED",entityType:"offering",entityId:id,after:{service_id:x.service_id,amount_cents:amountCents}});
        return json({ok:true,id,message:"Oferta registrada."},201,request);
      }

      if(path==="/api/admin/offerings"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const serviceId=url.searchParams.get("service_id");
        const q=await env.DB.prepare(`
          SELECT o.id,o.amount_cents,o.note,o.created_at,r.name room_name,s.name service_name,s.service_date
          FROM offerings o
          LEFT JOIN service_rooms sr ON sr.id=o.service_room_id LEFT JOIN rooms r ON r.id=sr.room_id
          JOIN services s ON s.id=o.service_id
          WHERE o.church_id=? ${serviceId?"AND o.service_id=?":""}
          ORDER BY o.created_at DESC LIMIT 200
        `).bind(...(serviceId?[cid,serviceId]:[cid])).all();
        const rows=q.results||[];
        const total=rows.reduce((sum,r)=>sum+Number(r.amount_cents||0),0);
        return json({ok:true,offerings:rows,total_cents:total},200,request);
      }

      // =====================================================
      // v3.3 — RELATÓRIOS (item 11) — só leitura, tabelas existentes
      // =====================================================

      if(path==="/api/admin/reports/attendance"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const from=url.searchParams.get("from")||"2000-01-01",to=url.searchParams.get("to")||"2999-12-31";
        const q=await env.DB.prepare(`
          SELECT s.id service_id,s.name,s.service_date,
            (SELECT COUNT(*) FROM checkins ci WHERE ci.service_id=s.id AND ci.status!='cancelled') checkins,
            (SELECT COUNT(*) FROM checkins ci WHERE ci.service_id=s.id AND ci.checkin_method='kiosk' AND ci.status!='cancelled') via_totem
          FROM services s
          WHERE s.church_id=? AND s.service_date BETWEEN ? AND ?
          ORDER BY s.service_date DESC LIMIT 200
        `).bind(cid,from,to).all();
        return json({ok:true,attendance:q.results||[]},200,request);
      }
      if(path==="/api/admin/reports/rooms"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),sid=url.searchParams.get("service_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        if(!isUuid(sid))return json({ok:false,message:"Culto inválido."},400,request);
        const q=await env.DB.prepare(`
          SELECT r.name room_name,
            (SELECT COUNT(*) FROM checkins ci WHERE ci.service_room_id=sr.id AND ci.status!='cancelled') children
          FROM service_rooms sr JOIN rooms r ON r.id=sr.room_id
          WHERE sr.service_id=? AND sr.active=1 ORDER BY r.name
        `).bind(sid).all();
        return json({ok:true,rooms:q.results||[]},200,request);
      }
      if(path==="/api/admin/reports/team"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchAdmin(request,env,cid);if(g.error)return g.error;
        const from=url.searchParams.get("from")||"2000-01-01",to=url.searchParams.get("to")||"2999-12-31";
        const q=await env.DB.prepare(`
          SELECT u.name,
            COUNT(*) total,
            SUM(CASE WHEN sa.status='confirmed' THEN 1 ELSE 0 END) confirmed,
            SUM(CASE WHEN sa.status='declined' THEN 1 ELSE 0 END) declined,
            SUM(CASE WHEN sa.status='pending' THEN 1 ELSE 0 END) pending
          FROM schedule_assignments sa
          JOIN schedules sc ON sc.id=sa.schedule_id
          JOIN services s ON s.id=sc.service_id
          JOIN users u ON u.id=sa.user_id
          WHERE sc.church_id=? AND s.service_date BETWEEN ? AND ? AND sa.status!='replaced'
          GROUP BY u.id,u.name ORDER BY u.name
        `).bind(cid,from,to).all();
        return json({ok:true,team:q.results||[]},200,request);
      }

      // =====================================================
      // v3.3 — COMUNICADOS DA PLATAFORMA (item 12)
      // =====================================================

      if(path==="/api/super/announcements"&&request.method==="GET"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT * FROM announcements ORDER BY created_at DESC LIMIT 200`).all();
        return json({ok:true,announcements:q.results||[]},200,request);
      }
      if(path==="/api/super/announcements"&&request.method==="POST"){
        const g=await requireSuperAdmin(request,env);if(g.error)return g.error;
        const x=await readJson(request);
        const title=String(x?.title||"").trim(),message=String(x?.message||"").trim();
        if(!title||!message)return json({ok:false,message:"Título e mensagem são obrigatórios."},400,request);
        if(!["info","warning","critical"].includes(x?.type||"info")||!["low","normal","high"].includes(x?.priority||"normal")||!["draft","published","cancelled"].includes(x?.status||"draft"))return json({ok:false,message:"Dados inválidos."},400,request);
        if(x.church_id&&!isUuid(x.church_id))return json({ok:false,message:"Igreja inválida."},400,request);
        let id=x.id;
        if(id){
          if(!isUuid(id))return json({ok:false,message:"Comunicado inválido."},400,request);
          await env.DB.prepare(`UPDATE announcements SET title=?,message=?,type=?,priority=?,audience=?,church_id=?,starts_at=?,ends_at=?,status=? WHERE id=?`)
            .bind(title,message,x.type||"info",x.priority||"normal",x.church_id?"church":"all",x.church_id||null,x.starts_at||null,x.ends_at||null,x.status||"draft",id).run();
        }else{
          id=crypto.randomUUID();
          await env.DB.prepare(`INSERT INTO announcements(id,title,message,type,priority,audience,church_id,starts_at,ends_at,status,author_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(id,title,message,x.type||"info",x.priority||"normal",x.church_id?"church":"all",x.church_id||null,x.starts_at||null,x.ends_at||null,x.status||"draft",g.auth.session.user_id).run();
        }
        await audit(env,{userId:g.auth.session.user_id,context:"super_admin",action:"ANNOUNCEMENT_SAVED",entityType:"announcement",entityId:id,after:{title,status:x.status||"draft"}});
        return json({ok:true,id,message:"Comunicado salvo."},200,request);
      }

      if(path==="/api/announcements"&&request.method==="GET"){
        const g=await requireAuth(request,env);if(g.error)return g.error;
        const cid=url.searchParams.get("church_id");
        const q=await env.DB.prepare(`
          SELECT a.id,a.title,a.message,a.type,a.priority,a.created_at,
            EXISTS(SELECT 1 FROM announcement_reads ar WHERE ar.announcement_id=a.id AND ar.user_id=?) is_read
          FROM announcements a
          WHERE a.status='published'
            AND (a.audience='all' OR a.church_id=?)
            AND (a.starts_at IS NULL OR datetime(a.starts_at)<=datetime('now'))
            AND (a.ends_at IS NULL OR datetime(a.ends_at)>=datetime('now'))
          ORDER BY a.created_at DESC LIMIT 20
        `).bind(g.auth.session.user_id,cid||"").all();
        return json({ok:true,announcements:q.results||[]},200,request);
      }
      if(path==="/api/announcements/read"&&request.method==="POST"){
        const g=await requireAuth(request,env);if(g.error)return g.error;
        const x=await readJson(request);if(!isUuid(x?.id))return json({ok:false,message:"Comunicado inválido."},400,request);
        try{await env.DB.prepare(`INSERT INTO announcement_reads(id,announcement_id,user_id) VALUES(?,?,?)`).bind(crypto.randomUUID(),x.id,g.auth.session.user_id).run();}catch{}
        return json({ok:true},200,request);
      }

      if(path==="/api/operations/checkin/options"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),g=await requireChurchRole(request,env,cid,["admin","reception","teacher"]);if(g.error)return g.error;
        const services=await env.DB.prepare(`SELECT id,name,service_date,starts_at,status FROM services WHERE church_id=? AND status IN('scheduled','open') ORDER BY service_date,starts_at LIMIT 30`).bind(cid).all();
        const children=await env.DB.prepare(`SELECT id,TRIM(first_name||' '||COALESCE(last_name,'')) name,birth_date FROM children WHERE church_id=? AND status='active' ORDER BY first_name,last_name`).bind(cid).all();
        return json({ok:true,services:services.results||[],children:children.results||[]},200,request);
      }
      if(path==="/api/operations/checkin"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),serviceId=url.searchParams.get("service_id"),g=await requireChurchRole(request,env,cid,["admin","reception","teacher","assistant"]);if(g.error)return g.error;
        if(!isUuid(serviceId))return json({ok:false,message:"Culto inválido."},400,request);
        const q=await env.DB.prepare(`SELECT ci.id,ci.child_id,ci.status,ci.public_code,ci.checked_in_at,TRIM(ch.first_name||' '||COALESCE(ch.last_name,'')) child_name,r.name room_name FROM checkins ci JOIN children ch ON ch.id=ci.child_id LEFT JOIN service_rooms sr ON sr.id=ci.service_room_id LEFT JOIN rooms r ON r.id=sr.room_id WHERE ci.church_id=? AND ci.service_id=? AND ci.status!='cancelled' ORDER BY ci.checked_in_at DESC`).bind(cid,serviceId).all();
        return json({ok:true,checkins:q.results||[]},200,request);
      }
      if(path==="/api/operations/checkin"&&request.method==="POST"){
        const x=await readJson(request),g=await requireChurchRole(request,env,x?.church_id,["admin","reception"]);if(g.error)return g.error;
        if(!isUuid(x?.service_id)||!isUuid(x?.child_id))return json({ok:false,message:"Culto/criança inválidos."},400,request);
        const service=await env.DB.prepare(`SELECT id FROM services WHERE id=? AND church_id=? AND status IN('scheduled','open')`).bind(x.service_id,g.church.church_id).first(),child=await env.DB.prepare(`SELECT id FROM children WHERE id=? AND church_id=? AND status='active'`).bind(x.child_id,g.church.church_id).first();
        if(!service||!child)return json({ok:false,message:"Culto ou criança não encontrado."},404,request);
        let sr=null;if(x.service_room_id)sr=await env.DB.prepare(`SELECT id FROM service_rooms WHERE id=? AND service_id=? AND active=1`).bind(x.service_room_id,x.service_id).first();
        const id=crypto.randomUUID(),code=String(Math.floor(100+Math.random()*900));
        try{await env.DB.prepare(`INSERT INTO checkins(id,church_id,service_id,child_id,service_room_id,participation_type,allocation_status,brought_by_name,checkin_method,checked_in_by,public_code,status) VALUES(?,?,?,?,?,'regular',?,?,? ,?,?,'checked_in')`).bind(id,g.church.church_id,x.service_id,x.child_id,sr?.id||null,sr?"allocated":"pending",String(x.brought_by_name||"").trim()||null,"reception",g.auth.session.user_id,code).run();}catch{return json({ok:false,message:"Essa criança já possui check-in neste culto."},409,request)}
        await audit(env,{churchId:g.church.church_id,userId:g.auth.session.user_id,context:"reception",action:"CHECKIN_CREATED",entityType:"checkin",entityId:id,after:{service_id:x.service_id,child_id:x.child_id}});
        return json({ok:true,id,public_code:code,message:"Check-in realizado."},201,request);
      }
      if(path==="/api/operations/service-rooms"&&request.method==="GET"){
        const cid=url.searchParams.get("church_id"),sid=url.searchParams.get("service_id"),g=await requireChurchRole(request,env,cid,["admin","reception","teacher","assistant"]);if(g.error)return g.error;
        const q=await env.DB.prepare(`SELECT sr.id,r.name FROM service_rooms sr JOIN rooms r ON r.id=sr.room_id JOIN services s ON s.id=sr.service_id WHERE sr.service_id=? AND s.church_id=? AND sr.active=1 ORDER BY r.name`).bind(sid,cid).all();
        return json({ok:true,rooms:q.results||[]},200,request);
      }

      // =====================================================
      // DASHBOARD DA IGREJA
      // Dados reais do D1 para o painel administrativo.
      // church_id é opcional e só é aceito se o usuário
      // autenticado realmente pertencer àquela igreja.
      // =====================================================

      if (path === "/api/dashboard" && request.method === "GET") {
        const auth = await getAuthenticatedUser(request, env);

        if (!auth) {
          return json({
            ok: false,
            error: "unauthorized",
            message: "Sessão inválida ou expirada.",
          }, 401, request);
        }

        const requestedChurchId = url.searchParams.get("church_id");
        if (!requestedChurchId || !isUuid(requestedChurchId)) {
          return json({ok:false,error:"church_id_required",message:"Informe uma igreja válida."},400,request);
        }
        const membership = await getAuthorizedChurch(
          env,
          auth.session.user_id,
          requestedChurchId
        );

        if (!membership) {
          return json({
            ok: false,
            error: "church_access_denied",
            message: "Usuário sem acesso à igreja solicitada.",
          }, 403, request);
        }

        // Neste primeiro dashboard real, restringimos o painel
        // administrativo a usuários com função admin.
        if (!membership.roles.includes("admin")) {
          return json({
            ok: false,
            error: "admin_required",
            message: "Este painel exige função de administrador.",
          }, 403, request);
        }

        const churchMeta=await env.DB.prepare(`SELECT timezone FROM churches WHERE id=?`).bind(membership.church_id).first();
        const churchToday=todayInTimezone(churchMeta?.timezone||"America/Sao_Paulo");

        // Prioridade:
        // 1) culto aberto;
        // 2) próximo culto agendado de hoje em diante;
        // 3) culto mais recente.
        let service = await env.DB.prepare(`
          SELECT id, name, service_date, starts_at, ends_at, status, allocation_mode
          FROM services
          WHERE church_id = ?
            AND status = 'open'
          ORDER BY opened_at DESC, service_date DESC, starts_at DESC
          LIMIT 1
        `).bind(membership.church_id).first();

        if (!service) {
          service = await env.DB.prepare(`
            SELECT id, name, service_date, starts_at, ends_at, status, allocation_mode
            FROM services
            WHERE church_id = ?
              AND status = 'scheduled'
              AND service_date >= ?
            ORDER BY service_date ASC, starts_at ASC
            LIMIT 1
          `).bind(membership.church_id,churchToday).first();
        }

        if (!service) {
          service = await env.DB.prepare(`
            SELECT id, name, service_date, starts_at, ends_at, status, allocation_mode
            FROM services
            WHERE church_id = ?
            ORDER BY service_date DESC, starts_at DESC
            LIMIT 1
          `).bind(membership.church_id).first();
        }

        if (!service) {
          return json({
            ok: true,
            church: {
              id: membership.church_id,
              name: membership.church_name,
              slug: membership.slug,
            },
            roles: membership.roles,
            service: null,
            summary: {
              children_present: 0,
              scheduled: 0,
              confirmed: 0,
              active_rooms: 0,
              active_calls: 0,
            },
            recent_checkins: [],
            schedule: [],
          }, 200, request);
        }

        const [
          childrenPresent,
          scheduled,
          confirmed,
          activeRooms,
          activeCalls,
          recentCheckins,
          scheduleRows,
        ] = await Promise.all([
          env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM checkins
            WHERE service_id = ?
              AND status = 'checked_in'
          `).bind(service.id).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM schedule_assignments sa
            JOIN schedules sc ON sc.id = sa.schedule_id
            WHERE sc.service_id = ?
              AND sc.status != 'cancelled'
              AND sa.status != 'replaced'
          `).bind(service.id).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM schedule_assignments sa
            JOIN schedules sc ON sc.id = sa.schedule_id
            WHERE sc.service_id = ?
              AND sc.status != 'cancelled'
              AND sa.status = 'confirmed'
          `).bind(service.id).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM service_rooms
            WHERE service_id = ?
              AND active = 1
          `).bind(service.id).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM parent_calls
            WHERE service_id = ?
              AND status IN ('waiting', 'acknowledged')
          `).bind(service.id).first(),

          env.DB.prepare(`
            SELECT
              ci.id,
              ci.public_code,
              ci.checked_in_at,
              ci.status,
              ci.participation_type,
              TRIM(ch.first_name || ' ' || COALESCE(ch.last_name, '')) AS child_name,
              r.name AS room_name
            FROM checkins ci
            JOIN children ch ON ch.id = ci.child_id
            LEFT JOIN service_rooms sr ON sr.id = ci.service_room_id
            LEFT JOIN rooms r ON r.id = sr.room_id
            WHERE ci.service_id = ?
              AND ci.status != 'cancelled'
            ORDER BY ci.checked_in_at DESC
            LIMIT 8
          `).bind(service.id).all(),

          env.DB.prepare(`
            SELECT
              sa.id,
              sa.role,
              sa.status,
              u.id AS user_id,
              u.name AS user_name,
              r.name AS room_name
            FROM schedule_assignments sa
            JOIN schedules sc ON sc.id = sa.schedule_id
            JOIN users u ON u.id = sa.user_id
            LEFT JOIN service_rooms sr ON sr.id = sa.service_room_id
            LEFT JOIN rooms r ON r.id = sr.room_id
            WHERE sc.service_id = ?
              AND sc.status != 'cancelled'
              AND sa.status != 'replaced'
            ORDER BY
              CASE sa.status
                WHEN 'confirmed' THEN 1
                WHEN 'pending' THEN 2
                WHEN 'declined' THEN 3
                WHEN 'absent' THEN 4
                ELSE 5
              END,
              u.name
            LIMIT 20
          `).bind(service.id).all(),
        ]);

        return json({
          ok: true,
          church: {
            id: membership.church_id,
            name: membership.church_name,
            slug: membership.slug,
          },
          roles: membership.roles,
          service,
          summary: {
            children_present: Number(childrenPresent?.total || 0),
            scheduled: Number(scheduled?.total || 0),
            confirmed: Number(confirmed?.total || 0),
            active_rooms: Number(activeRooms?.total || 0),
            active_calls: Number(activeCalls?.total || 0),
          },
          recent_checkins: recentCheckins.results || [],
          schedule: scheduleRows.results || [],
        }, 200, request);
      }

      // =====================================================
      // LOGOUT
      // =====================================================

      if (path === "/api/auth/logout" && request.method === "POST") {
        const auth = await getAuthenticatedUser(request, env);

        if (!auth) {
          return json({
            ok: false,
            error: "unauthorized",
            message: "Sessão inválida ou já encerrada.",
          }, 401, request);
        }

        await env.DB.batch([
          env.DB.prepare(`
            UPDATE sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(auth.session.session_id),

          env.DB.prepare(`
            INSERT INTO audit_log (
              id,
              actor_user_id,
              actor_context,
              action,
              entity_type,
              entity_id
            )
            VALUES (?, ?, 'logout', 'LOGOUT', 'user', ?)
          `).bind(
            crypto.randomUUID(),
            auth.session.user_id,
            auth.session.user_id
          ),
        ]);

        return json({
          ok: true,
          message: "Sessão encerrada com sucesso.",
        }, 200, request);
      }

      // =====================================================
      // NOT FOUND
      // =====================================================

      return json({
        ok: false,
        error: "not_found",
        message: "Rota não encontrada.",
        path,
        version: API_VERSION,
      }, 404, request);

    } catch (error) {
      console.error("TAF KIDS API ERROR:", error);

      return json({
        ok: false,
        error: "internal_error",
        message: "Erro interno na API.",
        version: API_VERSION,
      }, 500, request);
    }
  },
};