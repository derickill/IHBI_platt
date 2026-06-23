require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const path    = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname)));

// ── Base de données PostgreSQL ──────────────────────────────────────────────
// En prod : DATABASE_URL fourni automatiquement par Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'ihbi-dev-secret-changez-en-prod';
const JWT_EXPIRES = '7d';

// ── Utilitaires ─────────────────────────────────────────────────────────────
const sha256 = str => crypto.createHash('sha256').update(str).digest('hex');

// ── Génération de mot de passe sécurisé ────────────────────────────────────
function generatePassword() {
  const upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower   = 'abcdefghjkmnpqrstuvwxyz';
  const digits  = '23456789';
  const special = '@#!$%';
  const all     = upper + lower + digits + special;
  const bytes   = crypto.randomBytes(12);
  let pwd = '';
  // Au moins un de chaque catégorie
  pwd += upper[bytes[0]  % upper.length];
  pwd += lower[bytes[1]  % lower.length];
  pwd += digits[bytes[2] % digits.length];
  pwd += special[bytes[3] % special.length];
  for (let i = 4; i < 12; i++) pwd += all[bytes[i] % all.length];
  // Mélange (Fisher-Yates)
  const arr = pwd.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

// ── Extraction prénom / nom depuis l'email ──────────────────────────────────
function nameFromEmail(email) {
  const local = email.split('@')[0].replace(/[_\-]/g, '.');
  const parts = local.split('.').filter(Boolean);
  const cap   = s => s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : '';
  if (parts.length >= 2) return { prenom: cap(parts[0]), nom: parts.slice(1).map(cap).join(' ') };
  return { prenom: cap(parts[0] || 'Étudiant'), nom: 'IHBI' };
}

// ── Brevo API — envoi d'emails transactionnels via HTTPS ───────────────────
// Doc : https://developers.brevo.com/reference/sendtransacemail
// Prérequis : BREVO_API_KEY + BREVO_FROM (email expéditeur vérifié dans Brevo)
const APP_URL = process.env.APP_URL || '';

async function sendWelcomeEmail(email, prenom, nom, password, classe_id) {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_FROM) {
    console.log('BREVO_API_KEY ou BREVO_FROM non configuré — email non envoyé');
    return false;
  }

  const htmlContent = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;color:#1a1a1a">
      <div style="background:#250D42;padding:24px 32px">
        <h1 style="color:white;font-size:20px;margin:0">IHBI — Plateforme étudiante</h1>
      </div>
      <div style="padding:28px 32px;background:#fff;border:1px solid #e5e7eb">
        <h2 style="font-size:18px;color:#250D42;margin-top:0">Bienvenue, ${prenom} !</h2>
        <p style="color:#555;line-height:1.6">Votre compte étudiant a été créé pour la classe <strong>${classe_id}</strong>. Voici vos identifiants de connexion :</p>
        <div style="background:#f8f9fa;border-left:4px solid #250D42;padding:16px 20px;margin:20px 0;border-radius:0 4px 4px 0">
          <p style="margin:0 0 8px;font-size:14px"><strong>Email :</strong> ${email}</p>
          <p style="margin:0;font-size:14px"><strong>Mot de passe :</strong> <code style="background:#e8e8e8;padding:3px 8px;border-radius:3px;font-size:14px;letter-spacing:.5px">${password}</code></p>
        </div>
        ${APP_URL ? `<a href="${APP_URL}" style="display:inline-block;background:#250D42;color:white;padding:12px 24px;text-decoration:none;font-weight:600;border-radius:3px;margin-bottom:20px">Accéder à la plateforme →</a>` : ''}
        <p style="font-size:12px;color:#999;margin-bottom:0">Pour votre sécurité, nous vous recommandons de changer votre mot de passe après votre première connexion.</p>
      </div>
      <div style="padding:16px 32px;background:#f8f9fa;font-size:11px;color:#999;text-align:center">
        International High Business Institute — IHBI
      </div>
    </div>
  `;

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method:  'POST',
    headers: {
      'api-key':      process.env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      'accept':       'application/json',
    },
    body: JSON.stringify({
      sender:      { name: 'IHBI Platform', email: process.env.BREVO_FROM },
      to:          [{ email, name: `${prenom} ${nom}` }],
      subject:     'Vos identifiants de connexion — IHBI',
      htmlContent,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Brevo API error: ${res.status} — ${err}`);
  }
  return true;
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expirée, veuillez vous reconnecter' });
  }
}

// ── POST /api/auth/login ────────────────────────────────────────────────────
// Vérifie email + mot de passe, retourne JWT + données de la session
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Champs manquants' });

    const hash = sha256(password);
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND pwd_hash = $2',
      [email, hash]
    );

    if (!rows.length) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const user = rows[0];
    delete user.pwd_hash; // ne jamais renvoyer le hash

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    // Charger toutes les données (blob + tables SQL)
    const data = await getFullData();

    res.json({ token, user, data });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Création des tables SQL transactionnelles ───────────────────────────────
async function ensureTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS annonces (
        id           SERIAL PRIMARY KEY,
        titre        TEXT NOT NULL,
        corps        TEXT DEFAULT '',
        cible        TEXT DEFAULT 'Tous les étudiants',
        date         TEXT,
        published_at TIMESTAMPTZ DEFAULT NOW(),
        expiration   TEXT,
        statut       TEXT DEFAULT 'active',
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages_teacher (
        id      SERIAL PRIMARY KEY,
        de      TEXT NOT NULL,
        vers    TEXT NOT NULL,
        sujet   TEXT NOT NULL,
        corps   TEXT NOT NULL,
        date    TIMESTAMPTZ DEFAULT NOW(),
        statut  TEXT DEFAULT 'envoyé'
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages_delegates (
        id         SERIAL PRIMARY KEY,
        from_id    INTEGER,
        from_name  TEXT,
        classe_id  TEXT DEFAULT '',
        to_role    TEXT,
        to_id      INTEGER,
        to_name    TEXT,
        sujet      TEXT DEFAULT '',
        corps      TEXT DEFAULT '',
        date       TIMESTAMPTZ DEFAULT NOW(),
        lu         BOOLEAN DEFAULT FALSE
      )
    `);
    // Brouillons / emplois du temps publiés par classe et semaine
    await pool.query(`
      CREATE TABLE IF NOT EXISTS edt_drafts (
        id         SERIAL PRIMARY KEY,
        classe_id  TEXT NOT NULL,
        week_id    TEXT NOT NULL,
        slots      JSONB DEFAULT '[]',
        statut     TEXT DEFAULT 'brouillon',
        date_saved TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (classe_id, week_id)
      )
    `);
    // Formations publiées par l'admin
    await pool.query(`
      CREATE TABLE IF NOT EXISTS formations (
        id          SERIAL PRIMARY KEY,
        titre       TEXT NOT NULL,
        description TEXT DEFAULT '',
        lieu        TEXT DEFAULT '',
        date_debut  TEXT,
        date_fin    TEXT,
        places      INTEGER DEFAULT 30,
        public      BOOLEAN DEFAULT TRUE,
        statut      TEXT DEFAULT 'actif',
        created_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Inscriptions à une formation (visiteurs non connectés)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS inscriptions_formations (
        id           SERIAL PRIMARY KEY,
        formation_id INTEGER NOT NULL REFERENCES formations(id) ON DELETE CASCADE,
        nom          TEXT NOT NULL,
        prenom       TEXT NOT NULL,
        profession   TEXT DEFAULT '',
        email        TEXT NOT NULL,
        telephone    TEXT DEFAULT '',
        date         TEXT,
        created_at   TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (formation_id, email)
      )
    `);
    // Migration : ajouter is_delegue sur la table users si elle n'existe pas encore
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_delegue BOOLEAN DEFAULT FALSE
    `);
    console.log('[DB] Tables vérifiées ✓');
  } catch (e) {
    console.error('[DB] ensureTables error:', e.message);
  }
}
// NE PAS appeler ensureTables() ici — appelé dans startServer() ci-dessous, AVANT app.listen()

// ── Agrégateur de données — app_data blob + tables SQL ─────────────────────
async function getFullData() {
  const isoStr = d => (d ? new Date(d).toISOString() : null);
  // edt_drafts est dans une table séparée — requête isolée pour ne pas bloquer si la table n'existe pas encore
  const [snap, annR, mtR, mdR] = await Promise.all([
    pool.query("SELECT value FROM app_data WHERE key = 'main'"),
    pool.query('SELECT * FROM annonces ORDER BY created_at DESC'),
    pool.query('SELECT * FROM messages_teacher ORDER BY date DESC'),
    pool.query('SELECT * FROM messages_delegates ORDER BY date DESC'),
  ]);
  let edtRows = [];
  try {
    const edtR = await pool.query('SELECT * FROM edt_drafts ORDER BY date_saved DESC');
    edtRows = edtR.rows;
  } catch (e) {
    console.error('[getFullData] edt_drafts not available yet:', e.message);
  }
  const base = snap.rows.length ? snap.rows[0].value : {};
  const blobUsers = base.users || [];

  // Lire users depuis SQL séparément pour un fallback propre si la colonne manque
  let users = blobUsers; // fallback : blob si SQL échoue
  try {
    const usersR = await pool.query(
      'SELECT id, role, nom, prenom, email, classe_id, status, is_delegue FROM users'
    );
    // Fusionner SQL (IDs réels + is_delegue à jour) avec blob (matieres, classes, poste…)
    users = usersR.rows.map(sqlU => {
      const blobU = blobUsers.find(u => (u.email || '').toLowerCase() === (sqlU.email || '').toLowerCase());
      const { pwd_hash, ...blobSafe } = blobU || {}; // ne jamais retourner le hash
      return Object.assign({}, blobSafe, {
        id:         sqlU.id,
        role:       sqlU.role,
        nom:        sqlU.nom,
        prenom:     sqlU.prenom,
        email:      sqlU.email,
        classe_id:  sqlU.classe_id || (blobU && blobU.classe_id) || '',
        status:     sqlU.status,
        is_delegue: !!sqlU.is_delegue,
      });
    });
  } catch (e) {
    console.error('[getFullData] users SQL error (fallback blob):', e.message);
  }

  // Fusionner blob + SQL pour edt_drafts : SQL a la priorité sur le blob (migration progressive)
  const blobEdtDrafts = Array.isArray(base.edt_drafts) ? base.edt_drafts : [];
  const sqlEdtDrafts  = edtRows.map(r => ({
    id: r.id, classe_id: r.classe_id, week_id: r.week_id,
    slots: r.slots || [], statut: r.statut,
    date_saved: isoStr(r.date_saved),
  }));
  // Garder les entrées du blob qui n'ont pas encore de correspondance dans SQL
  const mergedEdtDrafts = [...sqlEdtDrafts];
  for (const b of blobEdtDrafts) {
    const alreadyInSql = sqlEdtDrafts.some(s => s.classe_id === b.classe_id && s.week_id === b.week_id);
    if (!alreadyInSql) mergedEdtDrafts.push(b);
  }

  // Formations : SQL a la priorité, blob comme migration progressive
  let sqlFormations = [];
  try {
    const [fRes, insRes] = await Promise.all([
      pool.query('SELECT * FROM formations ORDER BY created_at DESC'),
      pool.query('SELECT * FROM inscriptions_formations ORDER BY created_at ASC'),
    ]);
    sqlFormations = fRes.rows.map(f => ({
      id: f.id, titre: f.titre, description: f.description || '',
      lieu: f.lieu || '', date_debut: f.date_debut, date_fin: f.date_fin || f.date_debut,
      places: f.places, public: f.public, statut: f.statut,
      inscrits: insRes.rows
        .filter(i => i.formation_id === f.id)
        .map(i => ({ nom: i.nom, prenom: i.prenom, profession: i.profession || '', email: i.email, telephone: i.telephone || '', date: i.date })),
    }));
  } catch (e) {
    console.error('[getFullData] formations not available yet:', e.message);
  }
  const blobFormations = Array.isArray(base.formations) ? base.formations : [];
  const mergedFormations = [...sqlFormations];
  for (const b of blobFormations) {
    if (!sqlFormations.some(s => s.id === b.id)) mergedFormations.push(b);
  }

  return {
    ...base,
    users,
    annonces: annR.rows.map(r => ({
      id: r.id, titre: r.titre, corps: r.corps, cible: r.cible,
      date: r.date || isoStr(r.published_at)?.split('T')[0],
      published_at: isoStr(r.published_at), expiration: r.expiration, statut: r.statut,
    })),
    messages_teacher: mtR.rows.map(r => ({
      id: r.id, de: r.de, vers: r.vers, sujet: r.sujet, corps: r.corps,
      date: isoStr(r.date), statut: r.statut,
    })),
    messages_delegates: mdR.rows.map(r => ({
      id: r.id, from_id: r.from_id, from_name: r.from_name,
      classe_id: r.classe_id || '', to_role: r.to_role, to_id: r.to_id,
      to_name: r.to_name, sujet: r.sujet || '', corps: r.corps || '',
      date: isoStr(r.date), lu: !!r.lu,
    })),
    edt_drafts: mergedEdtDrafts,
    formations: mergedFormations,
  };
}

// ── GET /api/data — charger toutes les données ─────────────────────────────
app.get('/api/data', authMiddleware, async (req, res) => {
  try {
    res.json(await getFullData());
  } catch (err) {
    console.error('Load data error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/data — sauvegarder le blob (hors tables SQL) ─────────────────
app.post('/api/data', authMiddleware, async (req, res) => {
  try {
    // On retire les clés gérées par leurs propres tables pour éviter les conflits
    const { annonces, messages_teacher, messages_delegates, edt_drafts, formations, ...blob } = req.body;
    await pool.query(
      `INSERT INTO app_data (key, value, updated_at)
       VALUES ('main', $1, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
      [JSON.stringify(blob)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Save data error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/edt-drafts — sauvegarder / publier un emploi du temps ────────
app.post('/api/edt-drafts', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { classe_id, week_id, slots, statut } = req.body;
  if (!classe_id || !week_id) return res.status(400).json({ error: 'classe_id et week_id requis' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO edt_drafts (classe_id, week_id, slots, statut)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (classe_id, week_id)
       DO UPDATE SET slots = $3, statut = $4, date_saved = NOW()
       RETURNING *`,
      [classe_id, week_id, JSON.stringify(slots || []), statut || 'brouillon']
    );
    const r = rows[0];
    res.json({
      id: r.id, classe_id: r.classe_id, week_id: r.week_id,
      slots: r.slots || [], statut: r.statut,
      date_saved: r.date_saved ? new Date(r.date_saved).toISOString() : null,
    });
  } catch (err) {
    console.error('[POST /api/edt-drafts]', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/annonces ──────────────────────────────────────────────────────
app.post('/api/annonces', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { titre, corps, cible, date, expiration } = req.body;
  if (!titre) return res.status(400).json({ error: 'Titre requis' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO annonces (titre, corps, cible, date, expiration)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [titre, corps || '', cible || 'Tous les étudiants', date || null, expiration || null]
    );
    const r = rows[0];
    res.json({
      id: r.id, titre: r.titre, corps: r.corps, cible: r.cible,
      date: r.date, published_at: r.published_at ? new Date(r.published_at).toISOString() : null,
      expiration: r.expiration, statut: r.statut,
    });
  } catch (err) {
    console.error('Create annonce error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── DELETE /api/annonces/:id ────────────────────────────────────────────────
app.delete('/api/annonces/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  try {
    await pool.query('DELETE FROM annonces WHERE id = $1', [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete annonce error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/messages/teacher ──────────────────────────────────────────────
app.post('/api/messages/teacher', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const { de, vers, sujet, corps } = req.body;
  if (!sujet || !corps) return res.status(400).json({ error: 'Sujet et corps requis' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO messages_teacher (de, vers, sujet, corps) VALUES ($1,$2,$3,$4) RETURNING *`,
      [de || '', vers || '', sujet, corps]
    );
    const r = rows[0];
    res.json({ id: r.id, de: r.de, vers: r.vers, sujet: r.sujet, corps: r.corps,
               date: r.date ? new Date(r.date).toISOString() : null, statut: r.statut });
  } catch (err) {
    console.error('Create teacher msg error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/messages/delegate ─────────────────────────────────────────────
app.post('/api/messages/delegate', authMiddleware, async (req, res) => {
  const { from_id, from_name, classe_id, to_role, to_id, to_name, sujet, corps } = req.body;
  if (!sujet || !corps) return res.status(400).json({ error: 'Sujet et corps requis' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO messages_delegates
       (from_id, from_name, classe_id, to_role, to_id, to_name, sujet, corps)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [from_id || null, from_name || '', classe_id || '',
       to_role || '', to_id || null, to_name || '', sujet, corps]
    );
    const r = rows[0];
    res.json({ id: r.id, from_id: r.from_id, from_name: r.from_name, classe_id: r.classe_id,
               to_role: r.to_role, to_id: r.to_id, to_name: r.to_name,
               sujet: r.sujet, corps: r.corps,
               date: r.date ? new Date(r.date).toISOString() : null, lu: r.lu });
  } catch (err) {
    console.error('Create delegate msg error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PATCH /api/messages/delegate/:id/read ───────────────────────────────────
app.patch('/api/messages/delegate/:id/read', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE messages_delegates SET lu = true WHERE id = $1', [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Mark delegate msg read error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/admin/create-students ─────────────────────────────────────────
// Crée des comptes étudiants en masse, génère les mots de passe, envoie les emails
app.post('/api/admin/create-students', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès réservé à l\'administrateur' });

  const { emails, classe_id } = req.body;
  if (!Array.isArray(emails) || !emails.length || !classe_id) {
    return res.status(400).json({ error: 'emails (tableau) et classe_id sont requis' });
  }

  const results = [];
  const errors  = [];

  for (const rawEmail of emails) {
    const email = rawEmail.trim().toLowerCase();
    if (!email.includes('@')) { errors.push({ email, error: 'Adresse invalide' }); continue; }
    try {
      const password = generatePassword();
      const hash     = sha256(password);
      const { prenom, nom } = nameFromEmail(email);

      const { rows: inserted } = await pool.query(
        `INSERT INTO users (role, nom, prenom, email, pwd_hash, classe_id, status, is_delegue)
         VALUES ('student', $1, $2, $3, $4, $5, 'active', false)
         ON CONFLICT (email) DO NOTHING
         RETURNING id`,
        [nom, prenom, email, hash, classe_id]
      );

      // RETURNING renvoie 0 ligne si ON CONFLICT DO NOTHING s'est déclenché
      if (!inserted.length) { errors.push({ email, error: 'Email déjà utilisé' }); continue; }
      const sqlId = inserted[0].id;

      let email_sent = false;
      try { email_sent = await sendWelcomeEmail(email, prenom, nom, password, classe_id); }
      catch (e) { console.error('Email error for', email, ':', e.message); }

      results.push({ id: sqlId, email, prenom, nom, classe_id, password, email_sent });
    } catch (err) {
      console.error('Create student error:', err.message);
      errors.push({ email, error: err.message });
    }
  }

  res.json({ results, errors });
});

// ── DELETE /api/admin/users/:id — suppression d'un compte ──────────────────
// On supprime par email (fiable) ET par id (fallback) pour éviter les désynchs
app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  const email = req.body?.email;
  try {
    let deleted = 0;
    // Suppression par email (source de vérité)
    if (email) {
      const r = await pool.query('DELETE FROM users WHERE LOWER(email) = LOWER($1) AND id != $2', [email, req.user.id]);
      deleted = r.rowCount;
    }
    // Fallback par id si email non fourni ou non trouvé
    if (!deleted) {
      const id = parseInt(req.params.id);
      if (id) await pool.query('DELETE FROM users WHERE id = $1 AND id != $2', [id, req.user.id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PATCH /api/admin/users/:id/delegue — assigner / retirer le rôle délégué ─
// Met à jour directement la table SQL users.is_delegue
// → la prochaine connexion du student via n'importe quel navigateur reçoit le bon rôle
app.patch('/api/admin/users/:id/delegue', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const userId = parseInt(req.params.id);
  if (!userId) return res.status(400).json({ error: 'ID invalide' });
  const { is_delegue, classe_id } = req.body;
  try {
    if (is_delegue && classe_id) {
      // Retirer l'ancien délégué de la même classe avant d'en nommer un nouveau
      await pool.query(
        'UPDATE users SET is_delegue = false WHERE classe_id = $1 AND id != $2',
        [classe_id, userId]
      );
    }
    await pool.query('UPDATE users SET is_delegue = $1 WHERE id = $2', [!!is_delegue, userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Set delegue error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/formations — créer une formation (admin) ─────────────────────
app.post('/api/formations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { titre, description, lieu, date_debut, date_fin, places, public: pub } = req.body || {};
  if (!titre || !lieu || !date_debut) {
    return res.status(400).json({ error: 'Titre, lieu et date de début sont requis' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO formations (titre, description, lieu, date_debut, date_fin, places, public, statut)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'actif')
       RETURNING *`,
      [titre, description || '', lieu, date_debut, date_fin || date_debut, parseInt(places) || 30, pub !== false]
    );
    res.json({ ...rows[0], inscrits: [] });
  } catch (err) {
    console.error('Create formation error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/formations/:id/inscrits — liste des inscrits depuis SQL (admin) ─
app.get('/api/formations/:id/inscrits', authMiddleware, async (req, res) => {
  const fid = parseInt(req.params.id);
  if (!fid) return res.status(400).json({ error: 'ID formation invalide' });
  try {
    const [fRes, insRes] = await Promise.all([
      pool.query('SELECT * FROM formations WHERE id = $1', [fid]),
      pool.query('SELECT * FROM inscriptions_formations WHERE formation_id = $1 ORDER BY created_at ASC', [fid]),
    ]);
    if (!fRes.rows.length) return res.status(404).json({ error: 'Formation introuvable' });
    res.json({
      titre: fRes.rows[0].titre,
      inscrits: insRes.rows.map(i => ({ nom: i.nom, prenom: i.prenom, profession: i.profession || '', email: i.email, telephone: i.telephone || '', date: i.date })),
    });
  } catch (err) {
    console.error('Get inscrits error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/formations/:id/inscriptions — public (sans auth) ─────────────
app.post('/api/formations/:id/inscriptions', async (req, res) => {
  const fid = parseInt(req.params.id);
  if (!fid) return res.status(400).json({ error: 'ID formation invalide' });
  const { nom, prenom, profession, email, telephone } = req.body || {};
  if (!nom || !prenom || !email) {
    return res.status(400).json({ error: 'Nom, prénom et email sont requis' });
  }
  try {
    const fRes = await pool.query('SELECT * FROM formations WHERE id = $1', [fid]);
    if (!fRes.rows.length) return res.status(404).json({ error: 'Formation introuvable' });
    const f = fRes.rows[0];
    const countRes = await pool.query('SELECT COUNT(*) FROM inscriptions_formations WHERE formation_id = $1', [fid]);
    if (parseInt(countRes.rows[0].count) >= f.places) {
      return res.status(400).json({ error: 'Formation complète' });
    }
    await pool.query(
      `INSERT INTO inscriptions_formations (formation_id, nom, prenom, profession, email, telephone, date)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (formation_id, email) DO NOTHING`,
      [fid, nom, prenom, profession || '', email, telephone || '', new Date().toISOString().split('T')[0]]
    );
    const totalRes = await pool.query('SELECT COUNT(*) FROM inscriptions_formations WHERE formation_id = $1', [fid]);
    res.json({ ok: true, inscrits: parseInt(totalRes.rows[0].count) });
  } catch (err) {
    console.error('Inscription formation error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/admin/send-relance — envoi d'un email de relance via Brevo ────
app.post('/api/admin/send-relance', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });

  const { email, prenom, nom, message } = req.body || {};
  if (!email || !message) return res.status(400).json({ error: 'Email et message requis' });

  if (!process.env.BREVO_API_KEY || !process.env.BREVO_FROM) {
    return res.status(503).json({ error: 'Service email non configuré (BREVO_API_KEY / BREVO_FROM manquants)' });
  }

  // Convertit le texte brut en HTML lisible (sauts de ligne → paragraphes)
  const htmlBody = message
    .split('\n')
    .map(line => line.trim()
      ? `<p style="margin:0 0 10px;line-height:1.6;color:#333">${line}</p>`
      : '<br>')
    .join('');

  const htmlContent = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;color:#1a1a1a">
      <div style="background:#250D42;padding:24px 32px">
        <h1 style="color:white;font-size:20px;margin:0">IHBI — International High Business Institute</h1>
      </div>
      <div style="padding:28px 32px;background:#fff;border:1px solid #e5e7eb">
        ${htmlBody}
      </div>
      <div style="padding:16px 32px;background:#f8f9fa;font-size:11px;color:#999;text-align:center">
        International High Business Institute — IHBI, Yamoussoukro
      </div>
    </div>
  `;

  try {
    const brevoRes = await fetch('https://api.brevo.com/v3/smtp/email', {
      method:  'POST',
      headers: {
        'api-key':      process.env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'accept':       'application/json',
      },
      body: JSON.stringify({
        sender:      { name: 'IHBI Platform', email: process.env.BREVO_FROM },
        to:          [{ email, name: `${prenom || ''} ${nom || ''}`.trim() || email }],
        subject:     'Suivi de votre candidature — IHBI',
        htmlContent,
      }),
    });

    if (!brevoRes.ok) {
      const err = await brevoRes.text();
      throw new Error(`Brevo ${brevoRes.status} — ${err}`);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Send relance error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/health — vérification Railway ──────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', env: process.env.NODE_ENV }));

// ── Toutes les autres routes → index.html (SPA) ─────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Démarrage ────────────────────────────────────────────────────────────────
// ensureTables() est ATTENDU avant app.listen() pour éviter la race condition :
// sans await, une requête /api/data arrivant avant la création des tables renvoyait 500
// et autoRestoreSession() gardait les vieilles données localStorage au lieu de charger Railway.
const PORT = process.env.PORT || 3000;
async function startServer() {
  await ensureTables();          // ← tables garanties avant toute requête
  app.listen(PORT, () => {
    console.log(`Serveur IHBI démarré sur http://localhost:${PORT}`);
  });
}
startServer().catch(err => {
  console.error('[FATAL] Impossible de démarrer le serveur :', err.message);
  process.exit(1);
});
