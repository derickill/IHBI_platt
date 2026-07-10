require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const path    = require('path');

const app = express();
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname)));

// ── Base de données PostgreSQL ──────────────────────────────────────────────
// En prod : DATABASE_URL fourni automatiquement par Railway
const _dbUrl = process.env.DATABASE_URL || '';
const pool = new Pool({
  connectionString: _dbUrl,
  ssl: (_dbUrl.includes('localhost') || _dbUrl.includes('127.0.0.1'))
       ? false
       : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false),
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
      CREATE TABLE IF NOT EXISTS users (
        id           SERIAL PRIMARY KEY,
        role         VARCHAR(20)  NOT NULL CHECK (role IN ('student','teacher','admin')),
        nom          VARCHAR(100) NOT NULL,
        prenom       VARCHAR(100) NOT NULL,
        email        VARCHAR(255) UNIQUE NOT NULL,
        pwd_hash     VARCHAR(64)  NOT NULL,
        classe_id    VARCHAR(20)  DEFAULT '',
        status       VARCHAR(20)  DEFAULT 'active',
        is_delegue   BOOLEAN      DEFAULT false,
        email_parent VARCHAR(255) DEFAULT '',
        matieres     JSONB        DEFAULT '[]',
        classes      JSONB        DEFAULT '[]',
        poste        VARCHAR(100) DEFAULT '',
        parent_of    INTEGER      DEFAULT NULL,
        matiere      VARCHAR(100) DEFAULT '',
        profile_complete BOOLEAN  DEFAULT false,
        created_at   TIMESTAMP    DEFAULT NOW()
      )
    `);
    await pool.query(`
      INSERT INTO users (role, nom, prenom, email, pwd_hash, status)
      VALUES ('admin', 'Administrateur', 'IHBI', 'admin@ihbi.ci',
              'dc8c74284295f0de799587a295878c4f7d8e7b19070f37077fc407d1bddbeef4', 'active')
      ON CONFLICT (email) DO NOTHING
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_data (
        key        VARCHAR(50) PRIMARY KEY,
        value      JSONB       NOT NULL DEFAULT '{}',
        updated_at TIMESTAMP   DEFAULT NOW()
      )
    `);
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
    // Candidatures / demandes de contact (formulaire page d'accueil)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contact_submissions (
        id           SERIAL PRIMARY KEY,
        nom          TEXT NOT NULL,
        prenom       TEXT NOT NULL,
        email        TEXT NOT NULL,
        telephone    TEXT DEFAULT '',
        filiere      TEXT DEFAULT '',
        email_parent TEXT DEFAULT '',
        message      TEXT DEFAULT '',
        date         TEXT,
        statut       TEXT DEFAULT 'nouveau',
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Migration : ajout colonnes fichier si absentes
    await pool.query(`ALTER TABLE contact_submissions ADD COLUMN IF NOT EXISTS fichier TEXT DEFAULT ''`);
    await pool.query(`ALTER TABLE contact_submissions ADD COLUMN IF NOT EXISTS fichier_nom TEXT DEFAULT ''`);
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
    // Table des classes IHBI (liste fixe, ne peut pas être modifiée par les admins)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id  TEXT PRIMARY KEY,
        nom TEXT NOT NULL
      )
    `);
    await pool.query(`
      INSERT INTO classes (id, nom) VALUES
      ('2MA1',  '1ère année Moteur et Mécanique Automobile'),
      ('2MA2',  '2ème année Moteur et Mécanique Automobile'),
      ('FCGE1', '1ère année Finances Comptabilité Gestion des Entreprises'),
      ('FCGE2', '2ème année Finances Comptabilité Gestion des Entreprises'),
      ('GEC1',  '1ère année Gestion Commerciale'),
      ('GEC2',  '2ème année Gestion Commerciale'),
      ('IDA1',  '1ère année Informatique et Développeur d''Applications'),
      ('IDA2',  '2ème année Informatique et Développeur d''Applications'),
      ('MSP1',  '1ère année Maintenance des Systèmes de Production'),
      ('MSP2',  '2ème année Maintenance des Systèmes de Production'),
      ('RHC1',  '1ère année Ressources Humaines et Communication'),
      ('RHC2',  '2ème année Ressources Humaines et Communication'),
      ('RIT1',  '1ère année Réseaux Informatique et Télécommunication'),
      ('RIT2',  '2ème année Réseaux Informatique et Télécommunication'),
      ('ELT1',  '1ère année Electrotechnique'),
      ('ELT2',  '2ème année Electrotechnique'),
      ('TH1',   '1ère année Tourisme-Hôtellerie'),
      ('TH2',   '2ème année Tourisme-Hôtellerie'),
      ('ATA1',  '1ère année Agriculture Tropicale option Animale'),
      ('ATA2',  '2ème année Agriculture Tropicale option Animale'),
      ('ATV1',  '1ère année Agriculture Tropicale option Végétale'),
      ('ATV2',  '2ème année Agriculture Tropicale option Végétale'),
      ('SEI1',  '1ère année Systèmes Électroniques et Informatiques'),
      ('SEI2',  '2ème année Systèmes Électroniques et Informatiques'),
      ('GBAT1', '1ère année Génie Civil option Bâtiment'),
      ('GBAT2', '2ème année Génie Civil option Bâtiment'),
      ('GTP1',  '1ère année Génie Civil option Travaux Publics'),
      ('GTP2',  '2ème année Génie Civil option Travaux Publics'),
      ('GGT1',  '1ère année Génie Civil option Géomètre-Topographe'),
      ('GGT2',  '2ème année Génie Civil option Géomètre-Topographe'),
      ('MGP1',  '1ère année Mines Géologie Pétrole'),
      ('MGP2',  '2ème année Mines Géologie Pétrole'),
      ('CV1',   '1ère année Communication Visuelle'),
      ('CV2',   '2ème année Communication Visuelle'),
      ('AD1',   '1ère année Assistanat de Direction'),
      ('AD2',   '2ème année Assistanat de Direction'),
      ('LOG1',  '1ère année Logistique'),
      ('LOG2',  '2ème année Logistique')
      ON CONFLICT (id) DO NOTHING
    `);
    // Migration : ajouter is_delegue sur la table users si elle n'existe pas encore
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_delegue BOOLEAN DEFAULT FALSE
    `);
    // Migration : ajouter profile_complete — TRUE pour les comptes existants, FALSE pour les nouveaux étudiants
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_complete BOOLEAN DEFAULT TRUE
    `);
    // Migration : matière enseignée par l'enseignant
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS matiere TEXT DEFAULT ''
    `);
    // Classes assignées à un enseignant (relation N-N)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS teacher_classes (
        teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        classe_id  TEXT    NOT NULL REFERENCES classes(id),
        PRIMARY KEY (teacher_id, classe_id)
      )
    `);
    // Évaluations créées par un enseignant
    await pool.query(`
      CREATE TABLE IF NOT EXISTS evaluations (
        id         SERIAL PRIMARY KEY,
        teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        classe_id  TEXT    NOT NULL,
        matiere    TEXT    NOT NULL,
        intitule   TEXT    NOT NULL,
        type       TEXT    DEFAULT 'Devoir',
        coeff      REAL    DEFAULT 1,
        bareme     INTEGER DEFAULT 20,
        date       TEXT,
        statut     TEXT    DEFAULT 'brouillon',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Notes individuelles (une par étudiant par évaluation)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notes (
        id          SERIAL PRIMARY KEY,
        eval_id     INTEGER NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
        etudiant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        note        REAL,
        commentaire TEXT DEFAULT '',
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (eval_id, etudiant_id)
      )
    `);
    // Documents de correction joints à une évaluation (stockés en base64)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id         SERIAL PRIMARY KEY,
        eval_id    INTEGER NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
        name       TEXT    NOT NULL,
        type       TEXT    DEFAULT 'application/pdf',
        data       TEXT    NOT NULL,
        size       INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Réclamations étudiants
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reclamations (
        id           SERIAL PRIMARY KEY,
        etudiant_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        etudiant_nom TEXT    NOT NULL,
        classe_id    TEXT    DEFAULT '',
        sujet        TEXT    NOT NULL,
        corps        TEXT    NOT NULL,
        statut       TEXT    DEFAULT 'nouveau',
        reponse      TEXT    DEFAULT '',
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Lien parent → enfant
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS parent_of INTEGER REFERENCES users(id) ON DELETE SET NULL`);
    // Actualités / Événements publics du site vitrine
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news (
        id         SERIAL PRIMARY KEY,
        titre      TEXT NOT NULL,
        corps      TEXT DEFAULT '',
        type       TEXT DEFAULT 'événement',
        image_url  TEXT DEFAULT '',
        date_event TEXT DEFAULT '',
        lien       TEXT DEFAULT '',
        statut     TEXT DEFAULT 'publié',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // CMS : contenu éditable des sections du site vitrine
    await pool.query(`
      CREATE TABLE IF NOT EXISTS site_content (
        key        TEXT PRIMARY KEY,
        titre      TEXT DEFAULT '',
        contenu    TEXT DEFAULT '',
        image_url  TEXT DEFAULT '',
        ordre      INTEGER DEFAULT 0,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await pool.query(`
      INSERT INTO site_content (key, titre, contenu, ordre) VALUES
        ('elearning',   'Notre plateforme E-Learning', 'Accédez à vos cours, ressources pédagogiques et supports de formation en ligne, à tout moment et depuis n''importe quel appareil. La plateforme IHBI offre des contenus interactifs, des quiz et un suivi personnalisé de votre progression.', 2),
        ('temoignages', 'Ils ont choisi l''IHBI', '[{"nom":"Konan Yves","promo":"BTS FCGE 2023","texte":"L''IHBI m''a permis de décrocher mon premier emploi dès la fin de mes études. La formation bilingue est un vrai atout sur le marché du travail."},{"nom":"Adjoua Marie","promo":"BTS RHC 2022","texte":"Un encadrement de qualité et des professeurs disponibles. Je recommande l''IHBI à tous les bacheliers qui veulent réussir."},{"nom":"Bah Mamadou","promo":"BTS 2MA 2023","texte":"La filière Mécanique Automobile m''a ouvert des portes que je n''imaginais pas. Aujourd''hui j''ai mon propre atelier."}]', 3),
        ('partenaires', 'Nos partenaires', '[{"nom":"SODECI","description":"Partenaire stages & emploi"},{"nom":"Orange CI","description":"Partenaire stages & emploi"},{"nom":"Bolloré Africa","description":"Partenaire stages"},{"nom":"MTN CI","description":"Partenaire stages"},{"nom":"LONACI","description":"Partenaire stages"},{"nom":"SIR","description":"Partenaire stages"}]', 4),
        ('faq',         'Foire aux questions', '[{"q":"Quelles sont les conditions d''admission ?","r":"Le BTS IHBI est accessible aux titulaires du Baccalauréat ou d''un diplôme équivalent. Un entretien de sélection est organisé pour évaluer votre profil."},{"q":"Les cours sont-ils dispensés en anglais ?","r":"Oui, toutes les formations IHBI sont bilingues français-anglais. Des cours d''anglais intensifs sont intégrés au programme pour atteindre un niveau professionnel."},{"q":"Quel est le coût des études ?","r":"Les frais de scolarité varient selon la filière et sont discutés lors de l''entretien d''admission. Des facilités de paiement en tranches sont proposées."},{"q":"Y a-t-il des stages obligatoires ?","r":"Oui, chaque formation comprend des stages en entreprise obligatoires intégrés dans le programme, grâce à notre réseau de partenaires."},{"q":"L''IHBI est-il reconnu par l''État ?","r":"Oui, l''IHBI est un établissement privé d''enseignement supérieur agréé, dont les diplômes BTS sont reconnus par les autorités ivoiriennes."}]', 5),
        ('contacts',    'Contactez-nous', '{"tel":["27 30 64 43 92","07 07 52 35 97","01 03 62 02 70","07 49 04 81 70"],"email":"ihbi.info@gmail.com","adresse":"Yamoussoukro, Côte d''Ivoire","facebook":"","instagram":"","linkedin":"","twitter":""}', 6)
      ON CONFLICT (key) DO NOTHING
    `);
    // Candidatures enseignants / employés
    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_applications (
        id         SERIAL PRIMARY KEY,
        type       TEXT NOT NULL DEFAULT 'enseignant',
        nom        TEXT NOT NULL,
        prenom     TEXT NOT NULL,
        email      TEXT NOT NULL,
        telephone  TEXT DEFAULT '',
        poste      TEXT DEFAULT '',
        matiere    TEXT DEFAULT '',
        lettre     TEXT DEFAULT '',
        statut     TEXT DEFAULT 'nouveau',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS matieres (
        id          SERIAL PRIMARY KEY,
        nom         TEXT NOT NULL,
        filiere     TEXT NOT NULL,
        coefficient INTEGER DEFAULT 1,
        ordre       INTEGER DEFAULT 0,
        UNIQUE(nom, filiere)
      )
    `);
    console.log('[DB] Tables vérifiées ✓');
  } catch (e) {
    console.error('[DB] ensureTables error:', e.message);
  }
}

// ── Référentiel des matières par filière ─────────────────────────────────────
const MATIERES_SEED = [
  // 2MA — Moteur et Mécanique Automobile (34)
  { nom: "Technique d'Expression Ecrite et orale",     filiere:'2MA', coefficient:2, ordre:1  },
  { nom: "Anglais Technique",                           filiere:'2MA', coefficient:2, ordre:2  },
  { nom: "Entrepreneuriat",                             filiere:'2MA', coefficient:2, ordre:3  },
  { nom: "Santé, Sécurité, et Protection de l'Environnement", filiere:'2MA', coefficient:2, ordre:4 },
  { nom: "Prévention des Accidents",                    filiere:'2MA', coefficient:2, ordre:5  },
  { nom: "Mathématiques Générales",                     filiere:'2MA', coefficient:3, ordre:6  },
  { nom: "Informatique Appliquée",                      filiere:'2MA', coefficient:2, ordre:7  },
  { nom: "Droit Civil",                                 filiere:'2MA', coefficient:2, ordre:8  },
  { nom: "Droit commercial",                            filiere:'2MA', coefficient:2, ordre:9  },
  { nom: "Droit du travail",                            filiere:'2MA', coefficient:2, ordre:10 },
  { nom: "Droit de l'automobile",                       filiere:'2MA', coefficient:2, ordre:11 },
  { nom: "Economie",                                    filiere:'2MA', coefficient:2, ordre:12 },
  { nom: "Gestion",                                     filiere:'2MA', coefficient:2, ordre:13 },
  { nom: "Chimie",                                      filiere:'2MA', coefficient:2, ordre:14 },
  { nom: "Physiques Appliquées",                        filiere:'2MA', coefficient:2, ordre:15 },
  { nom: "Mécanique RDM",                               filiere:'2MA', coefficient:2, ordre:16 },
  { nom: "Thermodynamique",                             filiere:'2MA', coefficient:2, ordre:17 },
  { nom: "Dessin technique",                            filiere:'2MA', coefficient:3, ordre:18 },
  { nom: "Automatique",                                 filiere:'2MA', coefficient:3, ordre:19 },
  { nom: "Automatismes",                                filiere:'2MA', coefficient:2, ordre:20 },
  { nom: "Fabrication mécanique",                       filiere:'2MA', coefficient:2, ordre:21 },
  { nom: "Théories moteurs",                            filiere:'2MA', coefficient:2, ordre:22 },
  { nom: "Atelier moteur",                              filiere:'2MA', coefficient:2, ordre:23 },
  { nom: "Les organes d'utilisation",                   filiere:'2MA', coefficient:2, ordre:24 },
  { nom: "Les organes de transmission",                 filiere:'2MA', coefficient:2, ordre:25 },
  { nom: "Injection essence/diesel",                    filiere:'2MA', coefficient:2, ordre:26 },
  { nom: "Electricité automobile/codification",         filiere:'2MA', coefficient:2, ordre:27 },
  { nom: "Electronique appliquée",                      filiere:'2MA', coefficient:2, ordre:28 },
  { nom: "Climatisation auto",                          filiere:'2MA', coefficient:2, ordre:29 },
  { nom: "Maintenance appliquée à la Mécanique Automobile", filiere:'2MA', coefficient:2, ordre:30 },
  { nom: "Organisation et gestion de garage",           filiere:'2MA', coefficient:2, ordre:31 },
  { nom: "Hydraulique",                                 filiere:'2MA', coefficient:2, ordre:32 },
  { nom: "Pneumatique",                                 filiere:'2MA', coefficient:2, ordre:33 },
  { nom: "TP mécanique",                                filiere:'2MA', coefficient:2, ordre:34 },
  // IDA — Informatique Développeur d'Applications (25)
  { nom: "Technique de l'expression française",         filiere:'IDA', coefficient:2, ordre:1  },
  { nom: "Anglais technique",                           filiere:'IDA', coefficient:2, ordre:2  },
  { nom: "Économie de Gestion / Entrepreneuriat",       filiere:'IDA', coefficient:2, ordre:3  },
  { nom: "Comptabilité Générale",                       filiere:'IDA', coefficient:2, ordre:4  },
  { nom: "Droit (Travail-commercial-Civil)",            filiere:'IDA', coefficient:2, ordre:5  },
  { nom: "Mathématique Générale, Statistique",          filiere:'IDA', coefficient:3, ordre:6  },
  { nom: "Mathématique financière et Recherche opérationnelle", filiere:'IDA', coefficient:2, ordre:7 },
  { nom: "Architecture des systèmes",                   filiere:'IDA', coefficient:2, ordre:8  },
  { nom: "Systèmes d'Exploitation et sécurité informatique", filiere:'IDA', coefficient:2, ordre:9 },
  { nom: "Réseau et Téléinformatique",                  filiere:'IDA', coefficient:2, ordre:10 },
  { nom: "Développement Web (HTML, CSS, JavaScript)",   filiere:'IDA', coefficient:4, ordre:11 },
  { nom: "Langages Evolués (PHP)",                      filiere:'IDA', coefficient:3, ordre:12 },
  { nom: "Langage Visual Basic / Delphi",               filiere:'IDA', coefficient:3, ordre:13 },
  { nom: "Algorithmique",                               filiere:'IDA', coefficient:4, ordre:14 },
  { nom: "Langage Pascal et C",                         filiere:'IDA', coefficient:2, ordre:15 },
  { nom: "Méthodologie d'analyse (MERISE)",             filiere:'IDA', coefficient:4, ordre:16 },
  { nom: "Bases de Données",                            filiere:'IDA', coefficient:2, ordre:17 },
  { nom: "Webdesign (Photoshop, Fireworks, DreamWeaver)", filiere:'IDA', coefficient:2, ordre:18 },
  { nom: "Logiciel (MS Word, Excel, Power Point)",      filiere:'IDA', coefficient:2, ordre:19 },
  { nom: "Négociation Informatique",                    filiere:'IDA', coefficient:2, ordre:20 },
  { nom: "Gestion de Projet informatique",              filiere:'IDA', coefficient:2, ordre:21 },
  { nom: "Programmation orientée objet et événementielle", filiere:'IDA', coefficient:2, ordre:22 },
  { nom: "Architecture client/serveur",                 filiere:'IDA', coefficient:2, ordre:23 },
  { nom: "Technique d'administration",                  filiere:'IDA', coefficient:2, ordre:24 },
  { nom: "Atelier génie logiciel",                      filiere:'IDA', coefficient:2, ordre:25 },
  // MSP — Maintenance des Systèmes de Production (21)
  { nom: "Technique d'Expression Ecrite et Orale",      filiere:'MSP', coefficient:2, ordre:1  },
  { nom: "Anglais Technique",                           filiere:'MSP', coefficient:2, ordre:2  },
  { nom: "Economie et Gestion",                         filiere:'MSP', coefficient:2, ordre:3  },
  { nom: "Mathématiques",                               filiere:'MSP', coefficient:3, ordre:4  },
  { nom: "Informatique Appliquée",                      filiere:'MSP', coefficient:2, ordre:5  },
  { nom: "Mécanique RDM",                               filiere:'MSP', coefficient:3, ordre:6  },
  { nom: "Electronique Analogique",                     filiere:'MSP', coefficient:2, ordre:7  },
  { nom: "Electricité Générale",                        filiere:'MSP', coefficient:4, ordre:8  },
  { nom: "Electronique Industrielle",                   filiere:'MSP', coefficient:3, ordre:9  },
  { nom: "Thermodynamique",                             filiere:'MSP', coefficient:3, ordre:10 },
  { nom: "Automatique",                                 filiere:'MSP', coefficient:3, ordre:11 },
  { nom: "Electrotechnique",                            filiere:'MSP', coefficient:3, ordre:12 },
  { nom: "Etude des Installations Hydrauliques",        filiere:'MSP', coefficient:3, ordre:13 },
  { nom: "Technologie générale",                        filiere:'MSP', coefficient:2, ordre:14 },
  { nom: "Maintenance Industrielle - Hygiène Sécurité", filiere:'MSP', coefficient:6, ordre:15 },
  { nom: "Installations Electriques",                   filiere:'MSP', coefficient:3, ordre:16 },
  { nom: "Mesures et Essais des Machines Electriques",  filiere:'MSP', coefficient:3, ordre:17 },
  { nom: "Dessin Technique / Technologie Générale",     filiere:'MSP', coefficient:4, ordre:18 },
  { nom: "Technique des Systèmes Automatisés et Equipements", filiere:'MSP', coefficient:3, ordre:19 },
  { nom: "Fabrication mécanique",                       filiere:'MSP', coefficient:3, ordre:20 },
  { nom: "Analyse de fabrication / Bureau d'études des méthodes (BEM)", filiere:'MSP', coefficient:3, ordre:21 },
  // RHC — Ressources Humaines et Communication (18)
  { nom: "Perfectionnement Linguistique",               filiere:'RHC', coefficient:3, ordre:1  },
  { nom: "Anglais professionnel",                       filiere:'RHC', coefficient:3, ordre:2  },
  { nom: "Economie Générale",                           filiere:'RHC', coefficient:2, ordre:3  },
  { nom: "Economie et organisation d'entreprise",       filiere:'RHC', coefficient:2, ordre:4  },
  { nom: "Droit Civil",                                 filiere:'RHC', coefficient:2, ordre:5  },
  { nom: "Droit du travail",                            filiere:'RHC', coefficient:2, ordre:6  },
  { nom: "Droit des affaires",                          filiere:'RHC', coefficient:2, ordre:7  },
  { nom: "Informatique appliquée (logiciel)",           filiere:'RHC', coefficient:2, ordre:8  },
  { nom: "Psychosociologie appliquée",                  filiere:'RHC', coefficient:2, ordre:9  },
  { nom: "TCA - GAP",                                   filiere:'RHC', coefficient:3, ordre:10 },
  { nom: "Psychosociologie des organisations et GRH",   filiere:'RHC', coefficient:3, ordre:11 },
  { nom: "Statistiques appliquées à la Com. et GRH",    filiere:'RHC', coefficient:2, ordre:12 },
  { nom: "Négociation et relations sociales",           filiere:'RHC', coefficient:3, ordre:13 },
  { nom: "GPC + définition des concepts RH",            filiere:'RHC', coefficient:3, ordre:14 },
  { nom: "Rémunération + comptabilité",                 filiere:'RHC', coefficient:3, ordre:15 },
  { nom: "Politique et stratégie de communication",     filiere:'RHC', coefficient:3, ordre:16 },
  { nom: "Communication",                               filiere:'RHC', coefficient:2, ordre:17 },
  { nom: "Marketing Digital",                           filiere:'RHC', coefficient:2, ordre:18 },
  // RIT — Réseaux Informatiques et Télécommunications (24)
  { nom: "Transmission",                                filiere:'RIT', coefficient:4, ordre:1  },
  { nom: "Commutation",                                 filiere:'RIT', coefficient:4, ordre:2  },
  { nom: "Réseau d'Accès",                              filiere:'RIT', coefficient:4, ordre:3  },
  { nom: "Téléinformatique",                            filiere:'RIT', coefficient:4, ordre:4  },
  { nom: "Réseaux Locaux Informatiques",                filiere:'RIT', coefficient:4, ordre:5  },
  { nom: "Energie",                                     filiere:'RIT', coefficient:2, ordre:6  },
  { nom: "Systèmes d'Exploitation",                     filiere:'RIT', coefficient:2, ordre:7  },
  { nom: "Réseaux Mobiles",                             filiere:'RIT', coefficient:3, ordre:8  },
  { nom: "Réseaux de Télécommunication et Téléphonie",  filiere:'RIT', coefficient:3, ordre:9  },
  { nom: "Projet (Informatique et Télécom)",            filiere:'RIT', coefficient:3, ordre:10 },
  { nom: "Micro Processeur",                            filiere:'RIT', coefficient:2, ordre:11 },
  { nom: "Architecture des Systèmes Informatiques",     filiere:'RIT', coefficient:2, ordre:12 },
  { nom: "Electronique Analogique et Numérique",        filiere:'RIT', coefficient:3, ordre:13 },
  { nom: "Algorithmique et Langages",                   filiere:'RIT', coefficient:2, ordre:14 },
  { nom: "Traitement du Signal",                        filiere:'RIT', coefficient:4, ordre:15 },
  { nom: "Electricité",                                 filiere:'RIT', coefficient:2, ordre:16 },
  { nom: "Anglais",                                     filiere:'RIT', coefficient:2, ordre:17 },
  { nom: "Français",                                    filiere:'RIT', coefficient:2, ordre:18 },
  { nom: "Droit",                                       filiere:'RIT', coefficient:2, ordre:19 },
  { nom: "Economie",                                    filiere:'RIT', coefficient:2, ordre:20 },
  { nom: "Gestion",                                     filiere:'RIT', coefficient:2, ordre:21 },
  { nom: "Entrepreneuriat",                             filiere:'RIT', coefficient:2, ordre:22 },
  { nom: "Mathématiques",                               filiere:'RIT', coefficient:3, ordre:23 },
  { nom: "Informatique Appliquée",                      filiere:'RIT', coefficient:2, ordre:24 },
  // FCGE — Finances Comptabilité Gestion des Entreprises (19) — s'applique à FCGE1 et FCGE2
  { nom: "Technique d'Expression Ecrite et Orale",      filiere:'FCGE', coefficient:3, ordre:1  },
  { nom: "Anglais Commercial",                          filiere:'FCGE', coefficient:3, ordre:2  },
  { nom: "Economie Générale",                           filiere:'FCGE', coefficient:2, ordre:3  },
  { nom: "Economie et Organisation d'Entreprise",       filiere:'FCGE', coefficient:2, ordre:4  },
  { nom: "Droit des Affaires",                          filiere:'FCGE', coefficient:2, ordre:5  },
  { nom: "Droit du Travail",                            filiere:'FCGE', coefficient:2, ordre:6  },
  { nom: "Droit Civil",                                 filiere:'FCGE', coefficient:2, ordre:7  },
  { nom: "Marketing",                                   filiere:'FCGE', coefficient:3, ordre:8  },
  { nom: "Mathématiques Générales, Statistiques et Probabilités", filiere:'FCGE', coefficient:2, ordre:9 },
  { nom: "Comptabilité Générale",                       filiere:'FCGE', coefficient:5, ordre:10 },
  { nom: "Comptabilité des Sociétés",                   filiere:'FCGE', coefficient:3, ordre:11 },
  { nom: "Comptabilité Analytique",                     filiere:'FCGE', coefficient:3, ordre:12 },
  { nom: "Contrôle de Gestion",                         filiere:'FCGE', coefficient:3, ordre:13 },
  { nom: "Gestion Financière",                          filiere:'FCGE', coefficient:4, ordre:14 },
  { nom: "Fiscalité",                                   filiere:'FCGE', coefficient:3, ordre:15 },
  { nom: "Bureaux Comptable et Fiscal",                 filiere:'FCGE', coefficient:2, ordre:16 },
  { nom: "Mathématiques Financières et Recherche Opérationnelle", filiere:'FCGE', coefficient:2, ordre:17 },
  { nom: "Informatique Appliquée",                      filiere:'FCGE', coefficient:3, ordre:18 },
  { nom: "Marketing Digital",                           filiere:'FCGE', coefficient:2, ordre:19 },
  // GEC — Gestion Commerciale (21)
  { nom: "Technique d'Expression Ecrite et Orale",      filiere:'GEC', coefficient:3, ordre:1  },
  { nom: "Anglais Commercial",                          filiere:'GEC', coefficient:3, ordre:2  },
  { nom: "Economie Générale",                           filiere:'GEC', coefficient:2, ordre:3  },
  { nom: "Economie et Organisation d'Entreprise",       filiere:'GEC', coefficient:2, ordre:4  },
  { nom: "Droit des Affaires",                          filiere:'GEC', coefficient:2, ordre:5  },
  { nom: "Droit du Travail",                            filiere:'GEC', coefficient:2, ordre:6  },
  { nom: "Droit Civil",                                 filiere:'GEC', coefficient:2, ordre:7  },
  { nom: "Mathématiques Appliquées à la Gestion",       filiere:'GEC', coefficient:2, ordre:8  },
  { nom: "Fondement et Concepts Marketing - Etude de Marché", filiere:'GEC', coefficient:2, ordre:9 },
  { nom: "Techniques de Vente et Négociation",          filiere:'GEC', coefficient:2, ordre:10 },
  { nom: "Stratégie Marketing et Plan d'Action Commerciale", filiere:'GEC', coefficient:3, ordre:11 },
  { nom: "Distribution - Merchandising",                filiere:'GEC', coefficient:2, ordre:12 },
  { nom: "Techniques du Commerce International",        filiere:'GEC', coefficient:3, ordre:13 },
  { nom: "Comptabilité Générale",                       filiere:'GEC', coefficient:2, ordre:14 },
  { nom: "Comptabilité Analytique et Gestion Prévisionnelle", filiere:'GEC', coefficient:2, ordre:15 },
  { nom: "Informatique Appliquée",                      filiere:'GEC', coefficient:2, ordre:16 },
  { nom: "Gestion des Approvisionnements et des Stocks",filiere:'GEC', coefficient:2, ordre:17 },
  { nom: "Marketing International",                     filiere:'GEC', coefficient:2, ordre:18 },
  { nom: "Management de la Force de Vente",             filiere:'GEC', coefficient:2, ordre:19 },
  { nom: "Action Terrain Encadrée (ATE)",               filiere:'GEC', coefficient:5, ordre:20 },
  { nom: "Marketing Digital",                           filiere:'GEC', coefficient:2, ordre:21 },
  // ATV — Agriculture Tropicale option Production Végétale (33)
  { nom: "Anglais",                                     filiere:'ATV', coefficient:2, ordre:1  },
  { nom: "Comptabilité",                                filiere:'ATV', coefficient:2, ordre:2  },
  { nom: "Droit foncier et droit du travail",           filiere:'ATV', coefficient:2, ordre:3  },
  { nom: "Economie",                                    filiere:'ATV', coefficient:2, ordre:4  },
  { nom: "Economie rurale et gestion d'exploitation agricole", filiere:'ATV', coefficient:2, ordre:5 },
  { nom: "Gestion",                                     filiere:'ATV', coefficient:2, ordre:6  },
  { nom: "Gestion des ressources humaines",             filiere:'ATV', coefficient:2, ordre:7  },
  { nom: "Informatique",                                filiere:'ATV', coefficient:1, ordre:8  },
  { nom: "Marketing et force de vente",                 filiere:'ATV', coefficient:2, ordre:9  },
  { nom: "Agrochimie",                                  filiere:'ATV', coefficient:3, ordre:10 },
  { nom: "Agroclimatologie",                            filiere:'ATV', coefficient:2, ordre:11 },
  { nom: "Agronomie générale",                          filiere:'ATV', coefficient:4, ordre:12 },
  { nom: "Biochimie",                                   filiere:'ATV', coefficient:2, ordre:13 },
  { nom: "Biologie de la reproduction",                 filiere:'ATV', coefficient:2, ordre:14 },
  { nom: "Biométrie",                                   filiere:'ATV', coefficient:2, ordre:15 },
  { nom: "Botanique",                                   filiere:'ATV', coefficient:3, ordre:16 },
  { nom: "Chimie alimentaire",                          filiere:'ATV', coefficient:2, ordre:17 },
  { nom: "Cultures industrielles",                      filiere:'ATV', coefficient:4, ordre:18 },
  { nom: "Cultures maraîchères",                        filiere:'ATV', coefficient:2, ordre:19 },
  { nom: "Cultures vivrières",                          filiere:'ATV', coefficient:4, ordre:20 },
  { nom: "Défense des cultures",                        filiere:'ATV', coefficient:3, ordre:21 },
  { nom: "Ecologie générale et végétale",               filiere:'ATV', coefficient:2, ordre:22 },
  { nom: "Entomologie",                                 filiere:'ATV', coefficient:3, ordre:23 },
  { nom: "Fertilisation",                               filiere:'ATV', coefficient:3, ordre:24 },
  { nom: "Fruits et agrumes",                           filiere:'ATV', coefficient:2, ordre:25 },
  { nom: "Génétique et sélection végétale",             filiere:'ATV', coefficient:3, ordre:26 },
  { nom: "Irrigation",                                  filiere:'ATV', coefficient:4, ordre:27 },
  { nom: "Machinisme agricole",                         filiere:'ATV', coefficient:2, ordre:28 },
  { nom: "Pédologie",                                   filiere:'ATV', coefficient:3, ordre:29 },
  { nom: "Phytopathologie",                             filiere:'ATV', coefficient:2, ordre:30 },
  { nom: "Projet",                                      filiere:'ATV', coefficient:2, ordre:31 },
  { nom: "Technique d'expression écrite et orale",      filiere:'ATV', coefficient:2, ordre:32 },
  { nom: "Topographie",                                 filiere:'ATV', coefficient:2, ordre:33 },
  // ATA — Agriculture Tropicale option Production Animale (28)
  { nom: "Anglais",                                     filiere:'ATA', coefficient:2, ordre:1  },
  { nom: "Technique d'expression écrite",               filiere:'ATA', coefficient:2, ordre:2  },
  { nom: "Gestion",                                     filiere:'ATA', coefficient:2, ordre:3  },
  { nom: "Comptabilité",                                filiere:'ATA', coefficient:2, ordre:4  },
  { nom: "Informatique",                                filiere:'ATA', coefficient:1, ordre:5  },
  { nom: "Droit foncier et droit du travail",           filiere:'ATA', coefficient:2, ordre:6  },
  { nom: "Economie rurale et gestion d'exploitation agricole", filiere:'ATA', coefficient:2, ordre:7 },
  { nom: "Gestion des ressources humaines",             filiere:'ATA', coefficient:2, ordre:8  },
  { nom: "Marketing et force de vente",                 filiere:'ATA', coefficient:2, ordre:9  },
  { nom: "Anatomie et Physiologie Animales",            filiere:'ATA', coefficient:3, ordre:10 },
  { nom: "Biologie Animale",                            filiere:'ATA', coefficient:3, ordre:11 },
  { nom: "Génétique animale",                           filiere:'ATA', coefficient:2, ordre:12 },
  { nom: "Microbiologie",                               filiere:'ATA', coefficient:3, ordre:13 },
  { nom: "Ecologie Générale et Animale",                filiere:'ATA', coefficient:2, ordre:14 },
  { nom: "Alimentation des animaux d'élevage",          filiere:'ATA', coefficient:2, ordre:15 },
  { nom: "Biochimie",                                   filiere:'ATA', coefficient:2, ordre:16 },
  { nom: "Zootechnie Générale",                         filiere:'ATA', coefficient:2, ordre:17 },
  { nom: "Entomologie",                                 filiere:'ATA', coefficient:2, ordre:18 },
  { nom: "Biométrie",                                   filiere:'ATA', coefficient:2, ordre:19 },
  { nom: "Aviculture",                                  filiere:'ATA', coefficient:4, ordre:20 },
  { nom: "Elevage des ruminants",                       filiere:'ATA', coefficient:4, ordre:21 },
  { nom: "Cuniculture",                                 filiere:'ATA', coefficient:3, ordre:22 },
  { nom: "Aulacodiculture",                             filiere:'ATA', coefficient:4, ordre:23 },
  { nom: "Porciculture",                                filiere:'ATA', coefficient:4, ordre:24 },
  { nom: "Pisciculture",                                filiere:'ATA', coefficient:3, ordre:25 },
  { nom: "Santé Animale",                               filiere:'ATA', coefficient:3, ordre:26 },
  { nom: "Pharmacie Vétérinaire",                       filiere:'ATA', coefficient:2, ordre:27 },
  { nom: "Chimie alimentaire",                          filiere:'ATA', coefficient:2, ordre:28 },
  // ELT — Electrotechnique (18)
  { nom: "Technique d'Expression Ecrite et Orale",      filiere:'ELT', coefficient:2, ordre:1  },
  { nom: "Anglais Technique",                           filiere:'ELT', coefficient:2, ordre:2  },
  { nom: "Economie et Gestion",                         filiere:'ELT', coefficient:2, ordre:3  },
  { nom: "Mathématiques",                               filiere:'ELT', coefficient:2, ordre:4  },
  { nom: "Informatique",                                filiere:'ELT', coefficient:3, ordre:5  },
  { nom: "Electronique Industrielle",                   filiere:'ELT', coefficient:3, ordre:6  },
  { nom: "Electricité Générale et Electrotechnique",    filiere:'ELT', coefficient:5, ordre:7  },
  { nom: "Electronique Analogique",                     filiere:'ELT', coefficient:3, ordre:8  },
  { nom: "Mécanique",                                   filiere:'ELT', coefficient:2, ordre:9  },
  { nom: "Algorithme et Langage",                       filiere:'ELT', coefficient:2, ordre:10 },
  { nom: "Automatique",                                 filiere:'ELT', coefficient:2, ordre:11 },
  { nom: "Installations Electriques + Projet",          filiere:'ELT', coefficient:4, ordre:12 },
  { nom: "Mesures Electriques et Electroniques",        filiere:'ELT', coefficient:3, ordre:13 },
  { nom: "Mesures Electriques et Essais de Machines",   filiere:'ELT', coefficient:4, ordre:14 },
  { nom: "Technologie et Etude d'Equipement",           filiere:'ELT', coefficient:3, ordre:15 },
  { nom: "Schéma et Systèmes Automatisés",              filiere:'ELT', coefficient:3, ordre:16 },
  { nom: "Dessin Industriel - Technologie de Construction", filiere:'ELT', coefficient:2, ordre:17 },
  { nom: "Maintenance",                                 filiere:'ELT', coefficient:2, ordre:18 },
];

async function seedMatieres() {
  try {
    const { rows } = await pool.query('SELECT COUNT(*) FROM matieres');
    if (parseInt(rows[0].count) > 0) return;
    for (const m of MATIERES_SEED) {
      await pool.query(
        'INSERT INTO matieres (nom, filiere, coefficient, ordre) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
        [m.nom, m.filiere, m.coefficient, m.ordre]
      );
    }
    console.log(`[DB] Matières seeded: ${MATIERES_SEED.length} entrées`);
  } catch(e) {
    console.error('[DB] seedMatieres error:', e.message);
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
      'SELECT id, role, nom, prenom, email, classe_id, status, is_delegue, profile_complete, matiere, parent_of FROM users'
    );
    // Fusionner SQL (IDs réels + is_delegue à jour) avec blob (matieres, classes, poste…)
    users = usersR.rows.map(sqlU => {
      const blobU = blobUsers.find(u => (u.email || '').toLowerCase() === (sqlU.email || '').toLowerCase());
      const { pwd_hash, ...blobSafe } = blobU || {}; // ne jamais retourner le hash
      return Object.assign({}, blobSafe, {
        id:               sqlU.id,
        role:             sqlU.role,
        nom:              sqlU.nom,
        prenom:           sqlU.prenom,
        email:            sqlU.email,
        classe_id:        sqlU.classe_id || (blobU && blobU.classe_id) || '',
        status:           sqlU.status,
        is_delegue:       !!sqlU.is_delegue,
        profile_complete: sqlU.profile_complete !== false,
        matiere:          sqlU.matiere || '',
        parent_of:        sqlU.parent_of || null,
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

  // Candidatures : SQL a la priorité, blob comme migration progressive
  let sqlContacts = [];
  try {
    const csRes = await pool.query('SELECT * FROM contact_submissions ORDER BY created_at DESC');
    sqlContacts = csRes.rows.map(r => ({
      id: r.id, nom: r.nom, prenom: r.prenom, email: r.email,
      telephone: r.telephone || '', filiere: r.filiere || '',
      email_parent: r.email_parent || '', message: r.message || '',
      date: r.date, statut: r.statut,
      fichier: r.fichier || '', fichier_nom: r.fichier_nom || '',
    }));
  } catch (e) {
    console.error('[getFullData] contact_submissions not available yet:', e.message);
  }
  const blobContacts = Array.isArray(base.contact_submissions) ? base.contact_submissions : [];
  const mergedContacts = [...sqlContacts];
  for (const b of blobContacts) {
    if (!sqlContacts.some(s => s.id === b.id)) mergedContacts.push(b);
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

  // Actualités / Événements publics
  let sqlNews = [];
  try {
    const newsR = await pool.query("SELECT * FROM news ORDER BY created_at DESC");
    sqlNews = newsR.rows.map(r => ({
      id: r.id, titre: r.titre, corps: r.corps, type: r.type,
      image_url: r.image_url || '', date_event: r.date_event || '',
      lien: r.lien || '', statut: r.statut,
      created_at: isoStr(r.created_at),
    }));
  } catch(e) { console.error('[getFullData] news not available:', e.message); }

  // Contenu CMS du site vitrine
  let siteContent = {};
  try {
    const scR = await pool.query('SELECT key, titre, contenu, image_url, ordre FROM site_content ORDER BY ordre');
    scR.rows.forEach(r => {
      siteContent[r.key] = { titre: r.titre, contenu: r.contenu, image_url: r.image_url || '', ordre: r.ordre };
    });
  } catch(e) { console.error('[getFullData] site_content not available:', e.message); }

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
    contact_submissions: mergedContacts,
    news: sqlNews,
    site_content: siteContent,
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
    const { annonces, messages_teacher, messages_delegates, edt_drafts, formations, contact_submissions, ...blob } = req.body;
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
      // Le prénom/nom réel sera renseigné par l'étudiant à sa 1ère connexion
      // On dérive un prénom d'affichage depuis l'email uniquement pour l'email de bienvenue
      const { prenom: emailPrenom } = nameFromEmail(email);

      const { rows: inserted } = await pool.query(
        `INSERT INTO users (role, nom, prenom, email, pwd_hash, classe_id, status, is_delegue, profile_complete)
         VALUES ('student', 'À compléter', 'À compléter', $1, $2, $3, 'active', false, false)
         ON CONFLICT (email) DO NOTHING
         RETURNING id`,
        [email, hash, classe_id]
      );

      // RETURNING renvoie 0 ligne si ON CONFLICT DO NOTHING s'est déclenché
      if (!inserted.length) { errors.push({ email, error: 'Email déjà utilisé' }); continue; }
      const sqlId = inserted[0].id;

      let email_sent = false;
      try { email_sent = await sendWelcomeEmail(email, emailPrenom, '', password, classe_id); }
      catch (e) { console.error('Email error for', email, ':', e.message); }

      results.push({ id: sqlId, email, prenom: 'À compléter', nom: 'À compléter', classe_id, password, email_sent });
    } catch (err) {
      console.error('Create student error:', err.message);
      errors.push({ email, error: err.message });
    }
  }

  res.json({ results, errors });
});

// ── POST /api/admin/create-teacher — créer un compte enseignant ─────────────
app.post('/api/admin/create-teacher', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès réservé à l\'administrateur' });

  const { nom, prenom, email, matiere, classes } = req.body || {};
  if (!nom || !prenom || !email) {
    return res.status(400).json({ error: 'Nom, prénom et email sont requis' });
  }

  try {
    const password = generatePassword();
    const hash     = sha256(password);

    const { rows: inserted } = await pool.query(
      `INSERT INTO users (role, nom, prenom, email, pwd_hash, classe_id, status, is_delegue, matiere)
       VALUES ('teacher', $1, $2, $3, $4, '', 'active', false, $5)
       ON CONFLICT (email) DO NOTHING
       RETURNING id`,
      [nom, prenom, email.toLowerCase().trim(), hash, matiere || '']
    );

    if (!inserted.length) {
      return res.status(409).json({ error: 'Un compte avec cet email existe déjà' });
    }
    const sqlId = inserted[0].id;

    // Assigner les classes à l'enseignant
    if (Array.isArray(classes) && classes.length) {
      for (const classeId of classes) {
        await pool.query(
          `INSERT INTO teacher_classes (teacher_id, classe_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [sqlId, classeId]
        );
      }
    }

    let email_sent = false;
    try { email_sent = await sendWelcomeEmail(email, prenom, nom, password, 'Équipe pédagogique'); }
    catch (e) { console.error('Email teacher error:', e.message); }

    res.json({ id: sqlId, email: email.toLowerCase().trim(), prenom, nom, matiere: matiere || '', classes: classes || [], password, email_sent });
  } catch (err) {
    console.error('Create teacher error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── DELETE /api/admin/users/:id — suppression d'un compte ──────────────────
// On supprime par email (fiable) ET par id (fallback) pour éviter les désynchs
app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  const email = req.body?.email;
  try {
    // Récupérer le profil avant suppression pour nettoyer l'EDT si c'est un enseignant
    let teacherName = null;
    const lookupId = parseInt(req.params.id);
    const { rows: uRows } = await pool.query(
      'SELECT role, prenom, nom FROM users WHERE (id = $1 OR LOWER(email) = LOWER($2))',
      [lookupId || 0, email || '']
    );
    const uInfo = uRows[0];
    if (uInfo?.role === 'teacher') teacherName = `${uInfo.prenom} ${uInfo.nom}`;

    let deleted = 0;
    if (email) {
      const r = await pool.query('DELETE FROM users WHERE LOWER(email) = LOWER($1) AND id != $2', [email, req.user.id]);
      deleted = r.rowCount;
    }
    if (!deleted) {
      const id = parseInt(req.params.id);
      if (id) await pool.query('DELETE FROM users WHERE id = $1 AND id != $2', [id, req.user.id]);
    }

    // Nettoyer tous les créneaux EDT portant le nom de cet enseignant
    if (teacherName) {
      const { rows: drafts } = await pool.query('SELECT id, slots FROM edt_drafts');
      for (const draft of drafts) {
        const orig = Array.isArray(draft.slots) ? draft.slots : [];
        const clean = orig.filter(s => s.t !== teacherName);
        if (clean.length !== orig.length) {
          await pool.query('UPDATE edt_drafts SET slots = $1 WHERE id = $2', [JSON.stringify(clean), draft.id]);
        }
      }
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/admin/class-teachers/:classe_id — enseignants assignés à une classe ───
app.get('/api/admin/class-teachers/:classe_id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.prenom, u.nom, u.matiere
       FROM teacher_classes tc
       JOIN users u ON u.id = tc.teacher_id
       WHERE tc.classe_id = $1 AND u.role = 'teacher' AND u.status = 'active'
       ORDER BY u.nom, u.prenom`,
      [req.params.classe_id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Get class teachers error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/admin/teacher-classes/:teacher_id — classes assignées à un enseignant ──
app.get('/api/admin/teacher-classes/:teacher_id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const { rows } = await pool.query(
      `SELECT tc.classe_id, c.nom FROM teacher_classes tc
       JOIN classes c ON c.id = tc.classe_id
       WHERE tc.teacher_id = $1 ORDER BY tc.classe_id`,
      [req.params.teacher_id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Get teacher classes error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PUT /api/admin/teachers/:id — modifier infos d'un enseignant ─────────────
app.put('/api/admin/teachers/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { nom, prenom, matiere } = req.body || {};
  if (!nom || !prenom) return res.status(400).json({ error: 'Nom et prénom requis' });
  try {
    await pool.query(
      `UPDATE users SET nom = $1, prenom = $2, matiere = $3 WHERE id = $4 AND role = 'teacher'`,
      [nom.trim(), prenom.trim(), (matiere || '').trim(), req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Update teacher error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/admin/teacher-classes — assigner une classe à un enseignant ────
app.post('/api/admin/teacher-classes', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { teacher_id, classe_id } = req.body || {};
  if (!teacher_id || !classe_id) return res.status(400).json({ error: 'teacher_id et classe_id requis' });
  try {
    await pool.query(
      `INSERT INTO teacher_classes (teacher_id, classe_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [teacher_id, classe_id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Assign teacher class error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── DELETE /api/admin/teacher-classes/:teacher_id/:classe_id — retrait + nettoyage EDT ──
app.delete('/api/admin/teacher-classes/:teacher_id/:classe_id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { teacher_id, classe_id } = req.params;
  try {
    // 1. Récupérer le nom de l'enseignant (source de vérité pour les slots EDT)
    const { rows: uRows } = await pool.query('SELECT prenom, nom FROM users WHERE id = $1', [teacher_id]);
    const teacherName = uRows.length ? `${uRows[0].prenom} ${uRows[0].nom}` : null;

    // 2. Supprimer l'assignation
    await pool.query('DELETE FROM teacher_classes WHERE teacher_id = $1 AND classe_id = $2', [teacher_id, classe_id]);

    // 3. Nettoyer les slots EDT de cette classe qui portent le nom de l'enseignant
    let slotsRemoved = 0;
    if (teacherName) {
      const { rows: drafts } = await pool.query('SELECT id, slots FROM edt_drafts WHERE classe_id = $1', [classe_id]);
      for (const draft of drafts) {
        const orig  = Array.isArray(draft.slots) ? draft.slots : [];
        const clean = orig.filter(s => s.t !== teacherName);
        if (clean.length !== orig.length) {
          slotsRemoved += orig.length - clean.length;
          await pool.query('UPDATE edt_drafts SET slots = $1 WHERE id = $2', [JSON.stringify(clean), draft.id]);
        }
      }
    }

    res.json({ ok: true, slotsRemoved, teacherName });
  } catch (err) {
    console.error('Remove teacher class error:', err.message);
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

// ── GET /api/classes — liste fixe des classes IHBI (sans auth) ──────────────
app.get('/api/classes', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM classes ORDER BY id');
    res.json(rows);
  } catch (err) {
    console.error('Get classes error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/teacher/classes — classes assignées à l'enseignant connecté ──────
app.get('/api/teacher/classes', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.nom,
             COUNT(u.id)::int AS student_count
      FROM   teacher_classes tc
      JOIN   classes c  ON c.id  = tc.classe_id
      LEFT JOIN users u ON u.classe_id = tc.classe_id
                        AND u.role = 'student'
                        AND u.status = 'active'
      WHERE  tc.teacher_id = $1
      GROUP  BY c.id, c.nom
      ORDER  BY c.id
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    console.error('Get teacher classes error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/teacher/classes/:id/students — étudiants d'une classe ───────────
app.get('/api/teacher/classes/:id/students', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const classeId = req.params.id;
  try {
    const access = await pool.query(
      'SELECT 1 FROM teacher_classes WHERE teacher_id = $1 AND classe_id = $2',
      [req.user.id, classeId]
    );
    if (!access.rows.length) return res.status(403).json({ error: 'Accès refusé à cette classe' });
    const { rows } = await pool.query(
      `SELECT id, nom, prenom, email FROM users
       WHERE classe_id = $1 AND role = 'student' AND status = 'active'
       ORDER BY nom, prenom`,
      [classeId]
    );
    res.json(rows);
  } catch (err) {
    console.error('Get class students error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/teacher/evaluations — évaluations de l'enseignant ───────────────
app.get('/api/teacher/evaluations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const { rows } = await pool.query(`
      SELECT e.*,
             COUNT(DISTINCT n.id)::int          AS notes_count,
             AVG(n.note)                         AS moyenne,
             (SELECT id FROM documents WHERE eval_id = e.id LIMIT 1) AS has_document
      FROM   evaluations e
      LEFT JOIN notes n ON n.eval_id = e.id
      WHERE  e.teacher_id = $1
      GROUP  BY e.id
      ORDER  BY e.created_at DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    console.error('Get evaluations error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/teacher/evaluations — créer une évaluation ─────────────────────
app.post('/api/teacher/evaluations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const { classe_id, matiere, intitule, type, coeff, bareme, date, statut } = req.body || {};
  if (!classe_id || !matiere || !intitule) {
    return res.status(400).json({ error: 'classe_id, matiere et intitule sont requis' });
  }
  try {
    const access = await pool.query(
      'SELECT 1 FROM teacher_classes WHERE teacher_id = $1 AND classe_id = $2',
      [req.user.id, classe_id]
    );
    if (!access.rows.length) return res.status(403).json({ error: 'Accès refusé à cette classe' });
    const { rows } = await pool.query(
      `INSERT INTO evaluations (teacher_id, classe_id, matiere, intitule, type, coeff, bareme, date, statut)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [req.user.id, classe_id, matiere, intitule,
       type || 'Devoir', parseFloat(coeff) || 1, parseInt(bareme) || 20,
       date || new Date().toISOString().split('T')[0],
       statut || 'brouillon']
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('Create evaluation error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PUT /api/teacher/evaluations/:id — modifier statut/infos d'une évaluation ─
app.put('/api/teacher/evaluations/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const evalId = parseInt(req.params.id);
  const { statut, intitule, type, coeff, bareme, date } = req.body || {};
  try {
    const check = await pool.query(
      'SELECT id FROM evaluations WHERE id = $1 AND teacher_id = $2', [evalId, req.user.id]
    );
    if (!check.rows.length) return res.status(403).json({ error: 'Évaluation introuvable' });
    const updates = [];
    const vals    = [];
    let idx = 1;
    if (statut   !== undefined) { updates.push(`statut = $${idx++}`);   vals.push(statut); }
    if (intitule !== undefined) { updates.push(`intitule = $${idx++}`); vals.push(intitule); }
    if (type     !== undefined) { updates.push(`type = $${idx++}`);     vals.push(type); }
    if (coeff    !== undefined) { updates.push(`coeff = $${idx++}`);    vals.push(parseFloat(coeff)); }
    if (bareme   !== undefined) { updates.push(`bareme = $${idx++}`);   vals.push(parseInt(bareme)); }
    if (date     !== undefined) { updates.push(`date = $${idx++}`);     vals.push(date); }
    if (!updates.length) return res.json({ ok: true });
    vals.push(evalId);
    await pool.query(`UPDATE evaluations SET ${updates.join(', ')} WHERE id = $${idx}`, vals);
    res.json({ ok: true });
  } catch (err) {
    console.error('Update evaluation error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── DELETE /api/teacher/evaluations/:id — supprimer une évaluation ────────────
app.delete('/api/teacher/evaluations/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const evalId = parseInt(req.params.id);
  try {
    const check = await pool.query(
      'SELECT id FROM evaluations WHERE id = $1 AND teacher_id = $2', [evalId, req.user.id]
    );
    if (!check.rows.length) return res.status(403).json({ error: 'Évaluation introuvable' });
    await pool.query('DELETE FROM evaluations WHERE id = $1', [evalId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete evaluation error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/teacher/evaluations/:id/notes — sauvegarder notes en masse ──────
app.post('/api/teacher/evaluations/:id/notes', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const evalId = parseInt(req.params.id);
  const { notes, statut } = req.body || {};
  try {
    const check = await pool.query(
      'SELECT id FROM evaluations WHERE id = $1 AND teacher_id = $2', [evalId, req.user.id]
    );
    if (!check.rows.length) return res.status(403).json({ error: 'Évaluation introuvable' });
    for (const n of (notes || [])) {
      if (n.note === null || n.note === undefined || n.note === '') continue;
      await pool.query(
        `INSERT INTO notes (eval_id, etudiant_id, note, commentaire)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (eval_id, etudiant_id) DO UPDATE SET note = $3, commentaire = $4`,
        [evalId, n.etudiant_id, parseFloat(n.note), n.commentaire || '']
      );
    }
    if (statut) {
      await pool.query('UPDATE evaluations SET statut = $1 WHERE id = $2', [statut, evalId]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Save notes error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/teacher/evaluations/:id/notes — lire notes d'une évaluation ──────
app.get('/api/teacher/evaluations/:id/notes', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const evalId = parseInt(req.params.id);
  try {
    const check = await pool.query(
      'SELECT * FROM evaluations WHERE id = $1 AND teacher_id = $2', [evalId, req.user.id]
    );
    if (!check.rows.length) return res.status(403).json({ error: 'Évaluation introuvable' });
    const { rows } = await pool.query(
      'SELECT * FROM notes WHERE eval_id = $1', [evalId]
    );
    res.json({ eval: check.rows[0], notes: rows });
  } catch (err) {
    console.error('Get notes error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/teacher/evaluations/:id/document — uploader document correction ─
app.post('/api/teacher/evaluations/:id/document', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  const evalId = parseInt(req.params.id);
  const { name, type, data } = req.body || {};
  if (!name || !data) return res.status(400).json({ error: 'name et data (base64) requis' });
  try {
    const check = await pool.query(
      'SELECT id FROM evaluations WHERE id = $1 AND teacher_id = $2', [evalId, req.user.id]
    );
    if (!check.rows.length) return res.status(403).json({ error: 'Évaluation introuvable' });
    await pool.query('DELETE FROM documents WHERE eval_id = $1', [evalId]);
    const { rows } = await pool.query(
      `INSERT INTO documents (eval_id, name, type, data, size)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, name, type, size`,
      [evalId, name, type || 'application/octet-stream', data, data.length]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('Upload document error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/teacher/evaluations/:id/document — télécharger document correction
app.get('/api/teacher/evaluations/:id/document', authMiddleware, async (req, res) => {
  const evalId = parseInt(req.params.id);
  try {
    let authorized = false;
    if (req.user.role === 'teacher') {
      const c = await pool.query(
        'SELECT 1 FROM evaluations WHERE id = $1 AND teacher_id = $2', [evalId, req.user.id]
      );
      authorized = c.rows.length > 0;
    } else if (req.user.role === 'student') {
      const c = await pool.query(
        `SELECT 1 FROM evaluations e
         WHERE  e.id = $1 AND e.statut = 'publie'
           AND  e.classe_id = (SELECT classe_id FROM users WHERE id = $2)`,
        [evalId, req.user.id]
      );
      authorized = c.rows.length > 0;
    }
    if (!authorized) return res.status(403).json({ error: 'Accès refusé' });
    const { rows } = await pool.query('SELECT name, type, data FROM documents WHERE eval_id = $1', [evalId]);
    if (!rows.length) return res.status(404).json({ error: 'Document introuvable' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Download document error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/student/notes — notes publiées pour l'étudiant connecté ──────────
app.get('/api/student/notes', authMiddleware, async (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const userRes = await pool.query('SELECT classe_id FROM users WHERE id = $1', [req.user.id]);
    if (!userRes.rows.length) return res.status(404).json({ error: 'Utilisateur introuvable' });
    const { classe_id } = userRes.rows[0];
    const { rows } = await pool.query(`
      SELECT e.id, e.classe_id, e.matiere, e.intitule, e.type, e.coeff, e.bareme, e.date,
             n.note, n.commentaire,
             u.nom AS teacher_nom, u.prenom AS teacher_prenom,
             (SELECT id FROM documents WHERE eval_id = e.id LIMIT 1) AS document_id
      FROM   evaluations e
      LEFT JOIN notes n ON n.eval_id = e.id AND n.etudiant_id = $1
      LEFT JOIN users  u ON u.id = e.teacher_id
      WHERE  e.classe_id = $2 AND e.statut = 'publie'
      ORDER  BY e.date DESC, e.created_at DESC
    `, [req.user.id, classe_id]);
    res.json(rows);
  } catch (err) {
    console.error('Get student notes error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PATCH /api/users/me/profile — compléter son profil (1ère connexion étudiant)
app.patch('/api/users/me/profile', authMiddleware, async (req, res) => {
  const { nom, prenom } = req.body || {};
  if (!nom || !prenom) return res.status(400).json({ error: 'Nom et prénom requis' });
  try {
    await pool.query(
      'UPDATE users SET nom = $1, prenom = $2, profile_complete = true WHERE id = $3',
      [nom.trim(), prenom.trim(), req.user.id]
    );
    res.json({ ok: true, nom: nom.trim(), prenom: prenom.trim() });
  } catch (err) {
    console.error('Complete profile error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/formations — liste publique des formations actives (sans auth) ──
app.get('/api/formations', async (req, res) => {
  try {
    const [fRes, insRes] = await Promise.all([
      pool.query("SELECT * FROM formations WHERE statut = 'actif' AND public = TRUE ORDER BY created_at DESC"),
      pool.query('SELECT * FROM inscriptions_formations ORDER BY created_at ASC'),
    ]);
    res.json(fRes.rows.map(f => ({
      id: f.id, titre: f.titre, description: f.description || '',
      lieu: f.lieu || '', date_debut: f.date_debut, date_fin: f.date_fin || f.date_debut,
      places: f.places, public: f.public, statut: f.statut,
      inscrits: insRes.rows
        .filter(i => i.formation_id === f.id)
        .map(i => ({ nom: i.nom, prenom: i.prenom, profession: i.profession || '', email: i.email, telephone: i.telephone || '', date: i.date })),
    })));
  } catch (err) {
    console.error('Get formations public error:', err.message);
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

// ── DELETE /api/formations/:id — supprimer une formation (admin) ─────────────
app.delete('/api/formations/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const fid = parseInt(req.params.id);
  if (!fid) return res.status(400).json({ error: 'ID invalide' });
  try {
    await pool.query('DELETE FROM formations WHERE id = $1', [fid]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete formation error:', err.message);
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

// ── POST /api/candidatures — soumettre une candidature (public, sans auth) ───
app.post('/api/candidatures', async (req, res) => {
  const { nom, prenom, email, telephone, filiere, email_parent, message, fichier, fichier_nom } = req.body || {};
  if (!nom || !prenom || !email) return res.status(400).json({ error: 'Nom, prénom et email sont requis' });
  if (!filiere) return res.status(400).json({ error: 'Filière requise' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO contact_submissions (nom, prenom, email, telephone, filiere, email_parent, message, date, statut, fichier, fichier_nom)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'nouveau', $9, $10)
       RETURNING *`,
      [nom, prenom, email, telephone || '', filiere, email_parent || '', message || '', new Date().toISOString().split('T')[0], fichier || '', fichier_nom || '']
    );
    res.json({ ok: true, id: rows[0].id });
  } catch (err) {
    console.error('Create candidature error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PATCH /api/candidatures/:id/statut — marquer traité (admin) ─────────────
app.patch('/api/candidatures/:id/statut', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const id = parseInt(req.params.id);
  const { statut } = req.body || {};
  if (!id || !statut) return res.status(400).json({ error: 'ID et statut requis' });
  try {
    await pool.query('UPDATE contact_submissions SET statut = $1 WHERE id = $2', [statut, id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Update candidature statut error:', err.message);
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

// ══════════════════════════════════════════════════════════════════════════════
// RÉCLAMATIONS ÉTUDIANTS
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/student/reclamations — soumettre une réclamation
app.post('/api/student/reclamations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Accès refusé' });
  const { sujet, corps } = req.body || {};
  if (!sujet || !corps) return res.status(400).json({ error: 'Sujet et corps requis' });
  try {
    const userR = await pool.query('SELECT nom, prenom, classe_id FROM users WHERE id = $1', [req.user.id]);
    const u = userR.rows[0];
    const nom = u ? `${u.prenom} ${u.nom}` : 'Étudiant';
    const { rows } = await pool.query(
      `INSERT INTO reclamations (etudiant_id, etudiant_nom, classe_id, sujet, corps)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, nom, u?.classe_id || '', sujet, corps]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('Reclamation error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/student/reclamations — voir ses propres réclamations
app.get('/api/student/reclamations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const { rows } = await pool.query(
      'SELECT * FROM reclamations WHERE etudiant_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// GET /api/admin/reclamations — toutes les réclamations
app.get('/api/admin/reclamations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const { rows } = await pool.query('SELECT * FROM reclamations ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// PUT /api/admin/reclamations/:id — répondre / changer statut
app.put('/api/admin/reclamations/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { statut, reponse } = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE reclamations SET statut = COALESCE($1, statut), reponse = COALESCE($2, reponse)
       WHERE id = $3 RETURNING *`,
      [statut || null, reponse ?? null, parseInt(req.params.id)]
    );
    res.json(rows[0] || {});
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ESPACE PARENTS
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/admin/create-parent — créer un compte parent lié à un étudiant
app.post('/api/admin/create-parent', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  const { nom, prenom, email, student_id } = req.body || {};
  if (!nom || !prenom || !email || !student_id) return res.status(400).json({ error: 'Champs manquants' });
  const password = generatePassword();
  const hash = sha256(password);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (role, nom, prenom, email, pwd_hash, status, parent_of)
       VALUES ('parent', $1, $2, $3, $4, 'active', $5)
       ON CONFLICT (email) DO NOTHING RETURNING id`,
      [nom, prenom, email.toLowerCase().trim(), hash, parseInt(student_id)]
    );
    if (!rows.length) return res.status(409).json({ error: 'Email déjà utilisé' });
    let email_sent = false;
    try { email_sent = await sendWelcomeEmail(email, prenom, nom, password, 'Parent / Tuteur'); } catch(e) {}
    res.json({ id: rows[0].id, email: email.toLowerCase().trim(), prenom, nom, password, email_sent });
  } catch (err) {
    console.error('Create parent error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/parent/child — infos de l'enfant (notes + classe)
app.get('/api/parent/child', authMiddleware, async (req, res) => {
  if (req.user.role !== 'parent') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const parentR = await pool.query('SELECT parent_of FROM users WHERE id = $1', [req.user.id]);
    const studentId = parentR.rows[0]?.parent_of;
    if (!studentId) return res.status(404).json({ error: 'Aucun étudiant associé' });
    const stuR = await pool.query(
      'SELECT id, nom, prenom, email, classe_id, profile_complete FROM users WHERE id = $1',
      [studentId]
    );
    if (!stuR.rows.length) return res.status(404).json({ error: 'Étudiant introuvable' });
    const student = stuR.rows[0];
    // Notes publiées
    const notesR = await pool.query(`
      SELECT e.intitule, e.matiere, e.type, e.coeff, e.bareme, e.date,
             n.note, n.commentaire,
             u.prenom AS teacher_prenom, u.nom AS teacher_nom
      FROM notes n
      JOIN evaluations e ON n.eval_id = e.id
      JOIN users u ON e.teacher_id = u.id
      WHERE n.etudiant_id = $1 AND e.statut = 'publie'
      ORDER BY e.date DESC
    `, [studentId]);
    res.json({ student, notes: notesR.rows });
  } catch (err) {
    console.error('Parent child error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// VOLUME HORAIRE ENSEIGNANT
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/teacher/volume-horaire — heures effectuées depuis les EDT publiés
app.get('/api/teacher/volume-horaire', authMiddleware, async (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Accès refusé' });
  try {
    const userR = await pool.query('SELECT matiere FROM users WHERE id = $1', [req.user.id]);
    const matiere = userR.rows[0]?.matiere || '';
    const classesR = await pool.query(
      'SELECT classe_id FROM teacher_classes WHERE teacher_id = $1', [req.user.id]
    );
    const classes = classesR.rows.map(r => r.classe_id);
    if (!classes.length) return res.json({ total_heures: 0, par_classe: [], matiere });
    // Récupérer tous les slots publiés pour ces classes où l'enseignant enseigne
    const edtR = await pool.query(
      `SELECT classe_id, week_id, slots FROM edt_drafts
       WHERE classe_id = ANY($1) AND statut = 'publie'`,
      [classes]
    );
    const today = new Date().toISOString().split('T')[0];
    const parClasse = {};
    classes.forEach(c => { parClasse[c] = { effectuees: 0, aVenir: 0 }; });
    for (const row of edtR.rows) {
      const slots = row.slots || [];
      const weekPassed = row.week_id <= today;
      const teacherSlots = slots.filter(s => s.t && s.t.toLowerCase().includes(
        userR.rows[0]?.matiere?.toLowerCase() || '___'
      ) || (s.n && s.n.toLowerCase() === matiere.toLowerCase()));
      for (const s of teacherSlots) {
        const [sh, sm] = s.s.split(':').map(Number);
        const [eh, em] = s.e.split(':').map(Number);
        const heures = ((eh * 60 + em) - (sh * 60 + sm)) / 60;
        if (weekPassed) parClasse[row.classe_id].effectuees += heures;
        else parClasse[row.classe_id].aVenir += heures;
      }
    }
    const result = classes.map(c => ({ classe_id: c, ...parClasse[c] }));
    const total = result.reduce((s, r) => s + r.effectuees, 0);
    res.json({ total_heures: total, par_classe: result, matiere });
  } catch (err) {
    console.error('Volume horaire error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/public/site-content — contenu CMS (public, sans auth) ──────────
app.get('/api/public/site-content', async (req, res) => {
  try {
    const r = await pool.query('SELECT key, titre, contenu, image_url, ordre FROM site_content ORDER BY ordre');
    const obj = {};
    r.rows.forEach(row => { obj[row.key] = { titre: row.titre, contenu: row.contenu, image_url: row.image_url || '' }; });
    res.json(obj);
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

// ── NEWS (Actualités / Événements publics) ───────────────────────────────────
app.get('/api/public/news', async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM news WHERE statut='publié' ORDER BY created_at DESC LIMIT 20");
    res.json(r.rows);
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

app.get('/api/admin/news', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  try {
    const r = await pool.query('SELECT * FROM news ORDER BY created_at DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

app.post('/api/admin/news', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  const { titre, corps, type, image_url, date_event, lien } = req.body;
  if (!titre) return res.status(400).json({error:'Titre requis'});
  try {
    const { rows } = await pool.query(
      `INSERT INTO news (titre, corps, type, image_url, date_event, lien)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [titre, corps||'', type||'événement', image_url||'', date_event||'', lien||'']
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

app.delete('/api/admin/news/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  try {
    await pool.query('DELETE FROM news WHERE id=$1', [req.params.id]);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

// ── CMS — Contenu du site vitrine ────────────────────────────────────────────
app.get('/api/admin/site-content', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  try {
    const r = await pool.query('SELECT * FROM site_content ORDER BY ordre');
    const obj = {};
    r.rows.forEach(row => { obj[row.key] = row; });
    res.json(obj);
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

app.put('/api/admin/site-content/:key', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  const { titre, contenu, image_url } = req.body;
  try {
    await pool.query(
      `INSERT INTO site_content (key, titre, contenu, image_url)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (key) DO UPDATE SET titre=$2, contenu=$3, image_url=$4, updated_at=NOW()`,
      [req.params.key, titre||'', contenu||'', image_url||'']
    );
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

// ── Candidatures enseignants / employés ──────────────────────────────────────
app.post('/api/public/job-application', async (req, res) => {
  const { type, nom, prenom, email, telephone, poste, matiere, lettre } = req.body;
  if (!nom || !prenom || !email) return res.status(400).json({error:'Champs requis manquants'});
  try {
    await pool.query(
      `INSERT INTO job_applications (type,nom,prenom,email,telephone,poste,matiere,lettre)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [type||'enseignant', nom, prenom, email, telephone||'', poste||'', matiere||'', lettre||'']
    );
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

app.get('/api/admin/job-applications', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  try {
    const r = await pool.query('SELECT * FROM job_applications ORDER BY created_at DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

app.put('/api/admin/job-applications/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Accès refusé'});
  const { statut } = req.body;
  try {
    await pool.query('UPDATE job_applications SET statut=$1 WHERE id=$2', [statut, req.params.id]);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:'Erreur serveur'}); }
});

// ── GET /api/health — vérification Railway ──────────────────────────────────
// ── Routes Matières ─────────────────────────────────────────────────────────
// Public: liste des matières pour une filière (utilisé par les dropdowns)
app.get('/api/matieres/:filiere', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, nom, coefficient FROM matieres WHERE filiere=$1 ORDER BY ordre ASC',
      [req.params.filiere.toUpperCase()]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: toutes les matières
app.get('/api/admin/matieres', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM matieres ORDER BY filiere, ordre ASC');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: ajouter une matière
app.post('/api/admin/matieres', authMiddleware, async (req, res) => {
  const { nom, filiere, coefficient, ordre } = req.body;
  if (!nom || !filiere) return res.status(400).json({ error: 'nom et filiere requis' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO matieres (nom, filiere, coefficient, ordre) VALUES ($1, $2, $3, $4) RETURNING *',
      [nom.trim(), filiere.toUpperCase(), coefficient || 1, ordre || 0]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: modifier une matière
app.put('/api/admin/matieres/:id', authMiddleware, async (req, res) => {
  const { nom, coefficient } = req.body;
  try {
    const { rows } = await pool.query(
      'UPDATE matieres SET nom=$1, coefficient=$2 WHERE id=$3 RETURNING *',
      [nom.trim(), coefficient || 1, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Matière non trouvée' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: supprimer une matière
app.delete('/api/admin/matieres/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM matieres WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', env: process.env.NODE_ENV }));

// ── Toutes les autres routes → index.html (SPA) ─────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Debug endpoint ───────────────────────────────────────────────────────────
app.get('/api/debug', async (req, res) => {
  const info = { node: process.version, db_url: (process.env.DATABASE_URL||'').replace(/:([^:@]+)@/, ':***@'), ssl_disabled: (_dbUrl.includes('localhost')||_dbUrl.includes('127.0.0.1')) };
  try {
    const r = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name");
    info.tables = r.rows.map(x=>x.table_name);
    info.db_ok = true;
  } catch(e) { info.db_ok = false; info.db_error = e.message; }
  res.json(info);
});

// ── Démarrage ────────────────────────────────────────────────────────────────
// ensureTables() est ATTENDU avant app.listen() pour éviter la race condition :
// sans await, une requête /api/data arrivant avant la création des tables renvoyait 500
// et autoRestoreSession() gardait les vieilles données localStorage au lieu de charger Railway.
const PORT = process.env.PORT || 3000;
async function startServer() {
  await ensureTables();
  await seedMatieres();
  app.listen(PORT, () => {
    console.log(`Serveur IHBI démarré sur http://localhost:${PORT}`);
  });
}
startServer().catch(err => {
  console.error('[FATAL] Impossible de démarrer le serveur :', err.message);
  process.exit(1);
});
