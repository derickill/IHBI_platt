-- ═══════════════════════════════════════════════════════════════════
-- IHBI Platform — Schéma PostgreSQL initial
-- À exécuter une seule fois sur la DB Railway (Query Tool)
-- ═══════════════════════════════════════════════════════════════════

-- ── Table des utilisateurs ──────────────────────────────────────────
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
  created_at   TIMESTAMP    DEFAULT NOW()
);

-- ── Table de données applicatives (snapshot JSON) ───────────────────
-- Structure temporaire : une seule ligne contient tout le DB de l'app.
-- En production finale : remplacer par des tables normalisées.
CREATE TABLE IF NOT EXISTS app_data (
  key        VARCHAR(50) PRIMARY KEY,
  value      JSONB       NOT NULL DEFAULT '{}',
  updated_at TIMESTAMP   DEFAULT NOW()
);

-- ── Comptes de test ─────────────────────────────────────────────────
-- Mots de passe (SHA-256) :
--   etudiant@ihbi.ci  →  Eleve2025#IHBI
--   prof@ihbi.ci      →  Prof2025#IHBI
--   admin@ihbi.ci     →  Admin2025#IHBI
INSERT INTO users (role, nom, prenom, email, pwd_hash, classe_id, status, is_delegue)
VALUES
  ('student', 'Étudiant',  'Test', 'etudiant@ihbi.ci',
   '91400f1b7e8dfee5c5abf3f170bde3698833251dfdd6acf879ca17aae0bbea7e',
   '', 'active', false),
  ('teacher', 'Professeur','Test', 'prof@ihbi.ci',
   '895f5f7fffe0beb545e9f4dd2de7fdba0ad3ab6c56b7cccbaa017275fa2f375b',
   NULL, 'active', false),
  ('admin',   'Admin',     'Test', 'admin@ihbi.ci',
   'dc8c74284295f0de799587a295878c4f7d8e7b19070f37077fc407d1bddbeef4',
   NULL, 'active', false)
ON CONFLICT (email) DO NOTHING;
