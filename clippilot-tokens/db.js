const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is missing. Set it to your Supabase Postgres connection string (Render → Environment).');
}

// Supabase requires SSL. rejectUnauthorized:false avoids local CA-chain issues on Render.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  // Users (for per-account isolation)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Gmails / channels (in case they don't exist yet on a fresh database)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gmails (
      id BIGSERIAL PRIMARY KEY,
      gmail TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS channels (
      id BIGSERIAL PRIMARY KEY,
      gmail_id BIGINT REFERENCES gmails(id) ON DELETE CASCADE,
      channel_handler TEXT NOT NULL,
      refresh_token TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Migrate existing (already-created) tables: add user_id so each user's Gmail
  // accounts stay separate from everyone else's.
  await pool.query(`ALTER TABLE gmails ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE CASCADE;`);

  // The old schema had a GLOBAL unique constraint on gmail. Drop it so two
  // different users are each allowed to store the same address.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'gmails_gmail_key') THEN
        ALTER TABLE gmails DROP CONSTRAINT gmails_gmail_key;
      END IF;
    END $$;
  `);

  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_gmails_user_gmail ON gmails(user_id, gmail);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_gmail ON gmails(gmail);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_channel ON channels(channel_handler);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_channels_gmail_id ON channels(gmail_id);`);

  console.log('✅ Connected to Supabase Postgres and verified schema.');
}

module.exports = { pool, migrate };
