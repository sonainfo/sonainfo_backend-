require("dotenv").config();
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");

  const email = process.env.SEED_ADMIN_EMAIL;
  const password = process.env.SEED_ADMIN_PASSWORD;
  const name = process.env.SEED_ADMIN_NAME || "Sonainfo Admin";
  const role = process.env.SEED_ADMIN_ROLE || "admin";

  if (!email || !password || password === "CHANGE_THIS_PASSWORD") {
    throw new Error("Set SEED_ADMIN_EMAIL and a strong SEED_ADMIN_PASSWORD before running npm run seed.");
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
  });

  const hash = await bcrypt.hash(password, 12);
  await pool.query(
    `INSERT INTO users(email,password_hash,name,role)
     VALUES($1,$2,$3,$4)
     ON CONFLICT(email) DO UPDATE SET
       password_hash=EXCLUDED.password_hash,
       name=EXCLUDED.name,
       role=EXCLUDED.role,
       active=TRUE,
       updated_at=NOW()`,
    [email.toLowerCase(), hash, name, role]
  );

  console.log(`Seeded admin user: ${email}`);
  await pool.end();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
