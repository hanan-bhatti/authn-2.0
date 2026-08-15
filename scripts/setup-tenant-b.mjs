import pg from 'pg';

async function main() {
  const client = new pg.Client({ connectionString: 'postgres://postgres:postgres@localhost:5432/authn?sslmode=disable' });
  await client.connect();

  // Check tenants
  const tenants = await client.query('SELECT id, name, slug FROM tenants');
  console.log('Existing Tenants:', tenants.rows);

  // Check secret api keys
  const keys = await client.query('SELECT id, tenant_id, key_prefix, environment, revoked_at FROM api_keys');
  console.log('Existing API Keys:', keys.rows);

  await client.end();
}

main().catch(console.error);
