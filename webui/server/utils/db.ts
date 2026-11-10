// PostgreSQL : pool, transactions, migrations. Requêtes toujours paramétrées.
import pg from 'pg'
import { cfg } from './config'

let pool: pg.Pool | null = null
export function getPool(): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({ connectionString: cfg().databaseUrl, max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 })
    pool.on('error', (e) => console.error('[db] erreur de connexion inactive :', e.message))
  }
  return pool
}
export async function closePool(): Promise<void> { if (pool) { await pool.end(); pool = null } }

export async function query<T = any>(text: string, params: unknown[] = []): Promise<T[]> {
  const r = await getPool().query(text, params as any[])
  return r.rows as T[]
}
export async function one<T = any>(text: string, params: unknown[] = []): Promise<T | null> {
  return (await query<T>(text, params))[0] ?? null
}
export async function tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await getPool().connect()
  try {
    await c.query('begin')
    const r = await fn(c)
    await c.query('commit')
    return r
  } catch (e) {
    await c.query('rollback').catch(() => undefined)
    throw e
  } finally {
    c.release()
  }
}

const SCHEMA_1 = String.raw`
create table users (
  id serial primary key,
  username text not null,
  display_name text,
  role text not null check (role in ('admin','operator','viewer')),
  source text not null default 'local' check (source in ('local','ad')),
  password_hash text,
  disabled boolean not null default false,
  created_at timestamptz not null default now(),
  last_login timestamptz
);
create unique index users_username_lower on users (lower(username));
create table sessions (
  id bigserial primary key,
  token_hash text not null unique,
  user_id int not null references users(id) on delete cascade,
  csrf_token text not null,
  created_at timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  expires_at timestamptz not null,
  ip inet, user_agent text
);
create table login_attempts (
  id bigserial primary key, username text not null, ip inet, success boolean not null, at timestamptz not null default now()
);
create index login_attempts_user on login_attempts (lower(username), at);
create index login_attempts_ip on login_attempts (ip, at);
create table audit_log (
  id bigserial primary key, at timestamptz not null default now(), user_id int, username text,
  action text not null, entity text, entity_id text, detail jsonb, ip inet
);
create index audit_log_at on audit_log (at desc);
create table settings (key text primary key, value jsonb not null, updated_at timestamptz not null default now());

create table vlans (
  id serial primary key,
  vlan_id int not null unique check (vlan_id between 1 and 4094),
  name text not null, description text
);
create table subnets (
  id serial primary key,
  cidr cidr not null unique,
  name text not null, description text,
  vlan_id int references vlans(id) on delete set null,
  site text, gateway inet,
  tags text[] not null default '{}',
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index subnets_cidr_gist on subnets using gist (cidr inet_ops);
create table addresses (
  id serial primary key,
  subnet_id int not null references subnets(id) on delete cascade,
  ip inet not null,
  status text not null default 'used' check (status in ('used','reserved','dhcp','gateway','infra')),
  hostname text, mac macaddr, description text, owner text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (subnet_id, ip)
);
create function addresses_in_subnet() returns trigger language plpgsql as $$
begin
  if not (new.ip <<= (select cidr from subnets where id = new.subnet_id)) then
    raise exception 'ip_outside_subnet' using errcode = 'P0001';
  end if;
  return new;
end $$;
create trigger addresses_in_subnet_trg before insert or update of ip, subnet_id on addresses
  for each row execute function addresses_in_subnet();

create table dns_zones (
  id serial primary key,
  name text not null,
  type text not null check (type in ('primary','secondary','forward')),
  masters text[] not null default '{}',
  forwarders text[] not null default '{}',
  allow_transfer text[] not null default '{}',
  ddns_enabled boolean not null default false,
  soa_mname text, soa_rname text,
  soa_refresh int not null default 3600, soa_retry int not null default 600,
  soa_expire int not null default 1209600, soa_minimum int not null default 3600,
  default_ttl int not null default 3600,
  serial bigint not null default 1,
  dirty boolean not null default true,
  ad_integrated boolean not null default false,
  disabled boolean not null default false,
  comment text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index dns_zones_name on dns_zones (lower(name));
create table dns_records (
  id serial primary key,
  zone_id int not null references dns_zones(id) on delete cascade,
  name text not null,
  type text not null,
  ttl int check (ttl is null or ttl between 0 and 2147483647),
  rdata text not null,
  comment text,
  protected boolean not null default false,
  disabled boolean not null default false,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index dns_records_uniq on dns_records (zone_id, lower(name), type, rdata);
create index dns_records_lookup on dns_records (zone_id, lower(name));

create table dhcp_scopes (
  id serial primary key,
  subnet_id int not null unique references subnets(id) on delete cascade,
  name text,
  lease_time int not null default 86400 check (lease_time between 60 and 31536000),
  enabled boolean not null default true,
  options jsonb not null default '{}',
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table dhcp_pools (
  id serial primary key,
  scope_id int not null references dhcp_scopes(id) on delete cascade,
  start_ip inet not null, end_ip inet not null,
  check (family(start_ip) = family(end_ip) and start_ip <= end_ip),
  unique (scope_id, start_ip, end_ip)
);
create table dhcp_reservations (
  id serial primary key,
  scope_id int not null references dhcp_scopes(id) on delete cascade,
  mac macaddr not null, ip inet not null, hostname text, description text,
  unique (scope_id, mac), unique (scope_id, ip)
);

create table block_lists (
  id serial primary key,
  name text not null unique,
  category text not null,
  source_url text,
  format text not null default 'domains' check (format in ('hosts','domains','adblock')),
  enabled boolean not null default true,
  entries int not null default 0,
  sha256 text, updated_at timestamptz, last_error text,
  created_at timestamptz not null default now()
);
create table block_entries (
  list_id int not null references block_lists(id) on delete cascade,
  domain text not null,
  primary key (list_id, domain)
);
create index block_entries_domain on block_entries (domain);
create table filter_rules (
  id serial primary key,
  domain text not null,
  action text not null check (action in ('block','allow')),
  comment text,
  created_at timestamptz not null default now(),
  unique (domain, action)
);
create table dns_stats (
  bucket timestamptz not null, kind text not null, key text not null default '', count bigint not null default 0,
  primary key (bucket, kind, key)
);
create table import_runs (
  id serial primary key, kind text not null, filename text, summary jsonb not null default '{}',
  username text, created_at timestamptz not null default now()
);
create table deployments (
  id serial primary key, at timestamptz not null default now(), username text,
  ok boolean not null, files jsonb not null default '{}', results jsonb not null default '[]'
);
`

// Version 2 : origine des objets IPAM (import externe, découverte), points de restauration, statut des déploiements.
const SCHEMA_2 = String.raw`
alter table vlans add column source text not null default 'manual', add column external_id text;
alter table subnets add column source text not null default 'manual', add column external_id text;
alter table addresses add column source text not null default 'manual', add column external_id text, add column last_seen timestamptz;
create table config_snapshots (
  id serial primary key, at timestamptz not null default now(), username text,
  kind text not null check (kind in ('manual','deploy','pre-import','pre-restore')),
  label text, schema_version int not null, counts jsonb not null default '{}', size int not null default 0,
  pinned boolean not null default false, data jsonb not null
);
create index config_snapshots_at on config_snapshots (at desc);
alter table deployments add column snapshot_id int references config_snapshots(id) on delete set null,
  add column applied boolean, add column apply_message text;
alter table import_runs add column snapshot_id int references config_snapshots(id) on delete set null;
`

// Version 3 : journal des requêtes DNS (cockpit de filtrage). Rétention et anonymisation réglables ; purgeable.
const SCHEMA_3 = String.raw`
create table dns_queries (
  id bigserial primary key, at timestamptz not null, client text not null, domain text not null, qtype text not null default '',
  status text not null check (status in ('allowed','blocked')),
  reason text not null default '',
  category text not null default ''
);
create index dns_queries_at on dns_queries (at desc);
create index dns_queries_domain on dns_queries (domain, at desc);
create index dns_queries_client on dns_queries (client, at desc);
`

export const MIGRATIONS: Array<{ version: number; sql: string }> = [{ version: 1, sql: SCHEMA_1 }, { version: 2, sql: SCHEMA_2 }, { version: 3, sql: SCHEMA_3 }]

export async function migrate(): Promise<number[]> {
  const c = await getPool().connect()
  const applied: number[] = []
  try {
    await c.query('select pg_advisory_lock(727727)')
    await c.query('create table if not exists schema_migrations (version int primary key, applied_at timestamptz not null default now())')
    const done = new Set((await c.query('select version from schema_migrations')).rows.map((r) => r.version as number))
    for (const m of MIGRATIONS) {
      if (done.has(m.version)) continue
      await c.query('begin')
      try {
        await c.query(m.sql)
        await c.query('insert into schema_migrations (version) values ($1)', [m.version])
        await c.query('commit')
        applied.push(m.version)
      } catch (e) {
        await c.query('rollback')
        throw e
      }
    }
  } finally {
    await c.query('select pg_advisory_unlock(727727)').catch(() => undefined)
    c.release()
  }
  return applied
}

export async function getSetting<T>(key: string, fallback: T): Promise<T> {
  const r = await one<{ value: T }>('select value from settings where key = $1', [key])
  return r ? r.value : fallback
}
export async function setSetting(key: string, value: unknown): Promise<void> {
  await query('insert into settings (key, value) values ($1, $2::jsonb) on conflict (key) do update set value = excluded.value, updated_at = now()', [key, JSON.stringify(value)])
}
