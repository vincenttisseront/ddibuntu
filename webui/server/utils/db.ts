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


// Version 4 : espaces IPAM (même plan d'adressage réutilisable), conteneurs de réseaux, pools d'adresses.
// L'existant migre dans l'espace « Défaut » (id 1) ; la hiérarchie reste déduite de l'inclusion des préfixes dans un espace.
const SCHEMA_4 = String.raw`
create table ipam_spaces (
  id serial primary key,
  name text not null, description text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index ipam_spaces_name on ipam_spaces (lower(name));
insert into ipam_spaces (id, name, description) values (1, 'Défaut', 'Espace créé automatiquement');
select setval(pg_get_serial_sequence('ipam_spaces', 'id'), 1);
alter table subnets add column space_id int not null default 1 references ipam_spaces(id) on delete restrict,
  add column kind text not null default 'network' check (kind in ('network','container'));
alter table subnets drop constraint subnets_cidr_key;
create unique index subnets_space_cidr on subnets (space_id, cidr);
create index subnets_space on subnets (space_id);
create table ipam_pools (
  id serial primary key,
  subnet_id int not null references subnets(id) on delete cascade,
  name text not null, description text,
  start_ip inet not null, end_ip inet not null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  check (family(start_ip) = family(end_ip) and start_ip <= end_ip)
);
create index ipam_pools_subnet on ipam_pools (subnet_id);
create function ipam_pools_check() returns trigger language plpgsql as $$
declare c cidr;
begin
  select cidr into c from subnets where id = new.subnet_id;
  if not (new.start_ip <<= c and new.end_ip <<= c) then
    raise exception 'pool_outside_subnet' using errcode = 'P0001';
  end if;
  if exists (select 1 from ipam_pools p where p.subnet_id = new.subnet_id and p.id <> coalesce(new.id, 0)
             and p.start_ip <= new.end_ip and p.end_ip >= new.start_ip) then
    raise exception 'pool_overlap' using errcode = 'P0001';
  end if;
  return new;
end $$;
create trigger ipam_pools_check_trg before insert or update of start_ip, end_ip, subnet_id on ipam_pools
  for each row execute function ipam_pools_check();
`


// Version 5 : génération de configuration (compteur monotone incrémenté par déclencheur, hors numéros de série et indicateurs de déploiement),
// réservations DHCP liées à l'adresse IPAM qui les pilote, gabarits de réseau.
const SCHEMA_5 = String.raw`
create table config_generation (
  id int primary key check (id = 1),
  generation bigint not null default 1,
  changed_at timestamptz not null default now()
);
insert into config_generation (id) values (1);
create function bump_config_generation() returns trigger language plpgsql as $$
begin
  update config_generation set generation = generation + 1, changed_at = now() where id = 1;
  return null;
end $$;
create function bump_config_generation_settings() returns trigger language plpgsql as $$
begin
  if (case when tg_op = 'DELETE' then old.key else new.key end) in ('dns', 'dhcp') then
    update config_generation set generation = generation + 1, changed_at = now() where id = 1;
  end if;
  return null;
end $$;
create trigger cfg_gen_zones after insert or delete or update of name, type, masters, forwarders, allow_transfer, ddns_enabled, soa_mname, soa_rname,
  soa_refresh, soa_retry, soa_expire, soa_minimum, default_ttl, ad_integrated, disabled on dns_zones for each statement execute function bump_config_generation();
create trigger cfg_gen_records after insert or update or delete on dns_records for each statement execute function bump_config_generation();
create trigger cfg_gen_scopes after insert or update or delete on dhcp_scopes for each statement execute function bump_config_generation();
create trigger cfg_gen_dpools after insert or update or delete on dhcp_pools for each statement execute function bump_config_generation();
create trigger cfg_gen_reservations after insert or update or delete on dhcp_reservations for each statement execute function bump_config_generation();
create trigger cfg_gen_rules after insert or update or delete on filter_rules for each statement execute function bump_config_generation();
create trigger cfg_gen_lists after insert or delete or update of enabled, category on block_lists for each statement execute function bump_config_generation();
create trigger cfg_gen_entries after insert or delete on block_entries for each statement execute function bump_config_generation();
create trigger cfg_gen_settings after insert or update or delete on settings for each row execute function bump_config_generation_settings();
alter table deployments add column generation bigint;

alter table dhcp_reservations add column address_id int references addresses(id) on delete cascade;
create unique index dhcp_reservations_address on dhcp_reservations (address_id);
update dhcp_reservations r set address_id = a.id from addresses a, dhcp_scopes d
  where d.id = r.scope_id and a.subnet_id = d.subnet_id and a.ip = r.ip;

create table network_templates (
  id serial primary key,
  name text not null, description text,
  create_scope boolean not null default true,
  lease_time int not null default 86400 check (lease_time between 60 and 31536000),
  dhcp_options jsonb not null default '{}',
  dns_zone_id int references dns_zones(id) on delete set null,
  hostname_pattern text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index network_templates_name on network_templates (lower(name));
alter table subnets add column template_id int references network_templates(id) on delete set null;
`

// Itération 3 (cluster) : configuration Kea déployée, copiée dans la base répliquée. Le nœud secondaire (base en lecture seule) la relit et l'applique
// lui-même, en root, après les mêmes contrôles. Jamais de mot de passe ni de bloc « hooks » ici : la base des baux est remplacée par un fichier local.
const SCHEMA_6 = String.raw`
create table rendered_configs (
  name text primary key check (name in ('kea-dhcp4.conf')),
  content text not null,
  generation bigint not null,
  sha256 text not null,
  deployed_at timestamptz not null default now()
);
`

// Itération 4 : le secondaire BIND dérive sa configuration des fichiers named déployés (les zones, elles, arrivent par transfert signé TSIG).
const SCHEMA_7 = String.raw`
alter table rendered_configs drop constraint rendered_configs_name_check;
alter table rendered_configs add constraint rendered_configs_name_check check (name in ('kea-dhcp4.conf', 'named.conf.options', 'named.conf.zones'));
`

export const MIGRATIONS: Array<{ version: number; sql: string }> = [{ version: 1, sql: SCHEMA_1 }, { version: 2, sql: SCHEMA_2 }, { version: 3, sql: SCHEMA_3 }, { version: 4, sql: SCHEMA_4 }, { version: 5, sql: SCHEMA_5 }, { version: 6, sql: SCHEMA_6 }, { version: 7, sql: SCHEMA_7 }]

// Vrai quand le schéma est à jour : la santé n'est annoncée qu'à partir de là (le démarrage du serveur n'attend pas les migrations).
let schemaReady = false
export const isSchemaReady = () => schemaReady

// Vrai sur un nœud secondaire du cluster : la base est répliquée en lecture seule (le schéma y arrive du leader).
let recoveryCache: { at: number; v: boolean } | null = null
export async function inRecovery(maxAgeMs = 2000): Promise<boolean> {
  if (recoveryCache && Date.now() - recoveryCache.at < maxAgeMs) return recoveryCache.v
  const v = (await getPool().query('select pg_is_in_recovery() as r')).rows[0].r === true
  recoveryCache = { at: Date.now(), v }
  return v
}
export class SchemaPendingError extends Error {}

export async function migrate(): Promise<number[]> {
  if (await inRecovery(0)) {
    // secondaire : aucune écriture possible. Le schéma est géré par le leader ; on n'annonce « prêt » que lorsqu'il est au niveau attendu par ce logiciel.
    const have = Number((await getPool().query('select coalesce(max(version), 0) as v from schema_migrations').catch(() => ({ rows: [{ v: 0 }] }))).rows[0].v)
    if (have >= MIGRATIONS[MIGRATIONS.length - 1]!.version) { schemaReady = true; return [] }
    schemaReady = false
    throw new SchemaPendingError(`nœud secondaire : schéma en attente du leader (version ${have}/${MIGRATIONS[MIGRATIONS.length - 1]!.version})`)
  }
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
  schemaReady = true
  return applied
}

export async function getSetting<T>(key: string, fallback: T): Promise<T> {
  const r = await one<{ value: T }>('select value from settings where key = $1', [key])
  return r ? r.value : fallback
}
export async function setSetting(key: string, value: unknown): Promise<void> {
  await query('insert into settings (key, value) values ($1, $2::jsonb) on conflict (key) do update set value = excluded.value, updated_at = now()', [key, JSON.stringify(value)])
}
