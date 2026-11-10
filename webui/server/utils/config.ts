// Configuration lue dans l'environnement (jamais dans le code). DDI_TEST_MODE=1 : tests uniquement.
export function cfg() {
  const e = process.env
  const test = e.DDI_TEST_MODE === '1'
  const num = (v: string | undefined, d: number) => (v !== undefined && /^\d+$/.test(v) ? Number(v) : d)
  return {
    testMode: test,
    databaseUrl: e.DDI_DATABASE_URL ?? 'postgresql://ddi@127.0.0.1/ddibuntu',
    secretKey: e.DDI_SECRET_KEY ?? '',
    cookieSecure: e.DDI_COOKIE_SECURE !== 'false',
    sessionHours: num(e.DDI_SESSION_HOURS, 8),
    idleMinutes: num(e.DDI_IDLE_MINUTES, 30),
    setupToken: e.DDI_SETUP_TOKEN ?? '',
    // 600 000 itérations PBKDF2-HMAC-SHA256 ; la valeur n'est modifiable qu'en mode test
    pbkdf2Iterations: test ? num(e.DDI_PBKDF2_ITERATIONS, 600000) : 600000,
    generatedDir: e.DDI_GENERATED_DIR ?? '/var/lib/ddibuntu/generated',
    // chemin des fichiers de zone tel qu'il apparaît dans named.conf déployé (≠ dossier de dépôt de la console)
    zonesRuntimeDir: e.DDI_ZONES_RUNTIME_DIR ?? '',
    keaDbPassword: e.DDI_KEA_DB_PASSWORD ?? '',
    // écrit par ddibuntu-reload (root) après chaque application : at=epoch, ok=1|0, message=…
    // écrit par ddibuntu-selfupdate (root) : version installée / disponible, état de l'installation
    updateStatusFile: e.DDI_UPDATE_STATUS ?? '/var/lib/ddibuntu/update-status.json',
    versionFile: e.DDI_VERSION_FILE ?? '/usr/local/lib/ddibuntu/VERSION',
    reloadStatusFile: e.DDI_RELOAD_STATUS ?? '/var/lib/ddibuntu/reload-status',
    allowPrivateFetch: test && e.DDI_ALLOW_PRIVATE_FETCH === '1',
    dig: e.DDI_DIG ?? 'dig',
    // journal des requêtes BIND lu par la console (le dossier est lisible par le groupe ddiconsole)
    queryLogFile: e.DDI_QUERY_LOG ?? '/var/log/named/query.log',
    queryLogIntervalMs: num(e.DDI_QUERYLOG_INTERVAL_MS, 3000),
    namedCheckzone: e.DDI_NAMED_CHECKZONE ?? 'named-checkzone',
    namedCheckconf: e.DDI_NAMED_CHECKCONF ?? 'named-checkconf',
    keaDhcp4: e.DDI_KEA_DHCP4 ?? 'kea-dhcp4',
    maxBodyBytes: num(e.DDI_MAX_BODY_BYTES, 30 * 1024 * 1024),
  }
}

export function requireSecret(): string {
  const c = cfg()
  if (c.testMode && !c.secretKey) return 'test-mode-secret-key-0123456789abcdef'
  if (c.secretKey.length < 32) throw new Error('DDI_SECRET_KEY absent ou trop court (32 caractères minimum)')
  return c.secretKey
}
