// Configuration lue dans l'environnement (jamais dans le code). DDI_TEST_MODE=1 : tests uniquement.
/** Même adresse de base de données avec un autre nom de base (identifiants et paramètres conservés) : la base d'EJBCA est lue avec le rôle de la console. */
export function withDatabase(url: string, name: string): string {
  try { const u = new URL(url); u.pathname = `/${name}`; return u.toString() } catch { return url }
}
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
    clusterStatusFile: e.DDI_CLUSTER_STATUS ?? '/run/ddibuntu/cluster-status.json',
    // pare-feu (ddibuntu-fw, root) : configuration lue directement (0644), résultat de la dernière demande et délai de confirmation publiés dans /run
    fwConfFile: e.DDI_FW_CONF ?? '/etc/ddibuntu/firewall.conf',
    fwResultFile: e.DDI_FW_RESULT ?? '/run/ddibuntu/fw-result.json',
    fwPendingFile: e.DDI_FW_PENDING ?? '/run/ddibuntu/fw-pending.json',
    adStatusFile: e.DDI_AD_STATUS ?? '/run/ddibuntu/ad-status.json',
    // service RADIUS (ddibuntu-radius, root) : état du service et résultat de la dernière demande
    radiusStatusFile: e.DDI_RADIUS_STATUS ?? '/run/ddibuntu/radius-status.json',
    // journal des authentifications RADIUS (écrit par FreeRADIUS, lisible par le groupe ddiconsole) et fenêtre lue en fin de fichier
    radiusAuthLogDir: e.DDI_RADIUS_AUTHLOG_DIR ?? '/var/log/ddibuntu-radius',
    radiusAuthLogMaxBytes: Math.max(10_000, num(e.DDI_RADIUS_AUTHLOG_MAX_BYTES, 4_000_000)),
    radiusResultFile: e.DDI_RADIUS_RESULT ?? '/run/ddibuntu/radius-result.json',
    radiusPort: num(e.DDI_RADIUS_PORT, 1812),
    // service PKI (ddibuntu-pki, root) : état de l'instance EJBCA et résultat de la dernière demande
    pkiStatusFile: e.DDI_PKI_STATUS ?? '/run/ddibuntu/pki-status.json',
    pkiResultFile: e.DDI_PKI_RESULT ?? '/run/ddibuntu/pki-result.json',
    pkiProgressFile: e.DDI_PKI_PROGRESS ?? '/run/ddibuntu/pki-progress.json',
    pkiClusterFile: e.DDI_PKI_CLUSTER ?? '/run/ddibuntu/pki-cluster.json',
    pkiUpdateFile: e.DDI_PKI_UPDATE ?? '/run/ddibuntu/pki-update.json',
    // SCEP (0.14.8) : alias et équipements préenregistrés, publiés par root (jamais un défi : EJBCA ne garde qu'une empreinte du mot de passe)
    pkiScepFile: e.DDI_PKI_SCEP ?? '/run/ddibuntu/pki-scep.json',
    // autorités de la PKI (publiées par root) : liste JSON et dossier des fichiers publics (certificat, chaîne, demande de certificat, CRL)
    pkiCasFile: e.DDI_PKI_CAS ?? '/run/ddibuntu/pki-cas.json',
    pkiCaDir: e.DDI_PKI_CA_DIR ?? '/run/ddibuntu/pki-ca',
    // certificats émis (publics, publiés par root puis purgés au bout d'une heure) et base d'EJBCA lue par la console (rôle ddi : lecture seule, deux tables publiques)
    pkiCertDir: e.DDI_PKI_CERT_DIR ?? '/run/ddibuntu/pki-cert',
    /** Délai maximal d'attente de root pour une émission ou une révocation (EJBCA démarre une JVM par commande : une dizaine de secondes en pratique). */
    pkiIssueTimeoutMs: num(e.DDI_PKI_ISSUE_TIMEOUT_MS, 120000),
    ejbcaDatabaseUrl: e.DDI_EJBCA_DATABASE_URL ?? withDatabase(e.DDI_DATABASE_URL ?? 'postgresql://ddi@127.0.0.1/ddibuntu', 'ejbca'),
    // sauvegardes de la base (ddibuntu-backup, root) : état, résultat de la dernière demande, phase d'une restauration en cours
    backupStatusFile: e.DDI_BACKUP_STATUS ?? '/run/ddibuntu/backup-status.json',
    backupResultFile: e.DDI_BACKUP_RESULT ?? '/run/ddibuntu/backup-result.json',
    backupRestoreFile: e.DDI_BACKUP_RESTORE ?? '/run/ddibuntu/backup-restore.json',
    // photographie de santé de CE nœud (ddibuntu-health, root, chaque minute) ; alertes : intervalle d'évaluation
    healthStatusFile: e.DDI_HEALTH_STATUS ?? '/run/ddibuntu/health.json',
    alertIntervalMs: num(e.DDI_ALERT_INTERVAL_MS, 60_000),
    siemIntervalMs: num(e.DDI_SIEM_INTERVAL_MS, 10_000),
    // une alerte n'est résolue qu'après N évaluations consécutives sans constat (évite les rebonds) ; 1 en test
    alertResolveMisses: Math.max(1, num(e.DDI_ALERT_RESOLVE_MISSES, 2)),
    reloadStatusFile: e.DDI_RELOAD_STATUS ?? '/var/lib/ddibuntu/reload-status',
    allowPrivateFetch: test && e.DDI_ALLOW_PRIVATE_FETCH === '1',
    dig: e.DDI_DIG ?? 'dig',
    // journal des requêtes BIND lu par la console (le dossier est lisible par le groupe ddiconsole)
    queryLogFile: e.DDI_QUERY_LOG ?? '/var/log/named/query.log',
    queryLogIntervalMs: num(e.DDI_QUERYLOG_INTERVAL_MS, 3000),
    leaseTraceIntervalMs: num(e.DDI_LEASETRACE_INTERVAL_MS, 60000),
    leaseTraceRetentionDays: num(e.DDI_LEASETRACE_RETENTION_DAYS, 400),
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
