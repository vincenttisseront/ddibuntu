# Console web DDI-Buntu 0.2.0

Console d'administration DDI : **IPAM**, **DNS** (18 types d'enregistrements), **DHCP**, **filtrage DNS** (RPZ),
**import / compatibilité Active Directory**, utilisateurs et audit. Nuxt 4 + Nuxt UI 4 + Tailwind 4, PostgreSQL.
Français et anglais, thèmes clair et sombre, onglets adressables (`/dns#records`).

## Contenu

| Archive | Contenu |
|---|---|
| `ddibuntu-console-0.2.0-sources.tar.gz` | Sources, tests, `package-lock.json` (versions épinglées), système de design |
| `ddibuntu-console-0.2.0-output.tar.gz` | Application **construite**, autonome (`node .output/server/index.mjs`), prête à embarquer |

## Prérequis

Node.js **22** ou plus récent, PostgreSQL 16. Pour la validation des configurations : `named-checkzone`, `named-checkconf`
(paquet `bind9-utils`) et `kea-dhcp4` (paquet `kea-dhcp4-server`).

```sql
create role ddi login password '<mot de passe>';
create database ddibuntu owner ddi;
```

Le schéma est créé et migré automatiquement au démarrage.

## Variables d'environnement

| Variable | Rôle |
|---|---|
| `DDI_DATABASE_URL` | Connexion PostgreSQL (obligatoire) |
| `DDI_SECRET_KEY` | Clé de chiffrement des secrets (mot de passe de liaison AD, mot de passe Kea) : **32 caractères minimum**, le serveur refuse de démarrer sans elle |
| `DDI_SETUP_TOKEN` | Jeton de première configuration (page `/setup`, valable tant qu'aucun utilisateur n'existe) |
| `DDI_COOKIE_SECURE` | `false` seulement pour un essai en HTTP ; par défaut les cookies sont `Secure` |
| `DDI_GENERATED_DIR` | Dossier où la configuration validée est déployée (défaut `/var/lib/ddibuntu/generated`) |
| `DDI_SESSION_HOURS` / `DDI_IDLE_MINUTES` | Durée de session (8 h) et inactivité maximale (30 min) |
| `PORT`, `NITRO_HOST` | Port et adresse d'écoute |

Ne jamais définir `DDI_TEST_MODE` en production : il n'existe que pour les tests (itérations PBKDF2 réduites, téléchargements privés).

## Premier démarrage

```bash
export DDI_DATABASE_URL=postgresql://ddi:...@127.0.0.1/ddibuntu
export DDI_SECRET_KEY="$(openssl rand -base64 48)"      # à conserver : sans elle, les secrets sont illisibles
export DDI_SETUP_TOKEN="$(openssl rand -hex 16)"
node .output/server/index.mjs
```

Ouvrir `/setup`, saisir le jeton, créer l'administrateur, puis se connecter. La console doit être servie en **HTTPS**
(reverse proxy ou TLS devant Node) : l'intégration à l'ISO s'en charge à l'itération suivante.

## Tests

```bash
npm ci --ignore-scripts && npx nuxt prepare && npx nuxt build
npx vitest run          # 124 tests : unitaires (outils BIND/Kea réels) + bout en bout (serveur construit + PostgreSQL)
```

Les tests de bout en bout exigent une base `ddibuntu_test` (propriétaire `ddi`) et **effacent son schéma** à chaque exécution.

## Limites connues

- Interface jamais pilotée dans un vrai navigateur : le rendu serveur, les traductions et l'association étiquette/champ sont testés, pas les clics ni les graphiques.
- Analyseurs Windows (`dnscmd /ZoneExport`, `Export-DhcpServer`) validés sur des échantillons reconstitués, pas sur de vrais exports.
- Authentification AD validée sur un annuaire simulé, pas sur un vrai Active Directory.
- CSP avec `'unsafe-inline'` pour les scripts (script d'amorçage de Nuxt) : passage à un nonce prévu.
- Le déploiement écrit les fichiers validés ; le rechargement de BIND et de Kea (privilégié) reste à intégrer à l'appliance.
- Options DHCP personnalisées : prises en charge par l'API (codes 224 à 254), pas encore par l'interface.
- Le noyau de Kea 2.4 (Ubuntu 24.04) ne fournit pas GSS-TSIG : le DDNS sécurisé vers l'AD exige Kea 3.x.

## Outil de design

`docs/design-system.md` : système de design produit par `uipro-cli` 2.2.3 (module `uxpro-cli` inexistant sur npm) puis adapté :
polices Fira embarquées (aucun téléchargement), palette bleu `#1E40AF` / ambre `#F59E0B`. `uipro-cli` est un outil de développement,
installé sans scripts, absent de l'appliance.
