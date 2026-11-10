# Architecture

## Chaîne de livraison
`build-ddibuntu.sh` télécharge l'ISO Ubuntu Server, vérifie **la signature Canonical du fichier de sommes puis la somme de l'ISO**, embarque la charge utile (`src/rootfs`, `src/iso`, la console construite, Node.js vérifié par signature, les paquets résolus dans un conteneur propre) et produit une ISO hybride BIOS + UEFI. En mode dépôt, la charge utile est préparée depuis les dossiers (`--stage`) ; le fichier unique de publication embarque exactement la même (test b05).

## Sur l'appliance
1. **Installation** (Subiquity, `src/iso/user-data.tmpl` + `late.sh`) : paquets installés hors ligne, fichiers déployés, console installée.
   **Mise à jour** (même ISO, entrée « Update » du menu GRUB, graine `ddibuntu/update/user-data`) : `early-commands` lance `src/iso/update.sh` AVANT toute étape de stockage. Il active LVM, repère l'unique installation DDI-Buntu, la monte, sauvegarde les fichiers qu'il remplace (`/var/lib/ddibuntu/update-backup/`), installe les seuls paquets plus récents (`--force-confold`), remplace la console et Node, redéploie les fichiers de l'appliance (en conservant `firewall.conf` et `nftables.nft`), puis **arrête la machine**. Il ne rend jamais la main à Subiquity (qui effacerait le disque) : un échec laisse un message et attend. La base est migrée par la console au prochain démarrage (`server/plugins/migrate.ts`).
2. **Premier démarrage** : `ddibuntu-setup` (langue, **clavier appliqué puis testé**, réseau, réseaux d'administration, compte) → `ddibuntu-apply` (idempotent) → `ddibuntu-db-init` (PostgreSQL, certificat TLS, jeton de première configuration).
3. **Console web** : processus Node **sans privilège** (`ddiconsole`, port 443 par capacité), écrit seulement dans `/var/lib/ddibuntu/generated`.

## Mises à jour en ligne
La console (sans privilège) ne télécharge ni n'installe rien : elle dépose `generated/.update-request` et lit `update-status.json`. `ddibuntu-selfupdate` (root, déclenché par `ddibuntu-selfupdate.path` ; recherche quotidienne par `ddibuntu-update-check.timer`) **ne fait confiance à rien de la demande** : il relit lui-même la dernière release du dépôt de `update.conf`, n'installe que cette version, vérifie la signature Ed25519 de `SHA256SUMS` (clé publique épinglée `update-pubkey.pem`) puis la somme de l'archive, sauvegarde (`pg_dump` + fichiers remplacés, dans `update-backup/`), remplace console et fichiers de l'appliance (en conservant `firewall.conf`, `nftables.nft`, `update.conf`), redémarre la console et attend `/api/health` ; sans réponse, il restaure l'ancienne console et les fichiers. Test : `tests/b09-selfupdate.sh` (faux GitHub local, vraies signatures).

## Frontière de privilèges
La console génère la configuration BIND/Kea à partir de la base, la valide (`named-checkzone`, `named-checkconf`, `kea-dhcp4 -t`) et dépose les fichiers puis un marqueur. `ddibuntu-reload` (root, déclenché par une unité `.path`) **contrôle le contenu déposé** (pas d'`include`, pas de `controls`, chemins imposés, pas de hooks Kea…), l'installe, recharge les services, et **remet l'ancienne configuration (et la fait relire) en cas d'échec**. Son résultat est écrit dans `/var/lib/ddibuntu/reload-status`, lu par la console.

## Retour arrière
- **Système** (`ddibuntu-rollback`) : un point (`ddibuntu.conf` sans secret) avant chaque `ddibuntu-apply` ; restaurer = ré-appliquer par le même chemin ; minuteur `systemd-run` : retour automatique sans confirmation.
- **Données** (table `config_snapshots`) : un point avant chaque déploiement et chaque import ; restauration atomique (une transaction), l'état actuel est conservé d'abord.

## Filtrage DNS
Listes et règles → zone RPZ générée. BIND écrit `/var/log/named/query.log` (`querylog yes`, catégories `queries`, `rpz`, `rpz-passthru`, groupe `ddiconsole` en lecture) ; la console le lit en continu (`server/plugins/querylog.ts`), fusionne requête et réécriture RPZ, explique chaque blocage (précédence : le plus spécifique l'emporte, « autoriser » gagne à égalité) et alimente `dns_queries` (rétention et anonymisation réglables).

## Console web
Nuxt 4 (Nitro) + PostgreSQL. API : un seul routeur (`server/api/[...slug].ts`) qui centralise authentification, CSRF, rôles, validation (zod), audit et assainissement des erreurs. Migrations numérotées dans `server/utils/db.ts`.
