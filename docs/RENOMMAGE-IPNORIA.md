# Renommage DDI-Buntu → Ipnoria

Statut : **étape 1 réalisée** (0.23.0). Étapes 2 et 3 à faire, chacune dans sa version, avec un essai réel sur un cluster avant publication.

Principe : une appliance installée doit toujours pouvoir se mettre à jour en ligne, nœud par nœud, sans intervention manuelle, et revenir en arrière si la mise à jour échoue. Aucun identifiant stocké n'est renommé sans migration testée et sans compatibilité pendant au moins une version.

## Étape 1 (0.23.0) : le nom visible — fait

Console, ISO, script de construction, descriptions des unités, documentation, en-têtes des fichiers générés, logo. Aucun chemin, aucune unité, aucune commande, aucune base n'a changé.

## Inventaire des identifiants techniques

| Identifiant | Où il vit | Risque si on le change | Décision |
|---|---|---|---|
| Dépôt GitHub `vincenttisseront/ddibuntu` | Appliances (URL des mises à jour), clones | Faible : GitHub redirige après renommage, tant qu'aucun dépôt ne reprend l'ancien nom | Renommer le dépôt (manuel, Settings) ; étape 2 : URL `ipnoria` dans le code, l'ancienne reste valide par redirection |
| Archives `ddibuntu-update-X.tar.gz`, `SHA256SUMS(.sig)` | Releases ; `ddibuntu-selfupdate` des appliances déjà installées | **Élevé** : une appliance 0.23 ne cherche que `ddibuntu-update-*` | Étape 2 : publier les deux noms pendant au moins deux versions ; l'appliance cherche d'abord `ipnoria-update-*` |
| `build-ddibuntu.sh`, `make-iso.ps1` | Postes de construction | Faible | Étape 2 : `build-ipnoria.sh`, l'ancien nom devient un lanceur qui le signale et l'appelle |
| Commandes `ddibuntu-*` (15, root) | Appliances, scripts d'exploitation, documentation, sudoers | Moyen | Étape 2 : nouveaux noms `ipnoria-*` ; les anciens deviennent des liens symboliques, retirés en étape 3 + 2 versions |
| Unités systemd `ddibuntu-*` (≈ 40) | Appliances | **Élevé** : la mise à jour est elle-même pilotée par `ddibuntu-selfupdate.path/.service` | Étape 3 : nouvelles unités installées et activées par le script de mise à jour **après** la fin de la mise à jour en cours ; anciennes désactivées puis masquées ; retour arrière restaure les anciennes |
| Chemins `/etc/ddibuntu`, `/usr/local/lib/ddibuntu`, `/var/lib/ddibuntu`, `/var/log/ddibuntu` | Appliances (données, secrets, certificats) | **Élevé** | Étape 3 : déplacement atomique (`mv` sur le même système de fichiers) puis lien `ancien → nouveau` ; tous les programmes lisent le nouveau chemin |
| Base PostgreSQL `ddibuntu` | Appliances, réplication Patroni, sauvegardes PITR | **Élevé** : `ALTER DATABASE … RENAME` exige zéro connexion, s'applique au leader et se réplique | Étape 3 : renommage pendant la fenêtre d'arrêt de la console, sur le leader seulement, après la mise à jour de tous les secondaires ; restauration PITR : la procédure accepte les deux noms |
| Espaces de noms etcd `/ddibuntu/`, `/ddibuntu-cluster/` (Patroni) | Cluster | **Très élevé** : changer le `namespace` de Patroni revient à recréer le cluster | **Conservés.** Invisibles pour l'utilisateur ; aucun bénéfice à les renommer |
| Constantes de dérivation (`ddibuntu-pki-state-v1`, `ddibuntu-ad-keytab-v…`) | Secrets chiffrés en base | **Très élevé** : secrets indéchiffrables | **Conservées.** Invisibles |
| Table nftables `inet ddibuntu` | Appliances | Faible | Étape 3 : recréée sous le nouveau nom au rechargement du pare-feu, l'ancienne supprimée dans la même transaction |
| Métriques `ddibuntu_*` | Supervision externe (Prometheus, tableaux de bord) | Moyen : tableaux de bord et alertes cassés | Étape 3 : métriques exposées sous les deux noms pendant deux versions, puis `ipnoria_*` seulement ; annoncé dans le journal |
| En-tête webhook `X-DDIbuntu-Signature`, `User-Agent` | Récepteurs des clients | Moyen | Étape 3 : envoyer `X-Ipnoria-Signature` **et** l'ancien pendant deux versions |
| CEF/LEEF fabricant/produit `DDI-Buntu` | Règles SIEM des clients | Moyen | Étape 3 : réglage « nom dans les journaux SIEM » (ancien / nouveau), nouveau par défaut pour les nouvelles destinations, ancien conservé pour les existantes |
| GPO « DDI-Buntu enrolement », dossier `C:\Program Files\DDI-Buntu`, tâche planifiée | Active Directory, postes Windows | Moyen : deux GPO concurrentes si on recrée | Étape 3 : renommer la GPO existante (attribut `displayName`, même GUID), le script de démarrage déplace le dossier et recrée la tâche sous le nouveau nom au premier passage |
| Émetteur TOTP | Applications d'authentification | Aucun (le code ne dépend pas du libellé) | Fait en étape 1 pour les nouveaux enrôlements |

## Étape 2 (0.24.0) : noms de commandes, construction et publication

1. `build-ipnoria.sh` ; `build-ddibuntu.sh` devient un lanceur de compatibilité (message + `exec`).
2. Commandes `ipnoria-*` installées ; `ddibuntu-*` deviennent des liens. sudoers et unités appellent les nouveaux noms.
3. `release.yml` publie `ipnoria-update-X.tar.gz` **et** `ddibuntu-update-X.tar.gz` (même contenu), un seul `SHA256SUMS` signé couvrant les deux.
4. `ipnoria-selfupdate` cherche d'abord `ipnoria-update-*`, puis l'ancien nom.
5. Tests : b05 (construction), b09 (mise à jour en ligne : une appliance 0.23 passe en 0.24 avec l'ancien nom d'archive), batteries existantes inchangées.

## Étape 3 (0.25.0) : migration des appliances

Exécutée par le script de mise à jour, après validation du nouveau logiciel et avant le redémarrage des services, sur chaque nœud :

1. Point de restauration complet (comme pour toute mise à jour).
2. Arrêt des services applicatifs (console, RADIUS, PKI) ; DNS et DHCP continuent de répondre.
3. Chemins : `mv` atomiques + liens de compatibilité ; vérification de chaque cible.
4. Unités : installation des `ipnoria-*`, `daemon-reload`, activation, désactivation et masquage des `ddibuntu-*`.
5. Base (leader seulement, quand tous les secondaires sont en 0.25) : `ALTER DATABASE ddibuntu RENAME TO ipnoria`, mise à jour des chaînes de connexion répliquées.
6. Redémarrage des services, contrôle de santé ; en cas d'échec, retour arrière automatique (restauration des chemins, unités et nom de base).
7. Tests à écrire : migration sur une appliance seule, sur un cluster deux nœuds + arbitre (secondaires d'abord, leader ensuite), retour arrière forcé à chaque étape, restauration PITR antérieure à la migration.

**Prérequis avant de publier l'étape 3** : essai réel sur le banc de test (cluster deux nœuds), mise à jour depuis la 0.22 et depuis la 0.24, et retour arrière constaté.
