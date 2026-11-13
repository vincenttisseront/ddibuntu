# DDI-Buntu

Appliance **DDI** (DNS, DHCP, IPAM) sur Ubuntu Server 24.04 LTS, installable par une ISO qui s'installe seule, avec une console d'administration web. *(English: a self-installing DNS/DHCP/IPAM appliance ISO builder with a web console.)*

- **Installation automatique** : l'ISO (BIOS + UEFI) installe tout pendant l'installation ; rien n'est téléchargé au premier démarrage.
- **Mises à jour en ligne** : la console détecte les nouvelles versions (releases GitHub signées) et les installe sur clic, avec sauvegarde de la base et retour arrière automatique.
- **Mise à jour par la même ISO** : l'entrée « Update » du menu met à niveau une installation existante en conservant toutes les données.
- **Console web HTTPS** (français / anglais, thèmes clair et sombre, onglets adressables) : IPAM, DNS (BIND 9), DHCP (Kea), filtrage DNS (RPZ), utilisateurs et audit.
- **Cockpit de filtrage DNS** à la Pi-hole : journal des requêtes, tops, liste blanche/noire en un clic, pause du blocage.
- **Imports et découverte** : NetBox, Active Directory en direct (LDAP, transfert de zone), exports Windows DHCP/DNS, découverte réseau.
- **Sauvegarde et restauration à un instant donné** de la base (PITR) : sauvegardes planifiées, journaux archivés en continu, copie externe, restauration depuis la console, cluster compris.
- **Alertes et supervision** : 23 règles (cluster, quorum, réplication, chaque nœud arbitre compris, sauvegardes, sous-réseaux), mise en silence, notifications par webhook (signé) et e-mail, exportateur Prometheus `/api/metrics`, tableau de bord qui se rafraîchit seul.
- **Réglages du cluster à chaud** : adresse virtuelle et réseau dédié publiés une fois pour tous les nœuds, **certificats renouvelés automatiquement sans interruption** (la clé ne quitte jamais le nœud, seule l'autorité signe), **changement d'adresse d'un nœud** sans perdre le quorum, avec retour arrière automatique si etcd ne redémarre pas.
- **Test de bascule guidé** : pré-contrôles, **vraie bascule du primaire mesurée de bout en bout** (fenêtre sans primaire, promotion, réintégration de l'ancien primaire, rattrapage, ligne de temps, continuité WAL), retour au primaire d'origine et **rapport conservé dans le cluster**, depuis la console ou `ddibuntu-cluster drill`; les opérations de topologie sont suspendues pendant le test.
- **Retour arrière partout** : un point de restauration est créé avant chaque configuration, déploiement ou import ; les changements réseau s'annulent seuls sans confirmation.
- **Sécurité** : chaîne d'approvisionnement vérifiée (signatures et empreintes), console sans privilège, application privilégiée séparée et contrôlée, pare-feu nftables, durcissement.

> État : version de développement **0.12.5**. Voir « Limites connues » ci-dessous avant tout usage en production.

## Démarrage rapide

```bash
git clone <URL-du-dépôt> ddibuntu && cd ddibuntu
tools/build-console.sh          # Node 22 ou Docker ; construit webui/.output
./build-ddibuntu.sh             # macOS/Windows : via Docker ; Linux : natif (root) ou Docker
```

Sans cloner : télécharger le fichier unique `build-ddibuntu.sh` (ou `build-ddibuntu.ps1` sous Windows) d'une *release*. Détails, proxys d'entreprise et essai sous VMware : [docs/INSTALL.md](docs/INSTALL.md).

## Organisation du dépôt

```
build-ddibuntu.sh        point d'entrée : construit l'ISO (mode dépôt, ou fichier unique de publication)
src/rootfs/              fichiers installés sur l'appliance (assistant, menu, pare-feu, retour arrière, unités systemd…)
src/iso/                 installation automatique (Subiquity) et script late-commands
src/ps1/                 modèle du lanceur Windows
src/VERSION              numéro de version unique
webui/                   console web (Nuxt 4 + Nuxt UI 4, serveur Nitro, PostgreSQL)
tools/                   construction de la console, fichier unique, bases de test, traductions
tests/                   batteries shell b01..b22 (système, ISO, QEMU, cluster, sauvegardes) ; webui/tests : vitest
docs/                    architecture, installation, tests, publication
```

## Développement

| Besoin | Commande |
|---|---|
| Construire la console | `make console` |
| Typage et tests unitaires de la console | `make test-unit` |
| Tests de bout en bout de la console (PostgreSQL) | `tools/setup-test-db.sh` puis `make test-e2e` |
| Batteries shell (Linux, root, QEMU, chroot Ubuntu) | `make test-shell` — voir [docs/TESTING.md](docs/TESTING.md) |
| Fichier unique de publication | `make single` — voir [docs/RELEASING.md](docs/RELEASING.md) |

Principes de travail : une fonction n'est « faite » que si un test réel l'a prouvée ; un test qui échoue est d'abord soupçonné d'être faux, puis vérifié ; aucune donnée réelle (messages, clients, secrets) dans les tests.

## Cluster (en construction — itération 5 sur 6)

Deux nœuds de données + un arbitre, sur un réseau dédié ; architecture et décisions : [docs/ARCHITECTURE-CLUSTER.md](docs/ARCHITECTURE-CLUSTER.md).

```
# nœud 1 (celui qui porte déjà la base)
ddibuntu-cluster init --name n1 --ip 10.9.0.1 --net 10.9.0.0/24
# option : adresse virtuelle de service qui suit le leader PostgreSQL
#   ddibuntu-cluster init ... --vip 192.0.2.10/24 --vip-iface ens192 [--vip-vrid 51]
# sur le nœud 1, un lot par nouveau nœud (la phrase de passe s'affiche une seule fois)
ddibuntu-cluster bundle --name n3 --ip 10.9.0.3 --role witness     # arbitre
ddibuntu-cluster bundle --name n2 --ip 10.9.0.2 --role data
# sur le nouveau nœud, après copie du lot (la base locale d'un nœud de données est remplacée)
ddibuntu-cluster join n2.bundle --wipe-local-db
ddibuntu-cluster status          # état JSON
ddibuntu-cluster switchover      # bascule contrôlée
```
Ajoutez d'abord l'arbitre, puis le second nœud de données. Dès que deux nœuds de données existent, Kea passe en **HA load-balancing** (configuration ajoutée par root ; `ddibuntu-cluster status` montre l'état HA) : les relais DHCP doivent lister les deux adresses réelles des nœuds. BIND devient **primaire/secondaire** : le secondaire est dérivé par root de la configuration répliquée et reçoit les zones (et la RPZ) par transfert signé TSIG sur le réseau dédié. Pour une adresse de service unique, ajoutez une **IP virtuelle** qui suit le leader PostgreSQL (Keepalived ; voir `docs/ARCHITECTURE-CLUSTER.md`). La **page « Cluster »** de la console montre l'état et permet la bascule contrôlée ; BIND est promu automatiquement quand Patroni change de leader et un nœud secondaire de la console est en lecture seule (utilisez l'adresse de service). **Mise à jour en ligne** : secondaires d'abord, puis bascule, puis l'ancien leader (le leader refuse tant que les secondaires ne sont pas à jour).

## Limites connues

- Jamais exécuté sur **VMware réel**, **Docker Desktop réel** ni **PowerShell 5.1** ; l'interface web n'a pas été pilotée dans un navigateur automatisé.
- Le DDNS reçu par BIND est écrasé au déploiement suivant. Kea 2.4 (Ubuntu 24.04) n'a pas GSS-TSIG : le serveur DNS de l'appliance accepte bien les mises à jour sécurisées des machines du domaine (0.5.6), mais l'envoi des enregistrements DHCP vers les contrôleurs Active Directory en GSS-TSIG (Kea 3.x ou `nsupdate -g`) n'est pas fait. L'authentification Kerberos n'a été essayée qu'avec un KDC MIT, pas avec un vrai Active Directory.
- Certificat TLS de la console auto-signé ; haute disponibilité en cours de construction (voir ci-dessus) ; pas de règles par client ni par expression régulière dans le filtrage.
- La découverte réseau lit l'ARP dans `/proc/net/arp` ; le ping dépend des réglages du système.

## Licence

**À définir** : aucun fichier `LICENSE` n'est fourni tant que le choix n'est pas fait ; sans licence, tous droits sont réservés. Composants tiers : [OPEN-SOURCE.md](OPEN-SOURCE.md).
