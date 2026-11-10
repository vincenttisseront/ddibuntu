# DDI-Buntu

Appliance **DDI** (DNS, DHCP, IPAM) sur Ubuntu Server 24.04 LTS, installable par une ISO qui s'installe seule, avec une console d'administration web. *(English: a self-installing DNS/DHCP/IPAM appliance ISO builder with a web console.)*

- **Installation automatique** : l'ISO (BIOS + UEFI) installe tout pendant l'installation ; rien n'est téléchargé au premier démarrage.
- **Mises à jour en ligne** : la console détecte les nouvelles versions (releases GitHub signées) et les installe sur clic, avec sauvegarde de la base et retour arrière automatique.
- **Mise à jour par la même ISO** : l'entrée « Update » du menu met à niveau une installation existante en conservant toutes les données.
- **Console web HTTPS** (français / anglais, thèmes clair et sombre, onglets adressables) : IPAM, DNS (BIND 9), DHCP (Kea), filtrage DNS (RPZ), utilisateurs et audit.
- **Cockpit de filtrage DNS** à la Pi-hole : journal des requêtes, tops, liste blanche/noire en un clic, pause du blocage.
- **Imports et découverte** : NetBox, Active Directory en direct (LDAP, transfert de zone), exports Windows DHCP/DNS, découverte réseau.
- **Retour arrière partout** : un point de restauration est créé avant chaque configuration, déploiement ou import ; les changements réseau s'annulent seuls sans confirmation.
- **Sécurité** : chaîne d'approvisionnement vérifiée (signatures et empreintes), console sans privilège, application privilégiée séparée et contrôlée, pare-feu nftables, durcissement.

> État : version de développement **0.5.0**. Voir « Limites connues » ci-dessous avant tout usage en production.

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
tests/                   batteries shell b01..b08 (système, ISO, QEMU) ; webui/tests : vitest
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

## Limites connues

- Jamais exécuté sur **VMware réel**, **Docker Desktop réel** ni **PowerShell 5.1** ; l'interface web n'a pas été pilotée dans un navigateur automatisé.
- Le DDNS reçu par BIND est écrasé au déploiement suivant ; Kea 2.4 (Ubuntu 24.04) n'a pas GSS-TSIG (DDNS sécurisé vers l'AD : Kea 3.x).
- Certificat TLS de la console auto-signé ; pas de haute disponibilité ; pas de règles par client ni par expression régulière dans le filtrage.
- La découverte réseau lit l'ARP dans `/proc/net/arp` ; le ping dépend des réglages du système.

## Licence

**À définir** : aucun fichier `LICENSE` n'est fourni tant que le choix n'est pas fait ; sans licence, tous droits sont réservés. Composants tiers : [OPEN-SOURCE.md](OPEN-SOURCE.md).
