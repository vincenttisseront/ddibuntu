# Tests

| Où | Quoi | Prérequis |
|---|---|---|
| `tests/b01-statique.sh` | shellcheck, bash 3.2, schéma Subiquity, PowerShell, unités systemd | shellcheck, pwsh |
| `tests/b02-i18n.sh` | catalogues fr/en de la console texte | — |
| `tests/b03-apply.sh` | `ddibuntu-apply` hors ligne (réseau, pare-feu, idempotence, injections) | root |
| `tests/b04-pare-feu.sh` | trafic réel entre espaces de noms réseau | root, `ip netns` |
| `tests/b05-construction-iso.sh` | construction de l'ISO, vérifications de signature, mode dépôt | root, xorriso |
| `tests/b06-systeme-cible.sh` | chroot Ubuntu réel : PostgreSQL, console HTTPS, BIND, Kea, cockpit | root, chroot Ubuntu (`tools/make-chroot.sh`) |
| `tests/b07-demarrage.sh` | démarrage de l'ISO sous QEMU, BIOS et UEFI | qemu |
| `tests/b08-assistant.sh` | assistant dans un terminal (faux whiptail), clavier, logo, retour arrière | root, `script` |
| `tests/b10-*.sh` … `tests/b17-cluster-wizards-live.sh` | cluster : PKI, Patroni + etcd, Kea HA, BIND, Keepalived, Active Directory, quorum, assistants | root, démons réels (etcd, Patroni, PostgreSQL, Kea, BIND) |
| `tests/b18-backup-live.sh` | sauvegardes et restauration à un instant donné sur une vraie base PostgreSQL 16 (156 contrôles) | root, PostgreSQL 16 |
| `tests/b19-backup-cluster-live.sh` | sauvegardes et restauration dans un vrai cluster Patroni + etcd (76 contrôles) | root, PostgreSQL 16, Patroni, etcd |
| `tests/b20-health-live.sh` | santé de nœud : collecte réelle, partage par un vrai etcd, écritures et valeurs piégées refusées (50 contrôles) | root, etcd |
| `tests/b21-cluster-settings-live.sh` | réglages communs (adresse virtuelle, réseau), renouvellement des certificats, changement d'adresse des trois types de nœuds, retour arrière, verrou, demandes de la console, pare-feu et accusés lors d'un changement d'adresse (309 contrôles) | root, etcd, Patroni, PostgreSQL 16 |
| `webui/tests/unit-*.test.ts` | analyseurs, rendu, NetBox, découverte, AD, moteur d'alertes, client SMTP (sans base) | Node 22 |
| `webui/tests/e2e*.test.ts` | serveur construit + PostgreSQL + BIND/Kea réels | `tools/setup-test-db.sh`, `tools/build-console.sh` |

`tests/run-all.sh` rejoue toutes les batteries shell (et reconstruit le fichier unique avant, pour tester ce qui sera livré). Les fichiers e2e partagent une base : `tools/run-console-tests.sh e2e` les lance l'un après l'autre. Ne jamais lancer deux exécutions en parallèle.

Règles du banc : un test qui échoue est d'abord soupçonné d'être faux, puis vérifié ; jamais d'assouplissement sans explication ; chaque test remet à zéro l'état qu'il modifie ; données de test synthétiques uniquement.
