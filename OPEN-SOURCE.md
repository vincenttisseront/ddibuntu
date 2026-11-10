# Composants libres

Liste **indicative** à vérifier avant publication (`npm ls`, `apt-cache show`). Les versions des dépendances JavaScript sont épinglées dans `webui/package-lock.json` ; celles des paquets Ubuntu sont celles de la 24.04 au moment de la construction.

| Composant | Rôle | Licence |
|---|---|---|
| Ubuntu Server 24.04 LTS | système de base de l'ISO | paquets sous licences diverses |
| PostgreSQL 16 | base de données | PostgreSQL License |
| BIND 9.18 | DNS (zones, RPZ) | MPL-2.0 |
| Kea 2.4 | DHCP | MPL-2.0 |
| nftables | pare-feu | GPL-2.0-only |
| newt / whiptail | assistant et menu en console | LGPL-2.0 |
| open-vm-tools | intégration VMware | LGPL-2.1 |
| Node.js 22 | exécution de la console web | MIT |
| Nuxt, Vue, Nitro | console web | MIT |
| Nuxt UI, Tailwind CSS | interface | MIT |
| pg, zod, ldapts, fast-xml-parser | serveur de la console | MIT |
| Fira Sans / Fira Code | polices embarquées (hors ligne) | SIL OFL 1.1 |

Le dépôt lui-même n'a **pas encore de licence** (voir README).
