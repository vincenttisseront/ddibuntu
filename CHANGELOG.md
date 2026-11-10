# Journal des modifications

## 0.5.3 — itération 3 « Kea HA load-balancing »
- **Kea en haute disponibilité** (mode `load-balancing`, hooks `libdhcp_ha` + `libdhcp_lease_cmds`) dès qu'un cluster compte deux nœuds de données. Synchronisation des baux par un écouteur HTTP dédié de Kea (port 8000) en **TLS mutuel** avec les certificats du cluster, sur le réseau dédié.
- **Frontière de privilèges** : la console ne peut toujours pas déclarer de hook ; `ddibuntu-reload` (root) ajoute le bloc HA à partir de `cluster.conf`, exige les fichiers TLS, relit la configuration finale avec `kea-dhcp4 -t` et revient en arrière en cas d'échec. Rôles `primary`/`secondary` du hook déterminés par l'ordre des noms (identique sur les deux nœuds). Base de baux locale (fichier) en mode cluster ; le mot de passe de la base de baux n'est jamais copié.
- **Le secondaire suit la configuration** : migration 6 (`rendered_configs`, répliquée) alimentée à chaque déploiement ; `ddibuntu-cluster follow` (minuterie `ddibuntu-cluster-follow`, 1 min) vérifie l'empreinte, dépose le fichier et appelle `ddibuntu-reload --kea-only`. Sur le primaire, `follow` réapplique à l'arrivée du second nœud (le HA s'active sans nouveau déploiement).
- `ddibuntu-cluster status` : état HA de Kea (rôle, état local, état du partenaire, clients sans réponse) lu sur la socket de contrôle.
- Pare-feu : port 8000 ouvert aux seuls pairs du cluster. Utilisateur `_kea` ajouté au groupe `ddicluster` (lecture de la clé du nœud).
- Tests : `b11-kea-ha.sh` (injection, ordre des rôles, hostiles, retour arrière, vrai `kea-dhcp4 -t`) ; `b11-kea-ha-live.sh` (deux vrais Kea : load-balancing, TLS mutuel, 14 baux obtenus par de vrais échanges DHCP via un relais et retrouvés chez le partenaire, arrêt brutal du partenaire → `partner-down` → l'autre sert 10/10 nouveaux clients, retour → baux rattrapés) ; `b10-cluster-live.sh` étendu (`follow` sur un vrai Patroni : secondaire, primaire, empreinte altérée, hook injecté en base refusé).
- **Limites connues** : minuteries accélérées dans le test réel (production : 10 s / 60 s) ; pas de coupure réseau réelle entre machines ; les relais doivent lister les deux nœuds (le DHCP ne passe pas par la VIP) ; la console du secondaire ne suit pas encore le primaire (itération 5) ; DHCP en cluster = fichier de baux (les baux déjà en base PostgreSQL ne sont pas migrés).

## 0.5.2 — itération 2 « Fondations du cluster »
- **`ddibuntu-cluster`** (root) : `init`, `bundle`, `join`, `render`, `activate`, `status`, `switchover`. Un cluster = 2 nœuds de données (PostgreSQL conduit par **Patroni**) + 1 **arbitre** (etcd seul), sur le **réseau dédié**.
- **Quorum etcd (3 membres)** en TLS mutuel, écoute limitée à l'adresse du réseau dédié. Un nœud ajouté entre comme **learner** (sans voix) puis est promu votant une fois synchronisé : le quorum n'est jamais dégradé pendant l'enrôlement.
- **Autorité interne** (EC P-256) créée par `init` ; sa clé ne quitte jamais le premier nœud. Certificats de nœud (SAN = adresse du réseau dédié). La réplication PostgreSQL s'authentifie **par certificat client** (correspondance `pg_ident`), sans mot de passe de réplication ; l'API Patroni exige un certificat client.
- **Lot d'enrôlement chiffré** (OpenPGP AES-256, phrase de passe affichée une seule fois, empreintes SHA-256 vérifiées) : certificat et clé du nouveau nœud, configuration, et — pour un nœud de données — les secrets de la console qui doivent être identiques partout (`DDI_SECRET_KEY`…). Le contenu d'un lot est revalidé comme une entrée non fiable ; un lot ne peut pas créer d'autorité ; un nœud de données refuse de reprendre la base du cluster sans `--wipe-local-db`.
- Reprise d'une base existante : `init` adopte la base PostgreSQL de l'appliance (Patroni devient leader sur les données conservées).
- **Pare-feu** : nouvelle clé `CLUSTER_PEERS` ; 2379, 2380, 5432 et 8008 ne s'ouvrent qu'aux autres nœuds du cluster.
- **Console** : indicateur d'attente global (spinner + barre) sur toute écriture/déploiement/import/mise à jour dépassant 400 ms ; contrôle automatique qu'aucune boîte système (`confirm`/`alert`/`prompt`) n'est utilisée (les confirmations passent par la modale maison).
- Paquets embarqués : `patroni`, `etcd-server`, `etcd-client`, `python3-psycopg2`, `gnupg`, `openssl`, `curl`. etcd et Patroni restent **désactivés** tant que `ddibuntu-cluster` ne les active pas (le paquet etcd démarrerait sinon un magasin en clair).
- Tests : `b10-cluster.sh` (analyse stricte, lots hostiles, pare-feu) et `b10-cluster-live.sh` (3 nœuds simulés avec de vrais etcd/Patroni/PostgreSQL : enrôlement, réplication, bascule contrôlée, bascule automatique après arrêt brutal, réintégration, isolation sans quorum).
- **Registre des nœuds** dans etcd + minuterie `ddibuntu-cluster-sync` (chaque minute) : chaque nœud apprend les autres, met à jour Patroni et ouvre son pare-feu à leur adresse ; commande `sync`.
- Résultat des tests : `b10-cluster.sh` 73/73 ; `b10-cluster-live.sh` 81/81 (vrais etcd/Patroni/PostgreSQL sur 3 nœuds simulés). Console : build OK, 259 tests passent ; les 15 échecs restants sont ceux du banc sans `named`/`kea` (identiques à 0.5.1).
- **Limites connues** : pas encore de page « Cluster » dans la console (état via `ddibuntu-cluster status`) ; la console, BIND et Kea ne suivent pas encore le primaire (itérations 3 à 5) ; une installation existante doit recevoir les paquets ci-dessus (la mise à jour en ligne ne les installe pas) ; test de panne réelle sur machines non réalisé.

## 0.5.1 — itération 1 « Smart DDI »
- **Génération de configuration** : compteur monotone tenu par des déclencheurs en base (zones, enregistrements, étendues, pools, réservations DHCP, règles et listes de filtrage, réglages DNS/DHCP). Les numéros de série de zone et l'inventaire IPAM seul ne l'incrémentent pas. Chaque déploiement enregistre la génération rendue ; le tableau de bord affiche « déployée / à déployer » ; API `GET /api/system/config-generation`. Base de la détection d'écart entre nœuds du futur cluster.
- **Réservation DHCP pilotée par l'IPAM** : une adresse au statut « Réservation DHCP » avec MAC crée, met à jour ou retire sa réservation Kea dans la **même transaction** ; supprimer l'adresse supprime la réservation (clé étrangère en cascade) ; supprimer la réservation côté DHCP redonne le statut « utilisée ». Les réservations existantes sont rattachées à leur adresse par la migration. Retour explicite (`dhcp: created|updated|removed|no_mac|no_scope`).
- **Gabarits de réseau** : étendue DHCP créée avec le réseau (durée de bail, options DNS/domaine/NTP, routeur = passerelle), zone DNS des hôtes (A/AAAA + PTR automatiques à l'allocation, ou refusés explicitement avec `dns_zone_id: null`), règle de nommage par motif simple (`#` chiffre, `?` caractère, `*` suite) — volontairement pas d'expression régulière saisie (pas de ReDoS). Onglet « Gabarits » ; champ « Gabarit » sur les réseaux.
- **Santé honnête** : `/api/health` répond 503 tant que les migrations ne sont pas terminées (la vérification de santé de la mise à jour en ligne et les tests ne peuvent plus conclure trop tôt).
- Document d'architecture du cluster validé : `docs/ARCHITECTURE-CLUSTER.md`.

## 0.5.0
- **IPAM multi-espaces** : table des espaces (le même plan d'adressage peut exister dans plusieurs espaces, façon VRF). L'existant migre dans l'espace « Défaut » ; l'unicité du CIDR devient « par espace » (migration 4).
- **Hiérarchie** : conteneurs (regroupent des réseaux, sans adresses) et réseaux imbriqués, parent déduit de l'inclusion des préfixes dans l'espace ; agrégats par conteneur (taille, % alloué, % d'IP utilisées sur tous les descendants).
- **Pools d'adresses** : plages nommées dans un réseau (sans chevauchement, contenues dans le réseau, contrôlé en base), taux d'utilisation, « prochaine IP libre » dans un pool donné.
- **Nouvelle page IPAM** : onglets Espaces / Réseaux / Pools / Adresses ; tableau dense (filtre par colonne, tri, sélection multiple, arborescence repliable, compteur de résultats, export CSV de la vue), sélecteur d'espace et boutons IPv4/IPv6, actions groupées (déplacer vers un espace, supprimer). Vue « toutes les adresses » transverse avec pagination côté serveur.
- Points de restauration : espaces et pools inclus (les points antérieurs à la 0.5.0 restent consultables mais ne sont pas restaurables : schéma différent).
- Garde-fou : une étendue DHCP ne se crée que sur un réseau de l'espace par défaut (Kea ne distingue pas les espaces) et jamais sur un conteneur.
- Feuille de route : `docs/ROADMAP.md`.

## 0.4.2
- Mises à jour en ligne : la recherche distingue « aucune release publiée sur le dépôt » (HTTP 404), « accès refusé / limite de débit » et une vraie panne réseau ; auparavant tout s'affichait « Impossible de joindre GitHub ».
- `make-iso.ps1 -BundleOnly` : produit seulement l'archive de mise à jour signée (sans reconstruire l'ISO).

## 0.4.1
- **Mises à jour en ligne** : onglet « Mises à jour » de la console (administrateurs) : détection quotidienne et manuelle des nouvelles versions publiées sur GitHub, notes de version, installation sur clic. Un service root (`ddibuntu-selfupdate`) vérifie la signature Ed25519 (clé publique épinglée) et la somme SHA-256, sauvegarde la base (pg_dump) et les fichiers remplacés, remplace la console, et **revient en arrière** si elle ne redémarre pas. Publication : tag `vX.Y.Z` → workflow `release.yml` (archive + fichier unique + signature).
- **Affichage** : version et nom d'hôte dans la barre latérale, pastille « MàJ » sur Système, carte « Système » du tableau de bord (version, disponibilité, mémoire, disque, charge, dernière application DNS/DHCP) et bandeau de mise à jour disponible.
- **Mode mise à jour** (par l'ISO) : nouvelle entrée « Update an existing DDI-Buntu installation… » dans le menu de l'ISO. Elle met à niveau une installation existante (console, Node, fichiers de l'appliance, paquets plus récents) **sans effacer le disque** ni toucher aux données (PostgreSQL, `/etc/ddibuntu`, certificat, comptes, réseau). Sauvegarde des fichiers remplacés, refus d'une ISO plus ancienne, arrêt de la machine à la fin.

## 0.4.0
- Console texte : la disposition du clavier est appliquée **tout de suite** puis vérifiée par une saisie de test (le mot de passe n'est plus saisi avec la mauvaise disposition) ; logo ; points de restauration système (`ddibuntu-rollback`) avec retour arrière automatique après N secondes sans confirmation.
- Console web : points de restauration des données (avant chaque déploiement et chaque import), aperçu et restauration atomique ; résultat réel du rechargement BIND/Kea.
- IPAM : import NetBox, import Active Directory en direct (LDAP + transfert de zone), découverte réseau.
- Cockpit de filtrage DNS à la Pi-hole : journal des requêtes, tableau de bord, liste blanche/noire en un clic, pause du blocage, conservation et anonymisation.
- BIND : `querylog yes` et catégorie `rpz-passthru` (sans eux, aucune requête n'était journalisée) ; `ddibuntu-reload` fait relire l'ancienne configuration après un retour arrière.
- Dépôt : `build-ddibuntu.sh` à la racine (mode dépôt) ; `tools/make-single.sh` produit le fichier unique avec le même code.

## 0.3.x
- Construction de l'ISO depuis macOS (Docker, conteneur amd64 forcé), proxys d'entreprise (`--ca-from-keychain`, `--ca-cert`, `--insecure-tls`), sélection de l'ISO Ubuntu la plus récente parmi celles du fichier de sommes signé, `open-vm-tools`.

## 0.2.0
- Console web (Nuxt 4) : IPAM, DNS, DHCP, filtrage RPZ, imports Windows, utilisateurs, audit.

## 0.1.0
- Socle : script de construction, ISO hybride BIOS/UEFI, installation automatique, assistant, pare-feu.
