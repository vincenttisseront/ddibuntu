# Architecture du mode cluster (décisions validées)

Statut : **validée** (itération 0). Aucune ligne de code de cluster n'existe encore ; ce document fixe ce que les itérations 2 à 5 réalisent.

## Décisions
| # | Décision | Choix validé |
|---|---|---|
| 1 | Bascule | **Automatique**, avec un **3e nœud arbitre** (quorum) |
| 2 | Ordre des travaux | Cluster **avant** l'interopérabilité AD |
| 3 | Laboratoire | Pas de machines de test pour l'instant : seuls la validation des configurations et les tests en conteneurs/espaces de noms sont garantis ; le comportement en panne réelle reste à éprouver |
| 4 | Réseau | Un **réseau dédié** à la réplication PostgreSQL et à la synchronisation HA de Kea (séparé du réseau de service) |

## Topologie
```
        clients DNS · relais DHCP · administrateurs
                        │  réseau de service
        VIP de service (Keepalived, suit le nœud ACTIF)
           │                                │
 ┌─────────┴──────────┐          ┌──────────┴─────────┐        ┌───────────────┐
 │ Nœud 1 — ACTIF     │          │ Nœud 2 — SECONDAIRE│        │ Nœud 3 ARBITRE│
 │ Console Nuxt (rw)  │          │ Console (lecture)  │        │ pas de données│
 │ PostgreSQL primaire├─ WAL ───►│ PostgreSQL standby │        │ DCS (quorum)  │
 │ BIND primaire      ├─ AXFR ──►│ BIND secondaire    │        │ Keepalived    │
 │ Kea ◄── HA load-balancing ──► │ Kea                │        │  (témoin)     │
 └─────────┬──────────┘          └──────────┬─────────┘        └───────┬───────┘
           └──────── réseau dédié : réplication, HA Kea, quorum ───────┘
```

## Principes
- **Source de vérité** : PostgreSQL. Le nœud ACTIF est le primaire de la base ; tout rôle (console en écriture, BIND primaire, VIP) suit ce primaire. Un seul « actif » : pas de rôles partagés entre nœuds.
- **Quorum et anti split-brain** : la promotion automatique exige l'accord de 2 nœuds sur 3. Un nœud isolé du quorum se met lui-même en lecture seule (isolation par le nœud lui-même : arrêt des services en écriture, VIP retirée). Candidat retenu pour le magasin de quorum : etcd sur les trois nœuds, avec orchestration de la bascule PostgreSQL par un composant dédié (à trancher à l'itération 2 après prototype).
- **Baux DHCP** : pas dans la base répliquée. Chaque Kea garde ses baux localement ; le hook HA (`libdhcp_ha`, mode load-balancing, avec `libdhcp_lease_cmds`) les synchronise sur le réseau dédié, par un **écouteur HTTP dédié** de Kea (port 8000) en **TLS mutuel** avec les certificats du cluster — pas d'agent de contrôle, donc pas de service de plus à exposer. Les deux serveurs sont en `load-balancing` : chacun répond à sa moitié des clients (hachage), et si l'un tombe (`partner-down`) l'autre sert tout le monde ; au retour du partenaire, les baux accordés entre-temps sont rattrapés avant de reprendre.
- **DHCP et VIP** : le DHCP ne passe pas par la VIP. Les relais DHCP déclarent les deux adresses réelles des nœuds. La VIP sert la console, l'API et le point d'entrée DDNS.
- **DNS** : le nœud actif est BIND primaire (zones, DDNS, RPZ). L'autre est secondaire (AXFR/IXFR signé TSIG sur le réseau dédié, NOTIFY). Les deux répondent aux requêtes des clients. À la bascule, le secondaire est promu primaire ; le numéro de série ne baisse jamais.
- **Configuration identique** : les deux Kea doivent avoir les mêmes sous-réseaux et pools (exigence du hook HA). Chaque nœud rend sa configuration depuis la base répliquée ; la **génération de configuration** (itération 1) permet de vérifier que les deux nœuds ont appliqué la même.
- **Secrets et PKI** : une autorité interne émet les certificats des nœuds (PostgreSQL en `verify-full`, Kea HA, API inter-nœuds). Enrôlement d'un nœud par jeton à usage unique.
- **Pare-feu** : nftables n'ouvre 5432, le port de contrôle Kea, le transfert DNS, le quorum et VRRP qu'aux pairs, sur le réseau dédié.
- **Mises à jour** : progressives (secondaire, puis bascule contrôlée, puis ancien actif) ; les nœuds doivent être à la même version.

## Écarts assumés par rapport au cahier des charges
1. **Atomicité** : aucune transaction ne couvre PostgreSQL et deux démons. Garantie réelle : écriture atomique en base (IPAM + DNS + réservation DHCP dans une transaction) ; application convergente avec **génération de configuration**, validation avant déploiement, retour arrière, détection d'écart entre nœuds.
2. **GSS-TSIG** : le hook GSS-TSIG de Kea n'existe pas dans Kea 2.4 (Ubuntu 24.04), vérifié (`libdhcp_*` du paquet : ni `gss_tsig`). Repli retenu à l'itération 6 : BIND authentifie lui-même les clients du domaine (`update-policy` `ms-self` / `krb5-self`). L'envoi des enregistrements de l'appliance vers les contrôleurs AD par `nsupdate -g` reste à écrire.
3. **Test de panne** : sans laboratoire, la bascule réelle n'est pas démontrée ; chaque itération livre ses procédures de test pour le premier labo.

## Itérations
| # | Contenu |
|---|---|
| 1 | Smart DDI : génération de configuration, réservation DHCP pilotée par l'IPAM, gabarits de réseau |
| 2 | Fondations : PKI interne, enrôlement, réplication PostgreSQL, quorum, état du cluster |
| 3 | Kea HA load-balancing (**fait**, 0.5.3 — voir ci-dessous) |
| 4 | BIND primaire/secondaire, distribution du RPZ, Keepalived (**fait**, 0.5.4 — voir ci-dessous) |
| 5 | La console, BIND et Kea suivent le leader ; bascule depuis la console ; mise à jour progressive (**fait**, 0.5.5 — voir ci-dessous) |
| 6 | Active Directory : Kerberos, GSS-TSIG, redirecteurs conditionnels (**fait**, 0.5.6 — voir ci-dessous) |
| 7 | Le keytab et le domaine Kerberos suivent le cluster (**fait**, 0.6.1 — voir « Itération 7 ») |

## Itération 3 — Kea HA : comment c'est réalisé
- **La console ne déclare jamais de hook.** Le bloc `hooks-libraries` donne l'exécution de code à Kea (root) : `ddibuntu-reload` (root) refuse tout `hooks-libraries` venant de la console et **ajoute lui-même** le bloc HA à partir de `/etc/ddibuntu-cluster/cluster.conf` (fichier root). Il le fait seulement sur un nœud de **données** quand **deux** nœuds de données existent ; un arbitre ou un nœud seul reste en Kea simple. Les bibliothèques sont cherchées dans les dossiers de Kea (jamais un chemin venu d'ailleurs), les certificats doivent exister, et la configuration **finale** est relue par `kea-dhcp4 -t` avant tout rechargement ; échec → retour arrière.
- **Rôles déterministes** : les deux nœuds de données sont triés par nom ; le premier est `primary` du hook, le second `secondary`. Même résultat sur les deux nœuds quel que soit l'ordre de `PEERS`. Ce rôle HA n'a rien à voir avec le primaire PostgreSQL : un nœud qui perd la base reste un serveur DHCP à part entière.
- **Baux** : en mode cluster, base de baux = fichier local (`/var/lib/kea/kea-leases4.csv`), synchronisé par le hook. La base PostgreSQL de baux n'est pas utilisée (elle est en lecture seule sur le secondaire). Le mot de passe de la base de baux n'est jamais copié dans la configuration partagée.
- **Même configuration sur les deux nœuds** : à chaque déploiement, la console enregistre la configuration Kea (sans mot de passe) dans la table répliquée `rendered_configs` avec sa génération et son empreinte SHA-256. Sur le **secondaire**, `ddibuntu-cluster follow` (minuterie d'une minute) lit cette ligne dans sa copie locale de la base, vérifie l'empreinte, dépose le fichier et appelle `ddibuntu-reload --kea-only` (mêmes contrôles qu'en local ; une base compromise ne peut donc pas faire charger un hook). Sur le **primaire**, `follow` réapplique quand la liste des nœuds de données change (arrivée du second nœud) : le HA s'active sans nouveau déploiement.
- **Pare-feu** : le port 8000 n'est ouvert qu'aux pairs du cluster (`CLUSTER_PEERS`). Les relais DHCP doivent lister **les deux adresses réelles** des nœuds de données.
- **Délais de production** : `heartbeat-delay` 10 s, `max-response-delay` 60 s, `max-ack-delay` 5 s, `max-unacked-clients` 5. Le serveur restant ne prend les clients du partenaire qu'après avoir constaté des clients sans réponse (champ `secs` > `max-ack-delay`) : sans trafic client, l'état reste `communication-recovery`.
- **À vérifier au premier laboratoire** : coupure réseau réelle entre deux machines, minuteries de production, relais réels, charge. Limite connue : tant que la console ne suit pas le primaire (itération 5), un déploiement lancé depuis le secondaire échoue à l'écriture en base.

## Itération 4 — BIND et adresse virtuelle : comment c'est réalisé
- **La console ne connaît pas le cluster.** Elle écrit une configuration BIND ordinaire (`allow-transfer { none; }` global). `ddibuntu-reload` (root) lit `named.conf.options` et `named.conf.zones` de façon **stricte** (formats exacts produits par `render.ts`) et refuse toute ligne inattendue : une base compromise ne peut pas ouvrir un transfert ni charger une clé.
- **Secondaire dérivé, jamais copié** : sur le nœud qui suit (`--replica`), chaque zone primaire devient une zone `secondary` dont le `primaries` est le pair du réseau dédié, signé par la clé `ddi-xfr`. Les fichiers de zone ne sont **pas** copiés : BIND les transfère (AXFR, puis IXFR après chaque mise à jour, y compris le DDNS). La copie locale périmée du dossier généré est supprimée à chaque passage.
- **Primaire** : `allow-transfer { key "ddi-xfr"; }` (en plus d'une ACL propre à la zone), `also-notify` vers le pair, `notify-source`/`transfer-source`/`listen-on` sur l'adresse du réseau dédié, `server PAIR { keys "ddi-xfr"; }`.
- **RPZ** : zone ordinaire transférée ; le secondaire applique donc les mêmes listes que le primaire sans mécanisme particulier.
- **Clé TSIG** : créée par le nœud autorité (`init`, ou premier `follow` d'un cluster plus ancien), embarquée dans le lot d'enrôlement, validée sur sa forme exacte avant installation (`root:bind 0640`).
- **IP virtuelle** : Keepalived (VRRP unicast sur le réseau dédié). Le script `vip-check` interroge l'API Patroni `/primary` en TLS mutuel : seul le leader PostgreSQL garde l'adresse. Sans leader, personne ne la porte (mieux vaut ne pas répondre que répondre depuis une base en lecture seule). Aucun Keepalived sur l'arbitre ; protocole 112 ouvert aux seuls pairs.
- **Différé à l'itération 5** : promotion du BIND secondaire (changement de rôle quand le leader change), console et Kea qui suivent le primaire, page « Cluster ». Tant que le leader ne change pas, le comportement est complet ; après une bascule, le DNS reste servi par les deux nœuds mais les modifications de zones doivent attendre l'itération 5.
- **À vérifier au premier laboratoire** : coupure réseau réelle, comportement de VRRP sur un vrai commutateur, charge des transferts, zones dynamiques (`rndc reload` ne les relit pas).

## Itération 5 — suivre le leader : comment c'est réalisé
- **Une seule source de vérité : Patroni.** Le leader de la base est aussi le nœud qui sert les écritures de la console, le BIND primaire et la VIP. `ddibuntu-cluster follow` (1 min) lit le rôle Patroni local et aligne le reste ; Keepalived déplace la VIP sans attendre (il interroge Patroni toutes les quelques secondes).
- **Promotion BIND (`ddibuntu-reload --promote`)** : la configuration `named.conf.*` répliquée est retransformée en primaire (même code que le déploiement). Les fichiers de zone, eux, sont ceux que le nœud a reçus par transfert : BIND les stocke en binaire avec un journal, `named-compilezone -j -f raw -F text` les convertit en texte avec le journal appliqué (les noms créés par DDNS avant la panne sont conservés), le journal devenu incohérent est supprimé. Tout est contrôlé **avant** la première modification ; un échec laisse le nœud secondaire.
- **Retour d'un ancien primaire** : `--replica` après un rôle `primary` supprime ses fichiers de zone et journaux : un transfert complet depuis le nouveau primaire remplace tout (une copie « plus récente » ne serait jamais écrasée, BIND la jugeant à jour).
- **Console** : `pg_is_in_recovery()` décide. Secondaire = lecture seule : les requêtes qui écrivent sont refusées par un 503 `replica` **avant** tout effet de bord (déploiement de fichiers compris), les sessions (répliquées) restent lisibles, aucune migration n'est tentée (elles viennent du leader), les tâches de fond qui écrivent sont suspendues. Promu, le nœud reprend l'écriture en quelques secondes.
- **Demande de bascule** : la console dépose un fichier d'une ligne (nom de nœud) dans le seul dossier qui lui est ouvert en écriture ; root le relit comme un simple nom, le vérifie contre `cluster.conf` et l'état réel de Patroni (candidat = secondaire de données en bonne santé, pas le leader), exécute `patronictl switchover` et publie un résultat à message fixe.
- **Mise à jour progressive** : chaque nœud publie sa version dans etcd. Le leader n'accepte la mise à jour en ligne que lorsque les secondaires sains sont déjà à la version visée : on met à jour les secondaires, on bascule, puis on met à jour l'ancien leader. Un secondaire sur le nouveau logiciel mais l'ancien schéma annonce `waiting_leader` (l'installation n'est pas annulée), répond `schema_pending` et attend les migrations du leader.
- **Isolation** (déjà éprouvée à l'itération 2 pour la base) : un leader sans quorum devient inutilisable en écriture ; sa VIP disparaît (vip-check) ; DNS et DHCP continuent de répondre (Kea HA, BIND secondaire).
- **À vérifier au premier laboratoire** : coupure réseau réelle, durée de la fenêtre de rétrogradation (≤ 1 min), bascule sous charge DHCP, grandes zones.

## Itération 6 — Active Directory : comment c'est réalisé
- **Deux rôles distincts.** (1) *Recevoir* : BIND de l'appliance accepte les mises à jour GSS-TSIG des machines du domaine. (2) *Résoudre* : les requêtes du domaine AD sont renvoyées à ses contrôleurs par des redirecteurs conditionnels (zone `forward only`, `ad_integrated`). L'*envoi* des baux vers les contrôleurs AD en GSS-TSIG n'est pas fait.
- **Qui détient quoi.** Le domaine Kerberos et le keytab appartiennent à **root** (`ddibuntu-ad` : `/etc/ddibuntu-ad/ad.conf`, `/etc/bind/krb5.keytab`). La console propose des octrois `update-policy` par zone ; `ddibuntu-reload` les **relit et les recompose** à partir du domaine de root (jamais celui de la console), refuse tout ce qui sort de la grammaire (trois formes seulement : `grant ddi-ddns zonesub ANY`, `grant REALM ms-self . A AAAA`, `grant REALM krb5-self . A AAAA`) et ajoute `tkey-gssapi-keytab`. `tkey-*` est une directive interdite venant de la console. Le rendu de la console lit le domaine dans `/run/ddibuntu/ad-status.json` (publié par root) : il ne peut pas diverger de ce que root acceptera.
- **Demandes de la console.** Même schéma que la bascule : `.ad-request` (JSON ≤ 4 Kio) + `.ad-keytab` (0600, secret) déposés dans le seul dossier ouvert à la console ; l'unité `ddibuntu-ad-request.path` lance `ddibuntu-ad request`, qui revalide tout, **supprime le keytab déposé même refusé**, relance `ddibuntu-reload` (sauf sur un secondaire) et publie `ad-result.json`. Une demande à la fois (409 `request_pending`). Le secret passe brièvement par le processus de la console (comme un mot de passe saisi dans un formulaire) ; la voie en ligne de commande (`ddibuntu-ad install-keytab`) l'évite.
- **Politiques et cluster.** Un secondaire ne retient aucun octroi (il n'accepte pas de mises à jour). À la promotion, le nouveau primaire applique les politiques avec **son propre** domaine et **son propre** keytab ; s'il n'en a pas, il retire les octrois Kerberos (avec avertissement) plutôt que de refuser la promotion : un défaut de configuration AD ne doit jamais empêcher une bascule. Depuis la 0.6.1, le keytab **est répliqué** entre les nœuds de données (voir « Itération 7 ») : on l'installe une fois, sur le leader ; son principal doit être `DNS/<nom que les clients résolvent>` (le nom de l'adresse de service).
- **Règles apprises à l'essai (KDC MIT, `named` 9.18).** `ms-self` lit `PC1$@CORP.LOCAL` comme le nom `pc1.corp.local` : il n'agit que dans la zone portant le nom du domaine ; `krb5-self` compare l'instance du principal (`host/pc1.corp.local`) au nom mis à jour. `update-policy` exclut `allow-update` : la clé DDNS de Kea devient donc un octroi de la politique. Le keytab doit se trouver dans `/etc/bind/` (profil AppArmor de `named`). `klist` marque RC4 « DEPRECATED » : accepté (anciens domaines), DES/3DES refusés.
- **À vérifier au premier laboratoire avec un vrai AD** : keytab produit par `ktpass` (type de chiffrement, `-mapuser`), négociation GSS-TSIG des clients Windows, mises à jour de PTR, interaction avec les zones intégrées à l'AD, cluster avec le même principal sur les deux nœuds (SPN dupliqué dans l'AD ?).

## Itération 7 — le keytab suit le cluster : comment c'est réalisé
- **Où vit l'état.** Dans etcd, clé `/ddibuntu-cluster/ad/state`, sous la forme `{"v":1,"sha":"<sha256 de l'état>","blob":"<état chiffré, base64>"}`. L'état clair est le JSON canonique `{"kdcs":[…],"keytab":"<base64>","realm":"…"}` produit par `ddibuntu-ad export-state` (`{}` = rien de configuré ; le retrait est publié avec `sha":"none"`).
- **Confidentialité.** Chiffrement symétrique gpg (AES-256, MDC) ; la phrase de passe est dérivée par HMAC-SHA256 de la clé de transfert de zone `ddi-xfr` avec l'étiquette `ddibuntu-ad-keytab-v1`. Seuls les nœuds de données ont cette clé : l'**arbitre, qui héberge etcd, ne peut rien déchiffrer**. etcd n'est joignable qu'en TLS mutuel. La phrase de passe transite par l'environnement et un descripteur de fichier, jamais par une ligne de commande ; les fichiers temporaires (dossier 0700) sont effacés (`shred`) à la sortie.
- **Qui applique quoi.** `ddibuntu-cluster ad-sync` (appelé au début de chaque `follow`, donc chaque minute, et par `ddibuntu-ad request` après toute modification) compare l'état local (L), celui d'etcd (E) et le dernier synchronisé (S, fichier local) : L = E → rien ; L ≠ S → publication ; sinon application de E ; S inconnu → E gagne s'il existe, sinon publication. Verrou `flock` contre les exécutions simultanées.
- **Application sûre.** `ddibuntu-ad import-state` lit strictement l'entrée, valide le domaine, les KDC et le keytab (mêmes contrôles que l'installation locale, avec le domaine **annoncé**) avant tout changement, puis configure, installe et relance BIND comme pour une demande de la console. Un état refusé ne modifie rien et n'est jamais republié : la valeur d'etcd est écrasée seulement par une modification locale légitime.
- **Bascule.** `ad-sync` s'exécute avant l'alignement de rôle de `follow` : à la promotion, le nouveau primaire a déjà le keytab (si le cluster en avait un depuis plus d'une minute).
- **État pour la console.** `/run/ddibuntu/ad-sync.json` (`synced`, `published`, `applied`, `failed` + motif, sans secret), affiché sur la page « Active Directory ».
- **À vérifier au premier laboratoire** : coupure réseau réelle pendant une publication, deux administrateurs modifiant l'AD pendant une partition, principal `DNS/…` identique sur les deux nœuds avec un vrai AD.
