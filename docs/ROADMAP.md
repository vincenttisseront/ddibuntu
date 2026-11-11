# Feuille de route

Référence : forces fonctionnelles d'une plate-forme DDI du marché (EfficientIP SOLIDserver) à émuler, rapprochées de l'état réel de DDI-Buntu.
Légende : ✅ fait · 🟡 partiel · ⬜ à faire.

## 1. Modèle unifié et cohérence
| Capacité | État | Détail |
|---|---|---|
| Espaces IP qui se chevauchent | ✅ 0.5.0 | Espaces, CIDR unique par espace. Limite : DHCP/Kea limité à l'espace par défaut. |
| Orchestration IPAM → DNS | 🟡 | A/AAAA + PTR créés à l'allocation d'une adresse (transaction unique). |
| Orchestration IPAM → DHCP | ✅ 0.5.1 | Réservation créée/maj/retirée dans la même transaction que l'adresse. |
| Gabarits (templates) de réseau | ✅ 0.5.1 | Étendue DHCP, options, zone DNS des hôtes, règle de nommage appliquées à la création. |
| Hiérarchie conteneurs / réseaux / pools | ✅ 0.5.0 | |

## 2. DHCP et DNS
| Capacité | État | Détail |
|---|---|---|
| Démons autonomes (Kea, BIND) pilotés par la console | ✅ | Déploiement validé avec retour arrière. |
| Haute disponibilité DHCP (Kea HA, actif/actif ou actif/passif) | ⬜ | Suppose deux appliances : jumelage, état de synchronisation dans la console. |
| Vues DNS (réponses selon l'IP source) | ⬜ | Zones rattachées à une vue (`view` BIND + ACL de clients). |
| DHCP multi-espaces | ⬜ | Une instance Kea par espace, ou refus de chevauchement. |

## 3. Sécurité
| Capacité | État | Détail |
|---|---|---|
| Filtrage par listes / RPZ | ✅ | Cockpit de filtrage, journal des requêtes. |
| Limitation de débit des requêtes (RRL) | ✅ 0.7.0 | BIND `rate-limit` (réponses/s, fenêtre, slip, clients exemptés), page DNS › Paramètres ; désactivé par défaut, « journaliser seulement » activé par défaut pour observer avant de bloquer. |
| Détection d'exfiltration / tunnel DNS | ✅ 0.7.0 | Heuristique sur le journal : nombre de sous-noms distincts, longueur, entropie des étiquettes longues, part TXT/NULL/CNAME, par client et domaine. Bloquer ou autoriser en un clic (règle de filtrage). Pas d'alerte automatique (0.8). |
| Hygiène IPAM : adresses fantômes | ✅ 0.7.0 | Onglet « Fantômes » : allouées, déjà vues par une découverte, muettes depuis N jours ; libération en masse (critère revérifié côté serveur). Pas d'alerte automatique, ni de découverte planifiée (0.8). |

## 4. Exploitation
| Capacité | État | Détail |
|---|---|---|
| Vue graphique d'un réseau (grille libre/occupé) | ✅ 0.6.0 | Grille par réseau IPv4 (jusqu'au /16), clic → l'adresse (filtre) ou sa création si libre. |
| Navigation latérale par module + recherche globale | ✅ 0.6.0 | Groupes Réseau / Sécurité / Exploitation, `Ctrl+K` (IP, CIDR, MAC, noms), liens profonds. Hors recherche : baux Kea, journal DNS. |
| Traçabilité bail ↔ MAC ↔ nom ↔ utilisateur AD | ⬜ | Corrélation baux Kea, DNS dynamique et ouvertures de session AD. |
| API REST complète et documentée | 🟡 | Toute l'interface passe par l'API ; il manque la description OpenAPI publiée et les jetons d'API (hors session). |
| Mises à jour en ligne signées | ✅ 0.4.1 | |

## Cluster (décisions validées : voir `ARCHITECTURE-CLUSTER.md`)
| Itération | État |
|---|---|
| 1 Smart DDI (génération de configuration, réservation pilotée par l'IPAM, gabarits) | ✅ 0.5.1 |
| 2 Fondations : autorité interne, enrôlement, réplication PostgreSQL (Patroni + etcd, arbitre), état | ✅ 0.5.2 (testé avec de vrais démons sur boucle locale ; pas de page console) |
| 3 Kea HA load-balancing : bloc HA injecté par root, secondaire qui suit la configuration par la base, TLS mutuel | ✅ 0.5.3 (testé avec deux vrais Kea et de vrais échanges DHCP sur boucle locale) |
| 4 BIND primaire/secondaire (transferts TSIG), distribution RPZ, Keepalived (VIP qui suit le leader Patroni) | ✅ 0.5.4 (deux vrais `named` et un vrai Keepalived sur boucle locale / espaces de noms ; promotion du BIND secondaire → itération 5) |
| 5 BIND promu au changement de leader, console qui suit (secondaire en lecture seule), bascule depuis la console, mise à jour progressive, page « Cluster » | ✅ 0.5.5 (vrais Patroni, vrais `named`, vraies consoles ; pas de coupure réseau réelle) |
| 6 Active Directory : Kerberos, GSS-TSIG (mises à jour sécurisées reçues par BIND), redirecteurs conditionnels | ✅ 0.5.6 (keytab répliqué dans le cluster : ✅ 0.6.1, voir ci-dessous) (vrai KDC MIT et vrai `named` ; pas d'Active Directory réel ; envoi DHCP → AD en GSS-TSIG non fait) |

| 7 Keytab et domaine Kerberos répliqués entre les nœuds de données (chiffrés dans etcd, arbitre aveugle) | ✅ 0.6.1 (trois vrais etcd ; pas d'AD réel) |

Constat à traiter : `rndc reload` ne relit pas le fichier d'une zone dynamique (`allow-update`) ; un déploiement qui modifie une telle zone doit passer par `rndc freeze`/`thaw` (qui fige les noms dynamiques) ou par un ajout via `nsupdate`. À arbitrer avec l'itération 5.

Ces itérations priment sur l'ordre ci-dessous, qui ne concerne que les fonctions hors cluster.

**Règles d'interface permanentes** (demande du 2026-11-10) : toute action un peu longue affiche un indicateur d'attente ; aucune boîte système (`confirm`/`alert`/`prompt`) — uniquement des modales du design de la console. Contrôlé par `tests/b10-cluster.sh`.

## Ordre proposé
1. ~~**0.6.0** — Navigation latérale, recherche globale, grille d'occupation d'un réseau.~~ ✅ fait
2. ~~**0.7.0**~~ ✅ fait — Hygiène IPAM (adresses fantômes), RRL, détection de tunnel DNS (les gabarits de réseau et la réservation DHCP automatique étaient déjà livrés en 0.5.1).
3. ~~**0.8.0**~~ ✅ fait — Exploitation du cluster : quorum en direct, retrait de nœud perdu, reprise après perte du quorum, séquestre de l'autorité.
3b. ~~**0.8.1**~~ ✅ fait — Assistants « Créer le cluster », « Ajouter un nœud » (lot d'enrôlement) et « Rejoindre un cluster » dans la console.
3c. **Série 0.9.x** — dix évolutions, une version chacune, chacune testée en conditions réelles avant publication :
    1. ~~**0.9.0**~~ ✅ fait — Sauvegarde et restauration à un instant donné (PITR), cluster compris.
    2. ~~**0.9.1**~~ ✅ fait — Alertes et supervision : exportateur Prometheus `/api/metrics`, e-mail, webhook, mise en silence, santé de chaque nœud partagée par etcd, tableau de bord évolué (les alertes « fantômes » et « tunnels » rejoignent l'itération 7).
    3. ~~**0.9.2**~~ ✅ fait — Remplacement d'adresse virtuelle / de réseau dédié, changement d'adresse d'un nœud, renouvellement des certificats (automatique, sans interruption), verrou de nœud.
    4. ~~**0.9.3**~~ ✅ fait — Test de bascule guidé avec rapport : pré-contrôles, vraie bascule mesurée (fenêtre sans primaire, promotion, réintégration, rattrapage, ligne de temps, continuité WAL), retour au primaire d'origine, rapports conservés dans etcd, refus des opérations de topologie pendant le test.
    4b. ~~**0.9.4**~~ ✅ fait — Correctif intercalaire : source NetBox (le test ne déconnecte plus, motif du refus affiché, jeton nettoyé).
    4c. ~~**0.9.5**~~ ✅ fait — Correctif intercalaire : les assistants (NetBox, AD) affichent enfin leurs erreurs.
    4d. ~~**0.9.6**~~ ✅ fait — Correctif intercalaire : jeton NetBox v2 (`<clé>.<jeton>`) envoyé en `Bearer`.
    4e. ~~**0.9.7**~~ ✅ fait — Correctif intercalaire : jeton NetBox collé avec le mot « Token ».
    5. ~~**0.9.8**~~ ✅ fait — Vues DNS (clé de transfert par vue, RPZ par vue, copie de zone, garde-fous).
    6. **0.9.9** — Traçabilité bail / MAC / nom / utilisateur AD.
    7. **0.9.10** — Découverte planifiée et alertes d'hygiène.
    8. **0.9.11** — API : description OpenAPI et jetons d'API.
    9. **0.9.12** — Connexion AD / LDAP, rôles par groupe, délégation par périmètre.
    10. **0.9.13** — DHCP multi-espaces.
5. **1.0** — Consolidation de la série 0.9.x et passage en revue avant usage en production.
