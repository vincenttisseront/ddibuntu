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
- **Baux DHCP** : pas dans la base répliquée. Chaque Kea garde ses baux localement ; le hook HA (`libdhcp_ha`, mode load-balancing, avec `libdhcp_lease_cmds`) les synchronise sur le réseau dédié, agent de contrôle en TLS mutuel.
- **DHCP et VIP** : le DHCP ne passe pas par la VIP. Les relais DHCP déclarent les deux adresses réelles des nœuds. La VIP sert la console, l'API et le point d'entrée DDNS.
- **DNS** : le nœud actif est BIND primaire (zones, DDNS, RPZ). L'autre est secondaire (AXFR/IXFR signé TSIG sur le réseau dédié, NOTIFY). Les deux répondent aux requêtes des clients. À la bascule, le secondaire est promu primaire ; le numéro de série ne baisse jamais.
- **Configuration identique** : les deux Kea doivent avoir les mêmes sous-réseaux et pools (exigence du hook HA). Chaque nœud rend sa configuration depuis la base répliquée ; la **génération de configuration** (itération 1) permet de vérifier que les deux nœuds ont appliqué la même.
- **Secrets et PKI** : une autorité interne émet les certificats des nœuds (PostgreSQL en `verify-full`, Kea HA, API inter-nœuds). Enrôlement d'un nœud par jeton à usage unique.
- **Pare-feu** : nftables n'ouvre 5432, le port de contrôle Kea, le transfert DNS, le quorum et VRRP qu'aux pairs, sur le réseau dédié.
- **Mises à jour** : progressives (secondaire, puis bascule contrôlée, puis ancien actif) ; les nœuds doivent être à la même version.

## Écarts assumés par rapport au cahier des charges
1. **Atomicité** : aucune transaction ne couvre PostgreSQL et deux démons. Garantie réelle : écriture atomique en base (IPAM + DNS + réservation DHCP dans une transaction) ; application convergente avec **génération de configuration**, validation avant déploiement, retour arrière, détection d'écart entre nœuds.
2. **GSS-TSIG** : la disponibilité du hook GSS-TSIG de Kea 2.4 (Ubuntu 24.04) reste à vérifier. Repli : BIND authentifie les clients AD (`update-policy` ms-self) et l'IPAM met à jour le DNS par `nsupdate -g`. Traité après le cluster.
3. **Test de panne** : sans laboratoire, la bascule réelle n'est pas démontrée ; chaque itération livre ses procédures de test pour le premier labo.

## Itérations
| # | Contenu |
|---|---|
| 1 | Smart DDI : génération de configuration, réservation DHCP pilotée par l'IPAM, gabarits de réseau |
| 2 | Fondations : PKI interne, enrôlement, réplication PostgreSQL, quorum, état du cluster |
| 3 | Kea HA load-balancing |
| 4 | BIND primaire/secondaire, distribution du RPZ, Keepalived |
| 5 | Bascule automatique, isolation, réintégration (`pg_rewind`), mise à jour progressive |
| 6 | Active Directory : Kerberos, GSS-TSIG, redirecteurs conditionnels |
