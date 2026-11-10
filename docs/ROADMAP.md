# Feuille de route

Référence : forces fonctionnelles d'une plate-forme DDI du marché (EfficientIP SOLIDserver) à émuler, rapprochées de l'état réel de DDI-Buntu.
Légende : ✅ fait · 🟡 partiel · ⬜ à faire.

## 1. Modèle unifié et cohérence
| Capacité | État | Détail |
|---|---|---|
| Espaces IP qui se chevauchent | ✅ 0.5.0 | Espaces, CIDR unique par espace. Limite : DHCP/Kea limité à l'espace par défaut. |
| Orchestration IPAM → DNS | 🟡 | A/AAAA + PTR créés à l'allocation d'une adresse (transaction unique). |
| Orchestration IPAM → DHCP | ⬜ | Une adresse « Réservation DHCP » ne crée pas encore la réservation Kea. |
| Gabarits (templates) de réseau | ⬜ | Zone DNS associée, options DHCP par défaut, règle de nommage appliquées à la création d'un réseau. |
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
| Limitation de débit des requêtes (RRL) | ⬜ | Réglage BIND `rate-limit`, exposé dans la console. |
| Détection d'exfiltration / tunnel DNS | ⬜ | Heuristiques sur le journal des requêtes (longueur/entropie des noms, volume TXT/NULL par client). |
| Hygiène IPAM : adresses fantômes | 🟡 | La découverte renseigne `last_seen` ; il manque le rapport « allouée mais muette depuis N jours » et l'alerte. |

## 4. Exploitation
| Capacité | État | Détail |
|---|---|---|
| Vue graphique d'un réseau (grille libre/occupé) | ⬜ | Grille compacte par réseau, clic → fiche de l'IP. |
| Navigation latérale par module + recherche globale | ⬜ 0.6.0 | |
| Traçabilité bail ↔ MAC ↔ nom ↔ utilisateur AD | ⬜ | Corrélation baux Kea, DNS dynamique et ouvertures de session AD. |
| API REST complète et documentée | 🟡 | Toute l'interface passe par l'API ; il manque la description OpenAPI publiée et les jetons d'API (hors session). |
| Mises à jour en ligne signées | ✅ 0.4.1 | |

## Ordre proposé
1. **0.6.0** — Navigation latérale, recherche globale, grille d'occupation d'un réseau.
2. **0.7.0** — Gabarits de réseau + réservation DHCP automatique depuis l'IPAM (cohérence IPAM/DNS/DHCP).
3. **0.8.0** — Hygiène IPAM (adresses fantômes) + RRL + détection de tunnel DNS.
4. **0.9.0** — API : description OpenAPI et jetons d'API.
5. **1.0** — Vues DNS, HA DHCP (nécessite deux appliances).
