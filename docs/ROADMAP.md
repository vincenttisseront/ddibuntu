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
| DHCP multi-espaces | ✅ 0.9.42 | Une instance Kea par espace, ou refus de chevauchement. |

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

## Série 0.12.x — migration depuis DNS / DHCP Windows Server (PRIORITAIRE, demande du 2026-11-13)
Traitée **avant** le reste des séries 0.10.x et 0.11.x. Déjà en place : import d'un export `Export-DhcpServer` (étendues, plages, exclusions, réservations, options), import de zones (fichiers `dnscmd /ZoneExport`, LDAP AD), sites et sous-réseaux AD, instantané avant import, Kerberos/AD. Il manque l'**accompagnement** : parcours guidé, évaluation de compatibilité, reprise des baux et des fonctions avancées, coexistence, vérification et bascule réversible.
| # | Version | Évolution | État |
|---|---|---|---|
| 1 | 0.12.0 | Assistant « Migration Windows » : parcours guidé (inventaire → évaluation → import → vérification → bascule), scripts PowerShell à copier, avancement conservé | ✅ 0.12.0 |
| 2 | 0.12.1 | Évaluation de compatibilité : rapport « repris / adapté / non pris en charge » pour DHCP (failover, politiques, filtres MAC, superscopes, classes) et DNS (zones intégrées AD, stub, redirecteurs conditionnels, DNSSEC, vieillissement) | ✅ 0.12.1 |
| 3 | 0.12.2 | Reprise des baux actifs (continuité des clients) ; le failover Windows se remplace par Kea HA du cluster | ✅ 0.12.2 |
| 4 | 0.12.3 | Zones DNS depuis Windows : création d'après l'inventaire (primaires, secondaires, redirecteurs conditionnels), transfert AXFR direct, enregistrements AD critiques protégés | ✅ 0.12.3 |
| 5 | 0.12.4 | Coexistence : notre BIND secondaire des zones Windows (synchronisation périodique), baux Windows lus en continu avant bascule | ✅ 0.12.4 |
| 6 | 0.12.5 | Vérification avant bascule : comparaison automatique Windows ↔ DDI (réponses DNS de chaque enregistrement, étendues / plages / réservations / options DHCP), rapport d'écarts | ✅ 0.12.5 |
| 7 | 0.12.6 | Plan de bascule et retour arrière : check-list ordonnée (TTL, relais DHCP, redirecteurs AD, arrêt des étendues Windows), exécution assistée, instantané et rollback | ✅ 0.12.6 |
| 8 | 0.12.7 | Après migration : localisation des contrôleurs de domaine (SRV), mises à jour dynamiques sécurisées (GSS-TSIG), retrait des rôles Windows | ✅ 0.12.7 |
| 9 | 0.12.8 | Classes de clients Kea dans la console : stratégies, classes fabricant / utilisateur, filtres MAC (autoriser / refuser), option 43 ; import correspondant depuis Windows | ✅ 0.12.8 |

## Série 0.13.x — accès réseau : RADIUS / 802.1X / VPN en EAP-TLS (remplace un NPS Windows, demande du 2026-11-16)
Un NPS Windows n'existe pas sous Linux : le service est **FreeRADIUS** intégré à l'appliance, piloté par la console (même frontière de privilèges que BIND et Kea). EAP-TLS dès le départ (pas de mot de passe : pas de jonction au domaine ; l'AD n'est lu qu'en LDAPS, lecture seule, pour l'état du compte et les groupes imbriqués). Maquette du parcours : assistant en 6 étapes (contexte, import NPS, annuaire AD, PKI / certificats, règles, validation).
| # | Version | Évolution | État |
|---|---|---|---|
| 1 | 0.13.0 | Service FreeRADIUS, clients (contrôleurs Wi-Fi, passerelles VPN), secrets chiffrés, déploiement avec retour arrière, pare-feu limité aux clients, test d'Access-Request | ✅ 0.13.0 (vrai FreeRADIUS 3.2.5 ; refus par défaut) |
| 2 | 0.13.1 | Annuaire : liaison LDAPS en lecture seule, état du compte et groupes imbriqués, test de recherche | ✅ 0.13.1 (vrai Samba AD en LDAPS ; pas encore testé sur un AD Microsoft) |
| 3 | 0.13.2 | PKI : autorité de confiance des certificats clients, certificat du serveur, EAP-TLS, révocation (CRL / OCSP) | ✅ 0.13.2 (vrai FreeRADIUS + `eapol_test` en TLS 1.2 et 1.3 ; CRL seulement, **OCSP reporté** ; pas encore essayé avec AD CS) |
| 4 | 0.13.3 | Règles d'accès : groupe AD → décision, VLAN, pool ; ordre d'évaluation, simulation avant publication | ✅ 0.13.3 (vrai FreeRADIUS + `eapol_test` + Samba AD, mêmes décisions que la simulation sur 15 cas ; **jamais essayé sur un AD Microsoft** ; DN de groupe à échappement hexadécimal refusés) |
| 5 | 0.13.10 | Import d'un NPS existant (`netsh nps export`) : clients, stratégies, rapport « repris / adapté / non pris en charge » | ✅ 0.13.10 (par fichier ; vrai Samba AD pour la résolution des groupes par SID ; **format non vérifié sur un export réel**, lecture directe par WinRM **reportée**) |
| 6 | à planifier | Comptabilité (1813), journal des authentifications, alertes | ⬜ |
| 7 | 0.13.6 | Cluster : **réalisé en 0.15.0 en actif / passif** derrière l'adresse virtuelle (et non en actif / actif : un échange EAP doit rester sur le même serveur) | ✅ 0.15.0 |
| 8 | 0.13.7 | Liens IPAM / DHCP : VLAN et pools issus de l'IPAM, session ↔ bail ↔ utilisateur dans la traçabilité | ⬜ |

## Série 0.14.x — PKI du DDI : EJBCA Community intégrée (demande du 2026-11-17)
La PKI est **EJBCA Community** (image officielle `keyfactor/ejbca-ce`, Podman + Quadlet, base PostgreSQL de l'appliance), pilotée par la console avec la même frontière de privilèges que BIND, Kea et FreeRADIUS : la console dépose une demande minuscule, un script root la revalide et l'applique, aucun secret ne transite par la console. Cycle de vie complet (installation, démarrage, arrêt, mise à jour à la demande avec retour arrière, désinstallation qui garde les données). **Toute autorité créée ou importée est publiée automatiquement dans l'Active Directory connecté au DDI** (racines → `Certification Authorities`, émettrices → `AIA`). Cahier des charges détaillé : document `ejbca-pki-spec` du projet.

| # | Version | Évolution | État |
|---|---|---|---|
| 1 | 0.14.0 | Service PKI : conteneur EJBCA CE (Quadlet, image figée par empreinte), base et secrets créés une fois, nom public `pki.<domaine>` (HTTP, port 8080), pare-feu limité aux réseaux autorisés, état, démarrage / arrêt, désinstallation sans perte, enregistrement DNS protégé, page « PKI » | ✅ 0.14.0 (conteneur EJBCA lancé de bout en bout avec Podman réel et la commande du vrai générateur Quadlet, validé en 0.14.1 ; démarrage sous systemd réel pas encore constaté) |
| 2 | 0.14.1 | Autorités : racine hors ligne (le DDI produit la demande, la racine signe ailleurs, import) ou racine auto-signée de laboratoire ; autorité émettrice ; CRL (servies en HTTP, renouvelées par minuteur) ; CDP / AIA ; remise à zéro | ✅ 0.14.1 (vrai conteneur EJBCA : 97 contrôles ; vrai Chrome) |
| 3 | 0.14.2 | Publication automatique dans l'AD : compte délégué, repli `certutil -dspublish`, relecture et comparaison d'empreinte, rejeu en cas d'échec, rapprochement quotidien (jamais de retrait automatique) | ✅ 0.14.2 (vrai Samba AD : 20 contrôles, délégation appliquée avec `samba-tool` ; vrai Chrome) |
| 4 | 0.14.3 | Émission depuis la console (CSR ou PKCS#12, clé jamais stockée), profils fournis, recherche, export CSV, révocation, lien « Utiliser la PKI du DDI » dans l'accès réseau (RADIUS) | ✅ 0.14.3 (vrai conteneur EJBCA : profils, droits SQL, révocation et CRL ; 36 + 13 contrôles de bout en bout ; vrai Chrome avec un « root » simulé) |
| 5 | 0.14.4 | Import d'une autorité existante (PKCS#12) : clé et certificat d'une autorité déjà en service repris dans EJBCA (dépôt dans la console, mot de passe jamais en ligne de commande, publication AD automatique) | ✅ 0.14.4 (vrai conteneur EJBCA : refus, émission et révocation depuis l'autorité reprise, racine reprise qui signe, **autorités reprises toujours en ligne après redémarrage du conteneur** ; 16 contrôles de bout en bout ; vrai Chrome) |
| 6 | 0.14.5 | Sauvegarde et restauration avec le reste de l'appliance (`ddibuntu-backup` : même dépôt, rétention et copie externe) ; **secrets d'EJBCA chiffrés pour une clé de récupération dont l'appliance ne garde que la partie publique** ; restauration en ligne de commande | ✅ 0.14.5 (vrai conteneur EJBCA, 278 contrôles : secrets et volume détruits puis restaurés sur la base existante, autorités du DDI et autorité reprise de nouveau opérationnelles ; 149 + 221 contrôles en lots hostiles, falsification et rotation de clé ; 17 contrôles de bout en bout ; vrai Chrome) |
| 7 | 0.14.6 | Correctif : page PKI sans bandeaux d'avertissement (Community, Podman) ; **Podman installé par l'installation de la PKI elle-même** (`apt-get install podman` en root) quand le paquet manque, au lieu d'être réservé à l'ISO | ✅ |
| 8 | 0.14.7 | Mises à jour de la version Community : détection (étiquettes Docker Hub, empreinte contrôlée au tirage), notes de version, sauvegarde + contrôles (santé, schéma, autorités, signature, CRL) + validation séparée + retour arrière manuel ou automatique, refus de rétrograder (version de la base) | ✅ 0.14.7 |
| 9 | 0.14.8 | SCEP pour les équipements réseau : alias créé en ligne de commande (`config scep addalias`), mode « autorité » (le mode RA à défi partagé est Enterprise), équipement préenregistré avec son défi à usage unique rendu une fois, nom distinctif imposé par l'enregistrement, renouvellement = ré-armement, expiration à 7 jours ; MDM en masse et Intune hors périmètre | ✅ 0.14.8 (vrai conteneur EJBCA 9.3.7 puis 9.6.3 et vrai client `sscep` : 102 contrôles ; l'alias survit à la mise à jour et au retour arrière) |
| 10 | 0.14.9 | Cluster : **la PKI suit le leader PostgreSQL** (un seul EJBCA, démarré par `ddibuntu-cluster follow` sur le primaire de Patroni ; unité Quadlet sans `[Install]` dans un cluster) ; base `ejbca` répliquée par Patroni, secrets / instance / clé de récupération / consigne d'arrêt / métadonnées des autorités / volume transportés **chiffrés dans une clé etcd** (phrase dérivée du secret d'échange : l'arbitre ne la lit pas) ; synchronisation à trois voies, secondaire qui converge toujours et ne publie jamais ; reprise sans manipulation ; arrêt volontaire respecté ; **marque etcd de mise à jour interrompue** (aucun démarrage tant qu'un administrateur n'a pas levé le blocage) ; écritures réservées au leader ; carte « PKI dans le cluster » dans la console ; `pki.<domaine>` sur l'adresse virtuelle | ✅ 0.14.9 (3 nœuds simulés avec un vrai etcd : 233 contrôles ; vrai conteneur EJBCA 9.6.3 : 64 contrôles — état exporté, nœud vidé, importé, promu sur la même base, CRL signée avec les secrets importés, reprise sur volume vide) |
| 11 | 0.14.10 | Correctif : texte de la carte « PKI et cluster » avant l'installation (la PKI n'est plus dite « en marche » sur un cluster qui n'en a pas ; relevé lors du premier essai sur un vrai cluster) |
| 12 | 0.14.11 | Correctif : **podman, freeradius et leurs dépendances livrés dans l'archive de mise à jour** (`debs/`, signée avec elle) et posés sur chaque nœud de données pendant la mise à jour progressive, sans accès à Internet (`dpkg`, puis `apt` en secours, jamais de rétrogradation, jamais de retour arrière pour un paquet) ; `ddibuntu-selfupdate packages` rattrape les nœuds mis à jour par une version qui n'en posait pas ; état `nopodman` dans la carte « PKI et cluster » (relevé lors du premier essai sur un vrai cluster : le secondaire n'avait pas podman) |
| 13 | 0.14.12 | Correctif : **suivi en direct de l'installation de la PKI** (`pki-progress.json` publié par `ddibuntu-pki` : étapes podman, préparation, image, unité, démarrage, puis initialisation d'EJBCA jusqu'à la santé ; grande carte avec barre de progression, temps écoulé et motif d'échec ; la page suit l'opération au lieu de s'arrêter à la prise en charge de la demande) ; textes de la racine créée par le DDI revus (« clé conservée par le DDI » au lieu de « laboratoire ») et aide dans la fenêtre « Créer une émettrice » quand aucune racine n'existe. |
| 14 | 0.14.13 | Correctif : **autorités de la PKI en arbre de dépendance** (hiérarchie compacte à gauche, détail complet de l'autorité cliquée à droite ; racines du DDI, racines hors ligne, autorités reprises) et **première CRL refaite à 7 jours** après le réglage de la période (`ca createcrl`). |
| 15 | 0.14.14 | Correctif : **noms proposés par défaut** dans les formulaires de la PKI (certificat : d'après le profil, le domaine du DDI et le premier numéro libre, ou le nom de la demande de certificat fournie ; noms DNS / UPN ; autorités ; PKCS#12 ; SCEP), toujours modifiables. |
| 16 | 0.14.15 | Correctif : noms proposés (suite) : **dialogue du certificat du serveur RADIUS** (`radius.<domaine>`, nom DNS qui suit), **organisation / unité / pays** repris de l'autorité choisie ou de la demande de certificat, message d'orientation vers l'onglet RADIUS pour le profil « Serveur RADIUS ». |
| 17 | 0.14.16 | Correctif : **le service RADIUS ne démarrait pas sous systemd avec EAP-TLS** (module `eap` illisible pour `freerad`) ; contrôle des batteries b29/b30 en tant que `freerad` ; **raison de l'échec du démarrage** (journal) affichée dans « Dernière opération ». |
| 18 | 0.14.17 | Correctif : **« Déployer » (RADIUS) remettait `/var/lib/ddibuntu` en 0750** et la console ne pouvait plus y écrire (mise à jour, cluster, déploiement : « Erreur interne ») ; le dossier d'état n'est plus modifié s'il existe ; contrôle dans la batterie b28. |
| 19 | 0.14.18 | **Journal des authentifications RADIUS** : une ligne par décision (poste, MAC, équipement, SSID, certificat, règle qui a décidé, raison du refus) écrite par FreeRADIUS, onglet **Journal** de la console (filtres, compteurs 24 h, motif expliqué en clair et quoi vérifier, diagnostics du démon : équipement inconnu, alerte TLS du poste), « Équipements déployés » au lieu de « Clients actifs », rotation. |
| 19b | 0.14.19 | Correctif : l'onglet **Journal** de RADIUS affichait une erreur 500 (déclarations mises en commentaire par erreur) ; test sur les sources des composants Vue | ✅ 0.14.19 |
| 20 | 0.15.0 | **RADIUS actif / passif dans le cluster** : un seul FreeRADIUS sur le leader (derrière l'adresse virtuelle), arrêté sur le secondaire ; « Déployer » mémorise (chiffré) le déploiement accepté et la console du nouveau leader le rejoue ; refus hors leader ; bloc « Cluster » de l'onglet Service | ✅ 0.15.0 (b28 vrai FreeRADIUS, unitaires, e2e ; **bascule réelle non essayée**) |
| 21 | 0.16.0 | **Identifiant et mot de passe** : PEAP-MSCHAPv2 (jonction de chaque nœud au domaine, `winbindd` privé) et EAP-TTLS/PAP (liaison LDAPS), désactivés par défaut, mêmes règles d'accès qu'EAP-TLS, décision avant la vérification du mot de passe, onglet « Mot de passe » |
| 22 | 0.17.0 | **Second facteur (MFA)** pour les accès PAP (passerelles VPN), réglé par client RADIUS : mot de passe + code à usage unique vérifiés par un fournisseur externe générique (OAuth2 « mot de passe »), décision des règles avant l'appel, secret partagé long exigé, onglet « Second facteur » | 🚧 en cours (b42, unitaires, e2e) |

## Série 0.10.x — gestion complète DNS ↔ IPAM ↔ DHCP (validée le 2026-11-13)
Dix évolutions, une version chacune, chacune testée (unitaires, e2e, batteries réelles) avant publication. Ordre retenu : les deux plus rentables d'abord, puis celles qui s'appuient dessus.
| # | Version | Évolution | État |
|---|---|---|---|
| 1 | 0.10.0 | Synchronisation bail DHCP → DNS (DDNS maîtrisé) : A/PTR créés et retirés avec le bail, enregistrements marqués « dynamiques », jamais d'écrasement d'un statique | ✅ 0.10.0 |
| 2 | 0.10.1 | Contrôle de cohérence continu (« DNS health ») : PTR orphelins, A sans fiche IPAM, IP sans nom, conflits DHCP/DNS, CNAME pendants ; correction en un clic, score par zone | ✅ 0.10.1 |
| 3 | 0.10.2 | Cycle de vie d'une adresse en un geste (réserver / libérer : fiche, réservation, A, PTR, alias, en tout-ou-rien, avec récapitulatif) | ✅ 0.10.2 |
| 4 | 0.10.3 | Historique et retour arrière par enregistrement ; diff avant déploiement de zone, validation `named-checkzone` | ✅ 0.12.9 |
| 5 | 0.10.4 | Zones inverses automatiques par sous-réseau, délégations CIDR (RFC 2317) | ✅ 0.12.10 |
| 6 | 0.10.5 | Modèles de nommage et d'enregistrements par sous-réseau / VLAN, contrôle de convention | ✅ 0.12.11 |
| 7 | 0.10.6 | Import / export et opérations en masse (CSV, AXFR, édition multiple avec prévisualisation) | ⬜ |
| 8 | 0.10.7 | Vues DNS (split-horizon) liées à l'IPAM : nom interne / externe, comparaison des réponses, alerte de mauvaise vue | ⬜ |
| 9 | 0.10.8 | Supervision corrélée par IP (baux, requêtes DNS, RPZ) et alertes (pools presque pleins, TTL incohérents, zones non transférées) | ⬜ |
| 10 | 0.10.9 | Approbation à deux personnes des changements sensibles, délégation par zone / sous-réseau / type, webhooks | ⬜ |

## Série 0.11.x — automatisation, sécurité et pilotage DDI (validée le 2026-11-13)
Dix évolutions supplémentaires, après la série 0.10.x ; même règle : une version chacune, testée (unitaires, e2e, batteries réelles) avant publication.
| # | Version | Évolution | État |
|---|---|---|---|
| 1 | 0.11.0 | DDNS IPv6 et clients externes : baux DHCPv6, mises à jour dynamiques RFC 2136 signées TSIG, droits de modification par client | ⬜ |
| 2 | 0.11.1 | Planificateur de changements DNS : création / modification / suppression à une date donnée, retour arrière automatique | ⬜ |
| 3 | 0.11.2 | Surveillance de l'état des services : sondes TCP / HTTP / ICMP sur les A et CNAME, bascule vers une IP de secours | ⬜ |
| 4 | 0.11.3 | Dérive de configuration : état voulu (console) contre état servi (BIND, Kea), alerte et resynchronisation | ⬜ |
| 5 | 0.11.4 | DNSSEC géré : signature de zone, rotation KSK / ZSK, suivi des DS chez le parent, alerte avant expiration | ⬜ |
| 6 | 0.11.5 | Conformité et rapports planifiés (e-mail / PDF) : inventaire, occupation, alertes, zones sans propriétaire | ⬜ |
| 7 | 0.11.6 | Propriétaires et cycle de vie : propriétaire, expiration, revue périodique, libération des adresses abandonnées | ⬜ |
| 8 | 0.11.7 | Cartographie visuelle réseau et DNS : espaces, réseaux, VLAN, zones, serveurs ; parcours depuis une IP | ⬜ |
| 9 | 0.11.8 | Contrôles de sécurité DNS : sous-domaines pendants, wildcards involontaires, SPF / DMARC absents, blocage par groupe de clients | ⬜ |
| 10 | 0.11.9 | API et automatisation : spécification OpenAPI, fournisseur Terraform, module Ansible, jetons à portée limitée, limitation de débit | ⬜ |

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
    4f. ~~**0.9.9**~~ ✅ fait — Correctif intercalaire : l'IPAM se rafraîchit après un import ou une annulation.
    4g. ~~**0.9.10**~~ ✅ fait — Lien « Première configuration » retiré une fois l'appliance initialisée ; validation réelle de l'élection du quorum.
    4h. ~~**0.9.11**~~ ✅ fait — Cluster : sélecteur de nœuds, bandeau et accès à l'adresse de service, nœud préféré du primaire, connexion sur un secondaire (jeton signé), icône de l'onglet.
    4i. ~~**0.9.12**~~ ✅ fait — Correctif intercalaire : plus de demandes d'actualisation (409 répétés) hors cluster.
    4j. ~~**0.9.13**~~ ✅ fait — Mise à jour du cluster nœud par nœud (ordre commun, arbitre → secondaires → primaire, un échec arrête la file).
    4k. ~~**0.9.14**~~ ✅ fait — Réglages de session communs à tous les nœuds (durée, inactivité) ; composants du cluster vérifiés avant l'assistant. (Reste : contrôle de cohérence des comptes entre nœuds, repris plus tard.)
    6. ~~**0.9.28**~~ ✅ fait — Traçabilité des baux : historique IP / MAC / nom, page de recherche (le nom d’'utilisateur AD reste à corréler avec les rôles par groupe).
    7. ~~**0.9.35**~~ ✅ fait — Découverte planifiée et alertes d'hygiène (fantômes, hôtes inconnus, MAC différente).
    8. ~~**0.9.40**~~ ✅ fait — API : description OpenAPI et jetons d'API ; correctif de la validation Kea différée.
    9. ~~**0.9.41**~~ ✅ fait — Délégation par périmètre (espaces IPAM) pour utilisateurs et groupes AD (la connexion AD et les rôles par groupe existaient déjà) ; correctif du minuteur de sauvegarde.
    11. **0.9.46** ✅ — SSO OpenID Connect (Entra ID, Keycloak, Okta…) ; 12. **0.9.47** ✅ — Retour à la normale après panne (nœud revenu, resynchronisation, retour au nœud préféré) ; 13. **0.9.48** ✅ — Connexion par annuaire LDAP générique (OpenLDAP, FreeIPA…) ; 14. **0.9.49** ✅ — Page Profil, sessions actives, action « Traiter » sur les alertes ; 15. **0.9.50** ✅ — Sauvegardes : rétention en jours, contrôle d'intégrité automatique et alerte ; 16. **0.9.51** ✅ — SonarQube dans la CI et premier lot de remédiation (docs/QUALITE.md) ; 17. **0.9.52** ✅ — MFA obligatoire par rôle (inscription forcée à la connexion) ; 18. **0.9.53** ✅ — CNAME gérés depuis l'adresse IP (vue unifiée).
    10. ~~**0.9.42**~~ ✅ fait — DHCP multi-espaces (refus de chevauchement entre espaces) ; correctif des droits de /var/lib/ddibuntu.
5. **1.0** — Consolidation de la série 0.9.x et passage en revue avant usage en production.
