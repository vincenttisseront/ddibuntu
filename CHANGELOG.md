# Journal des modifications

## 0.4.2 (en cours)
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
