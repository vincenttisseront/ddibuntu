# Générer l'ISO et l'installer

Un seul script produit une ISO hybride **BIOS + UEFI** qui installe sans question une appliance DDI complète :
Ubuntu Server 24.04 LTS, PostgreSQL 16, BIND 9.18 (DNS, filtrage RPZ), Kea 2.4 (DHCP) et la console web HTTPS
(IPAM, DNS, DHCP, filtrage, import Active Directory). Tout est installé pendant l'installation : **rien n'est téléchargé au premier démarrage**.

## Générer l'ISO sur macOS (construction validée par un essai réel : ISO produite, puis installée dans une VM)

1. Installer et démarrer **Docker Desktop** ; réserver au moins 4 Go de mémoire et 25 Go de disque (Réglages > Resources) ; prévoir **15 Go libres** sur le Mac pour le dossier de sortie.
2. Ouvrir un Terminal dans le dossier du script (par exemple `cd ~/Downloads`), puis :
   ```bash
   xattr -d com.apple.quarantine build-ddibuntu.sh 2>/dev/null   # si macOS bloque un script téléchargé
   chmod +x build-ddibuntu.sh
   ./build-ddibuntu.sh
   ```
3. Depuis un clone du dépôt, construire d'abord la console (`tools/build-console.sh`), puis lancer `./build-ddibuntu.sh` à la racine du dépôt. Avec le fichier unique de publication, aucune étape préalable. Résultat dans le même dossier : `ddibuntu-<version>-amd64.iso` et `ddibuntu-<version>-amd64.iso.sha256`.
   Vérifier : `shasum -a 256 -c ddibuntu-<version>-amd64.iso.sha256`.

**Mac Apple Silicon (M1 à M4)** : l'appliance est x86-64, donc le script force un conteneur `linux/amd64`
(émulé par Docker Desktop : la construction est **plus lente**, comptez plusieurs dizaines de minutes la première fois).
L'ISO obtenue est une ISO amd64 : elle **ne démarre pas** dans VMware Fusion sur Apple Silicon (qui n'exécute que des invités arm64).
Pour l'essayer, utiliser un hôte VMware x86 (ESXi, Workstation) ou une émulation (UTM/QEMU, très lente).

Le premier lancement télécharge l'ISO Ubuntu Server (**~3,8 Go** pour la 24.04.5, conservée dans `.ddibuntu-cache/`), Node.js (~30 Mo) et les paquets de l'appliance ; l'ISO produite fait environ 4 Go.
Canonical garde plusieurs versions dans le même fichier de sommes signé (24.04.3, .4, .5…) : **la plus récente est retenue automatiquement**.
Options utiles : `--timeout N` (délai du menu GRUB avant l'installation automatique, 10 s ; `-1` attend une validation),
`--iso FICHIER --sha256 EMPREINTE` (ISO Ubuntu locale), `--help`.
`--skip-debs` et `--skip-node` n'existent que pour les tests : l'ISO obtenue est incomplète.

Autres postes : Windows 11 `.\build-ddibuntu.ps1` (PowerShell + Docker Desktop) ; Linux `./build-ddibuntu.sh` (Docker) ou `sudo ./build-ddibuntu.sh --no-docker`.

## Mettre à jour une installation existante

Démarrer la machine DDI-Buntu sur l'ISO **de la nouvelle version** et choisir dans le menu **« Update an existing DDI-Buntu installation… »** (ce n'est pas l'entrée par défaut : le délai du menu lance l'installation, qui **efface le disque**, donc appuyer sur une touche à temps ou régler `--timeout -1` à la construction pour attendre un choix).

- Conservé : base PostgreSQL et console (comptes, IPAM, DNS, DHCP), certificat TLS, secrets, réseau, comptes système, pare-feu (`firewall.conf` et règles rendues), configuration BIND/Kea.
- Remplacé : console web, Node.js, fichiers de l'appliance (`/usr/local/...`, unités systemd, durcissement SSH/sysctl), et les paquets embarqués **uniquement s'ils sont plus récents** que ceux installés.
- Sauvegarde des fichiers remplacés : `/var/lib/ddibuntu/update-backup/<date>-<ancienne version>/replaced-files.tar.gz` (les 3 dernières sont gardées) ; journal : `/var/lib/ddibuntu/update-<date>.log`, historique : `update-history`.
- Refus si l'ISO est plus ancienne que l'installation (`ddi-force` en paramètre du noyau pour passer outre) ; si plusieurs installations sont trouvées, ajouter `ddi-root=/dev/mapper/...` au noyau (touche `e` dans le menu).
- À la fin, **la machine s'éteint** : retirer l'ISO avant de la rallumer (sinon le menu de l'ISO revient). La base est migrée par la console au premier démarrage de la nouvelle version ; **faire un point de restauration des données dans la console avant la mise à jour**, une migration de schéma ne se défait pas en revenant à l'ancienne version.
- Limites : pas de disque chiffré (LUKS), le système est mis à niveau hors ligne et n'est pas démarré pendant l'opération.

**Attention : l'installation automatique efface le disque cible.**

## Dépannage

**`curl: (60) SSL certificate problem: unable to get local issuer certificate`** : sur un poste d'entreprise, un proxy inspecte le HTTPS
(Zscaler, etc.) et re-signe les certificats avec une autorité que le conteneur de construction ne connaît pas, ou le réseau de Docker Desktop est filtré. Cause exacte non établie sur le premier poste d'essai : `--ca-from-keychain` a suffi. Pour diagnostiquer :
```bash
curl -vI https://releases.ubuntu.com 2>&1 | grep -iE "issuer|subject:"      # sur le Mac : l'émetteur est-il celui de l'entreprise ?
```
Solutions, de la plus simple à la moins sûre :
```bash
./build-ddibuntu.sh --ca-from-keychain        # reprend les certificats de votre trousseau macOS (dont celui de l'entreprise)
./build-ddibuntu.sh --ca-cert entreprise.pem  # ou fournir l'autorité (PEM) donnée par le service informatique
./build-ddibuntu.sh --insecure-tls            # en dernier recours : plus de vérification du certificat du serveur
```
`--insecure-tls` ne compromet pas l'intégrité : l'ISO Ubuntu (signature Canonical + SHA-256), Node.js (signature + SHA-256) et les clés
(empreintes épinglées) sont vérifiés indépendamment du TLS. Seule la confidentialité des téléchargements n'est plus protégée.
Les certificats exportés du trousseau ne servent que dans le conteneur de construction jetable ; aucune clé privée n'est exportée.

**Docker Desktop** doit être démarré (`docker info` doit répondre). **Espace disque** : au moins 25 Go pour le disque de Docker Desktop (ISO de base + ISO produite + copie de travail).

## Ce que le script vérifie avant d'écrire l'ISO

- **ISO Ubuntu** : signature Canonical de `SHA256SUMS` (clé « CD Image 2012 » épinglée), puis somme SHA-256 de l'ISO.
- **Node.js 22** : signature de `SHASUMS256.txt` par l'une des 8 clés de publication **actives**, épinglées par empreinte
  (README officiel de `nodejs/release-keys`), puis somme SHA-256 de l'archive. Toute autre signature est refusée.
- **Paquets** (PostgreSQL, BIND, Kea, Python…) : fermeture de dépendances calculée dans un conteneur Ubuntu encore propre, sommes SHA-256 enregistrées.
- **Console web** : construite, embarquée dans le script, somme vérifiée à l'installation.
- **ISO produite** : démarrage BIOS et UEFI conservés, contenu identique à la source.

## Après l'installation sur VMware ESXi / Workstation (x86)

Nouvelle VM : système « Ubuntu Linux (64 bits) », **2 vCPU, 4 Go, disque 40 Go**, micrologiciel BIOS ou UEFI,
carte réseau VMXNET 3 sur le bon réseau, lecteur CD/DVD sur l'ISO (téléversée dans un datastore).
`open-vm-tools` est installé (arrêt propre depuis l'hyperviseur, adresse IP visible dans vSphere).

1. Démarrer sur l'ISO : l'entrée « Install DDI-Buntu » se lance seule après le délai du menu.
2. Au premier démarrage, l'assistant demande langue, clavier, fuseau, nom, réseau, **réseaux autorisés à administrer l'appliance**, compte administrateur.
3. Se connecter sur la console ; menu **« Console web : adresse et jeton »** : URL `https://<adresse>/` et jeton de première configuration.
4. Ouvrir l'URL (certificat auto-signé, à remplacer à terme), page **/setup** : saisir le jeton, créer l'administrateur de la console.
5. Configurer zones, plages, étendues… puis **Valider et déployer** : les fichiers BIND et Kea sont validés (`named-checkzone`, `named-checkconf`,
   `kea-dhcp4 -t`), puis appliqués par un service root séparé avec retour arrière en cas d'échec.

Pare-feu : SSH (22) et console (443) réservés aux réseaux d'administration ; DNS (53) et DHCP (67) ouverts.

## Limites connues

- **Jamais exécuté** sur l'ISO Canonical réelle, ni dans l'installateur Subiquity, ni sous VMware, ni dans Docker Desktop (macOS/Windows) ou PowerShell 5.1. Le chemin macOS est vérifié avec un faux `uname` et un faux `docker` (arguments transmis, plateforme amd64), pas avec le vrai Docker.
- Les services ont été vérifiés dans un vrai système Ubuntu 24.04 (chroot, espace de noms réseau) **sans systemd en PID 1** : l'enchaînement
  assistant → initialisation de la base → console → application de la configuration n'a été validé que par `systemd-analyze verify`.
- **DDNS** : les mises à jour dynamiques reçues par BIND sont **écrasées** au déploiement suivant (la synchronisation BIND → IPAM reste à faire).
- Kea 2.4 (Ubuntu 24.04) n'offre pas GSS-TSIG : le DDNS sécurisé vers Active Directory exige Kea 3.x.
- Certificat TLS auto-signé ; CSP de la console avec `'unsafe-inline'` ; pas de haute disponibilité ; volume PostgreSQL dédié non séparé.
