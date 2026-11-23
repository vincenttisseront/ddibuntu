# Publier une version

## Publication automatique (recommandée) — ce que les appliances interrogent
Chaîne complète, contrôles et réglages : [CI-CD.md](CI-CD.md).

1. Dans une PR : mettre à jour `src/VERSION`, `src/rootfs/usr/local/lib/ddibuntu/VERSION` et `CHANGELOG.md`. La section `## X.Y.Z` devient les notes de version affichées dans la console, et le workflow refuse une version sans section.
2. Fusionner la PR (contrôle `ci-ok` vert). Le workflow `release.yml` se déclenche parce que `src/VERSION` a changé. Si `vX.Y.Z` n'existe pas encore, il rejoue toute la CI sur le commit, puis construit **une seule fois** `ddibuntu-update-X.Y.Z.tar.gz` (`build-ddibuntu.sh --bundle`, environ 46 Mo, avec **`debs/` = podman, freeradius, freeradius-ldap et leurs dépendances**, résolus dans un conteneur Ubuntu 24.04 neuf) et le fichier unique. Un travail séparé, rattaché à l'*environment* `release`, **signe `SHA256SUMS` (Ed25519)** avec le secret `RELEASE_SIGNING_KEY` ; il refuse une clé hors du jeu épinglé et contrôle la signature comme une appliance (voir « Clés de signature » plus bas). Il produit enfin le SBOM et l'attestation de provenance, et **publie une pré-version `vX.Y.Z`** sur le commit testé. Aucun `git tag` n'est à pousser.
3. Les appliances du canal `stable` ne voient pas la pré-version. L'**instance de validation** (AWX, `deploy/awx/`) l'installe, lance `ddibuntu-selftest` et rend son verdict. Si tout est vert, `promote.yml` en fait la **release publique** (« latest ») sans rien reconstruire. Sinon, elle est marquée rejetée et une issue est ouverte : corriger, puis publier X.Y.Z+1.
4. Si la release existe déjà (candidate, rejetée ou publiée), `release.yml` s'arrête sans rien faire : un numéro n'est jamais reconstruit, on publie X.Y.Z+1. *Actions → release → Run workflow* (depuis `main`) relance seulement une construction qui a échoué avant de créer la release. Ne jamais supprimer une release **publiée** : des appliances l'ont peut-être installée.
5. Les appliances voient la nouvelle version à leur prochaine recherche (quotidienne ou bouton). L'administrateur l'installe depuis la console.

**Paquets embarqués (0.14.11)** : l'archive de mise à jour contient `debs/` (les `.deb`, `SHA256SUMS`, `REQUESTED`) ; ils sont signés avec elle (la signature porte sur `SHA256SUMS` de la release, qui contient l'empreinte de l'archive). La liste est `DDI_UPDATE_PACKAGES` dans `build-ddibuntu.sh` — **à garder identique à `src/rootfs/usr/local/lib/ddibuntu/update-packages`** et incluse dans `DDI_PACKAGES` (`tests/b09-selfupdate.sh` le contrôle). Construction en local : avec Docker ou Podman, `./build-ddibuntu.sh --bundle --out dist` (les paquets se résolvent dans un conteneur `ubuntu:24.04` neuf, jamais sur la machine) ; dans un conteneur `ubuntu:24.04` **neuf** (c'est ce que fait `make-iso.ps1`), `DDI_CLEAN_CONTAINER=1` résout sur place. **`--skip-debs` produit une archive SANS paquets : ne jamais la publier** (les nœuds mis à jour n'auraient pas podman). Les paquets sont ceux d'Ubuntu au jour de la construction : republier une version si un correctif de sécurité de ces paquets doit être livré par la mise à jour.

Clés de signature : voir [plus bas](#clés-de-signature).

**Dépôt privé** : poser un jeton GitHub en lecture seule dans `/etc/ddibuntu/update-token` (root, 0600) sur chaque appliance. Dépôt autre : éditer `REPO` dans `/etc/ddibuntu/update.conf`.

L'archive de mise à jour ne contient ni Ubuntu, ni paquets, ni Node.js : elle remplace la console, les scripts et les unités. Les paquets système (BIND, Kea…) restent à jour par `apt` ; un changement de Node.js passe par l'ISO (mode Update).

## Clés de signature

Depuis la 0.24.0, une appliance fait confiance à un **jeu de clés publiques Ed25519** et non plus à une seule clé ; une signature valide pour l'une d'elles suffit. Mêmes règles sur l'appliance (`src/rootfs/usr/local/lib/ddibuntu/release-keys.sh`), dans `release.yml`, dans `promote.yml` et dans `make-iso.ps1` (`tools/release-keys.sh`).

| Clé | Rôle | Clé publique (dépôt → appliance) | Clé privée |
|---|---|---|---|
| active | signe `SHA256SUMS` de chaque version | `src/rootfs/etc/ddibuntu/keys/release.d/*.pem` | secret `RELEASE_SIGNING_KEY` de l'*environment* `release`, limité à `main` |
| ancienne (transition) | clé unique d'avant la 0.24.0, encore acceptée | `src/rootfs/etc/ddibuntu/update-pubkey.pem` | ancien secret `UPDATE_SIGNING_KEY`, à supprimer après la bascule |
| secours | signe **uniquement** les manifestes de rotation ; jamais une archive | `src/rootfs/etc/ddibuntu/keys/release-secours.pem` | **hors ligne** (coffre), jamais sur GitHub ni sur un poste connecté |

L'**empreinte** d'une clé est le SHA-256 de sa clé publique au format DER : `openssl pkey -pubin -in k.pub -outform DER | sha256sum` (Windows : `openssl pkey -pubin -in k.pub -outform DER -out k.der` puis `(Get-FileHash k.der).Hash.ToLower()`). Sur une appliance, `ddibuntu-selfupdate keys` liste les clés de confiance, la clé de secours, les empreintes révoquées et la dernière rotation ; `ddibuntu-selftest` contrôle qu'il y a au moins une clé de confiance et une clé de secours.

Claude ne reçoit et ne manipule que des clés **publiques**.

### Bascule vers la clé active (une seule fois)
1. Installer la 0.24.0 (signée par l'ancienne clé, donc acceptée partout) sur **tous** les nœuds et sur l'instance de validation ; vérifier avec `ddibuntu-selfupdate keys` que la clé active y figure.
2. Créer l'*environment* `release` (*Settings → Environments*), limité à la branche `main`, puis y poser la clé active : `gh secret set RELEASE_SIGNING_KEY --env release < ipnoria-release.key`.
3. Supprimer l'ancien secret : `gh secret delete UPDATE_SIGNING_KEY`. La version suivante est signée par la clé active.
4. Une version ultérieure retire l'ancienne clé du jeu (code de `ddibuntu-selfupdate`), quand plus aucune appliance n'a de raison d'en dépendre.

### Rotation et révocation de la clé
Un **manifeste de rotation** révoque des empreintes et, au besoin, ajoute une nouvelle clé active. Il n'est accepté que s'il est signé par la clé de secours épinglée. L'appliance l'applique **avant** de vérifier une archive, une seule fois (numéro de séquence croissant, jamais rejoué), et ne fait plus jamais confiance à une empreinte révoquée, même si une version la relivre. Même mécanisme pour une rotation planifiée et pour une **révocation d'urgence** (clé active compromise).

```json
{"format": 1, "usage": "release", "sequence": 1, "date": "AAAA-MM-JJ", "reason": "motif",
 "old_fingerprints": ["<empreinte révoquée>"], "new_public_key": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n"}
```
`new_public_key` peut valoir `null` (révocation seule). Procédure, sur un poste **hors ligne** pour l'étape de signature :

1. Générer la nouvelle clé active (`openssl genpkey -algorithm ed25519 -out nouvelle.key`, `openssl pkey -in nouvelle.key -pubout -out nouvelle.pub`) et calculer l'empreinte de la clé à révoquer.
2. Écrire le manifeste (numéro = dernier + 1), en UTF-8 sans BOM. Sous Windows :
   ```powershell
   $pub = (Get-Content .\nouvelle.pub -Raw) -replace "`r`n", "`n"
   $m = [ordered]@{ format = 1; usage = 'release'; sequence = 1; date = (Get-Date -Format 'yyyy-MM-dd'); reason = 'rotation planifiee'; old_fingerprints = @('<empreinte>'); new_public_key = $pub }
   [IO.File]::WriteAllText("$PWD\key-rotation-001.json", ($m | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
   ```
3. Le signer avec la clé de secours, sortie du coffre pour l'occasion : `openssl pkeyutl -sign -inkey ipnoria-release-secours.key -rawin -in key-rotation-001.json -out key-rotation-001.json.sig`. Ranger la clé de secours.
4. Ajouter `key-rotation-001.json` et `.sig` dans `keys/rotations/` par une PR (`tools/release-keys.sh check-rotations` les contrôle en CI), et la nouvelle clé publique dans `src/rootfs/etc/ddibuntu/keys/release.d/` si elle doit être livrée aussi aux nouvelles installations.
5. Remplacer le secret `RELEASE_SIGNING_KEY` par la nouvelle clé privée, puis publier une version : elle est signée par la nouvelle clé, et `release.yml` joint les manifestes à **chaque** release (une appliance qui saute des versions les trouve sur la dernière).
6. Après une rotation d'urgence, générer hors ligne une **nouvelle clé de secours** et l'épingler par la version suivante (`keys/release-secours.pem`).

Une clé **perdue** sans clé de secours, ou la clé de secours elle-même compromise, impose encore de réinstaller par ISO ou de poser les fichiers à la main sur chaque appliance.

## Publication depuis un poste Windows (sans GitHub Actions)
`.\make-iso.ps1 -Bundle -SigningKey dist\update-signing.key` construit l'ISO **et** `ddibuntu-update-<version>.tar.gz`, puis signe `SHA256SUMS` (la clé doit être une clé de confiance du dépôt, et la signature est contrôlée comme sur une appliance). Créer ensuite la release en joignant `ddibuntu-update-<version>.tar.gz`, `SHA256SUMS` et `SHA256SUMS.sig` : `gh release create v<version> dist/ddibuntu-update-<version>.tar.gz dist/SHA256SUMS dist/SHA256SUMS.sig --title "Ipnoria <version>" --notes-file notes.md` (ou depuis la page Releases de GitHub).

## Publication manuelle (fichiers seuls)

1. Mettre à jour `src/VERSION` et `CHANGELOG.md`.
2. `tools/build-console.sh`, puis `make test-unit`, `make test-e2e` et `make test-shell`.
3. `make single` produit `dist/build-ddibuntu.sh` (script racine + charge utile).
4. `dist/build-ddibuntu.sh --makeps1 --out dist` produit le lanceur Windows `build-ddibuntu.ps1` (l'empreinte du fichier unique y est vérifiée au lancement).
5. `cd dist && sha256sum build-ddibuntu.sh build-ddibuntu.ps1 > SHA256SUMS.txt`.
6. Créer une *release* GitHub avec ces trois fichiers ; l'ISO n'est pas publiée (elle dépend de l'ISO Canonical, construite par chaque utilisateur).
