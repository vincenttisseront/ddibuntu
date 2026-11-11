# Publier une version

## Publication automatique (recommandée) — ce que les appliances interrogent
1. Mettre à jour `src/VERSION`, `src/rootfs/usr/local/lib/ddibuntu/VERSION` et `CHANGELOG.md` (la section `## X.Y.Z` devient les notes de version affichées dans la console).
2. Pousser sur `main`. Le workflow `release.yml` se déclenche quand `src/VERSION` change : si la release `vX.Y.Z` n'existe pas encore, il construit la console, lance lint et tests, produit `ddibuntu-update-X.Y.Z.tar.gz` (`build-ddibuntu.sh --bundle`) et le fichier unique, **signe `SHA256SUMS` (Ed25519)** avec le secret `UPDATE_SIGNING_KEY`, contrôle la signature avec la clé publique du dépôt, puis **crée la release et le tag `vX.Y.Z`** sur le commit testé. Aucun `git tag` à pousser. (Pousser un tag `vX.Y.Z` à la main fonctionne toujours ; le tag doit alors égaler `src/VERSION`.)
3. Si la release existe déjà, le workflow s'arrête sans rien faire. Pour republier une version, supprimer d'abord sa release et son tag.
4. Les appliances voient la nouvelle version à leur prochaine recherche (quotidienne ou bouton) ; l'administrateur l'installe depuis la console.

**Clé de signature** : la clé publique `src/rootfs/etc/ddibuntu/update-pubkey.pem` est embarquée dans chaque appliance ; la clé privée n'existe que dans le secret GitHub `UPDATE_SIGNING_KEY`. Pour la renouveler : `openssl genpkey -algorithm ed25519 -out k.pem`, `openssl pkey -in k.pem -pubout -out src/rootfs/etc/ddibuntu/update-pubkey.pem`, `gh secret set UPDATE_SIGNING_KEY < k.pem`, puis publier une version signée avec **l'ancienne** clé qui embarque la nouvelle clé publique (les appliances n'acceptent que ce qui est signé par la clé qu'elles ont déjà). Une clé perdue ou compromise impose de réinstaller par ISO ou de poser le nouveau fichier à la main sur chaque appliance.

**Dépôt privé** : poser un jeton GitHub en lecture seule dans `/etc/ddibuntu/update-token` (root, 0600) sur chaque appliance. Dépôt autre : éditer `REPO` dans `/etc/ddibuntu/update.conf`.

L'archive de mise à jour ne contient ni Ubuntu, ni paquets, ni Node.js : elle remplace la console, les scripts et les unités. Les paquets système (BIND, Kea…) restent à jour par `apt` ; un changement de Node.js passe par l'ISO (mode Update).

## Publication depuis un poste Windows (sans GitHub Actions)
`.\make-iso.ps1 -Bundle -SigningKey dist\update-signing.key` construit l'ISO **et** `ddibuntu-update-<version>.tar.gz`, puis signe `SHA256SUMS` (contrôle avec la clé publique du dépôt). Créer ensuite la release en joignant `ddibuntu-update-<version>.tar.gz`, `SHA256SUMS` et `SHA256SUMS.sig` : `gh release create v<version> dist/ddibuntu-update-<version>.tar.gz dist/SHA256SUMS dist/SHA256SUMS.sig --title "DDI-Buntu <version>" --notes-file notes.md` (ou depuis la page Releases de GitHub).

## Publication manuelle (fichiers seuls)

1. Mettre à jour `src/VERSION` et `CHANGELOG.md`.
2. `tools/build-console.sh`, puis `make test-unit`, `make test-e2e` et `make test-shell`.
3. `make single` produit `dist/build-ddibuntu.sh` (script racine + charge utile).
4. `dist/build-ddibuntu.sh --makeps1 --out dist` produit le lanceur Windows `build-ddibuntu.ps1` (l'empreinte du fichier unique y est vérifiée au lancement).
5. `cd dist && sha256sum build-ddibuntu.sh build-ddibuntu.ps1 > SHA256SUMS.txt`.
6. Créer une *release* GitHub avec ces trois fichiers ; l'ISO n'est pas publiée (elle dépend de l'ISO Canonical, construite par chaque utilisateur).
