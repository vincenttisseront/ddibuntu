# Intégration et publication continues

Une version n'arrive sur les appliances qu'après trois barrières : la **CI** sur chaque PR, la **version candidate** construite et signée une seule fois, puis la **validation sur une vraie appliance de dev** pilotée par AWX. Le passage en release publique est automatique quand tout est vert. Ce qui est publié est exactement ce qui a été testé : même fichier, même empreinte.

```
 PR ──► ci.yml + codeql.yml ──► fusion sur main (protégée : « ci-ok » requis)
                                     │  src/VERSION a changé
                                     ▼
                             release.yml : CI rejouée ─► construction + signature + SBOM + provenance ─► PRÉ-VERSION vX.Y.Z
                                                                                                           │ (canal stable : invisible)
                                                         AWX (planning 15 min) ◄───── lit la pré-version ──┘
                                                         appliance de dev : mise à jour en ligne + ddibuntu-selftest
                                                                     │ repository_dispatch « dev-validation »
                                                                     ▼
                             promote.yml : signature + empreinte installée ─► ✅ release publique (latest)
                                                                           └► ❌ rejetée + issue
```

## 1. CI — `.github/workflows/ci.yml`

Lancée sur chaque PR, chaque push sur `main` et, en `workflow_call`, par chaque publication. `ci-ok` résume la CI : il échoue dès qu'un travail échoue ou est annulé. Les contrôles à exiger sur `main` sont listés en section 5.

| Travail | Contenu | Bloquant si |
|---|---|---|
| `lint` | `make lint` (shellcheck de tous les scripts), **actionlint** (workflows et leurs scripts), `b02-i18n`, `b09-selfupdate`, `b43-selftest` | un défaut est trouvé |
| `awx` | **ansible-lint** (profil `production`) sur `deploy/awx/`, `b44-awx-validation` (le playbook contre un faux GitHub) | idem |
| `secrets` | **gitleaks** sur **tout l'historique** (règles par défaut + `.gitleaks.toml`), résultats dans l'onglet *Security* | un secret est trouvé |
| `deps` | **osv-scanner** sur `webui/package-lock.json` ; en PR, **dependency-review** (dépendance ajoutée de gravité ≥ moyenne), une fois le *Dependency graph* activé et la variable `DEPENDENCY_REVIEW=on` posée | une vulnérabilité hors exceptions est trouvée, ou une exception a expiré |
| `unit` | construction de la console, typage du serveur, **tests unitaires** avec couverture | un test échoue |
| `e2e` | **tous les tests de bout en bout** (61 fichiers, ~840 tests) contre la console construite et un vrai **PostgreSQL 16** (locale `en_US.UTF-8`, celle de l'appliance), en 4 lots parallèles | un test échoue |
| `build` | archive de mise à jour et fichier unique construits depuis le dépôt | la construction échoue |
| `sonar` | **SonarQube Cloud**. Avec le secret `SONAR_TOKEN` (et l'*Automatic Analysis* désactivée) : analyse ici avec la couverture, quality gate attendu et bloquant. Sans secret : SonarQube Cloud analyse seul et publie le contrôle **« SonarCloud Code Analysis »**, qui est alors le quality gate à exiger | le quality gate échoue (nouveau code : fiabilité, sécurité, maintenabilité, duplication ≤ 3 %, points sensibles revus) |

`codeql.yml` analyse la console (JavaScript/TypeScript) et les workflows avec les requêtes `security-extended`, sur chaque PR, sur `main` et chaque lundi. Les résultats arrivent dans l'onglet *Security*.

**Chaîne d'approvisionnement.** Toutes les actions sont **épinglées par empreinte de commit**. Les outils téléchargés (gitleaks, osv-scanner, actionlint) le sont avec leur **SHA-256**. Chaque travail reçoit les seuls droits dont il a besoin, et `persist-credentials: false` est posé partout. Dependabot (`.github/dependabot.yml`) propose chaque semaine les mises à jour des actions et des dépendances npm. Chaque proposition passe toute la CI.

**Exceptions.**
- `webui/osv-scanner.toml` liste les vulnérabilités connues acceptées. Chacune a une raison et une **date de fin** : au-delà, la CI échoue de nouveau. La ligne de base du 2026-11-22 attend la mise à niveau de zod 4, vitest 4 et nuxt.
- `.gitleaks.toml` n'exempte que la règle heuristique `generic-api-key`, et seulement dans les tests et les traductions. Une vraie clé privée ou un vrai jeton reste bloquant partout.

## 2. Version candidate — `.github/workflows/release.yml`

Elle se déclenche par un push sur `main` qui change `src/VERSION`, ou à la main (*Actions → release → Run workflow*) pour relancer une construction échouée. Dans les deux cas, **depuis `main` seulement** : la clé de signature ne signe que du code fusionné.

1. **Contrôles** : `src/VERSION` et `src/rootfs/usr/local/lib/ddibuntu/VERSION` sont identiques, et `CHANGELOG.md` contient une section `## X.Y.Z`. Si `vX.Y.Z` existe déjà (candidate, rejetée ou publiée), rien n'est fait : un numéro n'est jamais reconstruit.
2. **CI complète** rejouée sur le commit exact (appel de `ci.yml`).
3. **Construction unique** à partir de la console construite et testée par cette CI. On produit l'archive `ddibuntu-update-X.Y.Z.tar.gz` (avec ses paquets embarqués), le fichier unique `build-ddibuntu.sh`, puis `SHA256SUMS` **signé Ed25519** (secret `UPDATE_SIGNING_KEY`) et contrôlé avec la clé publique du dépôt. S'y ajoutent le **SBOM** CycloneDX des dépendances livrées de la console et l'**attestation de provenance** GitHub (Sigstore). On la vérifie avec `gh attestation verify ddibuntu-update-X.Y.Z.tar.gz --repo <propriétaire>/<dépôt>`.
4. **Publication en pré-version** `vX.Y.Z`, avec le bandeau « ⏳ Version candidate ». Les appliances du canal `stable` ne lisent que `releases/latest` et ne voient pas les pré-versions. Celles du canal `prerelease` ne prennent jamais une candidate rejetée.

Le titre des releases vient de la variable de dépôt `PRODUCT_NAME`, avec « DDI-Buntu » par défaut. Changer le nom du produit ne demande donc aucune modification des workflows.

## 3. Validation sur l'instance de dev — AWX

Mise en place et détail : [deploy/awx/README.md](../deploy/awx/README.md).

L'instance de dev est une appliance autonome dédiée, réglée sur le canal **`prerelease`** (`CHANNEL=prerelease` dans `/etc/ddibuntu/update.conf`, à partir de la 0.22.2). Toutes les 15 minutes, AWX y joue `deploy/awx/dev-validation.yml` :

- il installe la version candidate **par la vraie mise à jour en ligne**, avec signature, sauvegarde, migrations et retour arrière ; la mise à jour depuis la version précédente est donc elle-même testée ;
- il lance `ddibuntu-selftest`, le test de fumée embarqué dans chaque version : version servie par la console, état de la mise à jour, services attendus, PostgreSQL, disques, certificat, `named-checkconf`, `kea-dhcp4 -t`, réponse DNS réelle d'une zone primaire ;
- il envoie le verdict à GitHub par une **requête sortante**. Aucune ouverture de votre réseau n'est nécessaire. Le dépôt étant public, le rapport ne donne que les noms et résultats des contrôles : aucun nom d'hôte, de zone ni d'adresse. Le détail reste dans la sortie du travail AWX.

## 4. Promotion — `.github/workflows/promote.yml`

Le workflow reçoit l'événement `dev-validation` : `{version, result, bundle_sha256, report, job_url}`.

- Il ne traite qu'une **pré-version qui attend encore un verdict**. Un verdict en double ou tardif ne change rien.
- Il **revérifie la signature** de `SHA256SUMS`, puis compare l'empreinte de l'archive **installée sur l'instance de dev** (`/var/lib/ddibuntu/installed-bundle.sha256`) à celle de la release. Si elles diffèrent, il n'y a pas de promotion.
- Il refuse de remplacer une release publiée plus récente.
- **Succès** : `--prerelease=false --latest`. La release devient publique telle quelle, sans reconstruction, et ses notes reçoivent « ✅ Validée sur l'instance de dev le … ». Les appliances la proposent à leur prochaine recherche.
- **Échec** : les notes passent à « ❌ Rejetée — ne pas installer », une **issue** est ouverte avec le rapport, et le workflow finit en rouge. On corrige, puis on publie **X.Y.Z+1**. Un rejet qui porte l'empreinte d'une autre archive est ignoré.
- **Veille quotidienne** : une version candidate restée plus de 24 h sans verdict ouvre une issue.
- **Procédure de secours** (*Actions → promote → Run workflow*) : verdict saisi à la main avec l'empreinte relevée sur l'instance de dev (`/var/lib/ddibuntu/installed-bundle.sha256`). Elle n'est acceptée que **depuis `main` et par un administrateur du dépôt**. Les mêmes contrôles s'appliquent, et les notes de version indiquent qui l'a saisi.

## 5. Réglages du dépôt

| Élément | Où | Rôle |
|---|---|---|
| `UPDATE_SIGNING_KEY` | secret Actions | clé privée Ed25519 de signature (docs/RELEASING.md) |
| `SONAR_TOKEN` | secret Actions | analyse SonarQube Cloud (docs/QUALITE.md) |
| `PRODUCT_NAME` | variable Actions (facultative) | nom du produit dans le titre des releases |
| Jeton AWX | identifiant AWX | jeton à granularité fine, ce dépôt seul, *Contents : Read and write* (exigé par `repository_dispatch`), un an au plus |
| `DEPENDENCY_REVIEW` | variable Actions | `on` une fois le *Dependency graph* activé (*Settings → Security*) : active dependency-review en PR |
| Protection de `main` | *Settings → Rules → Rulesets* | PR obligatoire ; contrôles requis **`ci-ok`**, **`analyze (javascript-typescript)`**, **`analyze (actions)`** et, en analyse automatique, **`SonarCloud Code Analysis`** ; pas de force-push ni de suppression. Le jeton AWX ne peut donc pas pousser de code. |

Le jeton AWX ne permet pas de publier une version acceptée par les appliances. Celles-ci et `promote.yml` vérifient la signature faite avec une clé que seul GitHub Actions détient.

**À la prochaine rotation de la clé de signature** (docs/RELEASING.md), placez la nouvelle clé dans un *environment* `release` limité à `main`, plutôt que dans les secrets du dépôt. Elle ne sera alors lisible que par les travaux de publication.

## 6. Ce qui reste hors de la CI

Les batteries qui demandent root, un vrai réseau ou des machines virtuelles (b03–b08, `*-live`, cluster, AD, PKI réelle) se rejouent sur une machine Linux de test (docs/TESTING.md). L'instance de dev valide une appliance **autonome**. La mise à jour progressive d'un cluster est couverte par `b26-cluster-update-live.sh`, pas par la chaîne.
