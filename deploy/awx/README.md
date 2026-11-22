# Instance de validation pilotée par AWX

Ce dossier contient tout ce qu'AWX exécute pour l'étape « validation » de la chaîne de publication (vue d'ensemble : [docs/CI-CD.md](../../docs/CI-CD.md)).

| Fichier | Rôle |
|---|---|
| `dev-validation.yml` | Le playbook : cherche la version candidate en attente, l'installe sur l'appliance de dev, lance `ddibuntu-selftest`, envoie le verdict à GitHub. |
| `credential-type-github.yml` | Le type d'identifiants AWX qui fournit le dépôt et le jeton GitHub au playbook. |
| `inventory.example.yml` | Un modèle d'inventaire (une seule appliance). |

Le playbook est rejoué à chaque PR contre un faux GitHub (`tests/b44-awx-validation.sh`, job `awx` de la CI).

## Prérequis

- **Une appliance de dev dédiée**, autonome (hors cluster), installée depuis l'ISO puis mise à jour au moins en **0.22.2** (première version qui sait lire le canal `prerelease`). Elle ne doit porter aucun service de production : on y installe des versions qui n'ont pas encore été validées.
- Depuis l'appliance de dev : accès sortant HTTPS à `api.github.com` et `github.com`.
- Depuis AWX : accès SSH à l'appliance de dev, et accès sortant HTTPS à `api.github.com`.
- Sur l'appliance de dev, un compte pour AWX avec `sudo` sans mot de passe (ou mot de passe de `become` dans l'identifiant AWX).

Rien n'entre dans votre réseau depuis GitHub : AWX va chercher la version candidate, puis rend son verdict par une requête sortante.

## Mise en place (une fois)

1. **Jeton GitHub.** Créez un jeton à granularité fine (GitHub → Settings → Developer settings → Fine-grained tokens) :
   - *Repository access* : uniquement le dépôt de l'appliance ;
   - *Permissions* : **Contents : Read and write** (exigé par l'API `repository_dispatch`), **Metadata : Read** ;
   - *Expiration* : un an au plus. Notez la date : un jeton expiré bloque les publications. La veille quotidienne de `promote.yml` ouvre alors une issue après 24 h sans verdict.

   Ce jeton peut écrire dans le dépôt. La protection de `main` (docs/CI-CD.md) l'empêche de pousser du code. Il ne peut pas non plus fabriquer une release acceptée par les appliances : seule la clé de signature, gardée dans les secrets GitHub, le permet.
2. **Type d'identifiants.** Dans AWX : *Administration → Types d'identifiants → Ajouter*, nom « Chaîne de publication (GitHub) ». Collez la partie `inputs` de `credential-type-github.yml` dans la configuration des entrées, et la partie `injectors` dans celle de l'injecteur.
3. **Identifiants.**
   - Un identifiant du type ci-dessus, avec le dépôt (`propriétaire/nom`) et le jeton.
   - Un identifiant *Machine* : clé SSH du compte AWX sur l'appliance de dev, méthode d'élévation `sudo`.
4. **Projet.** *Ressources → Projets → Ajouter* : type Git, URL du dépôt de l'appliance, branche `main`, option « Mettre à jour la révision au lancement ». Le dépôt étant public, aucun identifiant n'est nécessaire.
5. **Inventaire.** Créez un inventaire avec un groupe **`appliance_dev`** contenant **une seule** appliance (modèle : `inventory.example.yml`). Le playbook refuse de tourner sur plusieurs hôtes.
6. **Modèle de tâche.** *Ressources → Modèles → Ajouter un modèle de tâche* :
   - inventaire : celui de l'étape 5 ; projet : celui de l'étape 4 ; playbook : `deploy/awx/dev-validation.yml` ;
   - identifiants : la *Machine* et la « Chaîne de publication (GitHub) » ;
   - variables (facultatif) : `awx_public_url: https://awx.votre-domaine`. Le verdict portera un lien vers le travail AWX, **visible publiquement** dans les notes de version et les issues : laissez vide si l'adresse de votre AWX doit rester confidentielle.
   - Ne cochez pas « Élévation des privilèges » : le playbook la demande lui-même (`become: true`).
7. **Planning.** Dans le modèle, onglet *Plannings* : toutes les **15 minutes**. Un passage sans version candidate en attente se termine en quelques secondes, sans rien toucher.
8. **Premier essai.** Lancez le modèle à la main : « Aucune version candidate n'attend de verdict » est le résultat attendu tant que rien n'a été publié.

## Ce que fait un passage

1. Il lit les releases du dépôt et retient la plus récente des pré-versions qui portent encore le bandeau `<!-- validation:pending -->`. Les brouillons sont ignorés.
2. Il pose `CHANNEL=prerelease` dans `/etc/ddibuntu/update.conf`, puis lance `ddibuntu-selfupdate apply X.Y.Z`. C'est la vraie mise à jour en ligne, avec la vérification de la signature, la sauvegarde, les migrations et le retour arrière si la console ne redémarre pas.
3. Il lance `ddibuntu-selftest --expect-version X.Y.Z --wait 300 --json`. Le test contrôle la version servie, l'état de la mise à jour, les services attendus, PostgreSQL, les disques, le certificat de la console, les configurations BIND et Kea, et une réponse DNS réelle.
4. Il envoie à GitHub `{version, result, bundle_sha256, report, job_url}`. `bundle_sha256` vient de `/var/lib/ddibuntu/installed-bundle.sha256` : c'est la preuve que la version validée est bien celle de la release.
5. Si la version candidate est rejetée, le travail AWX échoue lui aussi. L'issue ouverte sur GitHub donne le contrôle ou l'étape en cause, sans détail sur votre infrastructure (dépôt public). Le détail complet se trouve dans la sortie du travail AWX.

L'instance de dev reste sur la version candidate, même rejetée, pour qu'on puisse l'examiner. Pour revenir en arrière : `ddibuntu-rollback` sur l'appliance, ou réinstallation depuis l'ISO.

## Dépannage

| Symptôme | Piste |
|---|---|
| Issue « … sans verdict de l'instance de validation » | Le planning AWX est-il actif ? L'appliance de dev est-elle allumée ? Le jeton a-t-il expiré ? Relancez le modèle à la main et lisez la sortie. |
| `Mise à jour en ligne vers la version candidate` échoue | Lisez `/var/lib/ddibuntu/update-status.json` et `journalctl -t ddibuntu-selfupdate` sur l'appliance de dev. L'appliance est-elle au moins en 0.22.2 ? |
| Verdict refusé par `promote.yml` (« une autre archive ») | L'empreinte relevée sur l'appliance de dev n'est pas celle de la release : l'appliance a été modifiée à la main, ou une ancienne installation est restée. Réinstallez l'appliance de dev, puis publiez X.Y.Z+1. |
| Tests de fumée en échec | Le rapport donne le contrôle en cause. `ddibuntu-selftest` sur l'appliance de dev produit le même tableau. |
