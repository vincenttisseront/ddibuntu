# Qualité du code — SonarQube Cloud et plan de remédiation

Projet : `vincenttisseront_ddibuntu` (organisation `vincenttisseront`). L'analyse est lancée par la CI (`.github/workflows/ci.yml`, job `sonar`) avec la couverture
des tests unitaires de la console ; la configuration est dans `sonar-project.properties`.

## Mise en route (une fois)
1. SonarQube Cloud → *My Account → Security* : créer un jeton, puis GitHub → *Settings → Secrets and variables → Actions* : secret **`SONAR_TOKEN`**.
2. SonarQube Cloud → projet → *Administration → Analysis Method* : **désactiver « Automatic Analysis »** (l'analyse automatique et l'analyse CI se contredisent).
3. Après un premier passage vert : activer l'attente de la porte qualité (`sonar.qualitygate.wait=true` dans `sonar-project.properties`) pour qu'une régression bloque la CI.
Sans le secret, le job s'exécute (tests + couverture) mais saute l'analyse : forks et premier démarrage ne cassent rien.

## État initial (13/11/2026, analyse automatique, 656 problèmes ouverts)
| Famille | Nombre | Nature | Décision |
|---|---|---|---|
| `shell:S7688` (préférer `[[ ]]`) | 549 | style des scripts shell, dont 404 dans les batteries de tests | tests = code de test (hors périmètre) ; `src/iso/*` = POSIX sh, règle écartée ; reste converti par lots (lot 4) |
| `typescript:S9383` promesses non attendues | 18 | fiabilité | **corrigé** (lot 1) : `void` explicite |
| `typescript:S8786` regex à retour arrière | 14 | déni de service (ReDoS) | **corrigé** (lot 1) : analyses linéaires (`text.ts`), regex bornées |
| `typescript:S6323` alternative vide | 4 | lisibilité | **corrigé** (lot 1) |
| `typescript:S2871` tri sans comparateur | 2 | fiabilité | **corrigé** (lot 1) : comparateur explicite, ordre inchangé (empreintes de snapshots) |
| `pythonsecurity:S8707` traversée de chemin | 3 | sécurité (outil de développement) | **corrigé** (lot 1) : arguments validés |
| `typescript:S2699` test sans assertion | 1 | **bloquant** | **corrigé** (lot 1) |
| `typescript:S4036` PATH | 3 | sécurité faible | **corrigé** pour `ping` (chemin absolu) ; l'assistant de test SMTP est du code de test |
| `githubactions:S8233` | 1 | permissions du workflow | **corrigé** (lot 1) : écriture au niveau du seul travail `release` |
| `shell:S6505`, `S8541` (npm/npx/pip) | 7 | chaîne d'approvisionnement | `npx --no-install` partout (lot 1) ; `npm ci` conserve les scripts d'installation (nécessaires à Nuxt), lockfile figé → revue « sûr » |
| `shell:S5332/S6506/S4790` | 9 | hotspots dans tests/outils (URL http locales, empreinte MD5 d'une ISO) | revue : sans risque (données publiques, vérification d'intégrité d'un fichier de test) |
| `typescript:S1313` IP en dur | 27 | faux positifs : plages réservées (RFC 1918, lien local…) que le produit doit connaître | écarté (propriétés) |
| `Web:S6853/S6840/S6842/S6843` accessibilité | 20 | faux positifs de composants (`<label>` autour de `UInput`) | écarté (propriétés) ; vraies corrections faites : `scope` des `<th>`, étiquette du champ fichier |

## Lots
- **Lot 0 — intégration** : job CI, couverture (vitest/v8, lcov), `sonar-project.properties`, séparation code/test. ✅ 0.9.51
- **Lot 1 — bugs et sécurité** (promesses, ReDoS, tri, test sans assertion, outil Python, permissions CI). ✅ 0.9.51
- **Lot 2 — hotspots** : revue et justification (tableau ci-dessus), à marquer « Safe » dans l'interface SonarQube Cloud après le premier passage CI.
- **Lot 3 — porte qualité** : activer l'attente de la porte, fixer le seuil de couverture du nouveau code (≥ 80 %), traiter les nouveaux problèmes avant fusion.
- **Lot 4 — `shell:S7688`** sur les scripts bash de production (`build-ddibuntu.sh`, `src/rootfs/**`, `tools/`), par fichier, avec `shellcheck` et les batteries système à chaque lot ; les scripts POSIX (`src/iso/*`) restent en `[ ]`.
- **Lot 5 — couverture** : mesurer la couverture réelle (aujourd'hui seuls les tests unitaires alimentent le rapport ; les tests e2e, qui couvrent l'essentiel des routes, ne sont pas encore agrégés) et l'augmenter sur `server/utils`.
