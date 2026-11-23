# Manifestes de rotation de la clé de signature des mises à jour

Ce dossier est vide tant qu'aucune rotation n'a eu lieu. Il ne contient **que** des fichiers publics :
`key-rotation-NNN.json` et sa signature `key-rotation-NNN.json.sig`, produite **hors ligne** par la clé de secours.

- `release.yml` joint ces fichiers à chaque release ; une appliance les applique avant de vérifier une archive
  (`src/rootfs/usr/local/lib/ddibuntu/release-keys.sh`).
- `tools/release-keys.sh check-rotations` contrôle qu'ils sont consécutifs, valides et signés par la clé de secours épinglée.
- Procédure complète (rotation planifiée, révocation d'urgence) : [docs/RELEASING.md](../../docs/RELEASING.md#rotation-et-révocation-de-la-clé).

Aucune clé privée ne doit jamais entrer dans ce dépôt.
