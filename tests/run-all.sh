#!/usr/bin/env bash
# run-all.sh — régression complète. Chaque batterie tourne dans son propre processus avec son
# propre journal (les sorties de deux processus ne sont jamais mêlées). Le script assemblé est
# reconstruit avant les tests : on teste toujours ce qui sera livré.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"; export ROOT
mkdir -p tests/logs tests/artifacts
rm -f tests/logs/*.log

tools/make-single.sh >tests/logs/00-assemblage.log 2>&1 || { cat tests/logs/00-assemblage.log; echo "ASSEMBLAGE EN ÉCHEC"; exit 1; }

total_pass=0; total_fail=0; batteries=0; broken=0
printf '%-26s %7s %7s\n' "batterie" "réussis" "échecs"
for b in tests/b[0-9][0-9]-*.sh; do
  name="$(basename "$b" .sh)"; log="tests/logs/$name.log"
  T_NAME="$name" bash "$b" >"$log" 2>&1
  rc=$?
  line="$(grep '^RESULT ' "$log" | tail -1 || true)"
  batteries=$((batteries + 1))
  if [ -z "$line" ]; then
    printf '%-26s %7s %7s   (aucun résultat : la batterie s'"'"'est arrêtée, voir %s)\n' "$name" "-" "?" "$log"
    broken=$((broken + 1)); continue
  fi
  p="$(printf '%s' "$line" | sed -n 's/.*pass=\([0-9]*\).*/\1/p')"; f="$(printf '%s' "$line" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')"
  total_pass=$((total_pass + p)); total_fail=$((total_fail + f))
  printf '%-26s %7d %7d\n' "$name" "$p" "$f"
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then broken=$((broken + 1)); fi
done
printf -- '----\n%d batteries, %d tests réussis, %d échecs, %d batteries interrompues\n' "$batteries" "$total_pass" "$total_fail" "$broken"
[ "$total_fail" -eq 0 ] && [ "$broken" -eq 0 ]
