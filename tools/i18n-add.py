#!/usr/bin/env python3
"""Ajoute des clés aux deux catalogues (fr = source, en) ; refuse un doublon. Usage : i18n-add.py WEBUI fichier.json  ({clé: [fr, en]})"""
import json, sys, os
root, src = sys.argv[1], sys.argv[2]
add = json.load(open(src, encoding='utf-8'))
for i, lang in enumerate(('fr', 'en')):
    p = os.path.join(root, 'app/i18n', lang + '.ts'); s = open(p, encoding='utf-8').read()
    cut = s.rindex('}\nexport default messages')
    todo = {k: v for k, v in add.items() if f'"{k}":' not in s}   # une clé déjà présente est conservée telle quelle (jamais écrasée)
    if len(todo) != len(add): print(lang, ': clés déjà présentes, conservées :', [k for k in add if k not in todo])
    lines = ''.join(f'  {json.dumps(k, ensure_ascii=False)}: {json.dumps(v[i], ensure_ascii=False)},\n' for k, v in todo.items())
    open(p, 'w', encoding='utf-8').write(s[:cut] + lines + s[cut:])
print(len(add), 'clés ajoutées')
