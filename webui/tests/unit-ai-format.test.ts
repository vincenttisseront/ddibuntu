// 0.23.1 — mise en forme des réponses de l'assistant IA : titres, gras, code, listes ; jamais de HTML interprété.
import { describe, expect, it } from 'vitest'
import { aiBlocks, aiInline } from '../app/utils/aiFormat'

describe('mise en forme des réponses', () => {
  it('réponse type d\'un modèle : titres en gras, listes numérotées et à puces', () => {
    const b = aiBlocks("**Ce qui s'est passé**\nUn utilisateur a tenté de se connecter\ndepuis 192.168.2.155.\n\n**Cause probable**\n1. Identifiants incorrects.\n2. Compte **désactivé**.\n\n**À vérifier :**\n- Statut du compte\n- Journal `ldap`")
    expect(b.map((x) => x.k)).toEqual(['h', 'p', 'h', 'ol', 'h', 'ul'])
    expect(b[0]).toEqual({ k: 'h', parts: [{ t: 'text', v: "Ce qui s'est passé" }] })
    expect(b[1]).toEqual({ k: 'p', parts: [{ t: 'text', v: 'Un utilisateur a tenté de se connecter depuis 192.168.2.155.' }] })
    expect((b[3] as any).items[1]).toEqual([{ t: 'text', v: 'Compte ' }, { t: 'strong', v: 'désactivé' }, { t: 'text', v: '.' }])
    expect((b[4] as any).parts[0].v).toBe('À vérifier')
    expect((b[5] as any).items[1]).toEqual([{ t: 'text', v: 'Journal ' }, { t: 'code', v: 'ldap' }])
  })
  it('titres « # », séparateurs ignorés, gras orphelin retiré, HTML laissé en texte', () => {
    expect(aiBlocks('## Titre\n---\ntexte')).toEqual([{ k: 'h', parts: [{ t: 'text', v: 'Titre' }] }, { k: 'p', parts: [{ t: 'text', v: 'texte' }] }])
    expect(aiInline('a ** b')).toEqual([{ t: 'text', v: 'a  b' }])
    expect(aiInline('<img src=x onerror=alert(1)>')).toEqual([{ t: 'text', v: '<img src=x onerror=alert(1)>' }])
  })
})
