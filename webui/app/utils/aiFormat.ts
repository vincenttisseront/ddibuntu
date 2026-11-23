// Mise en forme légère des réponses de l'assistant IA (0.23.1) : titres, gras, code, listes. Aucun HTML n'est jamais interprété :
// le texte est découpé en blocs et en segments, rendus par le gabarit (interpolations Vue, donc échappées).
export type AiInline = { t: 'text' | 'strong' | 'code'; v: string }
export type AiBlock = { k: 'h' | 'p'; parts: AiInline[] } | { k: 'ul' | 'ol'; items: AiInline[][] }

export function aiInline(s: string): AiInline[] {
  const out: AiInline[] = []
  for (const m of s.split(/(\*\*[^*\n]+?\*\*|`[^`\n]+`)/)) {
    if (!m) continue
    if (m.startsWith('**') && m.endsWith('**') && m.length > 4) out.push({ t: 'strong', v: m.slice(2, -2) })
    else if (m.startsWith('`') && m.endsWith('`') && m.length > 2) out.push({ t: 'code', v: m.slice(1, -1) })
    else out.push({ t: 'text', v: m.replace(/\*\*/g, '') })
  }
  return out
}

export function aiBlocks(text: string): AiBlock[] {
  const blocks: AiBlock[] = []
  let para: string[] = []
  const flush = () => { if (para.length) { blocks.push({ k: 'p', parts: aiInline(para.join(' ')) }); para = [] } }
  const item = (k: 'ul' | 'ol', v: string) => {
    const last = blocks[blocks.length - 1]
    if (last && last.k === k) last.items.push(aiInline(v)); else blocks.push({ k, items: [aiInline(v)] })
  }
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || /^(-{3,}|\*{3,}|_{3,})$/.test(line)) { flush(); continue }
    const h = line.match(/^#{1,6}\s+(.+)$/) ?? line.match(/^\*\*(.+?)\*\*\s*:?$/) ?? line.match(/^__(.+?)__\s*:?$/)
    if (h) { flush(); blocks.push({ k: 'h', parts: aiInline(h[1]!.replace(/\*\*/g, '').replace(/\s*:$/, '')) }); continue }
    const ul = line.match(/^[-*•]\s+(.+)$/)
    if (ul) { flush(); item('ul', ul[1]!); continue }
    const ol = line.match(/^\d{1,2}[.)]\s+(.+)$/)
    if (ol) { flush(); item('ol', ol[1]!); continue }
    para.push(line)
  }
  flush()
  return blocks
}
