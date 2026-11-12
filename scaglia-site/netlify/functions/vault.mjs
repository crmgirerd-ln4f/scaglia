// Team Support: shared encrypted vault.
// The server only ever sees ciphertext. Access requires a token derived from the team code;
// the server keeps a SHA-256 hash of that token, never the token or the code.
import { getStore } from '@netlify/blobs'

const HEADERS = { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' }
const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: HEADERS })
const MAX = 4_000_000
const adminOf = async (req) => {
  const t = req.headers.get('x-admin') || ''
  return t.length >= 32 && t.length <= 200 ? sha256(t) : null
}

async function sha256(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export default async (req) => {
  if (new URL(req.url).pathname.endsWith('/lock')) return lockRoute(req)
  if (new URL(req.url).pathname.endsWith('/member')) return memberRoute(req)
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')
  if (token.length < 32 || token.length > 200) return reply({ error: 'auth' }, 401)
  const hash = await sha256(token)
  const store = getStore({ name: 'team-support', consistency: 'strong' })
  const cur = await store.getWithMetadata('vault', { type: 'json' })

  if (req.method === 'GET') {
    if (!cur) return reply({ empty: true })
    if (cur.data.auth !== hash) return reply({ error: 'code' }, 403)
    const q = new URL(req.url).searchParams
    if (q.get('probe')) return reply({ ok: true, rev: cur.data.rev })
    const since = Number(q.get('since'))
    const adm = await adminOf(req)
    const meta = { hasAdmin: !!cur.data.admin, isAdmin: !!(adm && cur.data.admin && adm === cur.data.admin) }
    if (since && since === cur.data.rev) return reply({ rev: cur.data.rev, same: true, at: cur.data.at, ...meta })
    return reply({ rev: cur.data.rev, blob: cur.data.blob, at: cur.data.at, ...meta })
  }

  if (req.method === 'PUT') {
    let body
    try { body = await req.json() } catch { return reply({ error: 'bad' }, 400) }
    if (!body || typeof body.blob !== 'string' || body.blob.length > MAX || !Number.isInteger(body.rev)) return reply({ error: 'bad' }, 400)
    const at = new Date().toISOString()
    if (!cur) {
      if (body.rev !== 0) return reply({ empty: true }, 409)
      const doc = { auth: hash, rev: 1, blob: body.blob, at }
      const w = await store.setJSON('vault', doc, { onlyIfNew: true })
      if (w && w.modified === false) return reply({ error: 'race' }, 409)
      return reply({ rev: 1, at })
    }
    if (cur.data.auth !== hash) return reply({ error: 'code' }, 403)
    if (body.rev !== cur.data.rev) return reply({ rev: cur.data.rev, blob: cur.data.blob, at: cur.data.at }, 409)
    const adm = await adminOf(req)
    const isAdmin = !!(adm && cur.data.admin && adm === cur.data.admin)
    let auth = hash, admin = cur.data.admin || null
    if (typeof body.setAdmin === 'string') {
      if (body.setAdmin.length < 32 || body.setAdmin.length > 200) return reply({ error: 'bad' }, 400)
      if (admin && !isAdmin) return reply({ error: 'admin' }, 403)
      admin = await sha256(body.setAdmin)
    }
    if (typeof body.newAuth === 'string') {
      if (!isAdmin) return reply({ error: 'admin' }, 403)
      if (body.newAuth.length < 32 || body.newAuth.length > 200) return reply({ error: 'bad' }, 400)
      auth = await sha256(body.newAuth)
    }
    const doc = { auth, admin, rev: cur.data.rev + 1, blob: body.blob, at }
    const w = await store.setJSON('vault', doc, { onlyIfMatch: cur.etag })
    if (w && w.modified === false) {
      const now = await store.get('vault', { type: 'json' })
      return reply({ rev: now.rev, blob: now.blob, at: now.at }, 409)
    }
    return reply({ rev: doc.rev, at, hasAdmin: !!admin, isAdmin: !!(admin && (isAdmin || (typeof body.setAdmin === 'string'))) })
  }

  return reply({ error: 'method' }, 405)
}

// Site lock: public salt and hash of the team code, so a new device asks for the team code.
// Anyone may read it (it is also what a locked page embeds); only the team may change it.
async function lockRoute(req) {
  const store = getStore({ name: 'team-support', consistency: 'strong' })
  if (req.method === 'GET') return reply({ lock: (await store.get('lock', { type: 'json' })) || null, demo: (await store.get('demo', { type: 'json' })) || null })
  if (req.method !== 'PUT') return reply({ error: 'method' }, 405)
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')
  if (token.length < 32 || token.length > 200) return reply({ error: 'auth' }, 401)
  const cur = await store.get('vault', { type: 'json' })
  if (!cur) return reply({ error: 'nosync' }, 409)
  if (cur.auth !== (await sha256(token))) return reply({ error: 'code' }, 403)
  const adm = await adminOf(req)
  if (!cur.admin || adm !== cur.admin) return reply({ error: 'admin' }, 403)
  let body
  try { body = await req.json() } catch { return reply({ error: 'bad' }, 400) }
  if (body && 'demo' in body) {
    const d = body.demo
    if (d === null) { await store.delete('demo'); return reply({ demo: null }) }
    if (!d || d.v !== 1 || typeof d.s !== 'string' || typeof d.h !== 'string' || d.s.length > 64 || d.h.length > 128) return reply({ error: 'bad' }, 400)
    await store.setJSON('demo', { v: 1, s: d.s, h: d.h })
    return reply({ demo: { v: 1, s: d.s, h: d.h } })
  }
  const l = body && body.lock
  if (l === null) { await store.delete('lock'); return reply({ lock: null }) }
  if (!l || l.v !== 1 || typeof l.s !== 'string' || typeof l.h !== 'string' || l.s.length > 64 || l.h.length > 128) return reply({ error: 'bad' }, 400)
  await store.setJSON('lock', { v: 1, s: l.s, h: l.h })
  return reply({ lock: { v: 1, s: l.s, h: l.h } })
}

// Member details: each team member gets a personal link with a random token.
// The server stores only the SHA-256 hash of each token, the team public key, and
// submissions encrypted on the member's device with that public key. It can read none of them.
const B64 = /^[A-Za-z0-9+/=_-]+$/
async function teamOk(req, store) {
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')
  if (token.length < 32 || token.length > 200) return false
  const cur = await store.get('vault', { type: 'json' })
  return !!(cur && cur.auth === (await sha256(token)))
}
async function memberRoute(req) {
  const store = getStore({ name: 'team-support', consistency: 'strong' })
  const q = new URL(req.url).searchParams
  const op = q.get('op') || ''
  const t = q.get('t') || ''
  // public side: the member's form
  if (t) {
    if (t.length < 32 || t.length > 100 || !B64.test(t)) return reply({ error: 'link' }, 404)
    const h = await sha256(t)
    const inv = (await store.get('inv', { type: 'json' })) || {}
    if (!inv[h]) return reply({ error: 'link' }, 404)
    if (req.method === 'GET') {
      const pub = await store.get('pub', { type: 'json' })
      if (!pub) return reply({ error: 'link' }, 404)
      return reply({ pub })
    }
    if (req.method === 'POST') {
      let b
      try { b = await req.json() } catch { return reply({ error: 'bad' }, 400) }
      if (!b || typeof b.ct !== 'string' || typeof b.iv !== 'string' || !b.epk || typeof b.epk !== 'object') return reply({ error: 'bad' }, 400)
      if (b.ct.length > 40000 || b.iv.length > 40 || !B64.test(b.ct) || !B64.test(b.iv) || JSON.stringify(b.epk).length > 400) return reply({ error: 'bad' }, 400)
      const { blobs } = await store.list({ prefix: 'in/' + h })
      if (blobs.length >= 10) return reply({ error: 'full' }, 409)
      const at = new Date().toISOString(), k = 'in/' + h + '/' + Date.now().toString(36)
      await store.setJSON(k, { h, k, epk: b.epk, iv: b.iv, ct: b.ct, at })
      return reply({ ok: true })
    }
    return reply({ error: 'method' }, 405)
  }
  // team side: needs the team token
  if (!(await teamOk(req, store))) return reply({ error: 'code' }, 403)
  if (op === 'invite' && req.method === 'POST') {
    let b
    try { b = await req.json() } catch { return reply({ error: 'bad' }, 400) }
    if (!b || !/^[0-9a-f]{64}$/.test(b.h || '') || !b.pub || typeof b.pub !== 'object' || JSON.stringify(b.pub).length > 400) return reply({ error: 'bad' }, 400)
    const inv = (await store.get('inv', { type: 'json' })) || {}
    if (!inv[b.h] && Object.keys(inv).length >= 1000) return reply({ error: 'full' }, 409)
    inv[b.h] = inv[b.h] || new Date().toISOString()
    await store.setJSON('inv', inv)
    await store.setJSON('pub', b.pub)
    return reply({ ok: true })
  }
  if (op === 'revoke' && req.method === 'POST') {
    let b
    try { b = await req.json() } catch { return reply({ error: 'bad' }, 400) }
    if (!b || !/^[0-9a-f]{64}$/.test(b.h || '')) return reply({ error: 'bad' }, 400)
    const inv = (await store.get('inv', { type: 'json' })) || {}
    delete inv[b.h]
    await store.setJSON('inv', inv)
    const { blobs } = await store.list({ prefix: 'in/' + b.h })
    await Promise.all(blobs.map((x) => store.delete(x.key)))
    return reply({ ok: true })
  }
  if (op === 'list' && req.method === 'GET') {
    const { blobs } = await store.list({ prefix: 'in/' })
    const vals = await Promise.all(blobs.slice(0, 300).map((x) => store.get(x.key, { type: 'json' }).catch(() => null)))
    return reply({ items: vals.filter(Boolean).map((v, i) => Object.assign({ k: blobs[i].key }, v)) })
  }
  if (op === 'done' && req.method === 'POST') {
    let b
    try { b = await req.json() } catch { return reply({ error: 'bad' }, 400) }
    if (!b || !/^[0-9a-f]{64}$/.test(b.h || '')) return reply({ error: 'bad' }, 400)
    const k = typeof b.k === 'string' && new RegExp('^in/' + b.h + '(/[a-z0-9]{1,16})?$').test(b.k) ? b.k : 'in/' + b.h
    const cur = await store.get(k, { type: 'json' })
    if (cur && b.at && cur.at !== b.at) return reply({ error: 'newer' }, 409)
    await store.delete(k)
    return reply({ ok: true })
  }
  return reply({ error: 'bad' }, 400)
}

export const config = { path: ['/api/vault', '/api/lock', '/api/member'] }
