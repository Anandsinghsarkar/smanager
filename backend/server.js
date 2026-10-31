import express from 'express'
import cors from 'cors'
import { createClient } from '@supabase/supabase-js'

const app = express()

app.use(cors({ origin: '*' }))
app.use(express.json({ limit: '10mb' }))

// Lazy init — env vars runtime pe milte hain Vercel pe
let supabaseAdmin = null
function getSupabaseAdmin() {
  if (supabaseAdmin) return supabaseAdmin
  const url = process.env.SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY env vars required')
  }
  supabaseAdmin = createClient(url, key, {
    auth: { autoRefreshToken: false, persistSession: false }
  })
  return supabaseAdmin
}

// ---------- AUTH MIDDLEWARE ----------
const verifyAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (!token) return res.status(401).json({ error: 'No token provided' })

    const admin = getSupabaseAdmin()
    const { data: { user }, error } = await admin.auth.getUser(token)
    if (error || !user) return res.status(401).json({ error: 'Invalid token' })

    if (user.user_metadata?.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' })
    }

    req.user = user
    next()
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
}

// ---------- HEALTH ----------
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    configured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
    timestamp: new Date().toISOString()
  })
})

// ---------- USERS ----------
app.get('/api/users', verifyAdmin, async (req, res) => {
  try {
    const admin = getSupabaseAdmin()
    const { data, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 })
    if (error) throw error
    res.json(data.users)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

app.post('/api/users', verifyAdmin, async (req, res) => {
  try {
    const { email, password, role } = req.body
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' })

    const admin = getSupabaseAdmin()
    const { data, error } = await admin.auth.admin.createUser({
      email, password, email_confirm: true,
      user_metadata: { role: role || 'user' }
    })
    if (error) throw error
    res.json(data.user)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

app.patch('/api/users/:id', verifyAdmin, async (req, res) => {
  try {
    const { role } = req.body
    if (!role) return res.status(400).json({ error: 'Role required' })

    const admin = getSupabaseAdmin()
    const { data, error } = await admin.auth.admin.updateUserById(
      req.params.id,
      { user_metadata: { role } }
    )
    if (error) throw error
    res.json(data.user)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

app.delete('/api/users/:id', verifyAdmin, async (req, res) => {
  try {
    const admin = getSupabaseAdmin()
    const { error } = await admin.auth.admin.deleteUser(req.params.id)
    if (error) throw error
    res.json({ success: true })
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ---------- SQL LOGS ----------
app.get('/api/sql/logs', verifyAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50
    const admin = getSupabaseAdmin()
    const { data, error } = await admin
      .from('sql_audit_log')
      .select('*')
      .order('executed_at', { ascending: false })
      .limit(limit)
    if (error) throw error
    res.json(data)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ---------- 404 ----------
app.use((req, res) => {
  res.status(404).json({ error: 'Not found: ' + req.path })
})

// ---------- VERCEL EXPORT ----------
export default app

// Local dev start
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  const PORT = process.env.PORT || 4000
  app.listen(PORT, () => console.log(`✅ Local backend: http://localhost:${PORT}`))
}