require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'changeme123';

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ DB connected'))
  .catch(err => console.log('❌ DB error:', err));

const KeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  scriptId: { type: String, default: 'main' },
  hwid: { type: String, default: null },
  blacklisted: { type: Boolean, default: false },
  note: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  lastUsed: { type: Date, default: null }
});
const Key = mongoose.model('Key', KeySchema);

const BlacklistSchema = new mongoose.Schema({
  value: { type: String, required: true },
  type: { type: String, enum: ['key', 'hwid'], required: true },
  reason: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
const Blacklist = mongoose.model('Blacklist', BlacklistSchema);

const ScriptSchema = new mongoose.Schema({
  scriptId: { type: String, required: true, unique: true },
  code: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now }
});
const Script = mongoose.model('Script', ScriptSchema);

function checkAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.query.secret || req.body.secret;
  if (secret !== ADMIN_SECRET) return res.status(403).send('غير مسموح - Secret غلط');
  next();
}

// ======================
// الصفحات (الواجهة)
// ======================
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Natcho API</title>
  <style>
    body{font-family:system-ui;background:#0f0f13;color:#eee;margin:0;padding:20px;text-align:center}
    a{display:block;margin:12px auto;padding:14px;background:#7c5cfc;color:#fff;text-decoration:none;border-radius:10px;max-width:280px}
    h1{color:#7c5cfc}
  </style>
</head>
<body>
  <h1>Natcho Script System</h1>
  <p>نظام حماية سكريبتات بحال Luarmor / Polsec</p>
  <a href="/admin">لوحة الإدارة</a>
  <a href="/panel">لوحة اليوزر (Loader)</a>
</body>
</html>`);
});

app.get('/admin', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>لوحة الإدارة</title>
  <style>
    body{font-family:system-ui;background:#0f0f13;color:#eee;margin:0;padding:16px}
    input,textarea,button,select{width:100%;padding:12px;margin:6px 0;border-radius:8px;border:1px solid #333;background:#1a1a22;color:#fff;box-sizing:border-box}
    button{background:#7c5cfc;border:none;font-weight:bold;cursor:pointer}
    .card{background:#1a1a22;padding:16px;border-radius:12px;margin-bottom:16px}
    h2{margin-top:0;color:#7c5cfc;font-size:18px}
    pre{background:#111;padding:12px;border-radius:8px;overflow:auto;font-size:13px;white-space:pre-wrap}
  </style>
</head>
<body>
  <h1>لوحة الإدارة</h1>

  <div class="card">
    <h2>1. توليد كي</h2>
    <input id="secret1" type="password" placeholder="ADMIN_SECRET">
    <input id="note" placeholder="ملاحظة (اختياري)">
    <button onclick="generate()">توليد كي</button>
    <pre id="out1"></pre>
  </div>

  <div class="card">
    <h2>2. بحث عن كي</h2>
    <input id="secret2" type="password" placeholder="ADMIN_SECRET">
    <input id="lookupKey" placeholder="الكي">
    <button onclick="lookup()">بحث</button>
    <pre id="out2"></pre>
  </div>

  <div class="card">
    <h2>3. Reset HWID</h2>
    <input id="secret3" type="password" placeholder="ADMIN_SECRET">
    <input id="resetKey" placeholder="الكي">
    <button onclick="resetHwid()">مسح HWID</button>
    <pre id="out3"></pre>
  </div>

  <div class="card">
    <h2>4. حظر كي</h2>
    <input id="secret4" type="password" placeholder="ADMIN_SECRET">
    <input id="banKey" placeholder="الكي">
    <input id="banReason" placeholder="السبب (اختياري)">
    <button onclick="banKey()">حظر</button>
    <pre id="out4"></pre>
  </div>

  <div class="card">
    <h2>5. رفع سكريبت</h2>
    <input id="secret5" type="password" placeholder="ADMIN_SECRET">
    <input id="scriptId" value="main" placeholder="scriptId">
    <textarea id="scriptCode" rows="8" placeholder="كود السكريبت هنا..."></textarea>
    <button onclick="uploadScript()">حفظ السكريبت</button>
    <pre id="out5"></pre>
  </div>

  <script>
    async function generate(){
      const s=document.getElementById('secret1').value;
      const note=document.getElementById('note').value;
      const r=await fetch('/generate?secret='+encodeURIComponent(s)+'&note='+encodeURIComponent(note));
      const t=await r.text();
      document.getElementById('out1').textContent=t;
    }
    async function lookup(){
      const s=document.getElementById('secret2').value;
      const k=document.getElementById('lookupKey').value;
      const r=await fetch('/lookup/'+encodeURIComponent(k)+'?secret='+encodeURIComponent(s));
      const j=await r.json();
      document.getElementById('out2').textContent=JSON.stringify(j,null,2);
    }
    async function resetHwid(){
      const s=document.getElementById('secret3').value;
      const k=document.getElementById('resetKey').value;
      const r=await fetch('/reset-hwid',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k,secret:s})});
      const j=await r.json();
      document.getElementById('out3').textContent=JSON.stringify(j,null,2);
    }
    async function banKey(){
      const s=document.getElementById('secret4').value;
      const k=document.getElementById('banKey').value;
      const reason=document.getElementById('banReason').value;
      const r=await fetch('/blacklist-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k,reason,secret:s})});
      const j=await r.json();
      document.getElementById('out4').textContent=JSON.stringify(j,null,2);
    }
    async function uploadScript(){
      const s=document.getElementById('secret5').value;
      const id=document.getElementById('scriptId').value;
      const code=document.getElementById('scriptCode').value;
      const r=await fetch('/script',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scriptId:id,code,secret:s})});
      const j=await r.json();
      document.getElementById('out5').textContent=JSON.stringify(j,null,2);
    }
  </script>
</body>
</html>`);
});

app.get('/panel', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Get Script</title>
  <style>
    body{font-family:system-ui;background:#0f0f13;color:#eee;margin:0;padding:20px;text-align:center}
    input,button{width:100%;max-width:320px;padding:14px;margin:8px 0;border-radius:10px;border:1px solid #333;background:#1a1a22;color:#fff;box-sizing:border-box}
    button{background:#7c5cfc;border:none;font-weight:bold}
    pre{text-align:left;background:#111;padding:14px;border-radius:10px;overflow:auto;max-width:320px;margin:16px auto;font-size:13px}
  </style>
</head>
<body>
  <h1>Get Your Script</h1>
  <input id="key" placeholder="حط الكي هنا">
  <button onclick="getLoader()">جيب اللودر</button>
  <pre id="out"></pre>
  <script>
    function getLoader(){
      const key=document.getElementById('key').value.trim();
      if(!key){document.getElementById('out').textContent='حط الكي';return;}
      const domain=window.location.origin;
      const loader='script_key="'+key+'";\\nloadstring(game:HttpGet("'+domain+'/loader/main?key='+key+'"))()';
      document.getElementById('out').textContent=loader;
    }
  </script>
</body>
</html>`);
});

// ======================
// API Endpoints
// ======================
app.get('/generate', checkAdmin, async (req, res) => {
  try {
    const scriptId = req.query.scriptId || 'main';
    const note = req.query.note || '';
    const newKey = 'KEY-' + Math.random().toString(36).substring(2, 12).toUpperCase();
    await Key.create({ key: newKey, scriptId, note });
    res.type('text/plain').send('✅ تم توليد كي جديد:\\n\\n' + newKey);
  } catch (err) {
    res.status(500).send('خطأ: ' + err.message);
  }
});

app.post('/generate', checkAdmin, async (req, res) => {
  try {
    const scriptId = req.body.scriptId || 'main';
    const note = req.body.note || '';
    const newKey = 'KEY-' + Math.random().toString(36).substring(2, 12).toUpperCase();
    await Key.create({ key: newKey, scriptId, note });
    res.json({ success: true, key: newKey, scriptId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/loader/:scriptId', async (req, res) => {
  const key = req.query.key;
  const hwid = req.query.hwid || req.headers['x-hwid'] || null;
  const scriptId = req.params.scriptId;
  if (!key) return res.status(400).send('-- محتاج كي');
  try {
    const bl = await Blacklist.findOne({ $or: [{ value: key, type: 'key' }, { value: hwid, type: 'hwid' }] });
    if (bl) return res.status(403).send('-- محظور');
    const found = await Key.findOne({ key, scriptId });
    if (!found) return res.status(403).send('-- كي غلط');
    if (found.blacklisted) return res.status(403).send('-- كي محظور');
    if (found.hwid === null && hwid) {
      found.hwid = hwid;
      found.lastUsed = new Date();
      await found.save();
    } else if (found.hwid && hwid && found.hwid !== hwid) {
      return res.status(403).send('-- HWID مختلف');
    } else {
      found.lastUsed = new Date();
      await found.save();
    }
    const script = await Script.findOne({ scriptId });
    if (!script) {
      return res.type('text/plain').send('print("✅ تم التحقق")\\nprint("ماكاين سكريبت مرفوع")');
    }
    res.type('text/plain').send(script.code);
  } catch (err) {
    res.status(500).send('-- خطأ');
  }
});

app.post('/reset-hwid', checkAdmin, async (req, res) => {
  try {
    const found = await Key.findOne({ key: req.body.key });
    if (!found) return res.status(404).json({ error: 'الكي ماكاينش' });
    found.hwid = null;
    await found.save();
    res.json({ success: true, message: 'تم مسح الـ HWID' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/blacklist-key', checkAdmin, async (req, res) => {
  try {
    const { key, reason } = req.body;
    const found = await Key.findOne({ key });
    if (found) { found.blacklisted = true; await found.save(); }
    await Blacklist.findOneAndUpdate(
      { value: key, type: 'key' },
      { value: key, type: 'key', reason: reason || '' },
      { upsert: true }
    );
    res.json({ success: true, message: 'تم حظر الكي' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/lookup/:key', checkAdmin, async (req, res) => {
  try {
    const found = await Key.findOne({ key: req.params.key });
    if (!found) return res.status(404).json({ error: 'الكي ماكاينش' });
    res.json(found);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/script', checkAdmin, async (req, res) => {
  try {
    const { scriptId, code } = req.body;
    if (!scriptId || !code) return res.status(400).json({ error: 'محتاج scriptId و code' });
    await Script.findOneAndUpdate(
      { scriptId },
      { scriptId, code, updatedAt: new Date() },
      { upsert: true }
    );
    res.json({ success: true, message: 'تم حفظ السكريبت' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Server on port', PORT));
