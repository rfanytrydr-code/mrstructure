'use strict';
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(ROOT, 'uploads'));
fs.mkdirSync(DATA_DIR, { recursive: true }); fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (process.env.NODE_ENV === 'production' && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  console.error('SESSION_SECRET must be set to a random value of at least 32 characters in production.'); process.exit(1);
}
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');
const db = new Database(path.join(DATA_DIR, 'mrstructure.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, tracking_number TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(id),
 type TEXT NOT NULL, subject TEXT NOT NULL, topic TEXT DEFAULT '', description TEXT NOT NULL,
 details_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'registered', price REAL,
 delivery_notes TEXT DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS order_files (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 uploaded_by TEXT NOT NULL REFERENCES users(id), original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
 mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT 'request', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS status_history (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 actor_id TEXT NOT NULL REFERENCES users(id), from_status TEXT, to_status TEXT NOT NULL, note TEXT DEFAULT '', created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_order ON order_files(order_id);
CREATE INDEX IF NOT EXISTS idx_messages_order ON messages(order_id, created_at);
`);
const adminCount = db.prepare("SELECT COUNT(*) n FROM users WHERE role='admin'").get().n;
if (!adminCount) {
  const username = (process.env.ADMIN_USERNAME || 'admin').trim();
  const password = process.env.ADMIN_PASSWORD || (process.env.NODE_ENV === 'production' ? '' : 'ChangeMe-Local-2026!');
  if (!password || password.length < 12) {
    console.error('Set ADMIN_PASSWORD to at least 12 characters before starting the server.'); process.exit(1);
  }
  db.prepare('INSERT INTO users (id,username,email,name,password_hash,role,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(id('u'), username, `${username}@mrstructure.local`, process.env.ADMIN_NAME || 'مدیر سایت', bcrypt.hashSync(password, 12), 'admin', Date.now());
  console.log(`Initial administrator created: ${username}. Set a strong ADMIN_PASSWORD in your environment.`);
}
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieSession({ name: 'mrstructure_session', keys: [sessionSecret], httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(ROOT, 'public'), { maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));

function id(prefix='') { return prefix + crypto.randomUUID().replaceAll('-', '').slice(0, 18); }
function fail(res, status, message) { return res.status(status).json({ error: message }); }
function cleanUser(u) { return { id: u.id, username: u.username, email: u.email, name: u.name, role: u.role, createdAt: u.created_at }; }
function currentUser(req) { return req.session?.uid ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.uid) : null; }
function auth(req, res, next) { const u = currentUser(req); if (!u) return fail(res, 401, 'برای ادامه وارد حساب شوید.'); req.user = u; next(); }
function admin(req, res, next) { if (req.user?.role !== 'admin') return fail(res, 403, 'دسترسی مدیر لازم است.'); next(); }
function orderForViewer(orderId, user) {
 const o = db.prepare('SELECT o.*, u.name AS customer_name, u.email AS customer_email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').get(orderId);
 if (!o || (user.role !== 'admin' && o.user_id !== user.id)) return null;
 return o;
}
function publicOrder(o, viewer) {
 const details = (() => { try { return JSON.parse(o.details_json || '{}'); } catch { return {}; } })();
 const files = db.prepare('SELECT id,original_name,mime_type,size_bytes,kind,created_at FROM order_files WHERE order_id=? ORDER BY created_at').all(o.id).map(f => ({...f, url: `/api/files/${f.id}`}));
 const msgs = db.prepare('SELECT m.id,m.body,m.created_at,u.name AS sender_name,u.role AS sender_role FROM messages m JOIN users u ON u.id=m.user_id WHERE m.order_id=? ORDER BY m.created_at').all(o.id);
 const history = db.prepare('SELECT h.from_status,h.to_status,h.note,h.created_at,u.name AS actor_name FROM status_history h JOIN users u ON u.id=h.actor_id WHERE h.order_id=? ORDER BY h.created_at').all(o.id);
 return { id:o.id, trackingNumber:o.tracking_number, userId:o.user_id, customerName: viewer.role==='admin'?o.customer_name:undefined,
  customerEmail: viewer.role==='admin'?o.customer_email:undefined, type:o.type, subject:o.subject, topic:o.topic, description:o.description,
  details, status:o.status, price:o.price, deliveryNotes:o.delivery_notes, createdAt:o.created_at, updatedAt:o.updated_at,
  files, messages:msgs, history };
}
const storage = multer.diskStorage({ destination: (_req,_file,cb)=>cb(null,UPLOAD_DIR), filename: (_req,file,cb)=>cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase()) });
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024, files: 10 }, fileFilter: (_req,file,cb)=> {
 const ok = ['application/pdf','image/jpeg','image/png'].includes(file.mimetype) && ['.pdf','.jpg','.jpeg','.png'].includes(path.extname(file.originalname).toLowerCase());
 cb(ok ? null : new Error('فقط فایل PDF، JPG و PNG مجاز است.'), ok);
}});

app.get('/api/health', (_req,res)=>res.json({ok:true}));
app.get('/api/auth/me', (req,res)=>{ const u=currentUser(req); res.json({user:u?cleanUser(u):null}); });
app.post('/api/auth/register', (req,res)=>{
 const name=String(req.body.name||'').trim(), email=String(req.body.email||'').trim().toLowerCase(), username=String(req.body.username||'').trim(), password=String(req.body.password||'');
 if(name.length<2 || name.length>100) return fail(res,400,'نام باید بین ۲ تا ۱۰۰ نویسه باشد.');
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length>190) return fail(res,400,'ایمیل معتبر وارد کنید.');
 if(!/^[\p{L}\p{N}_.-]{3,30}$/u.test(username)) return fail(res,400,'نام کاربری باید ۳ تا ۳۰ نویسه و بدون فاصله باشد.');
 if(password.length<10 || password.length>128) return fail(res,400,'رمز عبور باید حداقل ۱۰ نویسه باشد.');
 if(db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username,email)) return fail(res,409,'این نام کاربری یا ایمیل قبلاً ثبت شده است.');
 const uid=id('u'), now=Date.now();
 db.prepare('INSERT INTO users (id,username,email,name,password_hash,role,created_at) VALUES (?,?,?,?,?,?,?)').run(uid,username,email,name,bcrypt.hashSync(password,12),'user',now);
 req.session={uid}; res.status(201).json({user:cleanUser(db.prepare('SELECT * FROM users WHERE id=?').get(uid))});
});
app.post('/api/auth/login', (req,res)=>{
 const login=String(req.body.login||'').trim(), password=String(req.body.password||'');
 const u=db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE').get(login,login);
 if(!u || !bcrypt.compareSync(password,u.password_hash)) return fail(res,401,'نام کاربری یا رمز عبور اشتباه است.');
 req.session={uid:u.id}; res.json({user:cleanUser(u)});
});
app.post('/api/auth/logout', (req,res)=>{ req.session=null; res.json({ok:true}); });
app.get('/api/orders', auth, (req,res)=>{
 const rows=req.user.role==='admin' ? db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all() : db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC').all(req.user.id);
 res.json({orders:rows.map(o=>publicOrder(o,req.user))});
});
app.post('/api/orders', auth, (req,res)=>{
 if(req.user.role==='admin') return fail(res,403,'حساب مدیر برای ثبت سفارش استفاده نمی‌شود.');
 const b=req.body||{}, type=String(b.type||''), subject=String(b.subject||'').trim(), description=String(b.description||'').trim();
 if(!['troubleshoot','exercise','tutoring'].includes(type)) return fail(res,400,'نوع خدمت معتبر نیست.');
 if(subject.length<2 || subject.length>180 || description.length<5 || description.length>10000) return fail(res,400,'عنوان و شرح درخواست را کامل وارد کنید.');
 const oid=id('o'), now=Date.now(); let tracking;
 do { tracking='MRS-'+String(crypto.randomInt(10000000,99999999)); } while(db.prepare('SELECT id FROM orders WHERE tracking_number=?').get(tracking));
 const details={}; for (const k of ['helpType','urgency','qcount','outputType','deadline','level','goal','duration','preferredTime','extraNotes']) if (b[k]!==undefined) details[k]=String(b[k]).slice(0,1000);
 const tx=db.transaction(()=>{ db.prepare('INSERT INTO orders (id,tracking_number,user_id,type,subject,topic,description,details_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(oid,tracking,req.user.id,type,subject,String(b.topic||'').slice(0,180),description,JSON.stringify(details),'registered',now,now); db.prepare('INSERT INTO status_history (id,order_id,actor_id,from_status,to_status,note,created_at) VALUES (?,?,?,?,?,?,?)').run(id('h'),oid,req.user.id,null,'registered','درخواست ثبت شد',now); }); tx();
 res.status(201).json({order:publicOrder(db.prepare('SELECT o.*,u.name AS customer_name,u.email AS customer_email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').get(oid),req.user)});
});
app.get('/api/orders/:id', auth, (req,res)=>{ const o=orderForViewer(req.params.id,req.user); if(!o)return fail(res,404,'درخواست پیدا نشد.'); res.json({order:publicOrder(o,req.user)}); });
app.post('/api/orders/:id/files', auth, (req,res)=>{
 upload.array('files',10)(req,res,err=>{
  if(err) return fail(res,400,err.message || 'بارگذاری فایل ناموفق بود.');
  const o=orderForViewer(req.params.id,req.user); if(!o){ for(const f of req.files||[])fs.rmSync(f.path,{force:true}); return fail(res,404,'درخواست پیدا نشد.'); }
  const kind=req.user.role==='admin'?'delivery':'request';
  const stmt=db.prepare('INSERT INTO order_files (id,order_id,uploaded_by,original_name,stored_name,mime_type,size_bytes,kind,created_at) VALUES (?,?,?,?,?,?,?,?,?)');
  for(const f of req.files||[]) stmt.run(id('f'),o.id,req.user.id,path.basename(f.originalname).slice(0,250),path.basename(f.filename),f.mimetype,f.size,kind,Date.now());
  db.prepare('UPDATE orders SET updated_at=? WHERE id=?').run(Date.now(),o.id);
  res.status(201).json({files:(req.files||[]).length});
 });
});
app.get('/api/files/:id', auth, (req,res)=>{
 const f=db.prepare('SELECT f.*,o.user_id FROM order_files f JOIN orders o ON o.id=f.order_id WHERE f.id=?').get(req.params.id);
 if(!f || (req.user.role!=='admin' && req.user.id!==f.user_id)) return fail(res,404,'فایل پیدا نشد.');
 const p=path.join(UPLOAD_DIR,path.basename(f.stored_name)); if(!fs.existsSync(p))return fail(res,404,'فایل در دسترس نیست.');
 res.setHeader('X-Content-Type-Options','nosniff'); res.download(p, f.original_name);
});
app.post('/api/orders/:id/messages', auth, (req,res)=>{
 const o=orderForViewer(req.params.id,req.user); if(!o)return fail(res,404,'درخواست پیدا نشد.');
 const body=String(req.body.body||'').trim(); if(!body||body.length>3000)return fail(res,400,'پیام باید بین ۱ تا ۳۰۰۰ نویسه باشد.');
 const mid=id('m'), now=Date.now(); db.prepare('INSERT INTO messages (id,order_id,user_id,body,created_at) VALUES (?,?,?,?,?)').run(mid,o.id,req.user.id,body,now); db.prepare('UPDATE orders SET updated_at=? WHERE id=?').run(now,o.id); res.status(201).json({ok:true});
});
app.patch('/api/orders/:id', auth, admin, (req,res)=>{
 const o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id); if(!o)return fail(res,404,'درخواست پیدا نشد.');
 const statuses=['registered','reviewing','need_info','priced','awaiting_user_confirm','awaiting_payment','in_progress','ready','completed','cancelled'];
 const status=req.body.status===undefined?o.status:String(req.body.status); if(!statuses.includes(status))return fail(res,400,'وضعیت معتبر نیست.');
 let price=o.price; if(req.body.price!==undefined){ price=req.body.price===null||req.body.price===''?null:Number(req.body.price); if(price!==null&&(!Number.isFinite(price)||price<0||price>1e12))return fail(res,400,'مبلغ معتبر نیست.'); }
 const notes=req.body.deliveryNotes===undefined?o.delivery_notes:String(req.body.deliveryNotes).slice(0,3000); const now=Date.now();
 const tx=db.transaction(()=>{db.prepare('UPDATE orders SET status=?,price=?,delivery_notes=?,updated_at=? WHERE id=?').run(status,price,notes,now,o.id); if(status!==o.status)db.prepare('INSERT INTO status_history (id,order_id,actor_id,from_status,to_status,note,created_at) VALUES (?,?,?,?,?,?,?)').run(id('h'),o.id,req.user.id,o.status,status,String(req.body.note||'').slice(0,500),now);}); tx();
 res.json({order:publicOrder(db.prepare('SELECT o.*,u.name AS customer_name,u.email AS customer_email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').get(o.id),req.user)});
});
app.get('/api/admin/users', auth, admin, (_req,res)=>res.json({users:db.prepare('SELECT id,username,email,name,role,created_at FROM users ORDER BY created_at DESC').all().map(cleanUser)}));
app.use((err,_req,res,_next)=>{ console.error(err); res.status(500).json({error:'خطای داخلی سرور رخ داد.'}); });
app.get('*', (req,res)=>{ if(req.path.startsWith('/api/')) return fail(res,404,'مسیر پیدا نشد.'); res.sendFile(path.join(ROOT,'public','index.html')); });
app.listen(PORT,()=>console.log(`MrStructure is running on port ${PORT}`));
