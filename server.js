require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET in .env to a random value of at least 32 characters.'); process.exit(1);
}
const db = new Database(path.join(__dirname, 'ics-intelligence.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('customer','admin')), email_verified INTEGER NOT NULL DEFAULT 0,
 theme TEXT NOT NULL DEFAULT 'blue', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS codes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, purpose TEXT NOT NULL,
 code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, action TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const defaults = {
 dailyPrice: '500', weeklyPrice: '2500', monthlyPrice: '8000', annualPrice: '80000',
 defaultTheme: 'blue', themesEnabled: 'true', publicRegistrationEnabled: 'true'
};
const insertSetting = db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)');
for (const [k,v] of Object.entries(defaults)) insertSetting.run(k,v);
const getSettings = () => Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x => [x.key,x.value]));
const saveSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
const audit = (actor, action, details='') => db.prepare('INSERT INTO audit_log(actor_id,action,details) VALUES(?,?,?)').run(actor || null, action, details);

let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({host:process.env.SMTP_HOST, port:Number(process.env.SMTP_PORT || 587), secure:process.env.SMTP_SECURE === 'true', auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
}
async function sendCode(email, code, purpose) {
  if (!mailer) throw new Error('Email delivery is not configured. Set SMTP_HOST, SMTP_USER and SMTP_PASS in .env.');
  await mailer.sendMail({from:process.env.EMAIL_FROM || process.env.SMTP_USER,to:email,subject:purpose === 'verify' ? 'Verify your ICS Intelligence email' : 'Your ICS Intelligence sign-in code',text:`Your ICS Intelligence verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`});
}
function normalizeEmail(value) { return String(value || '').trim().toLowerCase(); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }
function issueCode(email,purpose) {
  const code = String(crypto.randomInt(0,1000000)).padStart(6,'0');
  db.prepare('DELETE FROM codes WHERE email=? AND purpose=?').run(email,purpose);
  db.prepare('INSERT INTO codes(email,purpose,code_hash,expires_at,created_at) VALUES(?,?,?,?,?)')
    .run(email,purpose,bcrypt.hashSync(code,10),Date.now()+10*60*1000,Date.now());
  return code;
}
const authLimiter = rateLimit({windowMs:15*60*1000, limit:20, standardHeaders:true, legacyHeaders:false, message:{error:'Too many attempts. Please wait 15 minutes and try again.'}});
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],scriptSrc:["'self'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],upgradeInsecureRequests: isProd ? [] : null}}}));
app.use(express.json({limit:'20kb'}));
app.use(express.urlencoded({extended:false,limit:'20kb'}));
app.use(session({name:'ics.sid',secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'strict',secure:isProd,maxAge:8*60*60*1000}}));
app.use(express.static(path.join(__dirname,'public')));
const requireAuth = (req,res,next) => req.session.user ? next() : res.status(401).json({error:'Please sign in.'});
const requireAdmin = (req,res,next) => !req.session.user ? res.status(401).json({error:'Please sign in.'}) : req.session.user.role !== 'admin' ? res.status(403).json({error:'Administrator access required.'}) : next();
const safeUser = u => ({id:u.id,email:u.email,role:u.role,theme:u.theme,emailVerified:!!u.email_verified});

app.get('/api/health', (req,res) => res.json({ok:true, service:'ICS Intelligence'}));
app.get('/api/settings/public', (req,res) => { const s=getSettings(); res.json({defaultTheme:s.defaultTheme,themesEnabled:s.themesEnabled==='true',prices:{daily:Number(s.dailyPrice),weekly:Number(s.weeklyPrice),monthly:Number(s.monthlyPrice),annual:Number(s.annualPrice)}}); });
app.get('/api/auth/me', (req,res) => res.json({user:req.session.user || null}));

// First administrator is created only with the installation setup token. Remove/rotate token after setup.
app.post('/api/setup/admin', authLimiter, async (req,res) => {
  try {
    const suppliedToken=Buffer.from(String(req.body.setupToken || '')); const expectedToken=Buffer.from(String(process.env.ADMIN_SETUP_TOKEN || ''));
    if (!expectedToken.length || suppliedToken.length !== expectedToken.length || !crypto.timingSafeEqual(suppliedToken, expectedToken)) return res.status(403).json({error:'Invalid setup token.'});
    if (db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").get().n > 0) return res.status(409).json({error:'An administrator already exists. Use the existing admin account to manage access.'});
    const email=normalizeEmail(req.body.email), password=String(req.body.password || '');
    if (!validEmail(email) || password.length < 12) return res.status(400).json({error:'Enter a valid email and a password of at least 12 characters.'});
    const code=issueCode(email,'admin-setup');
    await sendCode(email,code,'verify');
    req.session.pendingAdminSetup={email,passwordHash:await bcrypt.hash(password,12)};
    res.json({message:'A verification code was sent to your email. Enter it to finish setting up the administrator.'});
  } catch(e) { console.error(e.message); res.status(503).json({error:e.message.includes('Email delivery')?e.message:'Unable to send verification email. Check your SMTP settings.'}); }
});
app.post('/api/setup/admin/verify', authLimiter, async (req,res) => {
  const pending=req.session.pendingAdminSetup; if(!pending) return res.status(400).json({error:'Start administrator setup first.'});
  const row=db.prepare("SELECT * FROM codes WHERE email=? AND purpose='admin-setup'").get(pending.email);
  if(!row || row.expires_at<Date.now() || row.attempts>=5) return res.status(400).json({error:'Code expired or unavailable. Start setup again.'});
  db.prepare('UPDATE codes SET attempts=attempts+1 WHERE id=?').run(row.id);
  if(!await bcrypt.compare(String(req.body.code||''),row.code_hash)) return res.status(400).json({error:'Incorrect verification code.'});
  try {
    const result=db.prepare("INSERT INTO users(email,password_hash,role,email_verified) VALUES(?,?,'admin',1)").run(pending.email,pending.passwordHash);
    db.prepare('DELETE FROM codes WHERE id=?').run(row.id); delete req.session.pendingAdminSetup;
    const u=db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
    req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'Could not start secure session.'}); req.session.user=safeUser(u); audit(u.id,'admin_created','First administrator created during setup'); res.json({message:'Administrator account created.',user:safeUser(u)}); });
  } catch(e) { res.status(409).json({error:'Could not create administrator. The email may already be registered.'}); }
});

app.post('/api/auth/register', authLimiter, async (req,res) => {
  try {
    if(getSettings().publicRegistrationEnabled!=='true') return res.status(403).json({error:'Public registration is currently disabled.'});
    const email=normalizeEmail(req.body.email), password=String(req.body.password||'');
    if(!validEmail(email) || password.length<10) return res.status(400).json({error:'Enter a valid email and a password of at least 10 characters.'});
    if(db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).json({error:'An account with this email already exists.'});
    const passwordHash=await bcrypt.hash(password,12);
    db.prepare("INSERT INTO users(email,password_hash,role,email_verified) VALUES(?,?,'customer',0)").run(email,passwordHash);
    const code=issueCode(email,'verify'); await sendCode(email,code,'verify');
    res.status(201).json({message:'Account created. Check your email for the verification code.'});
  } catch(e) { console.error(e.message); res.status(503).json({error:e.message.includes('Email delivery')?e.message:'Could not create account or send verification email. Check SMTP settings.'}); }
});
app.post('/api/auth/verify-email', authLimiter, async (req,res) => {
  const email=normalizeEmail(req.body.email), code=String(req.body.code||'');
  const row=db.prepare("SELECT * FROM codes WHERE email=? AND purpose='verify'").get(email);
  if(!row || row.expires_at<Date.now() || row.attempts>=5) return res.status(400).json({error:'Code expired or unavailable. Register again or request a new code.'});
  db.prepare('UPDATE codes SET attempts=attempts+1 WHERE id=?').run(row.id);
  if(!await bcrypt.compare(code,row.code_hash)) return res.status(400).json({error:'Incorrect verification code.'});
  db.prepare('UPDATE users SET email_verified=1 WHERE email=? AND role=\'customer\'').run(email);
  db.prepare('DELETE FROM codes WHERE id=?').run(row.id); res.json({message:'Email verified. You can now sign in.'});
});
app.post('/api/auth/login', authLimiter, async (req,res) => {
  const email=normalizeEmail(req.body.email), password=String(req.body.password||'');
  const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
  if(!u.email_verified) return res.status(403).json({error:'Please verify your email before signing in.'});
  if(u.role==='admin') {
    try { const code=issueCode(email,'login'); await sendCode(email,code,'login'); res.json({requiresCode:true,message:'A sign-in code was sent to your email.'}); }
    catch(e) { console.error(e.message); res.status(503).json({error:'Could not send sign-in code. Check the email service configuration.'}); }
    return;
  }
  req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'Could not start secure session.'}); req.session.user=safeUser(u); res.json({message:'Signed in.',user:safeUser(u)}); });
});
app.post('/api/auth/admin-verify-login', authLimiter, async (req,res) => {
  const email=normalizeEmail(req.body.email), row=db.prepare("SELECT * FROM codes WHERE email=? AND purpose='login'").get(email);
  if(!row || row.expires_at<Date.now() || row.attempts>=5) return res.status(400).json({error:'Code expired or unavailable. Sign in again.'});
  db.prepare('UPDATE codes SET attempts=attempts+1 WHERE id=?').run(row.id);
  if(!await bcrypt.compare(String(req.body.code||''),row.code_hash)) return res.status(400).json({error:'Incorrect verification code.'});
  const u=db.prepare("SELECT * FROM users WHERE email=? AND role='admin' AND email_verified=1").get(email);
  if(!u) return res.status(403).json({error:'Administrator account not found.'});
  db.prepare('DELETE FROM codes WHERE id=?').run(row.id);
  req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'Could not start secure session.'}); req.session.user=safeUser(u); audit(u.id,'admin_login','Administrator signed in'); res.json({message:'Signed in.',user:safeUser(u)}); });
});
app.post('/api/auth/logout',(req,res)=>{const actor=req.session.user?.id; req.session.destroy(()=>{res.clearCookie('ics.sid'); if(actor) audit(actor,'logout','Signed out'); res.json({message:'Signed out.'});});});
app.post('/api/account/theme', requireAuth, (req,res)=>{const theme=String(req.body.theme||''); const allowed=['blue','green','purple','dark']; if(!allowed.includes(theme)) return res.status(400).json({error:'Unsupported theme.'}); if(req.session.user.role==='customer' && getSettings().themesEnabled!=='true') return res.status(403).json({error:'Personal themes are disabled by the administrator.'}); db.prepare('UPDATE users SET theme=? WHERE id=?').run(theme,req.session.user.id); req.session.user.theme=theme; res.json({message:'Theme saved to your account.',theme});});
app.get('/api/admin/summary', requireAdmin, (req,res)=>{const s=getSettings(); res.json({settings:s,users:db.prepare('SELECT COUNT(*) n FROM users WHERE role=\'customer\'').get().n,admins:db.prepare("SELECT COUNT(*) n FROM users WHERE role='admin'").get().n,logs:db.prepare('SELECT id,actor_id,action,details,created_at FROM audit_log ORDER BY id DESC LIMIT 20').all(),prices:{daily:Number(s.dailyPrice),weekly:Number(s.weeklyPrice),monthly:Number(s.monthlyPrice),annual:Number(s.annualPrice)}});});
app.put('/api/admin/settings', requireAdmin, (req,res)=>{
 const body=req.body||{}; const priceKeys={dailyPrice:'daily',weeklyPrice:'weekly',monthlyPrice:'monthly',annualPrice:'annual'};
 for(const [key,short] of Object.entries(priceKeys)) { if(body.prices && body.prices[short]!==undefined) { const n=Number(body.prices[short]); if(!Number.isInteger(n)||n<0||n>100000000) return res.status(400).json({error:`Invalid ${short} price.`}); saveSetting.run(key,String(n)); } }
 if(body.defaultTheme!==undefined) { if(!['blue','green','purple','dark'].includes(body.defaultTheme)) return res.status(400).json({error:'Invalid default theme.'}); saveSetting.run('defaultTheme',body.defaultTheme); }
 if(body.themesEnabled!==undefined) saveSetting.run('themesEnabled',body.themesEnabled?'true':'false');
 if(body.publicRegistrationEnabled!==undefined) saveSetting.run('publicRegistrationEnabled',body.publicRegistrationEnabled?'true':'false');
 audit(req.session.user.id,'settings_updated','Updated theme, registration or pricing settings'); res.json({message:'Settings saved.',settings:getSettings()});
});
app.get('/api/admin/users',requireAdmin,(req,res)=>res.json({users:db.prepare('SELECT id,email,role,email_verified,theme,created_at FROM users ORDER BY id DESC LIMIT 200').all()}));
app.get('/api/admin/audit',requireAdmin,(req,res)=>res.json({logs:db.prepare('SELECT id,actor_id,action,details,created_at FROM audit_log ORDER BY id DESC LIMIT 100').all()}));
app.get('/api/admin/session',requireAdmin,(req,res)=>res.json({user:req.session.user}));
app.get('/account',(req,res)=>{ if(!req.session.user || req.session.user.role!=='customer') return res.redirect('/login'); res.sendFile(path.join(__dirname,'public','account.html')); });
app.get('/admin',(req,res)=>{ if(!req.session.user || req.session.user.role!=='admin') return res.redirect('/admin-login'); res.sendFile(path.join(__dirname,'public','admin.html')); });
app.get('/admin-login',(req,res)=>res.sendFile(path.join(__dirname,'public','admin-login.html')));
app.get('/login',(req,res)=>res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});
app.listen(PORT,()=>console.log(`ICS Intelligence running at http://localhost:${PORT}`));
