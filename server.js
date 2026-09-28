
const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const DB=require("better-sqlite3");
const path=require("path");
const crypto=require("crypto");
const app=express(), PORT=process.env.PORT||3000;
if(!process.env.SESSION_SECRET) console.warn("WARNING: SESSION_SECRET not set");
const db=new DB(process.env.DB_PATH||"killix.db");
app.use(express.json());
app.use(session({secret:process.env.SESSION_SECRET||"dev-only-change-me",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:30*24*3600*1000}}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL,
 username_key TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL,
 email_key TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 coins INTEGER NOT NULL DEFAULT 20 CHECK(coins>=0),
 referral_code TEXT NOT NULL UNIQUE,
 referred_by INTEGER,
 last_daily TEXT,
 blocked INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS coin_transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,
 reason TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS referrals(
 id INTEGER PRIMARY KEY AUTOINCREMENT,referrer_id INTEGER NOT NULL,referred_id INTEGER NOT NULL UNIQUE,
 reward INTEGER NOT NULL DEFAULT 100,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`);

const norm=x=>String(x||"").trim().toLowerCase();
const publicUser=u=>({id:u.id,username:u.username,email:u.email,coins:u.coins,referral_code:u.referral_code,blocked:!!u.blocked,last_daily:u.last_daily});
const userAuth=(req,res,next)=>{if(!req.session.userId)return res.status(401).json({error:"Avval login qiling"});let u=db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId);if(!u||u.blocked)return res.status(403).json({error:"Akkaunt bloklangan"});req.user=u;next()};
const adminAuth=(req,res,next)=>req.session.admin?next():res.status(401).json({error:"Admin login kerak"});
function code(){return crypto.randomBytes(5).toString("hex").toUpperCase()}
function tx(id,amount,reason){db.prepare("INSERT INTO coin_transactions(user_id,amount,reason) VALUES(?,?,?)").run(id,amount,reason)}

app.post("/api/register",async(req,res)=>{
 try{
  let username=String(req.body.username||"").trim(), email=norm(req.body.email), password=String(req.body.password||""), confirm=String(req.body.confirm||""), referral=String(req.body.referral||"").trim().toUpperCase();
  if(username.length<3||username.length>24)return res.status(400).json({error:"Username 3–24 belgi bo‘lsin"});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:"Email noto‘g‘ri"});
  if(password.length<6)return res.status(400).json({error:"Parol kamida 6 belgi"});
  if(password!==confirm)return res.status(400).json({error:"Parollar bir xil emas"});
  if(db.prepare("SELECT 1 FROM users WHERE username_key=?").get(norm(username)))return res.status(409).json({error:"Bu username band"});
  if(db.prepare("SELECT 1 FROM users WHERE email_key=?").get(email))return res.status(409).json({error:"Bu email ro‘yxatdan o‘tgan"});
  let ref=referral?db.prepare("SELECT * FROM users WHERE referral_code=?").get(referral):null;
  if(referral&&!ref)return res.status(400).json({error:"Referral kodi noto‘g‘ri"});
  let hash=await bcrypt.hash(password,12), rc; do{rc=code()}while(db.prepare("SELECT 1 FROM users WHERE referral_code=?").get(rc));
  let id;
  db.transaction(()=>{
    let r=db.prepare("INSERT INTO users(username,username_key,email,email_key,password_hash,coins,referral_code,referred_by) VALUES(?,?,?,?,?,20,?,?)").run(username,norm(username),email,email,hash,rc,ref?.id||null);
    id=Number(r.lastInsertRowid); tx(id,20,"Yangi akkaunt bonusi");
    if(ref){db.prepare("UPDATE users SET coins=coins+100 WHERE id=?").run(ref.id);tx(ref.id,100,`${username} referral orqali qo‘shildi`);db.prepare("INSERT INTO referrals(referrer_id,referred_id,reward) VALUES(?,?,100)").run(ref.id,id)}
  })();
  req.session.userId=id; res.json({user:publicUser(db.prepare("SELECT * FROM users WHERE id=?").get(id))});
 }catch(e){res.status(500).json({error:"Ro‘yxatdan o‘tishda server xatosi"})}
});
app.post("/api/login",async(req,res)=>{
 let login=norm(req.body.login),u=db.prepare("SELECT * FROM users WHERE username_key=? OR email_key=?").get(login,login);
 if(!u||!(await bcrypt.compare(String(req.body.password||""),u.password_hash)))return res.status(401).json({error:"Login yoki parol xato"});
 if(u.blocked)return res.status(403).json({error:"Akkaunt bloklangan"});
 req.session.userId=u.id;res.json({user:publicUser(u)});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",userAuth,(req,res)=>res.json({user:publicUser(req.user)}));
app.post("/api/daily",userAuth,(req,res)=>{
 let today=new Date().toISOString().slice(0,10);
 if(req.user.last_daily===today)return res.status(409).json({error:"Bugungi 4 coin olindi"});
 db.transaction(()=>{db.prepare("UPDATE users SET coins=coins+4,last_daily=? WHERE id=?").run(today,req.user.id);tx(req.user.id,4,"Kunlik bonus")})();
 res.json({user:publicUser(db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id))});
});
app.get("/api/transactions",userAuth,(req,res)=>res.json(db.prepare("SELECT amount,reason,created_at FROM coin_transactions WHERE user_id=? ORDER BY id DESC LIMIT 50").all(req.user.id)));

app.post("/api/admin/login",(req,res)=>{
 if(String(req.body.username)===(process.env.ADMIN_USERNAME||"admin")&&String(req.body.password)===(process.env.ADMIN_PASSWORD||"CHANGE_ME")){req.session.admin=true;return res.json({ok:true})}
 res.status(401).json({error:"Admin login yoki parol xato"});
});
app.post("/api/admin/logout",adminAuth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/admin/stats",adminAuth,(req,res)=>res.json({
 users:db.prepare("SELECT COUNT(*) n FROM users").get().n,
 coins:db.prepare("SELECT COALESCE(SUM(coins),0)n FROM users").get().n,
 referrals:db.prepare("SELECT COUNT(*) n FROM referrals").get().n,
 blocked:db.prepare("SELECT COUNT(*) n FROM users WHERE blocked=1").get().n
}));
app.get("/api/admin/users",adminAuth,(req,res)=>{
 let q=norm(req.query.q),rows=q?db.prepare("SELECT id,username,email,coins,referral_code,blocked,created_at FROM users WHERE username_key LIKE ? OR email_key LIKE ? ORDER BY id DESC LIMIT 200").all("%"+q+"%","%"+q+"%"):db.prepare("SELECT id,username,email,coins,referral_code,blocked,created_at FROM users ORDER BY id DESC LIMIT 200").all();
 res.json(rows)
});
app.post("/api/admin/users/:id/coins",adminAuth,(req,res)=>{
 let id=+req.params.id,amount=Math.trunc(+req.body.amount),u=db.prepare("SELECT * FROM users WHERE id=?").get(id);
 if(!u)return res.status(404).json({error:"User topilmadi"}); if(!amount||u.coins+amount<0)return res.status(400).json({error:"Coin miqdori noto‘g‘ri"});
 db.transaction(()=>{db.prepare("UPDATE users SET coins=coins+? WHERE id=?").run(amount,id);tx(id,amount,`Admin: ${String(req.body.reason||"coin o‘zgartirildi")}`)})();
 res.json({ok:true})
});
app.post("/api/admin/users/:id/block",adminAuth,(req,res)=>{db.prepare("UPDATE users SET blocked=? WHERE id=?").run(req.body.blocked?1:0,+req.params.id);res.json({ok:true})});
app.get("/api/admin/users/:id/transactions",adminAuth,(req,res)=>res.json(db.prepare("SELECT amount,reason,created_at FROM coin_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100").all(+req.params.id)));

app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log("KILLIX running",PORT));
