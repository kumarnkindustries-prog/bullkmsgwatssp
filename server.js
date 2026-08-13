const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const XLSX = require("xlsx");
const { parse } = require("csv-parse/sync");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "bullkmsgwatssp.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT DEFAULT '',
 phone TEXT NOT NULL,
 group_name TEXT DEFAULT 'General',
 opted_in INTEGER DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(phone)
);
CREATE INDEX IF NOT EXISTS idx_contacts_group ON contacts(group_name);
CREATE TABLE IF NOT EXISTS templates (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 template_name TEXT NOT NULL,
 language TEXT DEFAULT 'en_US',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS campaigns (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 template_id INTEGER NOT NULL,
 group_name TEXT DEFAULT 'ALL',
 status TEXT DEFAULT 'QUEUED',
 total INTEGER DEFAULT 0,
 sent INTEGER DEFAULT 0,
 delivered INTEGER DEFAULT 0,
 read_count INTEGER DEFAULT 0,
 failed INTEGER DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(template_id) REFERENCES templates(id)
);
CREATE TABLE IF NOT EXISTS campaign_messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 campaign_id INTEGER NOT NULL,
 contact_id INTEGER NOT NULL,
 status TEXT DEFAULT 'QUEUED',
 wa_message_id TEXT,
 error TEXT,
 sent_at TEXT,
 FOREIGN KEY(campaign_id) REFERENCES campaigns(id),
 FOREIGN KEY(contact_id) REFERENCES contacts(id)
);
`);

function setting(key, fallback="") {
  const row = db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) {
  db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key, value);
}

const keyPath = path.join(DATA_DIR, "secret.key");
let ENC_KEY;
if (fs.existsSync(keyPath)) {
  ENC_KEY = fs.readFileSync(keyPath);
} else {
  ENC_KEY = crypto.randomBytes(32);
  fs.writeFileSync(keyPath, ENC_KEY, { mode: 0o600 });
}
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64");
}
function decrypt(blob) {
  try {
    const b = Buffer.from(blob, "base64");
    const iv=b.subarray(0,12), tag=b.subarray(12,28), data=b.subarray(28);
    const decipher=crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
  } catch { return ""; }
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use(rateLimit({windowMs: 60*1000, limit: 300, standardHeaders: true, legacyHeaders: false}));
app.use(express.static(path.join(__dirname,"public")));

const upload = multer({ storage: multer.memoryStorage(), limits:{fileSize:25*1024*1024} });

function tokenFor(user) {
  return jwt.sign({id:user.id, username:user.username}, process.env.JWT_SECRET || "change-me", {expiresIn:"12h"});
}
function auth(req,res,next) {
  const token=req.cookies.bmw_token;
  if(!token) return res.status(401).json({error:"Login required"});
  try { req.user=jwt.verify(token, process.env.JWT_SECRET || "change-me"); next(); }
  catch { res.clearCookie("bmw_token"); return res.status(401).json({error:"Session expired"}); }
}

app.get("/api/status",(req,res)=>{
  res.json({
    setup: db.prepare("SELECT COUNT(*) c FROM users").get().c===0,
    whatsapp: !!setting("wa_phone_id"),
    contacts: db.prepare("SELECT COUNT(*) c FROM contacts").get().c,
    campaigns: db.prepare("SELECT COUNT(*) c FROM campaigns").get().c
  });
});

app.post("/api/setup", async (req,res)=>{
  if(db.prepare("SELECT COUNT(*) c FROM users").get().c) return res.status(400).json({error:"Setup already completed"});
  const {username,password}=req.body;
  if(!username || !password || password.length<8) return res.status(400).json({error:"Username and password are required; password must be at least 8 characters."});
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(username,password_hash) VALUES(?,?)").run(username.trim(),hash);
  const token=tokenFor({id:info.lastInsertRowid,username:username.trim()});
  res.cookie("bmw_token",token,{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:12*60*60*1000});
  res.json({ok:true});
});

app.post("/api/login", async (req,res)=>{
  const row=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username||"");
  if(!row || !(await bcrypt.compare(req.body.password||"",row.password_hash))) return res.status(401).json({error:"Invalid login"});
  res.cookie("bmw_token",tokenFor(row),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:12*60*60*1000});
  res.json({ok:true});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("bmw_token");res.json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json({username:req.user.username}));

app.get("/api/dashboard",auth,(req,res)=>{
  const contacts=db.prepare("SELECT COUNT(*) c FROM contacts").get().c;
  const opted=db.prepare("SELECT COUNT(*) c FROM contacts WHERE opted_in=1").get().c;
  const campaigns=db.prepare("SELECT COUNT(*) c FROM campaigns").get().c;
  const sums=db.prepare("SELECT COALESCE(SUM(sent),0) sent, COALESCE(SUM(delivered),0) delivered, COALESCE(SUM(read_count),0) read_count, COALESCE(SUM(failed),0) failed FROM campaigns").get();
  res.json({contacts,opted,campaigns,...sums,whatsapp:!!setting("wa_phone_id")});
});

app.post("/api/whatsapp/settings",auth,(req,res)=>{
  const {phoneId,accessToken,apiVersion="v23.0"}=req.body;
  if(!phoneId || !accessToken) return res.status(400).json({error:"Phone Number ID and access token are required."});
  setSetting("wa_phone_id",phoneId.trim());
  setSetting("wa_token",encrypt(accessToken.trim()));
  setSetting("wa_version",apiVersion.trim());
  res.json({ok:true});
});

app.get("/api/contacts",auth,(req,res)=>{
  const q=(req.query.q||"").trim();
  const group=(req.query.group||"").trim();
  let sql="SELECT id,name,phone,group_name,opted_in,created_at FROM contacts WHERE 1=1", params=[];
  if(q){sql+=" AND (name LIKE ? OR phone LIKE ?)";params.push("%"+q+"%","%"+q+"%")}
  if(group){sql+=" AND group_name=?";params.push(group)}
  sql+=" ORDER BY id DESC LIMIT 500";
  res.json({contacts:db.prepare(sql).all(...params)});
});

app.post("/api/contacts/import",auth,upload.single("file"),(req,res)=>{
  if(!req.file) return res.status(400).json({error:"CSV or Excel file required."});
  let rows=[];
  const ext=path.extname(req.file.originalname).toLowerCase();
  try {
    if(ext===".csv"){
      rows=parse(req.file.buffer.toString("utf8"),{columns:true,skip_empty_lines:true,relax_column_count:true});
    } else if(ext===".xlsx" || ext===".xls"){
      const wb=XLSX.read(req.file.buffer,{type:"buffer"});
      const sheet=wb.Sheets[wb.SheetNames[0]];
      rows=XLSX.utils.sheet_to_json(sheet,{defval:""});
    } else return res.status(400).json({error:"Only CSV, XLSX or XLS files are supported."});
  } catch(e){return res.status(400).json({error:"Could not read the file."});}
  const insert=db.prepare(`INSERT INTO contacts(name,phone,group_name,opted_in) VALUES(?,?,?,?)
    ON CONFLICT(phone) DO UPDATE SET name=excluded.name, group_name=excluded.group_name, opted_in=excluded.opted_in`);
  let imported=0, skipped=0;
  const tx=db.transaction((items)=>{
    for(const r of items){
      const phone=String(r.phone||r.Phone||r.mobile||r.Mobile||r.number||r.Number||"").replace(/[^\d+]/g,"");
      if(!phone){skipped++;continue}
      const name=String(r.name||r.Name||"");
      const group=String(r.group||r.Group||r.group_name||r.GroupName||req.body.group||"General");
      const opted = String(r.opted_in??r.optedIn??"1").toLowerCase();
      const yes=["1","true","yes","y","opted_in","opt-in"].includes(opted);
      insert.run(name,phone,group,yes?1:0); imported++;
    }
  });
  tx(rows);
  res.json({ok:true,imported,skipped});
});

app.get("/api/templates",auth,(req,res)=>res.json({templates:db.prepare("SELECT * FROM templates ORDER BY id DESC").all()}));
app.post("/api/templates",auth,(req,res)=>{
  const {name,templateName,language="en_US"}=req.body;
  if(!name||!templateName)return res.status(400).json({error:"Name and WhatsApp template name are required."});
  const info=db.prepare("INSERT INTO templates(name,template_name,language) VALUES(?,?,?)").run(name.trim(),templateName.trim(),language.trim());
  res.json({id:info.lastInsertRowid});
});

app.get("/api/campaigns",auth,(req,res)=>res.json({campaigns:db.prepare("SELECT * FROM campaigns ORDER BY id DESC LIMIT 100").all()}));

async function sendTemplate(phone, templateName, language) {
  const phoneId=setting("wa_phone_id"), token=decrypt(setting("wa_token")), version=setting("wa_version","v23.0");
  if(!phoneId||!token) throw new Error("WhatsApp API is not configured.");
  const url=`https://graph.facebook.com/${version}/${phoneId}/messages`;
  const body={messaging_product:"whatsapp",to:phone.replace(/^\+/,""),type:"template",template:{name:templateName,language:{code:language}}};
  const r=await fetch(url,{method:"POST",headers:{"Authorization":`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify(body)});
  const data=await r.json();
  if(!r.ok) throw new Error(data?.error?.message || "WhatsApp API error");
  return data?.messages?.[0]?.id || "";
}

app.post("/api/campaigns",auth,async(req,res)=>{
  const {name,templateId,group="ALL"}=req.body;
  const template=db.prepare("SELECT * FROM templates WHERE id=?").get(Number(templateId));
  if(!name||!template)return res.status(400).json({error:"Campaign name and template are required."});
  if(!setting("wa_phone_id"))return res.status(400).json({error:"Connect WhatsApp API in Settings first."});
  let contacts;
  if(group==="ALL") contacts=db.prepare("SELECT * FROM contacts WHERE opted_in=1").all();
  else contacts=db.prepare("SELECT * FROM contacts WHERE opted_in=1 AND group_name=?").all(group);
  if(!contacts.length)return res.status(400).json({error:"No opted-in contacts found in this group."});
  const info=db.prepare("INSERT INTO campaigns(name,template_id,group_name,status,total) VALUES(?,?,?,?,?)").run(name,template.id,group,"RUNNING",contacts.length);
  const campaignId=info.lastInsertRowid;
  const add=db.prepare("INSERT INTO campaign_messages(campaign_id,contact_id) VALUES(?,?)");
  const tx=db.transaction((cs)=>cs.forEach(c=>add.run(campaignId,c.id))); tx(contacts);

  // Controlled sequential sending. This avoids hammering the API; platform limits still apply.
  setImmediate(async()=>{
    const update=db.prepare("UPDATE campaign_messages SET status=?,wa_message_id=?,error=?,sent_at=? WHERE id=?");
    const incSent=db.prepare("UPDATE campaigns SET sent=sent+1 WHERE id=?");
    const incFail=db.prepare("UPDATE campaigns SET failed=failed+1 WHERE id=?");
    const msgs=db.prepare("SELECT cm.*,c.phone FROM campaign_messages cm JOIN contacts c ON c.id=cm.contact_id WHERE cm.campaign_id=?").all(campaignId);
    for(const m of msgs){
      try{
        const id=await sendTemplate(m.phone,template.template_name,template.language);
        update.run("SENT",id,"",new Date().toISOString(),m.id); incSent.run(campaignId);
      }catch(e){
        update.run("FAILED","",String(e.message).slice(0,500),new Date().toISOString(),m.id); incFail.run(campaignId);
      }
      await new Promise(r=>setTimeout(r,350));
    }
    db.prepare("UPDATE campaigns SET status='COMPLETED' WHERE id=?").run(campaignId);
  });
  res.json({ok:true,campaignId,total:contacts.length});
});

app.get("/webhook",(req,res)=>{
  const verify=setting("wa_verify_token");
  if(req.query["hub.mode"]==="subscribe" && req.query["hub.verify_token"]===verify) return res.status(200).send(req.query["hub.challenge"]);
  res.sendStatus(403);
});
app.post("/webhook",(req,res)=>{
  res.sendStatus(200);
  // Delivery/read webhook persistence can be expanded using the message ID.
  // We acknowledge immediately so the provider does not retry unnecessarily.
});

app.use((req,res)=>{
res.sendFile(path.join(__dirname,'public','index.html'));
});
app.listen(PORT,()=>console.log(`BullkMsgWatssp running on http://localhost:${PORT}`));
