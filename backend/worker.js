// ═══════════════════════════════════════════════════════
//  NEXUS v14 — Intelligent Analytical Engine
//  Cloudflare Worker
// ═══════════════════════════════════════════════════════

const ORIGIN_WHITELIST = [
  "https://nexus.onliraxter.workers.dev",
  "https://nexus-data-analyst-web.pages.dev",
  "https://*.nexus-data-analyst-web.pages.dev",
  "https://nexus-project.pages.dev",
  "https://*.nexus-project.pages.dev",
  "https://nexus-backend-clean.onliraxter.workers.dev",
  "http://localhost:*","http://127.0.0.1:*","null"
];
const SECURITY_HEADERS = {
  "X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY",
  "Strict-Transport-Security":"max-age=31536000; includeSubDomains",
  "X-XSS-Protection":"1; mode=block","Referrer-Policy":"no-referrer",
  "X-NEXUS-Origin":"onliraxter"
};
const CORS = {
  "Access-Control-Allow-Origin":"*",
  "Access-Control-Allow-Methods":"GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":"Content-Type, x-nexus-token, x-admin-secret, authorization",
  "Access-Control-Expose-Headers":"X-NEXUS-Origin, Content-Type",
  "Access-Control-Max-Age":"86400"
};

function json(data,status=200,origin=null){
  const h={"Content-Type":"application/json",...SECURITY_HEADERS};
  Object.entries(CORS).forEach(([k,v])=>h[k]=v);
  if(origin)h["Access-Control-Allow-Origin"]=origin;
  return new Response(JSON.stringify(data),{status,headers:h});
}
function err(msg,status=400,origin=null){return json({error:msg},status,origin);}
function sanitize(s){return typeof s==='string'?s.replace(/<[^>]*>/g,'').replace(/script/gi,''):s;}

async function logActivity(env,ip,type,details={}){
  const ts=Date.now();
  await env.NEXUS_KV.put(`log:${ts}:${ip}`,JSON.stringify({ts,ip,type,...details}),{expirationTtl:604800});
  const list=await env.NEXUS_KV.list({prefix:"log:"});
  if(list.keys.length>100){
    const sorted=list.keys.sort((a,b)=>a.name.localeCompare(b.name));
    for(const k of sorted.slice(0,list.keys.length-100))await env.NEXUS_KV.delete(k.name);
  }
}
async function checkRateLimit(env,ip,type,max){
  const key=`ratelimit:${type}:${ip}`;
  const count=parseInt(await env.NEXUS_KV.get(key)||"0")+1;
  if(count>max)return false;
  await env.NEXUS_KV.put(key,count.toString(),{expirationTtl:60});
  return true;
}
async function isBlacklisted(env,ip){
  if(await env.NEXUS_KV.get(`blacklist:${ip}`))return true;
  const hourKey=`hourly:${ip}`;
  const count=parseInt(await env.NEXUS_KV.get(hourKey)||"0")+1;
  await env.NEXUS_KV.put(hourKey,count.toString(),{expirationTtl:3600});
  if(count>200){
    await env.NEXUS_KV.put(`blacklist:${ip}`,"High frequency abuse",{expirationTtl:86400});
    await logActivity(env,ip,"AUTO_BLACKLIST",{count});
    return true;
  }
  return false;
}
async function signJWT(payload,secret){
  const iat=Math.floor(Date.now()/1000),exp=iat+86400;
  const fp={...payload,iat,exp};
  const header=btoa(JSON.stringify({alg:"HS256",typ:"JWT"}));
  const body=btoa(unescape(encodeURIComponent(JSON.stringify(fp))));
  const msg=`${header}.${body}`;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(msg));
  const b64=btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
  return `${msg}.${b64}`;
}
async function verifyJWT(token,secret){
  try{
    const [header,body,sig]=token.split(".");
    const msg=`${header}.${body}`;
    const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const sigBuf=Uint8Array.from(atob(sig.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
    const valid=await crypto.subtle.verify("HMAC",key,sigBuf,new TextEncoder().encode(msg));
    if(!valid)return null;
    const pl=JSON.parse(decodeURIComponent(escape(atob(body))));
    if(pl.exp&&Math.floor(Date.now()/1000)>pl.exp)return{expired:true};
    return pl;
  }catch{return null;}
}
async function verifyGoogleToken(credential,clientId){
  const res=await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
  if(!res.ok)return null;
  const data=await res.json();
  if(data.aud!==clientId)return null;
  return{email:data.email,name:data.name,picture:data.picture,sub:data.sub};
}
async function getUser(request,env){
  const token=request.headers.get("x-nexus-token");
  if(!token)return null;
  const payload=await verifyJWT(token,env.JWT_SECRET);
  if(!payload)return null;
  if(payload.expired)return{expired:true};
  const raw=await env.NEXUS_KV.get(`user:${payload.email}`);
  if(!raw)return null;
  return JSON.parse(raw);
}
async function saveUser(env,user){await env.NEXUS_KV.put(`user:${user.email}`,JSON.stringify(user));}
async function getAllUsers(env){
  const list=await env.NEXUS_KV.list({prefix:"user:"});
  const users=[];
  for(const key of list.keys){const raw=await env.NEXUS_KV.get(key.name);if(raw)users.push(JSON.parse(raw));}
  return users;
}

// ═══════════════════════════════════════════════════════
//  LAYER 1 — CSV PARSER
// ═══════════════════════════════════════════════════════
function parseCSV(text){
  const lines=text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n');
  const rows=[];
  for(const line of lines){
    if(!line.trim())continue;
    const row=[];let inQ=false,cur='';
    for(let i=0;i<line.length;i++){
      const ch=line[i];
      if(ch==='"'){if(inQ&&line[i+1]==='"'){cur+='"';i++;}else inQ=!inQ;}
      else if(ch===','&&!inQ){row.push(cur.trim());cur='';}
      else cur+=ch;
    }
    row.push(cur.trim());
    rows.push(row);
  }
  if(rows.length<2)return{headers:[],records:[]};
  const headers=rows[0].map(h=>h.replace(/^"|"$/g,'').trim());
  const records=[];
  for(let i=1;i<rows.length;i++){
    if(rows[i].every(c=>!c))continue;
    const rec={};
    headers.forEach((h,j)=>{rec[h]=rows[i][j]!==undefined?rows[i][j]:'';});
    records.push(rec);
  }
  return{headers,records};
}

// ═══════════════════════════════════════════════════════
//  LAYER 2 — SCHEMA DETECTION
// ═══════════════════════════════════════════════════════
const COL_ALIASES={
  revenue:  ['amount','revenue','sales','price','total','final_amount','sale_price','total_amount',
             'grand_total','net_amount','value','income','earning','payment','cost','fee','charge',
             'invoice_amount','order_value','gmv','transaction_amount','subtotal','unit_price'],
  date:     ['date','timestamp','created_at','order_date','transaction_date','signup_date',
             'purchase_date','time','datetime','created','updated_at','order_time','sale_date',
             'invoice_date','event_date','date_time','order_created'],
  user_id:  ['user_id','customer_id','cust_id','client_id','uid','userid','customerid',
             'buyer_id','account_id','member_id','contact_id','user','customer'],
  email:    ['email','email_address','user_email','customer_email'],
  category: ['category','type','group','department','segment','product_type','item_type',
             'channel','source','product_category','region','country','city','brand','vertical',
             'division','subcategory'],
  product:  ['product','product_name','item','item_name','sku','product_id','description',
             'name','title','product_title','item_description'],
  quantity: ['quantity','qty','units','count','volume','items','num_items','pieces'],
  status:   ['status','state','stage','order_status','payment_status','txn_status'],
};
function detectSchema(headers){
  const detected={};
  const lower=headers.map(h=>h.toLowerCase().replace(/[^a-z0-9_]/g,'_'));
  for(const[role,aliases]of Object.entries(COL_ALIASES)){
    if(detected[role])continue;
    for(let i=0;i<lower.length;i++){
      const h=lower[i];
      if(aliases.some(a=>h===a||h.startsWith(a+'_')||h.endsWith('_'+a)||(a.length>4&&h.includes(a)))){
        detected[role]=headers[i];break;
      }
    }
  }
  return detected;
}
function inferDatasetType(detected,headers,records){
  const h=headers.join(' ').toLowerCase();
  if(h.includes('mrr')||h.includes('churn')||h.includes('arr')||h.includes('subscription')||h.includes('plan'))return'saas';
  if(h.includes('salary')||h.includes('employee')||h.includes('department')||h.includes('attrition')||h.includes('headcount'))return'hr';
  if(h.includes('stock')||h.includes('portfolio')||h.includes('dividend')||h.includes('ticker')||h.includes('close_price'))return'finance';
  if(h.includes('campaign')||h.includes('ctr')||h.includes('impression')||h.includes('conversion')||h.includes('roas'))return'marketing';
  if(h.includes('inventory')||h.includes('warehouse')||h.includes('shipment')||h.includes('supplier'))return'operations';
  if(detected.user_id&&detected.revenue&&detected.date)return'ecommerce';
  if(detected.revenue&&detected.date)return'transactional';
  if(detected.revenue)return'revenue';
  return'generic';
}

// ═══════════════════════════════════════════════════════
//  LAYER 3 — INTENT PARSER
// ═══════════════════════════════════════════════════════
function parseIntent(question,dsType){
  const q=(question||'').toLowerCase();
  const i={primary:'overview',
    focusAnomaly:/anomal|outlier|unusual|spike|suspicious|fraud|duplic|weird|wrong/i.test(q),
    focusTrend:/trend|over time|growth|month|week|daily|period|forecast|project|future/i.test(q),
    focusUser:/user|customer|repeat|retention|cohort|loyal|churn|segment|who/i.test(q),
    focusCategory:/categ|segment|product|channel|group|break|split|top|best|worst/i.test(q),
    focusQuality:/clean|quality|miss|corrupt|valid|error|duplicate|issue|problem/i.test(q),
    focusStats:/distribut|median|percentile|std|variance|outlier|stat|min|max|avg/i.test(q),
    needsAction:/recommend|should|action|improve|fix|next|what to do|suggest|advice/i.test(q),
    needsComparison:/compare|vs|versus|difference|better|worse|against|benchmark/i.test(q),
  };
  if(i.focusAnomaly)i.primary='anomaly';
  else if(i.focusUser&&i.focusTrend)i.primary='cohort';
  else if(i.focusTrend)i.primary='trend';
  else if(i.focusUser)i.primary='user';
  else if(i.focusCategory)i.primary='category';
  else if(i.focusStats)i.primary='distribution';
  else if(i.focusQuality)i.primary='quality';
  else if(dsType==='saas')i.primary='saas';
  else if(dsType==='hr')i.primary='hr';
  return i;
}

// ═══════════════════════════════════════════════════════
//  LAYER 4 — DATA CLEANER
// ═══════════════════════════════════════════════════════
function toNum(val){
  if(val===null||val===undefined||val==='')return null;
  const s=String(val).replace(/[₹$€£¥,\s]/g,'').replace(/[()]/g,'');
  if(!s||s==='-'||/^(null|na|n\/a|nan|undefined)$/i.test(s))return null;
  const n=parseFloat(s);return isNaN(n)?null:n;
}
function toDate(val){
  if(!val)return null;
  const s=String(val).trim();if(!s)return null;
  let d=new Date(s);
  if(!isNaN(d.getTime())&&d.getFullYear()>1900&&d.getFullYear()<2100)return d;
  const parts=s.split(/[\/\-\.]/);
  if(parts.length===3){
    const[a,b,c]=parts;
    if(c.length===4){d=new Date(`${c}-${b.padStart(2,'0')}-${a.padStart(2,'0')}`);if(!isNaN(d.getTime()))return d;}
    if(a.length===4){d=new Date(`${a}-${b.padStart(2,'0')}-${c.padStart(2,'0')}`);if(!isNaN(d.getTime()))return d;}
  }
  return null;
}
function cleanData(records,detected){
  const issues=[],rowsBefore=records.length;
  const seen=new Set();
  let cleaned=records.filter(row=>{const fp=JSON.stringify(row);if(seen.has(fp))return false;seen.add(fp);return true;});
  const dupsRemoved=rowsBefore-cleaned.length;
  if(dupsRemoved>0)issues.push(`Removed ${dupsRemoved} exact duplicate rows`);
  if(detected.revenue){
    cleaned=cleaned.map(row=>({...row,_rev:toNum(row[detected.revenue])}));
    const before=cleaned.length;cleaned=cleaned.filter(row=>row._rev!==null);
    const dropped=before-cleaned.length;if(dropped>0)issues.push(`Dropped ${dropped} rows with unparseable ${detected.revenue}`);
  } else cleaned=cleaned.map(row=>({...row,_rev:null}));
  if(detected.date){
    cleaned=cleaned.map(row=>({...row,_date:toDate(row[detected.date])}));
    const before=cleaned.length;cleaned=cleaned.filter(row=>row._date!==null);
    const dropped=before-cleaned.length;if(dropped>0)issues.push(`Dropped ${dropped} rows with unparseable dates`);
  } else cleaned=cleaned.map(row=>({...row,_date:null}));
  if(detected.quantity)cleaned=cleaned.map(row=>({...row,_qty:toNum(row[detected.quantity])}));
  if(detected.revenue){
    const vals=cleaned.map(row=>row._rev).filter(v=>v!==null).sort((a,b)=>a-b);
    if(vals.length>=4){
      const q1=vals[Math.floor(vals.length*.25)],q3=vals[Math.floor(vals.length*.75)],iqr=q3-q1;
      const upper=q3+1.5*iqr,lower=q1-1.5*iqr;
      const oCount=cleaned.filter(row=>row._rev!==null&&(row._rev<lower||row._rev>upper)).length;
      if(oCount>0)issues.push(`Flagged ${oCount} IQR outliers (kept for analysis)`);
      cleaned=cleaned.map(row=>({...row,_iqr_out:row._rev!==null&&(row._rev<lower||row._rev>upper)}));
    } else cleaned=cleaned.map(row=>({...row,_iqr_out:false}));
  }
  return{cleaned,dataQuality:{rows_before:rowsBefore,rows_after:cleaned.length,clean_rate:rowsBefore>0?Math.round((cleaned.length/rowsBefore)*100):100,issues,detected_cols:detected}};
}

// ═══════════════════════════════════════════════════════
//  LAYER 5 — STATISTICS ENGINE
// ═══════════════════════════════════════════════════════
function rv(v,d=2){if(!isFinite(v))return 0;return Math.round(v*10**d)/10**d;}
function calcStats(arr){
  const s=[...arr].sort((a,b)=>a-b),n=s.length;
  if(!n)return null;
  const sum=s.reduce((a,v)=>a+v,0),mean=sum/n;
  const variance=s.reduce((a,v)=>a+(v-mean)**2,0)/n;
  const pct=p=>{const idx=(p/100)*(n-1),lo=Math.floor(idx),hi=Math.ceil(idx);return s[lo]+(s[hi]-s[lo])*(idx-lo);};
  return{n,sum:rv(sum),mean:rv(mean),median:rv(pct(50)),std:rv(Math.sqrt(variance)),
    min:rv(s[0]),max:rv(s[n-1]),p25:rv(pct(25)),p75:rv(pct(75)),p90:rv(pct(90)),p99:rv(pct(99))};
}

// ═══════════════════════════════════════════════════════
//  LAYER 6 — METRICS ENGINE
// ═══════════════════════════════════════════════════════
function computeMetrics(cleaned,detected){
  const m={revenue:null,orders:cleaned.length,aov:null,median_order:null,
    unique_users:null,repeat_rate:null,avg_daily_revenue:null,growth:0,
    revenue_trend:[],monthly_trend:[],day_of_week:[],
    category_breakdown:[],top_products:[],revenue_stats:null,pareto_concentration:null};
  if(detected.revenue){
    const vals=cleaned.map(row=>row._rev).filter(v=>v!==null&&isFinite(v));
    const s=calcStats(vals);
    if(s){m.revenue=s.sum;m.revenue_stats=s;m.aov=cleaned.length>0?rv(s.sum/cleaned.length):0;m.median_order=s.median;}
  }
  const uCol=detected.user_id||detected.email;
  if(uCol){
    const uMap={};
    cleaned.forEach(row=>{const u=row[uCol];if(u)uMap[u]=(uMap[u]||0)+1;});
    const uArr=Object.values(uMap);
    m.unique_users=uArr.length;
    m.repeat_rate=m.unique_users>0?rv((uArr.filter(c=>c>1).length/m.unique_users)*100):0;
    if(detected.revenue){
      const uRevMap={};
      cleaned.forEach(row=>{const u=row[uCol];if(u)uRevMap[u]=(uRevMap[u]||0)+(row._rev||0);});
      const revVals=Object.values(uRevMap).sort((a,b)=>b-a);
      const top20=Math.max(1,Math.floor(revVals.length*.2));
      const tot=revVals.reduce((s,v)=>s+v,0);
      m.pareto_concentration=tot>0?rv((revVals.slice(0,top20).reduce((s,v)=>s+v,0)/tot)*100):null;
    }
  }
  if(detected.date){
    const dailyMap={},monthlyMap={};
    const dowMap={0:0,1:0,2:0,3:0,4:0,5:0,6:0},dowCount={0:0,1:0,2:0,3:0,4:0,5:0,6:0};
    const DOW=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    cleaned.forEach(row=>{
      if(!row._date)return;
      const dk=row._date.toISOString().slice(0,10),mk=row._date.toISOString().slice(0,7),dow=row._date.getDay();
      const rev=detected.revenue?(row._rev||0):1;
      dailyMap[dk]=(dailyMap[dk]||0)+rev;monthlyMap[mk]=(monthlyMap[mk]||0)+rev;
      dowMap[dow]+=rev;dowCount[dow]++;
    });
    m.revenue_trend=Object.entries(dailyMap).sort((a,b)=>a[0].localeCompare(b[0])).map(([name,val])=>({name,val:rv(val)}));
    m.monthly_trend=Object.entries(monthlyMap).sort((a,b)=>a[0].localeCompare(b[0])).map(([name,val])=>({name,val:rv(val)}));
    m.day_of_week=DOW.map((name,i)=>({name,val:rv(dowMap[i]),count:dowCount[i]}));
    const trend=m.revenue_trend;
    if(trend.length>=14){
      const l7=trend.slice(-7).reduce((s,d)=>s+d.val,0),p7=trend.slice(-14,-7).reduce((s,d)=>s+d.val,0);
      m.growth=p7>0?rv(((l7-p7)/p7)*100):0;
    }
    if(trend.length>0)m.avg_daily_revenue=rv(trend.reduce((s,d)=>s+d.val,0)/trend.length);
  }
  if(detected.category){
    const catMap={},catRevMap={};
    cleaned.forEach(row=>{const cat=row[detected.category]||'Unknown';catMap[cat]=(catMap[cat]||0)+1;catRevMap[cat]=(catRevMap[cat]||0)+(row._rev||0);});
    m.category_breakdown=Object.entries(catRevMap).sort((a,b)=>b[1]-a[1]).slice(0,12).map(([name,val])=>({name,val:rv(val),count:catMap[name]}));
  }
  if(detected.product){
    const pMap={},pRevMap={};
    cleaned.forEach(row=>{const p=row[detected.product]||'Unknown';pMap[p]=(pMap[p]||0)+1;pRevMap[p]=(pRevMap[p]||0)+(row._rev||0);});
    m.top_products=Object.entries(pRevMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([name,val])=>({name,val:rv(val),orders:pMap[name]}));
  }
  return m;
}

// ═══════════════════════════════════════════════════════
//  LAYER 7 — COHORT ENGINE
// ═══════════════════════════════════════════════════════
function computeCohorts(cleaned,detected){
  const uCol=detected.user_id||detected.email;
  if(!uCol||!detected.date)return null;
  const firstSeen={};
  cleaned.forEach(row=>{if(!row._date||!row[uCol])return;const u=row[uCol];if(!firstSeen[u]||row._date<firstSeen[u])firstSeen[u]=row._date;});
  const matrix={},cohortSizes={};
  cleaned.forEach(row=>{
    if(!row._date||!row[uCol])return;
    const u=row[uCol];if(!firstSeen[u])return;
    const cohort=firstSeen[u].toISOString().slice(0,7);
    const order=row._date.toISOString().slice(0,7);
    const period=Math.round((new Date(order+'-01')-new Date(cohort+'-01'))/(30*86400000));
    if(period<0||period>11)return;
    if(!matrix[cohort])matrix[cohort]={};
    if(!matrix[cohort][period])matrix[cohort][period]=new Set();
    matrix[cohort][period].add(u);
  });
  const retention={};
  for(const cohort of Object.keys(matrix).sort()){
    const size=matrix[cohort][0]?.size||0;
    if(size<3)continue;
    cohortSizes[cohort]=size;retention[cohort]={};
    for(let p=0;p<=11;p++)retention[cohort][p]=rv((matrix[cohort][p]?.size||0)/size*100);
  }
  return Object.keys(retention).length>=2?{retention_matrix:retention,cohort_sizes:cohortSizes}:null;
}

// ═══════════════════════════════════════════════════════
//  LAYER 8 — ANOMALY ENGINE
// ═══════════════════════════════════════════════════════
function detectAnomalies(cleaned,detected){
  const anomalies=[];
  if(detected.revenue){
    const vals=cleaned.map(row=>row._rev).filter(v=>v!==null&&isFinite(v));
    const negs=cleaned.filter(row=>row._rev!==null&&row._rev<0);
    if(negs.length)anomalies.push({type:'NEGATIVE_REVENUE',severity:'HIGH',value:negs.length,
      impact:rv(Math.abs(negs.reduce((s,row)=>s+(row._rev||0),0))),
      reason:`${negs.length} transaction${negs.length>1?'s':''} with negative revenue — possible refunds, reversals, or data entry errors`});
    if(vals.length>=10){
      const mean=vals.reduce((s,v)=>s+v,0)/vals.length;
      const std=Math.sqrt(vals.reduce((s,v)=>s+(v-mean)**2,0)/vals.length);
      if(std>0){
        const outliers=cleaned.filter(row=>row._rev!==null&&Math.abs((row._rev-mean)/std)>3);
        if(outliers.length){
          const maxZ=rv(Math.max(...outliers.map(row=>Math.abs((row._rev-mean)/std))),1);
          anomalies.push({type:'STATISTICAL_OUTLIER',severity:'MEDIUM',value:outliers.length,
            impact:rv(outliers.reduce((s,row)=>s+(row._rev||0),0)),
            reason:`${outliers.length} orders with Z-score >3σ from mean ${rv(mean)}. Highest deviation: ${maxZ}σ`});
        }
      }
    }
    if(detected.date&&vals.length>=7){
      const dailyMap={};
      cleaned.forEach(row=>{if(!row._date||row._rev===null)return;const k=row._date.toISOString().slice(0,10);dailyMap[k]=(dailyMap[k]||0)+row._rev;});
      const dVals=Object.values(dailyMap);
      if(dVals.length>=5){
        const dmean=dVals.reduce((s,v)=>s+v,0)/dVals.length;
        const dstd=Math.sqrt(dVals.reduce((s,v)=>s+(v-dmean)**2,0)/dVals.length);
        if(dstd>0){
          const spikes=Object.entries(dailyMap).filter(([,v])=>Math.abs((v-dmean)/dstd)>2.5);
          if(spikes.length){
            const top=spikes.sort((a,b)=>Math.abs(b[1]-dmean)-Math.abs(a[1]-dmean))[0];
            anomalies.push({type:top[1]>dmean?'REVENUE_SPIKE':'REVENUE_DROP',severity:'MEDIUM',
              value:rv(top[1]),impact:rv(Math.abs(top[1]-dmean)),
              reason:`${top[0]}: revenue ${rv(top[1])} vs daily avg ${rv(dmean)} (${rv(Math.abs((top[1]-dmean)/dstd),1)}σ). ${spikes.length} anomalous day${spikes.length>1?'s':''} total`});
          }
        }
      }
    }
    const zeros=cleaned.filter(row=>row._rev===0).length;
    if(zeros>cleaned.length*.05&&zeros>3)
      anomalies.push({type:'ZERO_VALUE_TRANSACTIONS',severity:'LOW',value:zeros,impact:0,
        reason:`${zeros} zero-value transactions (${rv(zeros/cleaned.length*100)}% of total) — free orders, failed payments, or test data`});
  }
  const uCol=detected.user_id||detected.email;
  if(uCol&&detected.date){
    const byUser={};
    cleaned.forEach(row=>{if(!row[uCol]||!row._date)return;const u=row[uCol];if(!byUser[u])byUser[u]=[];byUser[u].push(row._date.getTime());});
    let rapidPairs=0;
    for(const times of Object.values(byUser)){times.sort((a,b)=>a-b);for(let i=1;i<times.length;i++)if(times[i]-times[i-1]<60000)rapidPairs++;}
    if(rapidPairs>0)anomalies.push({type:'SUSPICIOUS_FREQUENCY',severity:'HIGH',value:rapidPairs,impact:0,
      reason:`${rapidPairs} transaction pair${rapidPairs>1?'s':''} from same user within 60 seconds — possible duplicate charges or bot activity`});
  }
  return{anomalies:anomalies.slice(0,15),count:anomalies.length};
}

// ═══════════════════════════════════════════════════════
//  LAYER 9 — CONFIDENCE SCORER
// ═══════════════════════════════════════════════════════
function scoreConfidence(cleaned,dataQuality,detected,anomalyResult){
  let score=100;const n=cleaned.length;
  if(n<10)score-=40;else if(n<50)score-=20;else if(n<200)score-=10;
  const cr=dataQuality.clean_rate;
  if(cr<80)score-=20;else if(cr<90)score-=10;else if(cr<95)score-=5;
  if(!detected.revenue)score-=15;if(!detected.date)score-=10;if(!detected.user_id&&!detected.email)score-=5;
  const ad=n>0?anomalyResult.count/n:0;
  if(ad>0.2)score-=15;else if(ad>0.05)score-=5;
  score=Math.max(0,Math.min(100,score));
  return score>=80?'HIGH':score>=55?'MEDIUM':'LOW';
}

// ═══════════════════════════════════════════════════════
//  LAYER 10 — INTELLIGENT PROMPT BUILDER
// ═══════════════════════════════════════════════════════
function buildPrompt(metrics,detected,dataQuality,anomalyResult,cohortResult,dsType,intent,fileName,question,confidence){
  const fmt=v=>(v!=null&&isFinite(v))?Number(v).toLocaleString('en-IN'):'N/A';
  const pct=v=>(v!=null&&isFinite(v))?`${v}%`:'N/A';

  const coreBlock=[
    `DATASET: "${fileName||'data'}" | TYPE: ${dsType.toUpperCase()} | ROWS: ${metrics.orders} (${dataQuality.rows_before} raw, ${dataQuality.clean_rate}% clean)`,
    `COLUMNS DETECTED: ${Object.entries(detected).map(([k,v])=>`${k}="${v}"`).join(', ')||'none'}`,
    dataQuality.issues.length?`QUALITY ISSUES: ${dataQuality.issues.join(' | ')}`:`QUALITY: Clean`,
    `CONFIDENCE: ${confidence}`,
    ``,
    `── VERIFIED METRICS ──`,
    detected.revenue?[
      `Revenue: ${fmt(metrics.revenue)} | Orders: ${metrics.orders} | AOV: ${fmt(metrics.aov)} | Median: ${fmt(metrics.median_order)}`,
      metrics.revenue_stats?`Stats: min=${fmt(metrics.revenue_stats.min)} p25=${fmt(metrics.revenue_stats.p25)} p75=${fmt(metrics.revenue_stats.p75)} p90=${fmt(metrics.revenue_stats.p90)} max=${fmt(metrics.revenue_stats.max)} std=${fmt(metrics.revenue_stats.std)}`:'',
      metrics.growth!=null?`WoW Growth: ${pct(metrics.growth)} | Avg Daily: ${fmt(metrics.avg_daily_revenue)}`:'',
    ].filter(Boolean).join('\n'):'NO REVENUE COLUMN',
    metrics.unique_users!=null?`Users: ${metrics.unique_users} | Repeat Rate: ${pct(metrics.repeat_rate)} | Pareto (top 20% users): ${pct(metrics.pareto_concentration)} of revenue`:'',
  ].filter(Boolean).join('\n');

  const contextBlocks=[];

  // Time — include if relevant
  if((intent.focusTrend||intent.primary==='overview')&&metrics.monthly_trend.length>=2)
    contextBlocks.push('── MONTHLY TREND ──\n'+metrics.monthly_trend.map(d=>`${d.name}: ${fmt(d.val)}`).join('\n'));
  if((intent.focusTrend||intent.primary==='overview')&&metrics.revenue_trend.length>=2){
    const t=metrics.revenue_trend;
    contextBlocks.push(`── LAST 14 DAYS ──\n`+t.slice(-14).map(d=>`${d.name}: ${fmt(d.val)}`).join('\n'));
    const dow=metrics.day_of_week;
    if(dow.some(d=>d.val>0))
      contextBlocks.push('── DAY OF WEEK ──\n'+dow.map(d=>`${d.name}: ${fmt(d.val)} (${d.count} txns)`).join(' | '));
  }

  // Category — include if relevant
  if((intent.focusCategory||intent.primary==='overview'||intent.primary==='category')&&metrics.category_breakdown.length>=2)
    contextBlocks.push('── CATEGORIES ──\n'+metrics.category_breakdown.slice(0,10).map(c=>`${c.name}: ${fmt(c.val)} (${c.count} txns)`).join('\n'));
  if(metrics.top_products.length>=2)
    contextBlocks.push('── TOP PRODUCTS ──\n'+metrics.top_products.slice(0,8).map(p=>`${p.name}: ${fmt(p.val)} (${p.orders} orders)`).join('\n'));

  // Anomalies — always
  contextBlocks.push(anomalyResult.count>0
    ?`── ANOMALIES (${anomalyResult.count}) ──\n`+anomalyResult.anomalies.map(a=>`[${a.severity}] ${a.type}: ${a.reason} | impact: ${fmt(a.impact)}`).join('\n')
    :'── ANOMALIES ──\nNone detected');

  // Cohorts — only when relevant
  if(cohortResult&&(intent.focusUser||['ecommerce','saas'].includes(dsType))){
    const keys=Object.keys(cohortResult.retention_matrix).slice(0,6);
    contextBlocks.push('── COHORT RETENTION ──\n'+keys.map(k=>{
      const row=cohortResult.retention_matrix[k];
      return`${k} (n=${cohortResult.cohort_sizes[k]}): M0=${row[0]}% M1=${row[1]||0}% M2=${row[2]||0}% M3=${row[3]||0}%`;
    }).join('\n'));
  }

  const intentLabel={overview:'complete business intelligence',anomaly:'anomaly investigation',
    trend:'trend analysis',user:'customer analysis',category:'segment analysis',
    distribution:'statistical distribution',quality:'data quality assessment',
    saas:'SaaS metrics',hr:'HR analytics',cohort:'cohort retention'}[intent.primary]||'data analysis';

  const sysPrompt=`You are NEXUS v14 — elite data analyst AI. Precision of a senior data scientist, clarity of a McKinsey partner.

YOUR TASK: Deliver a focused ${intentLabel}.

ABSOLUTE RULES:
1. Use ONLY numbers from VERIFIED METRICS — never compute, estimate, or fabricate.
2. Every insight: FACT (exact number) → PATTERN (what it means) → IMPLICATION (why it matters) → ACTION (what to do).
3. Zero filler. Zero repetition of raw facts. Every sentence must add interpretation value.
4. Charts: [CHART:type|title|[{"name":"Label","val":EXACT_NUMBER}]] — types: bar/line/pie/doughnut — min 3 charts, ONLY verified values.
5. KPIs: [KPI:Label|Value|Delta|up/down/neutral] — ONLY verified values.
6. If data is insufficient for an analysis, say so once and move on.
7. Prioritize anomalies and deviations — they carry the highest signal.
8. Numbers: use ₹12.3L/₹1.2Cr format for Indian datasets; standard locale for others.
${intent.focusAnomaly?'9. ANOMALY FOCUS: Lead with anomalies. Provide 3 root cause hypotheses per anomaly, ranked by probability.':''}
${intent.needsAction?'9. END with exactly 5 actions: specific + measurable + timebound + expected ₹ impact.':''}

RESPONSE STRUCTURE:
${intent.primary==='anomaly'?`
══ ANOMALY INVESTIGATION ══
Each anomaly: What | When | 3 Root Causes (ranked) | Financial Impact | Immediate Action

══ RISK SUMMARY ══
Total exposure. Priority order. Which needs action today vs this week.

[KPI:...] blocks + [CHART:bar|Anomaly Impact|[...]] + [CHART:doughnut|Severity Split|[...]]

══ VALIDATION STEPS ══
3 specific checks to confirm each root cause hypothesis.`
:intent.primary==='trend'?`
══ TREND VERDICT ══
The single most important trend signal. Direction + magnitude + driver.

[KPI:...] blocks for key metrics

[CHART:line|Revenue Trend|[...]]

══ INFLECTION POINTS ══
Best period vs worst period with exact values. What changed between them.

[CHART:bar|Monthly Revenue|[...]]

══ PATTERN EXTRAPOLATION ══
If current trend continues: next period estimate based on visible pattern (not hallucination).

══ GROWTH LEVERS ══
2-3 specific actions to amplify positive trends or reverse negative ones.`
:intent.primary==='user'?`
══ CUSTOMER HEALTH ══
Acquisition vs retention balance. Cohort performance if available.

[KPI:...] blocks

══ VALUE CONCENTRATION ══
Pareto analysis. Which customers matter most.

[CHART:bar|Top Customers or Segments|[...]]

══ RETENTION SIGNALS ══
Repeat rate interpretation. What it says about product-market fit.

══ ACTION PLAN ══
Specific retention and acquisition levers with expected impact.`
:`
══ DIRECT ANSWER ══
Answer the user's question in 2 sentences using exact verified numbers.

[KPI:...] — top 6 most meaningful KPIs only

══ KEY PATTERNS ══
The 3 most important patterns. Each: fact + meaning + action.

${metrics.category_breakdown.length>=2?'[CHART:bar|Category Revenue|[...]]':''}
${metrics.revenue_trend.length>=2?'[CHART:line|Revenue Trend|[...]]':''}
[CHART:doughnut|...] — one more chart using verified data

══ VERDICT ══
Confidence: ${confidence} | Health: [STRONG/STABLE/NEEDS ATTENTION/CRITICAL]
Top 3 actions: specific + ₹ impact + timeframe.`}`;

  return{sysPrompt,userMsg:`VERIFIED FACTS:\n${coreBlock}\n\n${contextBlocks.join('\n\n')}\n\nUSER QUESTION: "${question||'Provide complete analysis'}"`};
}

// ═══════════════════════════════════════════════════════
//  LLM CALLERS + UTILITIES
// ═══════════════════════════════════════════════════════
async function callGroq(sysPrompt,userMsg,env){
  return fetch("https://api.groq.com/openai/v1/chat/completions",{
    method:"POST",
    headers:{"Content-Type":"application/json",Authorization:`Bearer ${env.GROQ_API_KEY}`},
    body:JSON.stringify({model:"llama-3.3-70b-versatile",messages:[{role:"system",content:sysPrompt},{role:"user",content:userMsg}],max_tokens:8192,temperature:0.15})
  });
}
async function callGemini(sysPrompt,userMsg,env){
  if(!env.GEMINI_API_KEY)return null;
  const res=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${env.GEMINI_API_KEY}`,{
    method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({contents:[{parts:[{text:`${sysPrompt}\n\n${userMsg}`}]}],generationConfig:{temperature:0.15,maxOutputTokens:8192}})
  });
  if(!res.ok)return null;
  const d=await res.json();return d.candidates?.[0]?.content?.parts?.[0]?.text||null;
}
function scrub(obj){
  if(obj===null||obj===undefined)return obj;
  if(typeof obj==='number')return isFinite(obj)?obj:0;
  if(Array.isArray(obj))return obj.map(scrub);
  if(typeof obj==='object'){const o={};for(const[k,v]of Object.entries(obj))o[k]=scrub(v);return o;}
  return obj;
}
function fallbackNarrative(metrics,detected,dataQuality,anomalyResult,confidence){
  const fmt=v=>v!=null&&isFinite(v)?Number(v).toLocaleString('en-IN'):'N/A';
  return['══ NEXUS ANALYSIS (AI narrative unavailable) ══',
    `All metrics are deterministically computed — no estimates.\n`,
    detected.revenue?`Revenue: ${fmt(metrics.revenue)} | Orders: ${metrics.orders} | AOV: ${fmt(metrics.aov)} | Median: ${fmt(metrics.median_order)}`:'',
    metrics.unique_users!=null?`Users: ${metrics.unique_users} unique | Repeat rate: ${metrics.repeat_rate}%`:'',
    metrics.growth!=null?`WoW growth: ${metrics.growth}%`:'',
    anomalyResult.count>0?`\n⚠ ${anomalyResult.count} anomalies:\n${anomalyResult.anomalies.slice(0,5).map(a=>`• [${a.severity}] ${a.reason}`).join('\n')}`:'\n✅ No anomalies detected.',
    dataQuality.issues.length?`\nData quality: ${dataQuality.issues.join(' | ')}`:'Data quality: Clean',
    `Confidence: ${confidence}`,
  ].filter(Boolean).join('\n');
}

// ═══════════════════════════════════════════════════════
//  MAIN HANDLER
// ═══════════════════════════════════════════════════════
export default{
  async fetch(request,env){
    const origin=request.headers.get("Origin"),nOrigin=origin?origin.replace(/\/$/,""):null;
    try{
      const url=new URL(request.url),path=url.pathname,method=request.method;
      const ip=request.headers.get("cf-connecting-ip")||"0.0.0.0";

      const isWhitelisted=!nOrigin||ORIGIN_WHITELIST.some(o=>{
        const wo=o.replace(/\/$/,"");
        if(wo===nOrigin)return true;
        if(o.includes("*")){const[p1,p2]=o.replace(/\/$/,"").split("*");return nOrigin.startsWith(p1)&&nOrigin.endsWith(p2);}
        return false;
      });

      if(method==="OPTIONS"){const h={...CORS};if(nOrigin)h["Access-Control-Allow-Origin"]=nOrigin;return new Response(null,{status:204,headers:h});}
      if(path==="/health")return json({status:"ok",version:"v14",ts:Date.now()},200,nOrigin);

      const rlType=path==="/api/auth/google"?"auth":path==="/api/analyze"?"analyze":"general";
      if(!(await checkRateLimit(env,ip,rlType,rlType==="auth"?10:rlType==="analyze"?20:60)))return err("Rate limit exceeded.",429,nOrigin);
      if(await isBlacklisted(env,ip))return err("Access denied.",403,nOrigin);

      const getJson=async()=>{try{return await request.clone().json();}catch{return null;}};

      // AUTH
      if(path==="/api/auth/google"&&method==="POST"){
        const body=await getJson();if(!body?.credential)return err("Missing credential",400,nOrigin);
        const gUser=await verifyGoogleToken(body.credential,env.GOOGLE_CLIENT_ID);
        if(!gUser)return err("Invalid Google token",401,nOrigin);
        let user=null;const raw=await env.NEXUS_KV.get(`user:${gUser.email}`);
        if(raw)user=JSON.parse(raw);
        else{user={email:gUser.email,name:gUser.name,picture:gUser.picture,plan:"free",credits:parseInt(env.FREE_CREDITS||"3"),active:true,createdAt:new Date().toISOString(),sub:gUser.sub};await saveUser(env,user);await logActivity(env,ip,"NEW_USER",{email:gUser.email});}
        return json({token:await signJWT({email:user.email},env.JWT_SECRET),user},200,nOrigin);
      }
      if(path==="/api/user/me"&&method==="GET"){
        const user=await getUser(request,env);if(!user)return err("Unauthorized",401,nOrigin);if(user.expired)return err("Token expired",401,nOrigin);return json({user},200,nOrigin);
      }
      if(path==="/api/user/deduct-credit"&&method==="POST"){
        const user=await getUser(request,env);if(!user)return err("Unauthorized",401,nOrigin);
        if(user.plan==="unlimited"||user.credits===-1)return json({credits:-1},200,nOrigin);
        if(user.credits<=0)return err("No credits remaining",402,nOrigin);
        user.credits--;await saveUser(env,user);return json({credits:user.credits},200,nOrigin);
      }
      if(path==="/api/user/refund-credit"&&method==="POST"){
        const user=await getUser(request,env);if(!user)return err("Unauthorized",401,nOrigin);
        if(user.plan!=="unlimited"&&user.credits!==-1){user.credits++;await saveUser(env,user);}
        return json({credits:user.credits},200,nOrigin);
      }

      // ── ANALYZE ──────────────────────────────────────
      if(path==="/api/analyze"&&method==="POST"){
        const tokenHdr=request.headers.get("x-nexus-token")||"";
        let user=null;
        if(tokenHdr&&tokenHdr!=="guest"&&tokenHdr!=="guest_token")user=await getUser(request,env);
        if(!user)user={email:"guest@nexus.ai",name:"Trial",plan:"unlimited",credits:-1};

        let csvText="",fileName="data.csv",userQuestion="Analyze this dataset",analysisMode="universal";
        const ct=request.headers.get("content-type")||"";
        if(ct.includes("multipart/form-data")){
          const fd=await request.formData();
          const file=fd.get("file"),q=fd.get("question")||fd.get("prompt")||fd.get("message"),mode=fd.get("mode");
          if(q)userQuestion=String(q).slice(0,2000);if(mode)analysisMode=String(mode);
          if(file&&typeof file.text==="function"){fileName=file.name||"data.csv";csvText=await file.text();}
          else if(typeof file==="string")csvText=file;
        } else {
          const body=await getJson();
          if(body){
            const{messages,fileData}=body;
            if(fileData?.text)csvText=fileData.text;if(fileData?.name)fileName=fileData.name;
            const lastUser=(messages||[]).filter(m=>m.role==="user").pop();
            if(lastUser?.content)userQuestion=String(lastUser.content).slice(0,2000);
          }
        }

        if(!csvText||csvText.trim().length<5)return err("No data provided. Upload a CSV file.",400,nOrigin);

        // Analytics pipeline
        const{headers,records}=parseCSV(csvText.slice(0,5_000_000));
        if(records.length===0)return err("Could not parse file. Ensure it has a header row and comma-separated values.",400,nOrigin);

        let detected=detectSchema(headers);
        if(!detected.revenue){
          for(const h of headers){
            const sample=records.slice(0,20).map(row=>toNum(row[h])).filter(v=>v!==null);
            if(sample.length>=5){detected.revenue=h;break;}
          }
        }

        const dsType=inferDatasetType(detected,headers,records);
        const intent=parseIntent(userQuestion,dsType);
        const{cleaned,dataQuality}=cleanData(records,detected);
        const metrics=computeMetrics(cleaned,detected);
        const anomalyResult=detectAnomalies(cleaned,detected);
        const cohortResult=computeCohorts(cleaned,detected);
        const confidence=scoreConfidence(cleaned,dataQuality,detected,anomalyResult);

        const{sysPrompt,userMsg}=buildPrompt(metrics,detected,dataQuality,anomalyResult,cohortResult,dsType,intent,fileName,userQuestion,confidence);

        let insight=null,attempts=0;
        while(attempts<2&&!insight){
          attempts++;
          try{
            const groqRes=await callGroq(sysPrompt,userMsg,env);
            if(groqRes.ok){const d=await groqRes.json();insight=d.choices?.[0]?.message?.content||null;}
            else if(groqRes.status===429){
              const et=await groqRes.text();const wait=et.match(/try again in ([0-9.]+)s/i);
              if(wait&&attempts<2){await new Promise(resolve=>setTimeout(resolve,(parseFloat(wait[1])*1000)+300));continue;}
              insight=await callGemini(sysPrompt,userMsg,env);
            }
          }catch{}
        }
        if(!insight)insight=fallbackNarrative(metrics,detected,dataQuality,anomalyResult,confidence);

        return json(scrub({insight,metrics,data_quality:dataQuality,anomalies:anomalyResult,
          cohorts:cohortResult,confidence,dataset_type:dsType,detected_cols:detected,
          intent:{primary:intent.primary},
          schema:{headers,row_count:records.length,clean_count:cleaned.length}
        }),200,nOrigin);
      }

      // PAYMENT / NOTIFY
      if(path==="/api/payment-request"&&method==="POST"){
        const body=await getJson();const{plan,utr,name,email,phone}=body||{};
        if(!utr||!name||!email)return err("Missing fields");
        await env.NEXUS_KV.put(`payment:${utr}`,JSON.stringify({plan,utr,name,email,phone,status:"pending",createdAt:new Date().toISOString()}));
        return json({ok:true,message:"Payment request received"});
      }
      if(path==="/api/notify"&&method==="POST"){
        const body=await getJson();
        await env.NEXUS_KV.put(`notify:${body.email}`,JSON.stringify({email:body.email,at:new Date().toISOString()}));
        return json({ok:true});
      }

      // ADMIN
      if(path==="/api/admin/users"&&method==="GET"){
        if(request.headers.get("x-admin-secret")!==env.ADMIN_SECRET)return err("Forbidden",403);
        const users=await getAllUsers(env),payments=[];
        const pList=await env.NEXUS_KV.list({prefix:"payment:"});
        for(const k of pList.keys){const raw=await env.NEXUS_KV.get(k.name);if(raw)payments.push(JSON.parse(raw));}
        return json({users,payments});
      }
      if(path==="/api/admin/activate"&&method==="POST"){
        if(request.headers.get("x-admin-secret")!==env.ADMIN_SECRET)return err("Forbidden",403);
        const body=await getJson();const{email,plan,credits}=body||{};if(!email)return err("Missing email");
        const raw=await env.NEXUS_KV.get(`user:${email}`);if(!raw)return err("User not found",404);
        const user=JSON.parse(raw);user.plan=plan||"pro";user.credits=plan==="unlimited"?-1:(credits||100);user.active=true;
        await saveUser(env,user);return json({ok:true,user});
      }
      if(path==="/api/admin/check-secrets"&&method==="GET"){
        if(request.headers.get("x-admin-secret")!==env.ADMIN_SECRET)return err("Forbidden",403);
        return json({config:{GROQ_API_KEY:!!env.GROQ_API_KEY,GEMINI_API_KEY:!!env.GEMINI_API_KEY,GOOGLE_CLIENT_ID:!!env.GOOGLE_CLIENT_ID,JWT_SECRET:!!env.JWT_SECRET,ADMIN_SECRET:!!env.ADMIN_SECRET,FREE_CREDITS:!!env.FREE_CREDITS,NEXUS_KV:!!env.NEXUS_KV}},200,nOrigin);
      }
      if(path==="/api/admin/logs"&&method==="GET"){
        if(request.headers.get("x-admin-secret")!==env.ADMIN_SECRET)return err("Forbidden",403);
        const list=await env.NEXUS_KV.list({prefix:"log:"});const logs=[];
        for(const k of list.keys){const raw=await env.NEXUS_KV.get(k.name);if(raw)logs.push(JSON.parse(raw));}
        return json({logs:logs.sort((a,b)=>b.ts-a.ts)},200,nOrigin);
      }

      return err("Not found",404,nOrigin);
    }catch(e){console.error("Worker Error:",e);return err(`Internal Server Error: ${e.message}`,500,nOrigin);}
  }
};
