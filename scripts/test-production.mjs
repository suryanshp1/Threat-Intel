import {oidcFixture} from './oidc-fixture.mjs';
import {spawn,spawnSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import net from 'node:net';
import assert from 'node:assert/strict';
import {environment} from './environment.mjs';
const authDir=mkdtempSync('/tmp/sentinel-security-');
const clientTokens={reader:randomBytes(32).toString('hex'),writer:randomBytes(32).toString('hex'),expired:randomBytes(32).toString('hex')};
let registry=Object.entries(clientTokens).map(([id,value])=>({id,token_sha256:createHash('sha256').update(value).digest('hex'),scopes:id==='writer'?['read','vex:write']:['read'],expires_at:id==='expired'?'2000-01-01T00:00:00Z':'2999-01-01T00:00:00Z'}));
const registryPath=authDir+'/clients.json';const saveRegistry=()=>writeFileSync(registryPath,JSON.stringify(registry),{mode:0o600});saveRegistry();
const baseEnv=environment();const database=`sentinel_test_${process.pid}`;const token=randomBytes(32).toString('hex');
function sql(database,statement){const r=spawnSync('docker',['compose','exec','-T','postgres','psql','-X','-v','ON_ERROR_STOP=1','-U','sentinel','-d',database],{input:statement,encoding:'utf8',env:baseEnv});if(r.status!==0)throw new Error(r.stderr);return r.stdout}
const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));const base=`http://127.0.0.1:${port}`;
sql('postgres',`CREATE DATABASE ${database} OWNER sentinel_app;`);
const env={...baseEnv,VI_DB_TLS_MODE:'disable',VI_DB_TLS_CA_FILE:'',VI_OIDC_ISSUER:'',VI_ENV:'production',VI_API_TOKEN:token,VI_PUBLIC_ORIGIN:'https://sentinel.test',PORT:String(port),DATABASE_URL:baseEnv.DATABASE_URL.replace(/\/[^/]+$/,`/${database}`)};
const redisUser=`sentinel_test_${process.pid}`;const redisPassword=randomBytes(32).toString('hex');
function acl(...args){const r=spawnSync('docker',['compose','exec','-T','valkey','valkey-cli','ACL',...args],{encoding:'utf8',env:baseEnv});if(r.status!==0||r.stdout.includes('ERR'))throw new Error('Test Valkey ACL operation failed');}
acl('SETUSER',redisUser,'on',`>${redisPassword}`,'~vi:*','+@all');
const testRedis=new URL(env.REDIS_URL);testRedis.username=redisUser;testRedis.password=redisPassword;env.REDIS_URL=testRedis.toString();env.VI_CLIENT_TOKENS_FILE=registryPath;
let proc;let checks=0;let provider;
async function start(){proc=spawn('backend/target/debug/vi-server',[],{env,stdio:['ignore','pipe','pipe']});let stderr='';proc.stderr.on('data',b=>stderr+=b.toString());for(let i=0;i<100;i++){try{const r=await fetch(base+'/readyz');if(r.ok)return}catch{}if(proc.exitCode!==null||proc.signalCode)throw new Error('API exited: '+stderr);await new Promise(r=>setTimeout(r,100));}throw new Error('API startup timed out: '+stderr)}
async function request(path,{body,expected=200,auth=true,headers={}}={}){const r=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:`Bearer ${token}`} :{}),...headers},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(180000)});const text=await r.text();assert.equal(r.status,expected,`${path}: ${text}`);checks++;return {data:text?JSON.parse(text):null,response:r}}
async function stop(){
 const running=proc;if(!running||running.exitCode!==null||running.signalCode)return;
 await new Promise(resolve=>{
  const timer=setTimeout(()=>{running.kill('SIGKILL');resolve()},3000);timer.unref();
  running.once('exit',()=>{clearTimeout(timer);resolve()});running.kill('SIGTERM');
 });
}
try{
 await start();await request('/api/stats/',{expected:401,auth:false});await request('/api/stats/',{expected:401,headers:{Authorization:'Bearer invalid'}});assert.equal((await request('/api/stats/')).data.total,0);
 const login=await request('/api/session',{auth:false,body:{token}});const cookie=login.response.headers.get('set-cookie');assert.match(cookie,/HttpOnly/);assert.match(cookie,/SameSite=Strict/);assert.match(cookie,/Secure/);await request('/api/stats/',{auth:false,headers:{Cookie:cookie.split(';')[0]}});
 await request('/api/session',{auth:false,body:{token:'wrong'},expected:401});await request('/api/session',{auth:false,body:{token},headers:{Origin:'https://evil.test'},expected:403});await request('/api/v2/vulnerabilities/filter',{body:{},headers:{Origin:'https://evil.test'},expected:403});
 // Read-only client keys cannot become operator sessions or invoke mutations.
 const reader={Authorization:`Bearer ${clientTokens.reader}`};
 await request('/api/stats/',{headers:reader});
 await request('/api/admin/ingest',{body:{source:'CISA KEV'},headers:reader,expected:403});
 await request('/api/v2/vex',{body:{},headers:reader,expected:403});
 await request('/api/v2/sbom/analyze',{body:{},headers:reader,expected:403});
 await request('/api/session',{auth:false,body:{token:clientTokens.reader},expected:401});
 await request('/api/stats/',{headers:{Authorization:`Bearer ${clientTokens.expired}`},expected:401});
 registry=registry.filter(c=>c.id!=='reader');saveRegistry();
 await request('/api/stats/',{headers:reader,expected:401});
 // Wrong Origins must never consume the login budget. Invalid credentials must not lock out valid ones.
 for(let i=0;i<25;i++)await request('/api/session',{auth:false,body:{token:'invalid'},headers:{Origin:'https://evil.test'},expected:403});
 let throttled=false;for(let i=0;i<25;i++){const r=await fetch(base+'/api/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'invalid'})});assert.ok([401,429].includes(r.status));throttled ||=r.status===429;await r.text();}assert.ok(throttled);checks++;
 const afterFailures=await request('/api/session',{auth:false,body:{token}});
 assert.equal(afterFailures.response.headers.get('cache-control'),'no-store');
 await request('/api/v2/vulnerabilities/filter',{body:{conditions:Array.from({length:31},()=>({field:'cvss',operator:'gte',value:0}))},expected:400});
 await request('/api/v2/vulnerabilities/filter',{body:{text_search:'x'.repeat(513)},expected:400});
 await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'id',operator:'in',value:Array(101).fill('CVE-2099-1000')}]},expected:400});
 await request('/api/v2/vex?limit=101',{expected:400});
 const reference=await fetch(base+'/scalar');assert.equal(reference.status,200);const referenceHtml=await reference.text();assert.ok(!referenceHtml.includes('cdn.jsdelivr.net'));assert.ok(referenceHtml.includes('/api-docs/ui.js'));checks++;
 // Production must reject development origins, even though dev mode supports both.
 await request('/api/v2/vulnerabilities/filter',{body:{limit:1},headers:{Origin:'https://sentinel.test'}});
 for(const origin of ['http://localhost:5173','http://127.0.0.1:5173']) {
  await request('/api/v2/vulnerabilities/filter',{body:{},headers:{Origin:origin},expected:403});
  await request('/api/session',{auth:false,body:{token},headers:{Origin:origin},expected:403});
 }
 const records=[1000,1001,1002].map((n,i)=>({id:`CVE-2099-${n}`,title:i===0?'Alpha fixture':'Beta fixture',description:'Synthetic record in isolated test database only.',cvss:9-i,cvss_known:true,epss_score:0.1*i,epss_known:true,priority_score:100*(i+1),ssvc_decision:'Unassessed',seen_wild:i===0,is_zeroday:false,published:`2099-01-0${i+1}`,ecosystem:'npm',vendor:'test',product:'test-package',purl:'pkg:npm/test-only',sources:['isolated-test'],ingested_at:'2026-01-01T00:00:00Z',aliases:[],provenance:[],score_breakdown:{exploitation:0,epss:0,severity:0,threat:0,supply_chain:0}}));
 for(const v of records)sql(database,`INSERT INTO vulnerabilities(id,data,priority_score,cvss,epss_score,published,ssvc_decision,seen_wild,ecosystem,vendor) VALUES('${v.id}','${JSON.stringify(v).replaceAll("'","''")}'::jsonb,${v.priority_score},${v.cvss},${v.epss_score},'${v.published}','Unassessed',${v.seen_wild},'npm','test');`);
 assert.equal((await request('/api/stats/')).data.total,3);
 sql(database,`INSERT INTO intelligence_entities(kind,id,source,data) SELECT 'actors','fixture-'||i,'isolated-test',jsonb_build_object('id','fixture-'||i,'source','isolated-test') FROM generate_series(1,105)i;`);
 const actorPage=(await request('/api/threat-actors',{body:{name:'fixture-',limit:100}})).data;assert.equal(actorPage.total,105);assert.equal(actorPage.results.length,100);
 assert.equal((await request('/api/threat-actors',{body:{name:'fixture-',limit:100,skip:100}})).data.results.length,5);
 await request('/api/threat-actors',{body:{limit:101},expected:400});
 const productFirst=(await request('/api/affected-product',{body:{name:'test',limit:1}})).data;const productNext=(await request('/api/affected-product',{body:{name:'test',limit:1,skip:1}})).data;assert.equal(productFirst.total,3);assert.notEqual(productFirst.results[0].cve_id,productNext.results[0].cve_id);
 sql(database,`INSERT INTO intelligence_entities(kind,id,source,data) SELECT 'rules','rule-'||i,'isolated-test',jsonb_build_object('id','rule-'||i,'cve_id','CVE-2099-1000','source','isolated-test') FROM generate_series(1,105)i;`);
 const rulePage=(await request('/api/v2/vulnerabilities/CVE-2099-1000/rules')).data;assert.equal(rulePage.results.length,100);assert.equal(rulePage.truncated,true);

 const first=(await request('/api/v2/vulnerabilities/filter',{body:{limit:1}})).data;const next=(await request('/api/v2/vulnerabilities/filter',{body:{limit:1,cursor:first.next_cursor}})).data;assert.notEqual(first.results[0].id,next.results[0].id);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{text_search:'Alpha'}})).data.total,1);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{text_search:'CVE-2099'}})).data.total,3);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{text_search:'pkg:npm/test-only'}})).data.total,3);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'seen_wild',operator:'eq',value:true}]}})).data.total,1);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'priority_score',operator:'gte',value:200}]}})).data.total,2);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'id',operator:'in',value:['CVE-2099-1000','CVE-2099-1002']}]}})).data.total,2);
 await request('/api/v2/vulnerabilities/filter',{body:{cursor:'bad'},expected:400});await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'cvss',operator:'gt',value:'wrong'}]},expected:400});await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'DROP TABLE',operator:'eq',value:true}]},expected:400});
 const detail=(await request('/api/vulnerabilities/CVE-2099-1000')).data;assert.deepEqual(detail.remediation_evidence,[]);assert.deepEqual(detail.source_assertions,[]);assert.deepEqual(detail.poc_references,[]);await request('/api/vulnerabilities/CVE-2099-9999',{expected:404});
 // New evidence survives the authenticated HTTP boundary and API restart.
 const evidenceOrigin={source:'isolated-test',url:'https://example.test/advisory',sha256:'fixture-hash',retrieved_at:'2026-10-21T00:00:00Z'};
 const evidenceFields={source_assertions:[{source:'CVE List V5',status:'REJECTED',metadata:{dateUpdated:'2026-10-20T00:00:00Z'},cna:{},provenance:evidenceOrigin}],poc_references:[{source:'Trickest PoC references',url:'https://github.com/example/research',verification:'unverified',provenance:evidenceOrigin}],remediation_evidence:[{source:'Debian Security Tracker',distribution:'Debian',release:'bookworm',product:'test',fixed_versions:['1:2.0~rc1-3+deb12u1'],provenance:evidenceOrigin}]};
 sql(database,`UPDATE vulnerabilities SET data=data||'${JSON.stringify(evidenceFields).replaceAll("'","''")}'::jsonb WHERE id='CVE-2099-1000';`);
 assert.deepEqual((await request('/api/vulnerabilities/CVE-2099-1000')).data.source_assertions,evidenceFields.source_assertions);
 // Knowledge kinds, API authentication, migration idempotence and restart persistence.
 await request('/api/knowledge/CWE-79',{auth:false,expected:401});
 await request('/api/knowledge/CWE-unknown',{expected:404});
 for(const [kind,id] of [['weaknesses','CWE-79'],['categories','OWASP-A01:2025']]) {
  const data={id,name:'Isolated knowledge fixture',source:'isolated-test',provenance:{url:'https://example.test/fixture',sha256:'test',retrieved_at:'2026-01-01T00:00:00Z'}};
  sql(database,`INSERT INTO intelligence_entities(kind,id,source,data) VALUES('${kind}','${id}','isolated-test','${JSON.stringify(data)}'::jsonb);`);
  assert.equal((await request('/api/knowledge/'+id)).data.id,id);
 }
 await stop();await start();
 assert.equal((await request('/api/knowledge/cwe-79')).data.id,'CWE-79');
 const retained=(await request('/api/vulnerabilities/CVE-2099-1000')).data;for(const key of Object.keys(evidenceFields))assert.deepEqual(retained[key],evidenceFields[key]);
 // MCP transport, security, discovery and tool dispatch against isolated records.
 registry.push({id:'reader',token_sha256:createHash('sha256').update(clientTokens.reader).digest('hex'),scopes:['read'],expires_at:'2999-01-01T00:00:00Z'});saveRegistry();
 const mcpHeaders={Accept:'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'};
 const scopedMcp=(await request('/api/mcp',{body:{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'get_statistics',arguments:{}}},headers:{...mcpHeaders,Authorization:`Bearer ${clientTokens.reader}`}})).data;assert.equal(scopedMcp.result.structuredContent.total,3);
 const rpc=async(method,params={},options={})=>(await request('/api/mcp',{body:{jsonrpc:'2.0',id:42,method,params},headers:mcpHeaders,...options})).data;
 await rpc('ping',{}, {auth:false,expected:401});
 await rpc('ping',{}, {headers:{...mcpHeaders,Origin:'https://evil.test'},expected:403});
 await request('/api/mcp',{headers:{Origin:'https://evil.test'},expected:403});
 await request('/api/mcp',{expected:405});
 await rpc('ping',{}, {headers:{Accept:'application/json'},expected:406});
 await rpc('ping',{}, {headers:{...mcpHeaders,'MCP-Protocol-Version':'2099-01-01'},expected:400});
 const initialized=await rpc('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'sentinel-test',version:'1'}});
 assert.equal(initialized.result.protocolVersion,'2025-11-25');assert.equal(initialized.result.capabilities.tools.listChanged,false);
 assert.equal((await rpc('initialize',{protocolVersion:'unsupported'})).result.protocolVersion,'2025-11-25');
 for(const version of ['2025-03-26','2025-06-18']) assert.equal((await rpc('initialize',{protocolVersion:version})).result.protocolVersion,version);
 await request('/api/mcp',{body:{jsonrpc:'2.0',method:'notifications/initialized'},headers:mcpHeaders,expected:202});
 const catalog=(await rpc('tools/list')).result.tools;assert.equal(catalog.length,9);assert.ok(catalog.every(t=>t.annotations.readOnlyHint));
 const call=async(name,args={})=>rpc('tools/call',{name,arguments:args});
 assert.equal((await call('search_vulnerabilities',{text_search:'Alpha'})).result.structuredContent.total,1);
 const mcpFirst=(await call('search_vulnerabilities',{limit:1})).result.structuredContent;
 assert.notEqual((await call('search_vulnerabilities',{limit:1,cursor:mcpFirst.next_cursor})).result.structuredContent.results[0].id,mcpFirst.results[0].id);
 assert.equal((await call('get_vulnerability',{id:'cve-2099-1000'})).result.structuredContent.id,'CVE-2099-1000');
 assert.equal((await call('get_vulnerability',{id:'CVE-2099-9999'})).result.isError,true);
 assert.equal((await call('get_statistics')).result.structuredContent.total,3);
 for(const [name,args] of [['get_sources',{}],['get_detection_rules',{id:'CVE-2099-1000'}],['get_relationships',{id:'CVE-2099-1000'}],['search_products',{name:'test'}],['search_threat_actors',{name:'test'}]]) assert.equal((await call(name,args)).result.isError,false);
 assert.equal((await call('lookup_patch',{kb:'KB-unknown'})).result.isError,true);
 for(const [name,args] of [['get_vulnerability',{}],['get_statistics',{unexpected:true}],['search_vulnerabilities',{limit:101}],['search_products',{limit:'10'}],['save_vex',{}]]) assert.equal((await call(name,args)).error.code,-32602);
 assert.equal((await call('search_vulnerabilities',{conditions:[{field:'cvss',operator:'gt',value:'wrong'}]})).result.isError,true);
 assert.equal((await rpc('missing')).error.code,-32601);
 assert.equal((await request('/api/mcp',{body:[],headers:mcpHeaders})).data.error.code,-32600);
 const malformed=await fetch(base+'/api/mcp',{method:'POST',headers:{...mcpHeaders,'Content-Type':'application/json',Authorization:`Bearer ${token}`},body:'{'});assert.equal((await malformed.json()).error.code,-32700);checks++;
 const bridge=spawn(process.execPath,['scripts/mcp-stdio.mjs'],{env:{...process.env,VI_API_TOKEN:token,VI_MCP_URL:base+'/api/mcp'},stdio:['pipe','pipe','pipe']});
 let bridgeOut='';let bridgeErr='';bridge.stdout.on('data',b=>bridgeOut+=b);bridge.stderr.on('data',b=>bridgeErr+=b);
 bridge.stdin.end([{jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1'}}},{jsonrpc:'2.0',method:'notifications/initialized'},{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'get_statistics',arguments:{}}}].map(JSON.stringify).join('\n')+'\n');
 const bridgeExit=await new Promise((resolve,reject)=>{bridge.on('error',reject);bridge.on('exit',resolve)});assert.equal(bridgeExit,0,bridgeErr);assert.equal(bridgeErr,'');
 const bridgeMessages=bridgeOut.trim().split('\n').map(JSON.parse);assert.equal(bridgeMessages.length,2);assert.equal(bridgeMessages[1].result.structuredContent.total,3);checks++;
 const sources=(await request('/api/sources')).data.results;assert.equal(sources.length,22);for(const name of ['CVE List V5','Debian Security Tracker','Ubuntu USN','Trickest PoC references'])assert.ok(sources.some(s=>s.source_name===name));for(const name of ['Apache HTTP Server','Apache Tomcat','OpenSSL','curl'])assert.ok(sources.some(s=>s.source_name===name));assert.ok(sources.some(s=>s.source_name==='MITRE CWE'));assert.ok(sources.some(s=>s.source_name==='OWASP Top 10')); assert.equal((await request('/api/admin/ingest',{body:{source:'CISA KEV'}})).data.queued,true);assert.equal((await request('/api/admin/ingest',{body:{source:'CISA KEV'}})).data.queued,false);await request('/api/admin/ingest',{body:{source:'invalid'},expected:400});assert.equal((await request('/api/admin/jobs')).data.results.length,1);assert.ok(sql(database,"SELECT subject FROM audit_events WHERE action='ingest.enqueue';").includes('operator'));
 const doc={'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:uuid:isolated-test',author:'Isolated QA',timestamp:'2026-01-01T00:00:00Z',version:1,statements:[{vulnerability:{name:'CVE-2099-1000'},products:[{'@id':'pkg:npm/test-only@1.0.0'}],status:'not_affected',justification:'vulnerable_code_not_in_execute_path'}]};await request('/api/v2/vex',{body:doc,headers:{Authorization:`Bearer ${clientTokens.writer}`}});assert.ok(sql(database,`SELECT subject FROM vex_revisions WHERE document_id='urn:uuid:isolated-test';`).includes('writer'));assert.equal((await request('/api/v2/vex')).data.results.length,1);await request('/api/v2/vex',{body:{...doc,author:''},expected:400});await request('/api/v2/vex',{body:{...doc,statements:[{...doc.statements[0],justification:'invalid'}]},expected:400});
 await request('/api/v2/sbom/analyze',{body:{},expected:400});await request('/api/v2/sbom/analyze',{body:{bomFormat:'CycloneDX',components:[]},expected:400});
 const graph=(await request('/api/graphql',{body:{query:'{ vulnerabilities(search:"Alpha") }'}})).data;assert.equal(graph.data.vulnerabilities.total,1);
 const stix=(await request('/api/v21/collections/sentinel/objects/?limit=1')).data;assert.equal(stix.objects.length,1);assert.equal(stix.more,true);
 const exported=await fetch(base+'/api/download/latest',{headers:{Authorization:`Bearer ${token}`}});assert.equal(exported.status,200);assert.equal((await exported.text()).trim().split('\n').length,3);checks++;
 const spec=(await request('/api-docs/openapi.json',{auth:false})).data;assert.equal(spec.openapi,'3.1.0');
 await stop();await start();assert.equal((await request('/api/v2/vex')).data.results.length,1);assert.equal((await request('/api/stats/')).data.total,3);
 // Durable revocation failure is explicit and does not clear the browser cookie.
 const uncertainLogin=await request('/api/session',{auth:false,body:{token}});const uncertainCookie=uncertainLogin.response.headers.get('set-cookie').split(';')[0];
 sql(database,'ALTER TABLE session_revocations RENAME TO hidden_session_revocations;');
 try{const failedLogout=await fetch(base+'/api/session',{method:'DELETE',headers:{Cookie:uncertainCookie}});assert.equal(failedLogout.status,503);assert.equal(failedLogout.headers.get('set-cookie'),null);await failedLogout.text();checks++;}
 finally{sql(database,'ALTER TABLE hidden_session_revocations RENAME TO session_revocations;');}
 await request('/api/stats/',{auth:false,headers:{Cookie:uncertainCookie}});
 const durableLogin=await request('/api/session',{auth:false,body:{token}});const durableCookie=durableLogin.response.headers.get('set-cookie').split(';')[0];
 acl('SETUSER',redisUser,'-del');
 const durableLogout=await fetch(base+'/api/session',{method:'DELETE',headers:{Cookie:durableCookie}});assert.equal(durableLogout.status,200);await durableLogout.text();checks++;
 await request('/api/stats/',{auth:false,headers:{Cookie:durableCookie},expected:401});
 await stop();await start();
 await request('/api/stats/',{auth:false,headers:{Cookie:durableCookie},expected:401});
 acl('SETUSER',redisUser,'+del');
 const expired=await fetch(base+'/api/session',{method:'DELETE',headers:{Cookie:cookie.split(';')[0]}});assert.equal(expired.status,200);await request('/api/stats/',{auth:false,headers:{Cookie:cookie.split(';')[0]},expected:401});
 // Reproduce the original local API launch: Compose origin in .env, Vite on 5173.
 await stop();env.VI_ENV='development';env.VI_PUBLIC_ORIGIN='http://localhost:3000';await start();
 for(const origin of ['http://localhost:5173','http://127.0.0.1:5173']) {
  const session=await request('/api/session',{auth:false,body:{token},headers:{Origin:origin}});
  const sessionCookie=session.response.headers.get('set-cookie').split(';')[0];
  assert.ok(!session.response.headers.get('set-cookie').includes('; Secure'));
  assert.equal((await request('/api/v2/vulnerabilities/filter',{auth:false,body:{limit:1},headers:{Origin:origin,Cookie:sessionCookie}})).data.total,3);
 }
 for(const origin of ['https://evil.test','null','http://localhost:5174']) {
  await request('/api/v2/vulnerabilities/filter',{body:{},headers:{Origin:origin},expected:403});
  await request('/api/session',{auth:false,body:{token},headers:{Origin:origin},expected:403});
 }
 // A rejected session-store write must not create a successful-login audit event.
 const beforeFailedLogin=sql(database,"SELECT count(*) FROM audit_events WHERE action='session.login';");acl('SETUSER',redisUser,'-setex');
 try{const rejected=await request('/api/session',{auth:false,body:{token},expected:503});assert.equal(rejected.response.headers.get('set-cookie'),null);}finally{acl('SETUSER',redisUser,'+setex')}
 assert.equal(sql(database,"SELECT count(*) FROM audit_events WHERE action='session.login';"),beforeFailedLogin);
 sql(database,'ALTER TABLE audit_events RENAME TO hidden_audit_events;');
 try{const rejected=await request('/api/session',{auth:false,body:{token},expected:503});assert.equal(rejected.response.headers.get('set-cookie'),null);}finally{sql(database,'ALTER TABLE hidden_audit_events RENAME TO audit_events;')}
 // Real OIDC code exchange against a local fixture. No external identity provider or credentials.
 await stop();provider=await oidcFixture();env.VI_OIDC_ISSUER=provider.issuer;env.VI_OIDC_CLIENT_ID='fixture-client';env.VI_OIDC_CLIENT_SECRET='fixture-secret';env.VI_OIDC_ALLOW_HTTP_LOOPBACK='true';env.VI_PUBLIC_ORIGIN=base;await start();
 assert.equal((await request('/api/auth/config',{auth:false})).data.oidc,true);
 await request('/api/auth/oidc/start',{auth:false,body:{},headers:{Origin:'https://evil.test'},expected:403});
 async function begin(){const {data,response}=await request('/api/auth/oidc/start',{auth:false,body:{},headers:{Origin:base}});return {...provider.code(data.authorization_url),cookie:response.headers.get('set-cookie').split(';')[0]}}
 async function finish(flow,expected='/vi',cookie=flow.cookie){const response=await fetch(base+'/api/auth/oidc/callback?'+new URLSearchParams({state:flow.state,code:flow.code}),{headers:{Cookie:cookie},redirect:'manual'});assert.equal(response.status,303);assert.equal(response.headers.get('location'),expected);await response.text();checks++;return response.headers.getSetCookie().find(v=>v.startsWith('sentinel_session='))?.split(';')[0]}
 const initial=await begin();await finish(initial,'/vi?signin=pending');await finish(initial,'/vi?signin=failed');
 const allUsers=(await request('/api/admin/users')).data;assert.equal(allUsers.data.length,1);const user=allUsers.data[0];assert.equal(user.role,'pending');assert.ok(user.id.startsWith('oidc:'));
 let version=user.version;
 async function access(role,disabled=false,expected=200,useVersion=version){const r=await fetch(base+'/api/admin/users/'+encodeURIComponent(user.id),{method:'PUT',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({role,disabled,version:useVersion})});assert.equal(r.status,expected);await r.text();checks++;if(expected===200)version++;}
 await access('reader');await access('admin',false,409,user.version);
 let flow=await begin();const beforeCalls=provider.tokenCalls;await finish(flow,'/vi?signin=failed','sentinel_oidc='+'0'.repeat(72));assert.equal(provider.tokenCalls,beforeCalls);const readerCookie=await finish(flow);assert.ok(readerCookie);
 const asReader={Cookie:readerCookie};assert.equal((await request('/api/auth/me',{auth:false,headers:asReader})).data.role,'reader');await request('/api/stats/',{auth:false,headers:asReader});await request('/api/audit/events',{auth:false,headers:asReader,expected:403});await request('/api/admin/users',{auth:false,headers:asReader,expected:403});await request('/api/v2/sbom/analyze',{auth:false,headers:asReader,body:{},expected:403});await request('/api/v2/vex',{auth:false,headers:asReader,body:doc,expected:403});
 await access('analyst');await request('/api/v2/vex',{auth:false,headers:asReader,body:{...doc,'@id':'urn:uuid:sso-test'}});assert.ok(sql(database,"SELECT subject FROM vex_revisions WHERE document_id='urn:uuid:sso-test';").includes(user.id));await request('/api/admin/jobs',{auth:false,headers:asReader,expected:403});
 await access('auditor');await request('/api/audit/events',{auth:false,headers:asReader});const history=(await request('/api/audit/vex-revisions?'+new URLSearchParams({document_id:'urn:uuid:sso-test'}),{auth:false,headers:asReader})).data;assert.equal(history.data.length,1);assert.equal(history.data[0].subject,user.id);await request('/api/v2/vex',{auth:false,headers:asReader,body:doc,expected:403});
 await access('admin');await request('/api/admin/users',{auth:false,headers:asReader});const selfUpdate=await fetch(base+'/api/admin/users/'+encodeURIComponent(user.id),{method:'PUT',headers:{...asReader,'Content-Type':'application/json'},body:JSON.stringify({role:'reader',disabled:false,version})});assert.equal(selfUpdate.status,409);await selfUpdate.text();checks++;
 await access('admin',true);await request('/api/stats/',{auth:false,headers:asReader,expected:401});
 const disabledLogout=await fetch(base+'/api/session',{method:'DELETE',headers:asReader});assert.equal(disabledLogout.status,200);await disabledLogout.text();checks++;assert.ok(sql(database,"SELECT subject FROM audit_events WHERE action='session.logout' ORDER BY id DESC LIMIT 1;").includes(user.id));
 await access('reader');await request('/api/stats/',{auth:false,headers:asReader,expected:401});asReader.Cookie=await finish(await begin());await request('/api/stats/',{auth:false,headers:asReader});
 const listed=(await request('/api/admin/users/'+encodeURIComponent(user.id)+'/sessions')).data;assert.equal(listed.data.length,1);const revoked=await fetch(base+'/api/admin/sessions/'+listed.data[0].id,{method:'DELETE',headers:{Authorization:`Bearer ${token}`}});assert.equal(revoked.status,200);await revoked.text();checks++;await request('/api/stats/',{auth:false,headers:asReader,expected:401});await stop();await start();await request('/api/stats/',{auth:false,headers:asReader,expected:401});
 // No malformed identity token can create a session, including valid signatures with wrong claims.
 for(const fault of ['issuer','audience','nonce','expired','future','access-hash','authorized-party','not-before','key','signature','hmac','critical','missing-exp']){provider.setFault('');flow=await begin();provider.setFault(fault);assert.equal(await finish(flow,'/vi?signin=failed'),undefined)}
 provider.setFault('redirect');await request('/api/auth/oidc/start',{auth:false,body:{},expected:503});provider.setFault('discovery-issuer');await request('/api/auth/oidc/start',{auth:false,body:{},expected:503});provider.setFault('');
 const events=(await request('/api/audit/events?limit=2')).data;assert.equal(events.data.length,2);assert.ok(events.next);const older=(await request('/api/audit/events?limit=2&before='+events.next)).data;assert.ok(older.data.every(r=>r.id<events.next));await request('/api/audit/events?limit=101',{expected:400});await request('/api/audit/events',{headers:reader,expected:403});const roleEvents=(await request('/api/audit/events?action=user.access')).data;assert.ok(roleEvents.data.length>=6);assert.ok(roleEvents.data.every(r=>r.subject==='operator'));
 const lastSsoCookie=await finish(await begin());await stop();env.VI_OIDC_ISSUER='';await start();await request('/api/stats/',{auth:false,headers:{Cookie:lastSsoCookie},expected:401});await request('/api/stats/');
 console.log(`PASS: ${checks} PostgreSQL/Valkey production API checks, including auth, CSRF, keyset paging, jobs, streaming export, OIDC/RBAC, audit management, and persistence.`);
}finally{await stop();await provider?.close();acl('DELUSER',redisUser);sql('postgres',`DROP DATABASE ${database} WITH (FORCE);`);rmSync(authDir,{recursive:true,force:true});}
