import test from 'node:test';
import assert from 'node:assert/strict';
import {evidenceTimeline, evidenceUrl, remediationScope} from '../src/evidence.ts';

test('publisher events stay distinct from collection times and repeat fetches deduplicate',()=>{
 const origin={source:'CVE List V5',url:'https://example.test/cve',sha256:'same',retrieved_at:'2026-10-21T00:00:00Z'};
 const events=evidenceTimeline({source_assertions:[{source:'CVE List V5',status:'PUBLISHED',metadata:{datePublished:'2026-05-07T12:00:00Z',dateUpdated:'2026-06-01T00:00:00Z',assignerShortName:'publisher'},provenance:origin}],
  provenance:[origin,{...origin,retrieved_at:'2026-10-22T00:00:00Z'}],cisa_date_added:'2026-05-08',remediation_evidence:[]});
 assert.equal(events.filter(e=>e.kind==='collection').length,1);
 assert.equal(events[0].date,'2026-10-21T00:00:00Z');
 assert.equal(events.find(e=>e.label==='CNA published record').source,'publisher');
 assert.equal(events.find(e=>e.source==='CISA KEV').date,'2026-05-08');
});
test('unknown dates never become invented timeline events',()=>{
 assert.deepEqual(evidenceTimeline({published:'2026-01-01',provenance:[],source_assertions:[{source:'CVE List V5',status:'REJECTED',metadata:{},provenance:{}}],remediation_evidence:[{published_at:'unknown'}]}),[]);
});
test('multi-package notice yields one publisher event with an explicit notice identity',()=>{
 const evidence={source:'Ubuntu USN',notice_id:'USN-9999-1',published_at:'2026-10-21T00:00:00',advisory_url:'https://ubuntu.com/security/notices/USN-9999-1'};
 const events=evidenceTimeline({provenance:[],remediation_evidence:[{...evidence,product:'one'},{...evidence,product:'two'}]});
 assert.equal(events.length,1); assert.equal(events[0].label,'USN-9999-1 published');
});
test('remediation scope preserves distribution release and upstream version semantics',()=>{
 assert.equal(remediationScope({distribution:'Debian',release:'bookworm',product:'openssl'}),'Debian · bookworm · openssl');
 assert.equal(remediationScope({product:'Tomcat',branch:'10.1'}),'10.1 · Tomcat');
 assert.equal(remediationScope({}),'See publisher scope');
});
test('evidence links reject executable protocols and embedded credentials',()=>{
 for(const raw of ['javascript:alert(1)','data:text/html,bad','file:///etc/passwd','https://user:secret@example.test','broken'])assert.equal(evidenceUrl(raw),undefined);
 assert.equal(evidenceUrl('https://github.com/example/research'),'https://github.com/example/research');
});
