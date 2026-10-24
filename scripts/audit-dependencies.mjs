// Query the public OSV database using only registry dependency names/versions.
import {readFileSync} from 'node:fs';
const lock=readFileSync('backend/Cargo.lock','utf8');
const packages=lock.split(/^\[\[package\]\]$/m).flatMap(section=>{
  const field=name=>new RegExp(`^${name} = "([^"]+)"$`,'m').exec(section)?.[1];
  return field('source')?.startsWith('registry+')?[{name:field('name'),version:field('version')}]:[];
});
if(!packages.length||packages.some(p=>!p.name||!p.version))throw Error('Unable to inspect Cargo registry dependencies.');
const matches=[];
for(let i=0;i<packages.length;i+=100){
 const chunk=packages.slice(i,i+100);const response=await fetch('https://api.osv.dev/v1/querybatch',{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({queries:chunk.map(p=>({package:{name:p.name,ecosystem:'crates.io'},version:p.version}))}),signal:AbortSignal.timeout(20000)});
 if(!response.ok)throw Error(`OSV advisory check failed: HTTP ${response.status}`);
 const data=await response.json();if(!Array.isArray(data.results)||data.results.length!==chunk.length)throw Error('OSV advisory response count mismatch.');
 data.results.forEach((result,j)=>{if(result.vulns?.length)matches.push({...chunk[j],advisories:result.vulns.map(v=>v.id)});});
}
if(matches.length){console.error(JSON.stringify(matches,null,2));process.exitCode=1;}else console.log(`PASS: ${packages.length} Rust registry versions checked; no OSV matches.`);
