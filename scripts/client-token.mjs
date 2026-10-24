// Local hash-only client registry. Secrets are written to an exclusive, private output file.
import {randomBytes,createHash} from 'node:crypto';
import {readFileSync,writeFileSync,renameSync,mkdirSync,existsSync,lstatSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
const args=process.argv.slice(2);const get=name=>args[args.indexOf(name)+1];
const id=get('--id');const config=get('--config');
if(!args.includes('--id')||!args.includes('--config')||!id||!config||!(/^[A-Za-z0-9_-]{1,64}$/).test(id)||['operator','local'].includes(id))throw Error('Supply --id and --config; use a unique client ID.');
if(existsSync(config)&&lstatSync(config).isSymbolicLink())throw Error('Registry path must not be a symlink.');
let clients=existsSync(config)?JSON.parse(readFileSync(config,'utf8')):[];
if(!Array.isArray(clients))throw Error('Registry must be a JSON array.');
if(args.includes('--revoke')){clients=clients.filter(c=>c.id!==id);}else{
 const scopes=(args.includes('--scopes')?get('--scopes'):'read').split(',');const expires=args.includes('--expires')?get('--expires'):null;const output=args.includes('--token-file')?get('--token-file'):null;
 if(!expires||!output||resolve(output)===resolve(config)||!Number.isFinite(Date.parse(expires))||Date.parse(expires)<=Date.now()||scopes.length>4||scopes.some(s=>!['read','analyze','vex:write','ingest'].includes(s)))throw Error('Supply a future --expires ISO timestamp, --token-file and valid --scopes.');
 if(clients.some(c=>c.id===id))throw Error('Client already exists; revoke before replacing.');
 if(clients.length>=100)throw Error('Registry exceeds 100 clients.');
 const token=randomBytes(32).toString('hex');
 mkdirSync(dirname(output),{recursive:true,mode:0o700});writeFileSync(output,token+'\n',{flag:'wx',mode:0o600});
 clients.push({id,token_sha256:createHash('sha256').update(token).digest('hex'),scopes,expires_at:new Date(expires).toISOString()});
}
mkdirSync(dirname(config),{recursive:true,mode:0o700});const temporary=config+`.${process.pid}.tmp`;writeFileSync(temporary,JSON.stringify(clients,null,2)+'\n',{flag:'wx',mode:0o600});renameSync(temporary,config);
console.log(args.includes('--revoke')?'Client revoked.':'Client registered. Credential written to the private token file.');
