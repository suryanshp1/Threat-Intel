import {randomBytes} from 'node:crypto';
import {existsSync,writeFileSync,readFileSync,chmodSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
let config=existsSync('.env')?readFileSync('.env','utf8'): 'VI_PUBLIC_ORIGIN=http://localhost:3000\n';
for(const key of ['POSTGRES_PASSWORD','VI_API_TOKEN','VI_DB_PASSWORD','GRAFANA_ADMIN_PASSWORD']){const pattern=new RegExp(`^${key}=(.*)$`,'m');const match=config.match(pattern);if(!match||!match[1].trim()){const line=`${key}=${randomBytes(32).toString('hex')}`;config=match?config.replace(pattern,line):config.replace(/\n?$/,'\n')+line+'\n';}}
writeFileSync('.env',config,{mode:0o600});chmodSync('.env',0o600);
const env={...process.env};for(const line of readFileSync('.env','utf8').split('\n')){const index=line.indexOf('=');if(index>0&&!line.startsWith('#'))env[line.slice(0,index)]=line.slice(index+1)}
mkdirSync('backend/data/auth',{recursive:true,mode:0o700});
const result=spawnSync('docker',['compose','-f','compose.yaml','-f','compose.dev.yaml','up','-d','--wait','postgres','valkey'],{stdio:'inherit',env});
if(result.status!==0)process.exit(result.status||1);
if(!/^[A-Za-z0-9]{32,}$/.test(env.VI_DB_PASSWORD))throw new Error('VI_DB_PASSWORD must contain at least 32 letters/digits');
const roleSql=`DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='sentinel_app') THEN CREATE ROLE sentinel_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$; ALTER ROLE sentinel_app PASSWORD '${env.VI_DB_PASSWORD}';\n`+readFileSync('deploy/runtime-role.sql','utf8');
const role=spawnSync('docker',['compose','exec','-T','postgres','psql','-X','-v','ON_ERROR_STOP=1','-U','sentinel','-d','sentinel'],{input:roleSql,encoding:'utf8',env});
if(role.status!==0){console.error(role.stderr);process.exit(1)}
console.log('PostgreSQL and Valkey are ready. Operator credentials were saved in .env (not printed). Run npm run dev.');
