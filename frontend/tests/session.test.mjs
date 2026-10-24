import test from 'node:test';
import assert from 'node:assert/strict';
import {logoutSession} from '../src/session.ts';
test('logout failure is surfaced rather than treated as a completed session revocation', async()=>{
 await assert.rejects(logoutSession(async()=>new Response('{}',{status:503})),/could not be confirmed/);
 await assert.rejects(logoutSession(async()=>{throw new Error('offline')}),/offline/);
});
test('successful logout uses the server revocation endpoint',async()=>{
 await logoutSession(async(url,options)=>{assert.equal(url,'/api/session');assert.equal(options.method,'DELETE');return new Response('{}',{status:200});});
});
