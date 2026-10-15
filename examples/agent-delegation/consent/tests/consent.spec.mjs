import { test, expect } from '@playwright/test';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
let fixture, origin;
const root = fileURLToPath(new URL('../../../..', import.meta.url));
const events = [];
test.beforeAll(async () => {
  const binary=join(tmpdir(),'identity-agent-consent-browser-'+process.pid+'.test');
  execFileSync('go',['test','-c','-o',binary,'./examples/agent-delegation'],{cwd:root,env:process.env});
  fixture=spawn(binary,['-test.run=^TestBrowserFixture$','-test.timeout=190s'],{cwd:root,env:{...process.env,IDENTITY_BROWSER_FIXTURE:'1'}});
  origin=await new Promise((resolve,reject)=>{let output='';const timer=setTimeout(()=>reject(new Error('fixture did not become ready')),20000);fixture.stdout.on('data',data=>{output+=data;const match=output.match(/BROWSER_FIXTURE_URL=(http:\/\/127\.0\.0\.1:\d+)/);if(match){clearTimeout(timer);resolve(match[1]);}});fixture.on('exit',code=>reject(new Error('fixture exited '+code+' '+output)));fixture.stderr.on('data',data=>events.push(String(data)));});
});
test.afterAll(async()=>{if(origin)await fetch(origin+'/fixture/stop',{method:'POST'});if(fixture&&fixture.exitCode===null)await once(fixture,'exit');});
test.beforeEach(async({page})=>{
 await page.route('https://challenges.cloudflare.com/turnstile/v0/api.js?*',route=>route.fulfill({contentType:'application/javascript',body:`let proofCallback;window.turnstile={render(element,options){proofCallback=options.callback;element.dataset.ready='true';queueMicrotask(()=>proofCallback('offline-browser-captcha-proof'));return 1;},reset(){queueMicrotask(()=>proofCallback('offline-browser-captcha-proof'));}};`}));
});
async function start(page){const response=await fetch(origin+'/fixture/request');expect(response.ok).toBeTruthy();const info=await response.json();await page.goto(info.url);return info;}
async function signIn(page){await expect(page.locator('#captcha')).toHaveAttribute('data-ready','true');await page.getByLabel('Email',{exact:true}).fill('browser-owner@example.com');await page.getByLabel('Password',{exact:true}).fill('Offline-Browser-Password123!');await page.getByRole('button',{name:'Sign in to review'}).click();await expect(page.getByRole('heading',{name:'Authorize access to files'})).toBeVisible();}
test('real password sign-in → explicit selected agent consent → native PKCE exchange → resource introspection',async({page})=>{
 const info=await start(page);await signIn(page);
 await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeDisabled();
 await expect(page.getByText('files:read',{exact:true})).toBeVisible();
 await page.getByRole('radio',{name:'Example product engineer'}).check();
 let callback;
 await page.route('http://127.0.0.1:31821/callback?*',route=>{callback=new URL(route.request().url());return route.fulfill({status:200,body:'Returned to native app'});});
 await page.getByRole('button',{name:'Allow selected agent'}).click();await expect(page.getByText('Returned to native app')).toBeVisible();
 expect(callback.searchParams.get('state')).toBe('browser-csrf-state');expect(callback.searchParams.get('iss')).toBe('https://auth.example.test');
 const tokens=await fetch(origin+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'desktop-client',redirect_uri:'http://127.0.0.1:31821/callback',resource:'https://files.example.test',code:callback.searchParams.get('code'),code_verifier:info.verifier})});expect(tokens.ok).toBeTruthy();const issued=await tokens.json();expect(issued.id_token).toBeUndefined();
 const admission=await fetch(origin+'/oauth/introspect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Authorization:'Basic '+Buffer.from('files-resource:offline-resource-test-secret').toString('base64')},body:new URLSearchParams({token:issued.access_token})});expect(admission.ok).toBeTruthy();const principal=await admission.json();expect(principal.active).toBe(true);expect(principal.sub).toBe(info.agent);expect(principal.kind).toBe('agent');expect(principal.act.sub).not.toBe(info.agent);
 const storage=await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length}));expect(storage).toEqual({local:0,session:0});
});
test('deny requires no agent selection and never grants a code',async({page})=>{
 await start(page);await signIn(page);let callback;
 await page.route('http://127.0.0.1:31821/callback?*',route=>{callback=new URL(route.request().url());return route.fulfill({status:200,body:'Denied'});});
 await page.getByRole('button',{name:'Don’t allow'}).click();await expect(page.getByText('Denied',{exact:true})).toBeVisible();expect(callback.searchParams.get('error')).toBe('access_denied');expect(callback.searchParams.has('code')).toBe(false);
});
for(const mode of [{name:'desktop-light',width:1180,height:1000,colorScheme:'light'},{name:'phone-dark',width:390,height:844,colorScheme:'dark'}]){
 test('responsive '+mode.name,async({page})=>{await page.setViewportSize({width:mode.width,height:mode.height});await page.emulateMedia({colorScheme:mode.colorScheme});await start(page);await signIn(page);await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeDisabled();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.screenshot({path:join(tmpdir(),'identity-agent-consent-'+mode.name+'.png'),fullPage:true});const colors=await page.evaluate(()=>({bg:getComputedStyle(document.body).backgroundColor,fg:getComputedStyle(document.body).color}));expect(colors.bg).not.toBe(colors.fg);});
}
test('missing request fails closed and no RPC is issued',async({page})=>{let calls=0;page.on('request',r=>{if(r.url().includes('/identity.v1.'))calls++;});await page.goto(origin+'/auth/agent-consent');await expect(page.getByRole('alert')).toContainText('incomplete');await expect(page.getByRole('button',{name:'Sign in to review'})).toBeHidden();expect(calls).toBe(0);});

test('normal TOTP recovery sign-in is required before reviewing consent',async({page})=>{
 await start(page); await expect(page.locator('#captcha')).toHaveAttribute('data-ready','true');
 await page.getByLabel('Email',{exact:true}).fill('browser-totp@example.com');
 await page.getByLabel('Password',{exact:true}).fill('Offline-Browser-Password123!');
 await page.getByRole('button',{name:'Sign in to review'}).click();
 await expect(page.getByLabel('Authenticator or recovery code')).toBeVisible();
 await expect(page.getByRole('heading',{name:'Authorize access to files'})).toBeHidden();
 const result=await fetch(origin+'/fixture/recovery');const proof=await result.json();
 await page.getByLabel('Authenticator or recovery code').fill(proof.code);
 await page.getByRole('button',{name:'Verify and review'}).click();
 await expect(page.getByRole('heading',{name:'Authorize access to files'})).toBeVisible();
 await expect(page.getByText('You have no eligible active agents',{exact:false})).toBeVisible();
 await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeDisabled();
});

test('expired human session returns to same-origin sign-in and never silently approves',async({page})=>{
 await start(page);let once=true;
 await page.route('**/identity.v1.IdentityService/GetAgentAuthorization',async route=>{if(once){once=false;await route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({code:'unauthenticated',message:'session ended'})});}else await route.continue();});
 await expect(page.locator('#captcha')).toHaveAttribute('data-ready','true');
 await page.getByLabel('Email',{exact:true}).fill('browser-owner@example.com');await page.getByLabel('Password',{exact:true}).fill('Offline-Browser-Password123!');
 await page.getByRole('button',{name:'Sign in to review'}).click();await expect(page.getByRole('alert')).toContainText('sign in again');
 await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeHidden();
 await signIn(page);await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeDisabled();
});
test('untrusted display strings stay text and exact scopes remain visible',async({page})=>{
 const payload='<img src=x onerror=alert(1)>';
 await start(page);
 await page.route('**/identity.v1.IdentityService/GetAgentAuthorization',async route=>{const response=await route.fetch();const data=await response.json();data.clientName=payload;data.agents[0].name=payload;await route.fulfill({response,json:data});});
 await signIn(page);await expect(page.getByText(payload,{exact:true})).toHaveCount(2);expect(await page.locator('img').count()).toBe(0);await expect(page.getByText('files:read',{exact:true})).toBeVisible();
});

test('review supports keyboard selection without automatic approval',async({page})=>{
 await start(page);await signIn(page);
 await page.keyboard.press('Tab');await expect(page.getByRole('radio',{name:'Example product engineer'})).toBeFocused();
 await page.keyboard.press('Space');await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeEnabled();
 await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Don’t allow'})).toBeFocused();
 await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Allow selected agent'})).toBeFocused();
 const before=await page.evaluate(()=>getComputedStyle(document.body).backgroundColor);
 await page.emulateMedia({colorScheme:'dark'});const after=await page.evaluate(()=>getComputedStyle(document.body).backgroundColor);
 expect(after).not.toBe(before);
});
