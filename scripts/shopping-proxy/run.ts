import { chromium } from 'patchright-core';
import { Faker, allLocales } from '@faker-js/faker';
import { readFileSync, appendFileSync } from 'node:fs';
import { detectBlock } from './src/detect.js';

const apiBase = process.env.NOTTE_API_URL || 'https://us-staging.notte.cc';
const apiKey = process.env.NOTTE_API_KEY!;
const siteKey = process.argv[2] || 'birkenstock-us';
const { spec, flow } = await import(`./sites/${siteKey}.ts`);
const hosts = ['postman-echo.com','www.birkenstock.com','checkoutshopper-live.adyen.com','live.adyen.com','www.booking.com','secure.booking.com'];
const started = Date.now();
const result: any = { site: siteKey, startedAt: new Date().toISOString(), apiBase, proxySourceCommit: '4a3e36a37c2c57207d89802179e5d5e3bb1aa8c6', stages: [], cardFields: [], purchased: false };
let owned: string | undefined, browser: any, page: any;
const safe = (s: unknown) => String(s).replaceAll(apiKey, '[api-key]').replaceAll(process.env.SECRET_PROXY_PASSWORD || '\u0000', '[proxy-password]').replaceAll(process.env.SECRET_PROXY_USERNAME || '\u0000', '[proxy-user]').replace(/wss?:\/\/[^\s"'<>]+/g, '[cdp]').replace(/(https?:\/\/[^\s?"'<>]+)\?[^\s"'<>]*/g, '$1?[query]').slice(0,1500);
function emit(kind: string, data: any) { console.log('BSP_EVENT '+JSON.stringify({at:new Date().toISOString(),elapsedS:Math.round((Date.now()-started)/1000),kind,...data})); }
async function api(method: string, path: string, body?: any) {
  const r = await fetch(apiBase+path,{method,headers:{Authorization:`Bearer ${apiKey}`,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(method==='POST'?120000:25000)});
  const text = await r.text();
  if(!r.ok) throw Error(`API ${method} ${path} HTTP ${r.status}: ${safe(text)}`);
  return text?JSON.parse(text):{};
}
async function inventory() {
  const frames=[];
  for(const [i,frame] of page.frames().entries()) {
    let origin='';try{origin=new URL(frame.url()).origin;}catch{}
    const inputs=await frame.locator('input').evaluateAll((els:any[])=>els.map((e,index)=>({index,type:e.type,name:e.name,id:e.id,placeholder:e.placeholder,autocomplete:e.autocomplete,ariaLabel:e.getAttribute('aria-label'),label:Array.from(e.labels||[]).map((l:any)=>l.innerText).join(' '),visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)})).filter(e=>e.visible&&!['hidden','submit','button'].includes(e.type))).catch(()=>[]);
    frames.push({index:i,origin,inputs});
  }
  return frames;
}
async function extendToCard() {
  // Only observed radio/label controls may be clicked. Never a submit/order button.
  const radios=await page.locator('input[type=radio]').evaluateAll((els:any[])=>els.map((e,index)=>({index,checked:e.checked,value:e.value,label:Array.from(e.labels||[]).map((l:any)=>l.innerText).join(' ').trim()})));
  emit('paymentChoices',{radios});
  const choice=radios.find((r:any)=>/credit|debit|card/i.test(r.label+' '+r.value)&&!/paypal|apple|google|klarna|afterpay/i.test(r.label+' '+r.value));
  if(choice&&!choice.checked){
    const radio=page.locator('input[type=radio]').nth(choice.index);
    if(await radio.isVisible()) await radio.check({timeout:10000});
    else {const id=await radio.getAttribute('id');if(id){const label=page.locator(`label[for=${JSON.stringify(id)}]`);if(await label.isVisible())await label.click({timeout:10000});}}
    await page.waitForTimeout(1500);
  }
  // The observed Birkenstock payment UI uses a Cards accordion, not a radio.
  // This exact row was visible in run41867915431; never click an order control.
  const cardRow=siteKey==='birkenstock-us'
    ? page.locator('#payment-button-scheme')
    : page.getByText(/^Cards$/).filter({visible:true}).first();
  if(siteKey==='birkenstock-us'){
    emit('waitingForCardsAccordion',{timeoutMs:45000});
    await cardRow.waitFor({state:'visible',timeout:45000});
  }
  if(await cardRow.isVisible().catch(()=>false)){
    const descriptor=await cardRow.evaluate((e:any)=>({text:e.innerText,tag:e.tagName,ancestorButtonType:e.closest('button')?.getAttribute('type')||null}));
    if(descriptor.ancestorButtonType==='submit')throw Error('Cards row unexpectedly belongs to a submit control');
    await cardRow.click({timeout:10000});emit('cardsAccordionOpened',descriptor);
  }
  const fieldsDeadline=Date.now()+45000;
  do{
    result.paymentInventory=await inventory();
    if(result.paymentInventory.some((f:any)=>f.inputs.some((i:any)=>/card.?number|cc-number|encryptedCardNumber/i.test([i.name,i.id,i.placeholder,i.autocomplete,i.ariaLabel,i.label].join(' ')))))break;
    await page.waitForTimeout(1000);
  }while(Date.now()<fieldsDeadline);
  emit('paymentInventory',{frames:result.paymentInventory});
  const fields:Record<string,any>={};
  for(const f of result.paymentInventory)for(const input of f.inputs){
    if(['radio','checkbox'].includes(input.type))continue;
    const text=[input.name,input.id,input.placeholder,input.autocomplete,input.ariaLabel,input.label].join(' ');
    let kind:string|undefined;
    if(/card.?number|cc-number|encryptedCardNumber|\bpan\b/i.test(text))kind='number';
    else if(/cvv|cvc|security.?code|encryptedSecurityCode|cc-csc/i.test(text))kind='cvv';
    else if(/exp.*month|cc-exp-month/i.test(text))kind='month';
    else if(/exp.*year|cc-exp-year/i.test(text))kind='year';
    else if(/expir|expiry|cc-exp|MM\s*[/]\s*YY/i.test(text))kind='expiry';
    else if(/card.?holder|name.*card|cc-name/i.test(text))kind='holder';
    if(kind&&!fields[kind])fields[kind]={frame:f.index,input:input.index};
  }
  result.cardFormReached=!!fields.number;
  const values:Record<string,string>={number:'4111111111111111',expiry:'12/30',month:'12',year:'2030',cvv:'123',holder:'Proxy Test'};
  for(const kind of ['holder','number','expiry','month','year','cvv']){
    const loc=fields[kind];if(!loc)continue;
    const el=page.frames()[loc.frame].locator('input').nth(loc.input);
    await el.fill(values[kind],{timeout:10000});await el.press('Tab');
    const state=await el.evaluate((e:any)=>({length:e.value.length,digits:e.value.replace(/\D/g,'').length,browserValid:e.checkValidity(),ariaInvalid:e.getAttribute('aria-invalid')}));
    result.cardFields.push({kind,...state});emit('cardFieldSet',{kind,...state});
  }
  result.cardFieldsSet=!!fields.number&&!!fields.cvv&&(!!fields.expiry||!!fields.month&&!!fields.year)&&result.cardFields.every((f:any)=>f.length>0);
  result.cardOriginSubstitutionProven=false;
  result.cardSubstitutionLimit='Stopped after field entry; browser observations cannot prove what the payment origin received; client encryption may hide numeric stand-ins from the proxy.';
  emit('cardEntryResult',{reached:result.cardFormReached,allRequiredSet:result.cardFieldsSet,cardOriginSubstitutionProven:false});
  if(!result.cardFieldsSet)throw Error('Dummy card number, expiry and CVV were not all set');
}
let cleanupPromise:Promise<void>|undefined;
function cleanup(){
  if(cleanupPromise)return cleanupPromise;
  cleanupPromise=(async()=>{
    await browser?.close().catch(()=>{});
    if(owned)try{
      await api('DELETE',`/sessions/${owned}/stop`);
      const end=Date.now()+40000;
      do{const state=await api('GET',`/sessions/${owned}`);const status=String(state.status||'').toLowerCase();result.cleanup={status,verified:['closed','stopped','expired','failed'].includes(status)};if(result.cleanup.verified)break;await new Promise(r=>setTimeout(r,2000));}while(Date.now()<end);
    }catch(e){result.cleanup={verified:false,error:safe(e)};}
  })();return cleanupPromise;
}
const killTimer=setTimeout(()=>{emit('hardDeadline',{sessionId:owned});void cleanup().finally(()=>process.exit(1));},650000);
process.on('SIGTERM',()=>{void cleanup().finally(()=>process.exit(1));});
process.on('SIGINT',()=>{void cleanup().finally(()=>process.exit(1));});
try{
  const body={max_duration_minutes:10,idle_timeout_minutes:5,advanced_stealth:true,block_ads:false,proxies:[{type:'notte',country:spec.country.toLowerCase()},{type:'secret',server:process.env.BSP_PROXY_SERVER,username:process.env.SECRET_PROXY_USERNAME,password:process.env.SECRET_PROXY_PASSWORD,ca_certificate:readFileSync(process.env.BSP_CA_FILE!,'utf8'),hosts}]};
  emit('sessionCreating',{apiBase,site:siteKey,hosts,advancedStealth:true,country:spec.country});
  const created=await api('POST','/sessions/start',body);owned=created.session_id;
  if(!owned)throw Error('No session ID; no retry attempted');
  result.sessionId=owned;emit('sessionCreated',{sessionId:owned,reportedHosts:created.secret_proxy?.hosts});
  if(!created.cdp_url)throw Error('No CDP URL returned');
  browser=await chromium.connectOverCDP(created.cdp_url,{timeout:60000});result.browserVersion=browser.version();
  const context=browser.contexts()[0];page=context.pages()[0]||await context.newPage();page.setDefaultTimeout(20000);page.setDefaultNavigationTimeout(60000);
  // A reflected stand-in with masking enabled cannot independently prove a swap.
  // Record the echo diagnostic, then test the merchant regardless of echo availability.
  result.liveProxySubstitutionProven=false;
  try {
    const response=await page.goto('https://postman-echo.com/get?probe=tok_bsp_shopping_probe',{waitUntil:'domcontentloaded',timeout:30000});
    const text=await page.locator('body').innerText();
    result.echoDiagnostic={status:response?.status(),standinVisible:text.includes('tok_bsp_shopping_probe'),replacementVisible:text.includes('dummy_bsp_shopping_replacement'),originSubstitutionProven:false};
  } catch(e) { result.echoDiagnostic={error:safe(e),originSubstitutionProven:false}; }
  emit('echoDiagnostic',result.echoDiagnostic);
  context.on('request',(r:any)=>{const data=r.postData()||'';if(data.includes('4111111111111111')||data.includes('4242424242424242')||/encryptedCardNumber|encryptedSecurityCode|encryptedExpiry/i.test(data))emit('cardRequestShape',{host:new URL(r.url()).hostname,method:r.method(),containsStandinPAN:data.includes('4111111111111111'),containsReplacementPAN:data.includes('4242424242424242'),containsEncryptedFields:/encryptedCardNumber|encryptedSecurityCode|encryptedExpiry/i.test(data)});});
  const faker=new Faker({locale:[allLocales[spec.fakerLocale],allLocales.en]});faker.seed(20261104);
  let flowTimer:ReturnType<typeof setTimeout>|undefined;
  try{await Promise.race([
    flow({page,faker,log:(m:string)=>emit('flowLog',{message:safe(m)}),reach:async(stage:string,detail?:string)=>{const block=await detectBlock(page);if(block)throw Error(`Visible block: ${block.vendor}`);const item={stage,detail:safe(detail||''),elapsedS:Math.round((Date.now()-started)/1000)};result.stages.push(item);emit('stage',item);},assertNotBlocked:async()=>{const block=await detectBlock(page);if(block)throw Error(`Visible block: ${block.vendor}`);}}),
    new Promise((_,reject)=>{flowTimer=setTimeout(()=>reject(Error('Frozen checkout flow exceeded 300s')),300000);})
  ]);}finally{clearTimeout(flowTimer);}
  await extendToCard();
}catch(e){result.error=safe(e);emit('error',{message:result.error});process.exitCode=1;}
finally{
  if(page&&!page.isClosed()){
    result.finalUrl=safe(page.url());result.finalTitle=await page.title().catch(()=>'');result.finalInventory=await inventory().catch(()=>[]);
    result.paymentControls=await page.locator('button,label,[role=button],summary').evaluateAll((els:any[])=>els.map(e=>({tag:e.tagName,role:e.getAttribute('role'),type:e.getAttribute('type'),id:e.id,text:(e.innerText||e.textContent||'').trim().slice(0,160),visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)})).filter(e=>/\bcards?\b|payment/i.test(e.text))).catch(()=>[]);
    emit('finalPage',{url:result.finalUrl,title:result.finalTitle,frames:result.finalInventory,paymentControls:result.paymentControls});
    const image=await page.screenshot({type:'jpeg',quality:40,timeout:10000}).catch(()=>null);if(image)console.log('BSP_SCREENSHOT '+image.toString('base64'));
  }
  await cleanup();clearTimeout(killTimer);result.durationS=Math.round((Date.now()-started)/1000);console.log('BSP_RESULT '+JSON.stringify(result));
  if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,'```json\n'+JSON.stringify(result,null,2)+'\n```\n');
}
