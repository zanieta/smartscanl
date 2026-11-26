// Run after building, with Playwright available to Node. No scanner calls.
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {once} = require('node:events');
const {chromium} = require('playwright');

async function run() {
  const port = 13061;
  const base = 'http://127.0.0.1:' + port;
  const server = spawn(process.execPath, [require.resolve('next/dist/bin/next'), 'start', '-H', '127.0.0.1', '-p', String(port)], {
    env: {...process.env, SECURITY360_BACKEND_URL: 'http://127.0.0.1:1'}, windowsHide: true
  });
  let browser;
  try {
    await Promise.race([
      (async () => {for await (const line of server.stdout) if (/Ready in/i.test(line.toString())) return; throw Error('Preview did not start');})(),
      once(server,'exit').then(()=>{throw Error('Preview exited');}),
      new Promise((_,reject)=>setTimeout(()=>reject(Error('Preview startup timeout')),20000).unref())
    ]);
    browser = await chromium.launch({channel:process.env.BROWSER_CHANNEL || 'chromium'});
    const page = await browser.newPage();
    const errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    page.on('console',m=>{if(m.type()==='error') errors.push(m.text());});
    page.on('requestfailed',r=>errors.push(r.url()));
    for(const width of [375,768,1280,1440]){
      await page.setViewportSize({width,height:900});
      await page.goto(base+'/?mode=sample');
      assert.equal(await page.title(),'Security360 | DE-Webnet');
      assert.equal(await page.locator('.brand small').innerText(),'DE-Webnet');
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      if(width===375){
        await page.getByText('Menu',{exact:true}).click();
        await page.getByRole('link',{name:'Assets',exact:true}).click();
        await page.getByRole('heading',{name:'Assets in scan reports'}).waitFor();
      }
    }
    for(const [filter,total] of [['Host','1'],['Website','2'],['All assessments','3']]){
      await page.getByRole('link',{name:filter,exact:true}).click();
      assert.equal(await page.locator('.metrics b').first().innerText(),total);
    }
    for(const view of ['Scans','Findings','Reports','Scanners','Settings']){
      await page.getByRole('link',{name:view,exact:true}).click();
      await page.getByRole('heading',{name:view,exact:true,level:1}).waitFor();
      assert.equal(new URL(page.url()).searchParams.get('mode'),'sample');
    }
    await page.goto(base);
    await page.getByText(/Unable to reach the scanner/).waitFor();
    assert.equal(await page.locator('.metrics b').first().innerText(),'—');
    assert.deepEqual(errors,[]);
    console.log('PASS: sample navigation, branding, filters, four viewport widths and offline error state.');
  } finally {try {await browser?.close();} finally {server.kill();}}
}
run().catch(e=>{console.error(e);process.exitCode=1;});
