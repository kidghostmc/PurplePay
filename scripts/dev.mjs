import http from 'node:http';
import fs from 'node:fs/promises';
import handler from '../api/app.js';
const server=http.createServer(async(req,res)=>{
  if(req.url.startsWith('/api/'))return handler(req,res);
  if(req.url==='/'||req.url.startsWith('/?')){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(await fs.readFile('index.html'))}
  res.statusCode=404;res.end('Not found');
});
server.listen(4173,'127.0.0.1',()=>console.log('Local URL: http://127.0.0.1:4173'));
