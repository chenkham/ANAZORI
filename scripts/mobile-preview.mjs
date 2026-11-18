import http from 'node:http';
import {networkInterfaces} from 'node:os';

const privateIPv4=ip=>/^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/.test(ip)&&ip.split('.').every(n=>Number(n)<=255);
const interfaces=Object.entries(networkInterfaces()).filter(([name])=>!/(?:wsl|vethernet|virtual|loopback)/i.test(name)).sort(([a],[b])=>Number(/wi.?fi|wireless|wlan/i.test(b))-Number(/wi.?fi|wireless|wlan/i.test(a)));
const addresses=interfaces.flatMap(([,rows])=>rows.filter(row=>row.family==='IPv4'&&!row.internal&&privateIPv4(row.address)).map(row=>row.address));
const host=process.argv[2]||addresses[0];
if(!host||!addresses.includes(host))throw Error('Connect the computer to your hotspot/Wi-Fi, then run npm run serve:mobile.');
const port=8000,authority=`${host}:${port}`;

// Bind only the selected LAN adapter; PHP stays on localhost through WSL.
const server=http.createServer((request,response)=>{
 if(request.headers.host!==authority){response.writeHead(400);response.end('Use the displayed mobile preview URL.');return;}
 // The private local/deployment configuration selects its database by this host.
 // Keep the upstream a localhost preview; browser navigation and assets use relative paths.
 const upstream=http.request({hostname:'127.0.0.1',port,method:request.method,path:request.url,headers:{...request.headers,host:`localhost:${port}`,connection:'close'}},reply=>{
  response.writeHead(reply.statusCode,reply.headers);reply.pipe(response);
 });
 upstream.on('error',()=>{
  if(response.headersSent)response.destroy();
  else{response.writeHead(503,{'Content-Type':'text/plain; charset=utf-8'});response.end('The local PHP server is unavailable. Run npm run serve on the computer.');}
 });
 request.on('aborted',()=>upstream.destroy());response.on('close',()=>upstream.destroy());request.pipe(upstream);
});
server.requestTimeout=120000;
server.on('error',error=>{console.error(error.code==='EADDRINUSE'?`Port ${port} on ${host} is already in use.`:error.message);process.exitCode=1;});
server.listen(port,host,()=>console.log(`Mobile preview: http://${authority}/\nKeep npm run serve running. Connect the phone to this same hotspot/Wi-Fi.`));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close());
