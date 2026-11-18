import {spawn} from 'node:child_process';
if(process.platform!=='win32')throw new Error('This helper starts the phpMyAdmin installation in this computer’s WSL Ubuntu.');
const server=spawn('wsl.exe',['-d','Ubuntu','-u','www-data','--exec','php','-S','127.0.0.1:8001','-t','/usr/share/phpmyadmin'],{stdio:'inherit',windowsHide:true});
server.on('error',error=>{console.error(error.message);process.exitCode=1;});
server.on('exit',code=>{process.exitCode=code||0;});
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.kill(signal));
