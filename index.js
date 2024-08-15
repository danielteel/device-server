const {encrypt, decrypt} = require('./encro');
const crypto = require('crypto');


const textDecoder = new TextDecoder;
const textEncoder = new TextEncoder;

const fs = require('fs');
const path = require('path');
const logFilePath = path.join(__dirname, 'devlog.log');
 

let server = null;


function logdev(...args){
    console.log(...args);
    let message='';
    for (const a of args){
        message+=String(a)+" ";
    }
    fs.appendFile(logFilePath, message + '\n', (err) => {
        if (err) {
            console.error('Device server: Error appending to log file:', err);
        }
    });
}

class DeviceIO {
    static timeoutPeriod=20000;
    static devices = [];
    static deviceCounter=0;

    static runManualTimeoutCheck(){
        try{
            for (const device of DeviceIO.devices){
                if (Date.now()-device.lastTimeRecvd>=DeviceIO.timeoutPeriod){
                    logdev("Manual timeout of "+device.name);
                    DeviceIO.removeDevice(device);
                }
            }
        }catch(e){

        }
        setTimeout(DeviceIO.runManualTimeoutCheck, DeviceIO.timeoutPeriod);   
    }
    static {
        setTimeout(this.runManualTimeoutCheck, this.timeoutPeriod);  
    }

    static getDevices = () => {
        return this.devices;
    }

    static removeDevice = (device) => {
        try{
            if (device.socket){
                device.socket.destroy();
            }
        }catch{
        }
        this.devices=this.devices.filter( v => {
            if (v===device) return false;
            return true;
        });
    }

    static isNameConnected = (name) =>{
        for (const device of this.devices){
            if (device.name===name){
                return true;
            }
        }
        return false;
    }

    static addDevice = (device) => {
        this.devices.push(device);
    }

    constructor(socket, name, key, deviceHandshakeNumber, actions, onError){
        this.lastTimeRecvd = Date.now();
        this.name=name;
        this.deviceHandshakeNumber=deviceHandshakeNumber;
        this.actions=actions;
        this.onError=onError;
        this.key=key;
        this.resetPacketData();
        this.socket=socket;

        this.socket.setNoDelay();

        this.handshakeNumber=Uint32Array.from([crypto.randomInt(4294967295)]); 

        socket.setTimeout(this.constructor.timeoutPeriod);

        this.constructor.addDevice(this);
        socket.on('data', this.onData);
        socket.on('end', () => {
            this.constructor.removeDevice(this);
            logdev(this.name, "closed its connection");
        });        
        socket.on('timeout', () => {
            socket.destroy();
            this.constructor.removeDevice(this);
            this.onError(this.name+' timed out, closing connection', this);
        });
        socket.on('error', (err)=>{
            socket.destroy();
            this.constructor.removeDevice(this);
            this.onError(this.name+' '+err, this);
        });

        this.sendInitialHandshake();
    }

    onDeviceDatabaseDelete = () => {
        socket.destroy();
        this.constructor.removeDevice(this);
        this.onError(this.name+' device was deleted from database, closing connection', this);
    }

    onCompletePacket = (device, data) => {
        if (data[0]===0xFF && data[1]===0xD8){
            device.image=data;
        }else if (data[0]==='i'.charCodeAt(0) && data[1]==='n'.charCodeAt(0)){
            const time=new Date();
            if (time.getHours()>=20 && time.getHours()<22){
                device.sendPacket(new Uint8Array([110, 116]));//It is night time
            }else{
                device.sendPacket(new Uint8Array([110, 102]));//Its not night time
            }
            return;
        }else{
            console.log('unresolved data', data[0], data[1]);
        }
    }

    sendAction = (actionTitle, data) => {
        if (!Array.isArray(this.actions)) return false;
        for (const action of this.actions){
            if (action.title.toLowerCase().trim()===actionTitle.toLowerCase().trim()){
                switch (action.type.toLowerCase().trim()){
                    case 'void':
                        this.sendPacket(new Uint8Array([action.commandByte]));
                        return true;
                    case 'byte':
                        this.sendPacket(new Uint8Array([action.commandByte, data]));
                        return true;
                }
            }
        }
        return false;
    }

    resetPacketData = () => {
        this.magic1=null;
        this.magic2=null;
        this.length1=null;
        this.length2=null;
        this.length3=null;
        this.length4=null;
        this.payload=null;
        this.payloadWriteIndex=0;
    }

    sendInitialHandshake = () => {
        const encryptedData = encrypt(this.handshakeNumber[0], null, this.key);

        const header=new Uint8Array([13, 37, 0, 0, 0, 0]);
        (new DataView(header.buffer)).setUint32(2, encryptedData.length, true);
        
        this.socket.write(header);
        this.socket.write(encryptedData);
    }

    sendPacket = (data) => {
        if (typeof data==='string') data=textEncoder.encode(data);
        if (data.length>(0x0FFFF0)){
            this.onError(this.name+' cant send a message bigger than 0x0FFFF0', this);
            return;
        }
  
        const encryptedData = encrypt(this.handshakeNumber[0], data, this.key);
        const header=new Uint8Array([73, 31, 0, 0, 0, 0]);
        (new DataView(header.buffer)).setUint32(2, encryptedData.length, true);
        this.socket.write(header);
        this.socket.write(encryptedData);

        this.handshakeNumber[0]++;
    }

    onData = (buffer) => {    
        this.lastTimeRecvd=Date.now();
        for (let i=0;i<buffer.length;i++){
            const byte=buffer[i];
            if (this.magic1===null){
                this.magic1=byte;
            }else if (this.magic2===null){
                this.magic2=byte;
                if (this.magic1===37 && this.magic2===13){
                    this.resetPacketData();
                }else if (this.magic1!=73 || this.magic2!=31){
                    this.socket.destroy();
                    this.constructor.removeDevice(this);
                    this.onError(this.name+' bad magic bytes, closing connection', this);
                    return;
                }
            }else if (this.length1===null){
                this.length1=byte;
            }else if (this.length2===null){
                this.length2=byte;
            }else if (this.length3===null){
                this.length3=byte;
            }else if (this.length4===null){
                this.length4=byte;

                const temp = new Uint8Array([this.length1, this.length2, this.length3, this.length4]);
                const tempView = new DataView(temp.buffer);
                this.length=tempView.getUint32(0, true);

                if (this.length>0x0FFFFF){
                    this.socket.destroy();
                    this.constructor.removeDevice(this);
                    this.onError(this.name+' device sent packet larger than 0x0FFFFF', this);
                }

                this.payload = Buffer.alloc(this.length);
                this.payloadWriteIndex=0;
            }else{
                const howFar = Math.min(this.length, buffer.length-i);
                buffer.copy(this.payload, this.payloadWriteIndex, i, howFar+i);
                this.payloadWriteIndex+=howFar;
                if (this.payloadWriteIndex>=this.length){
                    //Process complete packet here
                    try{
                        const {data: decrypted, handshake: recvdHandshake} = decrypt(this.payload, this.key);
                        if (recvdHandshake!=this.deviceHandshakeNumber[0]){
                            this.socket.destroy();
                            this.constructor.removeDevice(this);
                            this.onError(this.name+' incorrect handshake number, closing connection, recvd: '+recvdHandshake+' expected: '+this.deviceHandshakeNumber[0], this);
                            return;
                        }else{
                            this.deviceHandshakeNumber[0]++;
                            this.onCompletePacket(this, decrypted);
                        }
                        this.resetPacketData();
                    }catch(e){
                        this.socket.destroy();
                        this.constructor.removeDevice(this);
                        this.onError(this.name+' failed to decrypt incoming packet', this);
                        return; 
                    }
                }
                i+=howFar-1;
            }
        }
    }
}

class UndeterminedDevice {
    constructor(socket, onError){
        this.socket=socket;
        this.onError=onError;
        
        this.magic1=null;
        this.magic2=null;
        this.name=null;
        this.nameLength=null;
        this.nameWriteIndex=0;
        this.deviceHandshakeNumber=null;
        this.length=null;
        this.length1=null;
        this.length2=null;
        this.length3=null;
        this.length4=null;
        this.payload=null;
        this.payloadWriteIndex=0;
        this.actions=[];
        this.key=null;

        socket.setTimeout(20000);
        
        socket.on('data', this.onData);  
        
        socket.on('end', () => {
            this.onError('undetermined device ended connection before handshake complete');
        });        
        socket.on('timeout', () => {
            socket.destroy();
            this.onError('undetermined device timed out, closing connection');
        });
        socket.on('error', (err)=>{
            socket.destroy();
            this.onError('undetermined device had an error '+err);
        });
    }

    onData = async (buffer) => {    
        for (let i=0;i<buffer.length;i++){
            const byte=buffer[i];
            if (this.magic1===null){
                this.magic1=byte;
            }else if (this.magic2===null){
                this.magic2=byte;
                if (this.magic1!=13 || this.magic2!=37){
                    this.socket.destroy();
                    this.onError('undetermined device had bad magic bytes, closing connection');
                    return;
                }
            }else if (this.nameLength===null){
                this.nameLength=byte;
                this.name="";
                if (this.nameLength===0){
                    this.socket.destroy();
                    this.onError('undetermined device tried to have 0 length name, closing connection');
                    return;
                }
            }else if (this.nameWriteIndex<this.nameLength){
                this.name+=String.fromCharCode(byte);
                this.nameWriteIndex++;
                if (this.nameWriteIndex>=this.nameLength){
                    if (DeviceIO.isNameConnected(this.name)){
                        this.socket.destroy();
                        this.onError('device with name '+this.name+' is already connected, closing connection');
                        return;
                    }
                }
            }else if (this.length1===null){
                this.length1=byte;
            }else if (this.length2===null){
                this.length2=byte;
            }else if (this.length3===null){
                this.length3=byte;
            }else if (this.length4===null){
                this.length4=byte;

                const temp = new Uint8Array([this.length1, this.length2, this.length3, this.length4]);
                const tempView = new DataView(temp.buffer);
                this.length=tempView.getUint32(0, true);

                if (this.length>0x0FFFFF){
                    this.socket.destroy();
                    this.onError('undetermined device '+this.name+' sent packet larger than 0x0FFFFF');
                    return;
                }

                this.payload = Buffer.alloc(this.length);
                this.payloadWriteIndex=0;
            }else{
                const howFar = Math.min(this.length, buffer.length-i);
                buffer.copy(this.payload, this.payloadWriteIndex, i, howFar+i);
                this.payloadWriteIndex+=howFar;
                if (this.payloadWriteIndex>=this.length){
                    //Process complete packet here
                    try{
                        const [{encro_key}] = await getKnex()('devices').select('encro_key').where({name: this.name});
                        this.key=encro_key;
                        if (!this.key){
                            this.socket.destroy();
                            this.onError('device record "'+this.name+'" not found');
                            return;
                        }

                        const {data: decrypted, handshake: recvdHandshake} = decrypt(this.payload, this.key);
                        this.deviceHandshakeNumber=new Uint32Array([recvdHandshake]);

                        if (decrypted.length!=0){
                            const actions=textDecoder.decode(decrypted).split(',');
                            for (const action of actions){
                                const [title, type, commandByte] = action.split(':');
                                this.actions.push({title, type, commandByte});
                            }
                        }
                        this.socket.removeAllListeners();
                        new DeviceIO(this.socket, this.name, this.key, this.deviceHandshakeNumber, this.actions, this.onError);
                    }catch(e){                
                        this.socket.destroy();
                        this.onError('failed to fetch or decrypt device data');
                    }
                }
                i+=howFar-1;
            }
        }
    }
}

class Device{
    constructor(socket){
        socket.setTimeout(20000);
        
        socket.on('data', this.onData);  
        
        socket.on('end', () => {
            this.onError('undetermined device ended connection before handshake complete');
        });        
        socket.on('timeout', () => {
            socket.destroy();
            this.onError('undetermined device timed out, closing connection');
        });
        socket.on('error', (err)=>{
            socket.destroy();
            this.onError('undetermined device had an error '+err);
        });
    }
}

function createDeviceServer(){
    if (server) return;
    
    server = new (require('net')).Server();


    server.on('connection', function(socket) {

        logdev("Device connected");
        const onError = (msg, device) => {
            logdev('Device Error', msg);
        }
        new UndeterminedDevice(socket, onError);
    });

    return server;
}

createDeviceServer();