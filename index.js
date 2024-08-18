const {encrypt, decrypt} = require('./encro');
const crypto = require('crypto');


const textDecoder = new TextDecoder;
const textEncoder = new TextEncoder;


let server = null;

const deviceKeys = {
    'device1': '53bb3399120b109b6b655a28fddb90032a0b6f6d9d0052e2dc551d70d0631a9e',
    'device2': 'ab9a84fe09a82b7e0911798919e8e7f46ff7e4962caea6a939c8d884c3f837a6'
}


class PACKETSTATE {
    // Private Fields
    static get NAMELEN() { return 0; }
    static get NAME() { return 1; }
    static get LEN1() { return 2; }
    static get LEN2() { return 3; }
    static get LEN3() { return 4; }
    static get LEN4() { return 5; }
    static get PAYLOAD() {return 6; }
}

class NETSTATUS {
    static get OPENED() { return 1};
    static get READY() {return 2;}
}

class DeviceIO {

    constructor(socket){
        this.socket=socket;
        this.socket.setNoDelay();
        socket.on('data', this.onData);
        console.log(socket.address, 'connected');

        this.netStatus=NETSTATUS.OPENED;
        this.packetState=PACKETSTATE.NAMELEN;

        this.nameLength=0;
        this.nameWriteIndex=0;
        this.name=null;
        this.key=null;
        this.clientHandshake=Uint32Array.from([0]);
        this.serverHandshake=Uint32Array.from([crypto.randomInt(4294967295)]); 

        this.payloadLength=0;
        this.payloadWriteIndex=0;
        this.payload=null;

        socket.on('end', () => {
            console.log('name',this.name, this.socket.address, 'disconnected');
        });        
        socket.on('timeout', () => {
            console.log('name',this.name, this.socket.address, 'timed out');
        });
        socket.on('error', (err)=>{
            socket.destroy();
            console.log('name',this.name, this.socket.address, 'error occured', err);
        });
    }

    sendPacket = (data) => {
        if (typeof data==='string') data=textEncoder.encode(data);
        if (data && data.length>0x0FFFF0){
            console.log(this.name, this.socket.address, 'cant send a message bigger than 0x0FFFF0');
            return;
        }
  
        const encryptedData = encrypt(this.serverHandshake[0], data, this.key);
        const header=new Uint8Array([0, 0, 0, 0]);
        (new DataView(header.buffer)).setUint32(0, encryptedData.length, true);
        this.socket.write(header);
        this.socket.write(encryptedData);

        this.serverHandshake[0]++;
    }

    onFullPacket = (handshake, data) => {
        if (this.netStatus===NETSTATUS.OPENED)
    }

    onData = (buffer) => {    
        for (let i=0;i<buffer.length;i++){
            const byte=buffer[i];
            if (this.netStatus===NETSTATUS.OPENED && this.packetState===PACKETSTATE.NAMELEN){
                this.nameLength=byte;
                this.packetState=PACKETSTATE.NAME;
            }else if (this.netStatus===NETSTATUS.OPENED && this.packetState===PACKETSTATE.NAME){
                this.name+=String.fromCharCode(byte);
                this.nameWriteIndex++;
                if (this.nameWriteIndex>=this.nameLength){
                    if (deviceKeys[this.name]){
                        this.key=deviceKeys[this.name];
                        this.packetState=PACKETSTATE.LEN1;
                    }else{
                        console.log(this.name, this.socket.address, 'unknown device name');
                        this.socket.destroy();
                        return;
                    }
                }
            }else if (this.packetState===PACKETSTATE.LEN1){
                this.payloadLength=byte;
                this.packetState=PACKETSTATE.LEN2;

            }else if (this.packetState===PACKETSTATE.LEN2){
                this.payloadLength|=byte<<8;
                this.packetState=PACKETSTATE.LEN3;

            }else if (this.packetState===PACKETSTATE.LEN3){
                this.payloadLength|=byte<<16;
                this.packetState=PACKETSTATE.LEN4;

            }else if (this.packetState===PACKETSTATE.LEN4){
                this.payloadLength|=byte<<24;
                this.packetState=PACKETSTATE.PAYLOAD;

                if (this.payloadLength>0x0FFFFF){
                    this.socket.destroy();
                    console.log(this.name, this.socket.address, 'device sent packet larger than 0x0FFFFF');
                    return;
                }

                this.payload = Buffer.alloc(this.payloadLength);
                this.payloadWriteIndex=0;

            }else if (this.packetState===PACKETSTATE.PAYLOAD)
                const howFar = Math.min(this.payloadLength, buffer.length-i);
                buffer.copy(this.payload, this.payloadWriteIndex, i, howFar+i);
                this.payloadWriteIndex+=howFar;
                if (this.payloadWriteIndex>=this.payloadLength){
                    //Process complete packet here
                    try{
                        const {data: decrypted, handshake: recvdHandshake} = decrypt(this.payload, this.key);
                        this.onFullPacket(handshake, data);
                        this.packetState=PACKETSTATE.LEN1;
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