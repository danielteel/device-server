const {encrypt, decrypt} = require('./encro');
const crypto = require('crypto');


const textDecoder = new TextDecoder;
const textEncoder = new TextEncoder;


let server = null;
let devicePort = 4004;

let devices = [];

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
    static get PAYLOAD() { return 6; }
    static get ERROR() { return 7; }
}

class NETSTATUS {
    static get OPENED() { return 1; }
    static get READY() { return 2; }
    static get ERROR() { return 3; }
}

class Device {

    constructor(socket, onDone){
        this.lastData=null;//Added for debugging
        this.sendCount=0;//Added for debugging

        this.onDone=onDone;

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
            console.log('name',this.name, this.socket.address, 'error occured', err);
            this.deviceErrored();
        });
    }

    deviceErrored = () => {
        this.socket.destroy();
        this.socket=null;
        this.payload=null;
        this.packetState=PACKETSTATE.ERROR;
        this.netStatus=NETSTATUS.ERROR;
        this.onDone(this);
    }

    sendPacket = (data) => {
        if (typeof data==='string') data=textEncoder.encode(data);
        if (data && data.length>0x0FFFF0){
            console.log(this.name, this.socket.address, 'cant send a message bigger than 0x0FFFF0');
            return false;
        }
  
        const encryptedData = encrypt(this.serverHandshake[0], data, this.key);
        const header=new Uint8Array([0, 0, 0, 0]);
        (new DataView(header.buffer)).setUint32(0, encryptedData.length, true);
        this.socket.write(header);
        this.socket.write(encryptedData);

        this.serverHandshake[0]++;

        return true;
    }

    onFullPacket = (handshake, data) => {
        if (this.netStatus===NETSTATUS.OPENED){
            this.clientHandshake[0]=handshake;
            this.clientHandshake[0]++;
            this.netStatus=NETSTATUS.READY;
            this.sendPacket(null);
        }else{
            if (this.clientHandshake[0]!==handshake){
                console.log(this.name, this.socket.address, 'incorrect handshake, exepcted '+this.clientHandshake[0]+' but recvd '+handshake);

                //Added for Debugging
                console.log("Last data:",this.lastData);
                console.log("Current data:", textDecoder.decode(data));
                //End Added for Debugging

                this.deviceErrored();
                return;
            }
            this.clientHandshake[0]++;
            
            this.lastData=textDecoder.decode(data);//Added for debugging
            this.sendPacket("count: "+this.sendCount);//Added for debugging
        }
    }

    onData = (buffer) => {    
        for (let i=0;i<buffer.length;i++){
            const byte=buffer[i];
            if (this.netStatus===NETSTATUS.OPENED && this.packetState===PACKETSTATE.NAMELEN){
                this.nameLength=byte;
                this.name="";
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
                        this.deviceErrored();
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
                    console.log(this.name, this.socket.address, 'device sent packet larger than 0x0FFFFF');
                    this.deviceErrored();
                    return;
                }

                this.payload = Buffer.alloc(this.payloadLength);
                this.payloadWriteIndex=0;

            }else if (this.packetState===PACKETSTATE.PAYLOAD){
                const howFar = Math.min(this.payloadLength, buffer.length-i);
                buffer.copy(this.payload, this.payloadWriteIndex, i, howFar+i);
                this.payloadWriteIndex+=howFar;
                if (this.payloadWriteIndex>=this.payloadLength){
                    //Process complete packet here
                    try{
                        const {data: decrypted, handshake: recvdHandshake} = decrypt(this.payload, this.key);
                        this.onFullPacket(recvdHandshake, decrypted);
                        this.packetState=PACKETSTATE.LEN1;
                    }catch(e){
                        console.log('name',this.name, this.socket.address, 'failed to decrypt packet');
                        this.deviceErrored();
                        return;
                    }
                }
                i+=howFar-1;
            }else{
                console.log('name',this.name, this.socket.address, 'unknown packet/net status', this.packetState+'/'+this.netStatus);
                this.deviceErrored();
                return;
            }
        }
    }
}

function onDeviceDone(device){
    const devicesOriginalLength=devices.length;
    devices=devices.filter( (v) => {
        return !(v===device);
    });
    if (devices.length!==devicesOriginalLength-1){
        console.log("onDeviceDone: was supposed to remove one device. Started with "+devicesOriginalLength+" but ended up with "+devices.length);
    }
}

function createDeviceServer(){
    if (server) return;
    
    server = new (require('net')).Server();

    server.on('connection', function(socket) {
        devices.push(new Device(socket, onDeviceDone));
    });

    return server;
}

createDeviceServer();

server.listen(devicePort, function() {
    console.log(`Device server listening on port ${devicePort}`);
});
