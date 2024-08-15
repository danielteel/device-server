const crypto = require('crypto');

function leftRotate32(num,  places){
    return ((num << places) | (num >>> (32 - places))) & 0xFFFFFFFF;
}
function rightRotate32(num,  places){
    return ((num >>> places) | (num << (32 - places))) & 0xFFFFFFFF;
}
function leftRotate8(num,  places){
    return ((num << places) | (num >>> (8 - places))) & 0xFF;
}

function frame(handshake, bytes){
    if (bytes!=null && !(bytes instanceof Uint8Array)){
        throw 'frame expects data to be Uint8Array';
    }
    if (bytes===null){
        bytes={length: 0};
    }
    if (bytes.length>0x0FFFF0){
        throw 'data needs to be less than 0x0FFFF0 bytes';
    }
    let paddingLength=4;
    const handshakeLength=4;
    const sizeLength=4;
    const modLength = (paddingLength+sizeLength+handshakeLength+bytes.length)%16
    if (modLength){
        paddingLength=16-modLength%16 + 4;
    }
    const framed = new Uint8Array(paddingLength+sizeLength+handshakeLength+bytes.length);
    const framedView=new DataView(framed.buffer);
    framedView.setUint32(0, bytes.length+handshakeLength, true);
    for (let i=0;i<paddingLength;i++){
        framed[sizeLength+i]=crypto.randomInt(255);
    }
    framedView.setUint32(sizeLength+paddingLength, handshake, true);
    if (bytes && bytes.length) framed.set(bytes, sizeLength+handshakeLength+paddingLength);
    return framed;
}

function encrypt(handshake, data, keyString){
    let key=[];
    if (typeof keyString==='string'){
        if (keyString.length!=64){
            throw "Invalid hex key length: "+keyString.length+". Needs to be 64.";
        }
        for (let i=0;i<keyString.length;i+=2){
            key[Math.floor(i/2)] = parseInt(keyString.substring(i, i+2), 16);
        }
    }else{
        if (keyString.length!=32){
            throw 'Invalid array key length:'+keyString.length+". Needs to be 32.";
        }
        key=keyString;
    }

    let buffer = frame(handshake, data);

    for (let k=0;k<key.length;k++){
        for (let i=0;i<buffer.length-7;i++){

            let b4=leftRotate32(buffer[i+0] | buffer[i+2]<<8 | buffer[i+4]<<16 | buffer[i+6]<<24, key[k]%31);
            buffer[i+0] = b4 & 0xFF;
            buffer[i+2] = b4>>8 & 0xFF;
            buffer[i+4] = b4>>16 & 0xFF;
            buffer[i+6] = b4>>24 & 0xFF;
            
            b4=leftRotate32(buffer[i+1] | buffer[i+3]<<8 | buffer[i+5]<<16 | buffer[i+7]<<24, key[k]%31);
            buffer[i+1] = b4 & 0xFF;
            buffer[i+3] = b4>>8 & 0xFF;
            buffer[i+5] = b4>>16 & 0xFF;
            buffer[i+7] = b4>>24 & 0xFF;

            buffer[i+0] ^= buffer[i+1];
            buffer[i+1] ^= buffer[i+2];
            buffer[i+2] ^= buffer[i+3];
            buffer[i+3] ^= buffer[i+4];
            buffer[i+4] ^= buffer[i+5];
            buffer[i+5] ^= buffer[i+6];
            buffer[i+6] ^= buffer[i+7];
            buffer[i+7] ^= buffer[i+0];

            buffer[i+0] ^= key[k];
            buffer[i+1] ^= leftRotate8(key[k], 0 + buffer[i+0]%2);
            buffer[i+2] ^= leftRotate8(key[k], 1 + buffer[i+1]%2);
            buffer[i+3] ^= leftRotate8(key[k], 2 + buffer[i+2]%2);
            buffer[i+4] ^= leftRotate8(key[k], 3 + buffer[i+3]%2);
            buffer[i+5] ^= leftRotate8(key[k], 4 + buffer[i+4]%2);
            buffer[i+6] ^= leftRotate8(key[k], 5 + buffer[i+5]%2);
            buffer[i+7] ^= leftRotate8(key[k], 6 + buffer[i+6]%2);
        }
    }
    return buffer;
}

function decrypt(data, keyString){    
    let key=[];
    if (typeof keyString==='string'){
        if (keyString.length!=64){
            throw "Invalid hex key length: "+keyString.length+". Needs to be 64.";
        }
        for (let i=0;i<keyString.length;i+=2){
            key[Math.floor(i/2)] = parseInt(keyString.substring(i, i+2), 16);
        }
    }else{
        if (keyString.length!=32){
            throw 'Invalid array key length:'+keyString.length+". Needs to be 32.";
        }
        key=keyString;
    }

    let buffer = new Uint8Array(data.length);
    buffer.set(data);

    for (let k=key.length-1;k>=0;k--){
        for (let i=data.length-8;i>=0;i-=1){
            buffer[i+7] ^= leftRotate8(key[k], 6 + buffer[i+6]%2);
            buffer[i+6] ^= leftRotate8(key[k], 5 + buffer[i+5]%2);
            buffer[i+5] ^= leftRotate8(key[k], 4 + buffer[i+4]%2);
            buffer[i+4] ^= leftRotate8(key[k], 3 + buffer[i+3]%2);
            buffer[i+3] ^= leftRotate8(key[k], 2 + buffer[i+2]%2);
            buffer[i+2] ^= leftRotate8(key[k], 1 + buffer[i+1]%2);
            buffer[i+1] ^= leftRotate8(key[k], 0 + buffer[i+0]%2);
            buffer[i+0] ^= key[k];

            buffer[i+7] ^= buffer[i+0];
            buffer[i+6] ^= buffer[i+7];
            buffer[i+5] ^= buffer[i+6];
            buffer[i+4] ^= buffer[i+5];
            buffer[i+3] ^= buffer[i+4];
            buffer[i+2] ^= buffer[i+3];
            buffer[i+1] ^= buffer[i+2];
            buffer[i+0] ^= buffer[i+1];
            
            let b4=rightRotate32(buffer[i+0] | buffer[i+2]<<8 | buffer[i+4]<<16 | buffer[i+6]<<24, key[k]%31);
            buffer[i+0] = b4 & 0xFF;
            buffer[i+2] = b4>>8 & 0xFF;
            buffer[i+4] = b4>>16 & 0xFF;
            buffer[i+6] = b4>>24 & 0xFF;

            b4=rightRotate32(buffer[i+1] | buffer[i+3]<<8 | buffer[i+5]<<16 | buffer[i+7]<<24, key[k]%31);
            buffer[i+1] = b4 & 0xFF;
            buffer[i+3] = b4>>8 & 0xFF;
            buffer[i+5] = b4>>16 & 0xFF;
            buffer[i+7] = b4>>24 & 0xFF;
        }
    }

    const bufferView = new DataView(buffer.buffer);
    const dataLength = bufferView.getUint32(0, true)-4;
    if (dataLength>0x0FFFF0 || dataLength>data.length-4){
        throw 'data length is bigger than it should be';
    }
    const handshake=bufferView.getUint32(buffer.length-dataLength-4, true);
    return {handshake, data: buffer.subarray(buffer.length-dataLength)};
}

module.exports={decrypt, encrypt};