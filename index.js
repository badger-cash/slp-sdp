import * as eccryptoJS from '@vinarmani/eccrypto-js'

const ipToBuffer = (ipString) => {
    const ipSplit = ipString.split('.')
    const ipBufArray = ipSplit.map(num => Buffer.alloc(1, parseInt(num)))
    return Buffer.concat(ipBufArray)
}

const bufferToIp = (ipBuf) => {
    const ipArr = [...ipBuf]
    return ipArr.join('.')
}

const encodeCandidate = (candidateString) => {
    const type = candidateString.includes('srflx') ? 1 : 2
    const bufArr = [Buffer.alloc(1, type)]
    const candidateSplit = candidateString.split(' ')
    const priorityBuf = Buffer.alloc(5)
    priorityBuf.writeUIntLE(candidateSplit[3], 0, 5)
    const addrBuf = ipToBuffer(candidateSplit[4])
    const portBuf = Buffer.alloc(2)
    portBuf.writeUInt16LE(parseInt(candidateSplit[5]))
    bufArr.push(priorityBuf, addrBuf, portBuf)
    if (type === 1) {
        const raddrBuf = ipToBuffer(candidateSplit[9])
        const rportBuf = Buffer.alloc(2)
        rportBuf.writeUInt16LE(parseInt(candidateSplit[11]))
        bufArr.push(raddrBuf, rportBuf)
    }

    return Buffer.concat(bufArr)
}

const decodeCandidate = (encodedCandidate) => {
    let candidateString = '1 1 UDP '
    let offset = 0
    const type = encodedCandidate.readUint8(offset) === 1 ? 'srflx' : 'host'
    offset += 1
    const priority = encodedCandidate.readUintLE(offset, 5)
    offset += 5
    const addr = bufferToIp(encodedCandidate.subarray(offset, offset + 4))
    offset += 4
    const port = encodedCandidate.readUint16LE(offset)
    candidateString += `${priority} ${addr} ${port} typ ${type}`
    if (type === 'srflx') {
        offset += 2
        const raddr = bufferToIp(encodedCandidate.subarray(offset, offset + 4))
        offset += 4
        const rport = encodedCandidate.readUint16LE(offset)
        candidateString += ` raddr ${raddr} rport ${rport}`
    }

    return candidateString
}

const encodeSdp = (sdp) => {
    const encObj = {}
    const sdpSplit = sdp.split('\r\n')
    for (let i = 0; i < sdpSplit.length; i++) {
        const line = sdpSplit[i]
        const [key, val] = line.split(line.includes('m=application') ? / (.*)/s : /:(.*)/s)
        encObj[key] = val
    }

    let setupBuf = Buffer.alloc(1) // active, 1
    switch (encObj['a=setup']) {
        case 'active':
            setupBuf.writeUint8(1)
            break;
        case 'passive':
            setupBuf.writeUint8(2)
            break;
        case 'actpass':
            setupBuf.writeUint8(3)
            break;
        default:
            break
    }

    const ufragBuf = Buffer.from(encObj['a=ice-ufrag'], 'ascii')
    
    const pwdBuf = Buffer.from(encObj['a=ice-pwd'], 'ascii')

    const [, fullFingerprint] = encObj['a=fingerprint'].split(' ')
    const fingerprint = fullFingerprint.replaceAll(':', '')
    const fingerprintBuf = Buffer.from(fingerprint, 'hex')

    const candidateBuf = encodeCandidate(encObj['a=candidate'])

    const encArr = [
        setupBuf,
        ufragBuf,
        pwdBuf,
        fingerprintBuf,
        candidateBuf
    ]

    const encodedSdp = Buffer.concat(encArr)
    return encodedSdp
}

const decimalToHex = (d, padding) => {
    var hex = Number(d).toString(16);
    padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

    while (hex.length < padding) {
        hex = "0" + hex;
    }

    return hex;
}

const decodeSdp = (encodedSdp) => {
    let offset = 0
    let sdp = 'a=setup:'
    switch (encodedSdp.readUint8(offset)) {
        case 1:
            sdp += 'active'
            break;
        case 2:
            sdp += 'passive'
            break;
        case 3:
            sdp += 'actpass'
            break;
        default:
            break
    }
    
    sdp += '\r\na=ice-ufrag:'
    offset += 1
    sdp += encodedSdp.subarray(offset, offset + 4).toString('ascii')
    offset += 4

    sdp += '\r\na=ice-pwd:'
    sdp += encodedSdp.subarray(offset, offset + 22).toString('ascii')
    offset += 22

    sdp += '\r\na=fingerprint:sha-256 '
    const fingerprintBuf = encodedSdp.subarray(offset, offset + 32)
    const fingerprintArr = [...fingerprintBuf].map(num => decimalToHex(num).toUpperCase())
    sdp += fingerprintArr.join(':')
    offset += 32

    sdp += '\r\nm=application '
    const applicationInt = encodedSdp.readUint32LE(offset + 10)
    sdp += applicationInt + ' UDP/DTLS/SCTP webrtc-datachannel'

    sdp += '\r\na=candidate:'
    const encodedCandidate = encodedSdp.subarray(offset)
    sdp += decodeCandidate(encodedCandidate) + '\r\n'

    return sdp

}

const invalidIpStrings = [
    '127.0.0.1',
    '192.168',
    '169.254',
    '::'
]

const extraSdp = [
    'o=',
    'c=',
    's=',
    'v=',
    't=',
    'a=group',
    'a=msid',
    'a=ice-options',
    'a=mid',
    'a=sendrecv',
    'a=sctp-port',
    'a=max-message-size'
]

const isRemoteIpCandidate = (candidateLine) => {
    const lineSplit = candidateLine.split(' ')
    if (lineSplit[2].toUpperCase() !== 'UDP')
        return false
    // if (invalidIpStrings.some(sub => lineSplit[4].includes(sub)))
    //     return false
    if (lineSplit[7].toUpperCase() !== 'SRFLX')
        return false
    return true
}

// Only use remote candidate
const filterSdp = (sdp) => {
    const sdpSplit = sdp.split('\r\n')
    const filteredSplitSdp = []
    for (let i = 0; i < sdpSplit.length; i++) {
        const line = sdpSplit[i]
        if (extraSdp.some(prop => line.includes(prop)))
            continue
        // Only include remote candidates
        if (line.includes('a=candidate') && !isRemoteIpCandidate(line))
            continue

        filteredSplitSdp.push(line)
        // leave after the first remote candidate
        if (line.includes('a=candidate') && isRemoteIpCandidate(line))
            break
    }
    const filteredSdp = filteredSplitSdp.join('\r\n')
    return filteredSdp
}

const convertToEncryptStruct = (encbuf) => {
    let offset = 0;
    let tagLength = 32;
    let pub;
    switch(encbuf[0]) {
      case 4:
        pub = encbuf.slice(0, 65);
        break;
      case 3:
      case 2:
        pub = encbuf.slice(0, 33);
        break;
      default:
        throw new Error('Invalid type: ' + encbuf[0]);
    }
      offset += pub.length;
  
    let c = encbuf.slice(offset, encbuf.length - tagLength);
    let ivbuf = c.slice(0, 128 / 8);
    let ctbuf = c.slice(128 / 8);
  
    let d = encbuf.slice(encbuf.length - tagLength, encbuf.length);

    return {
        iv: ivbuf,
        ephemPublicKey: pub,
        ciphertext: ctbuf,
        mac: d
    }
}

const encryptSdp = (sdp, publicKey) => {
    const filteredSdp = filterSdp(sdp)
    const encodedSdp = encodeSdp(filteredSdp)
    const structuredEj = eccryptoJS.encryptSync(publicKey, encodedSdp)
    return Buffer.concat([structuredEj.ephemPublicKey, structuredEj.iv, structuredEj.ciphertext, structuredEj.mac])
}

const decryptSdp = (encryptedSdpBuf, privateKey) => {
    const encodedSdp = eccryptoJS.decryptSync(privateKey, convertToEncryptStruct(encryptedSdpBuf))
    return decodeSdp(encodedSdp)
}

export {
    filterSdp,
    isRemoteIpCandidate,
    encodeSdp,
    decodeSdp,
    encodeCandidate,
    decodeCandidate,
    encryptSdp,
    decryptSdp
}
