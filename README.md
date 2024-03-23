# slp-sdp

Encode and encrypt SDP data according to the Simple Ledger Session Description Protocol (SLSDP)

## Installation

###  npm
```shell
npm install slp-sdp
```

###  yarn
```shell
yarn install slp-sdp
```

### git

```shell
git clone https://github.com/badger-cash/slp-sdp.git
```
  
## Usage

```js
import * as slpsdp from "slp-sdp";

const sdp = 'v=0\r\n' +
'o=rtc 1074756789 0 IN IP4 127.0.0.1\r\n' +
's=-\r\n' +
't=0 0\r\n' +
'a=group:BUNDLE 0\r\n' +
'a=msid-semantic:WMS *\r\n' +
'a=setup:active\r\n' +
'a=ice-ufrag:7hJ1\r\n' +
'a=ice-pwd:SYJg4xHfZHfWHHjCMmXIZQ\r\n' +
'a=ice-options:ice2,trickle\r\n' +
'a=fingerprint:sha-256 09:5B:9D:35:59:A7:1E:87:24:FF:6B:68:D3:87:E0:B6:C4:B8:4E:CD:0F:5F:76:D3:AA:8E:38:CC:A6:92:DD:D6\r\n' +
'm=application 59405 UDP/DTLS/SCTP webrtc-datachannel\r\n' +
'c=IN IP4 192.168.1.119\r\n' +
'a=mid:0\r\n' +
'a=sendrecv\r\n' +
'a=sctp-port:5000\r\n' +
'a=max-message-size:262144\r\n' +
'a=candidate:1 1 UDP 2122317823 192.168.1.119 59405 typ host\r\n' +
'a=candidate:2 1 UDP 1686109951 176.99.247.125 59405 typ srflx raddr 0.0.0.0 rport 0\r\n' +
'a=end-of-candidates\r\n'

const privateKey = Buffer.from('0551c74103024b39b51f461a55d355d558b147cbfffcc7ae24c3f88ca25d826a', 'hex')
const publicKey = Buffer.from('0399539c7356d73a9d2e4e37f8f72539e60489f6a4753ffad3f6bf357e01ca47f9', 'hex')

const encryptedSdp = slpsdp.encryptSdp(sdp, publicKey)
const encryptedHex = encryptedSdp.toString('hex')
const decryptedSdp = slpsdp.decryptSdp(encryptedSdp, privateKey)
```

### Produces

```js
{
  sdp: 'v=0\r\n' +
    'o=rtc 1074756789 0 IN IP4 127.0.0.1\r\n' +
    's=-\r\n' +
    't=0 0\r\n' +
    'a=group:BUNDLE 0\r\n' +
    'a=msid-semantic:WMS *\r\n' +
    'a=setup:active\r\n' +
    'a=ice-ufrag:7hJ1\r\n' +
    'a=ice-pwd:SYJg4xHfZHfWHHjCMmXIZQ\r\n' +
    'a=ice-options:ice2,trickle\r\n' +
    'a=fingerprint:sha-256 09:5B:9D:35:59:A7:1E:87:24:FF:6B:68:D3:87:E0:B6:C4:B8:4E:CD:0F:5F:76:D3:AA:8E:38:CC:A6:92:DD:D6\r\n' +
    'm=application 59405 UDP/DTLS/SCTP webrtc-datachannel\r\n' +
    'c=IN IP4 192.168.1.119\r\n' +
    'a=mid:0\r\n' +
    'a=sendrecv\r\n' +
    'a=sctp-port:5000\r\n' +
    'a=max-message-size:262144\r\n' +
    'a=candidate:1 1 UDP 2122317823 192.168.1.119 59405 typ host\r\n' +
    'a=candidate:2 1 UDP 1686109951 176.99.247.125 59405 typ srflx raddr 0.0.0.0 rport 0\r\n' +
    'a=end-of-candidates\r\n',
  encrypted: '043345aa19d896182fb39b8722f751b560241f9cf295306b7100578147a2263664abf7eb6d1f3cc2f70f5cd62d54c50df1d97460af6fd11c0739a400792f4c6ae2c70926b5cd8bd1f160a9216488c6df8b699f9538de62bf352797078cd256722c9d29837f38c440dd00f4cb890f9e4e99d24ec23fedd9604e124d86f0322a03b40b1872c3fda9d94d599d123d12a514dd7939bff3b3f598e2a717f0653f40e3751ce503887da01b12d65eb09edb2a63b87fe94f4243d9f324365bfe14dda4db3fb24b20c62a9e39a786fd2642503b9595',
  encryptedLength: 209,
  decrypted: 'a=setup:active\r\n' +
    'a=ice-ufrag:7hJ1\r\n' +
    'a=ice-pwd:SYJg4xHfZHfWHHjCMmXIZQ\r\n' +
    'a=fingerprint:sha-256 09:5B:9D:35:59:A7:1E:87:24:FF:6B:68:D3:87:E0:B6:C4:B8:4E:CD:0F:5F:76:D3:AA:8E:38:CC:A6:92:DD:D6\r\n' +
    'm=application 59405 UDP/DTLS/SCTP webrtc-datachannel\r\n' +
    'a=candidate:1 1 UDP 1686109951 176.99.247.125 59405 typ srflx raddr 0.0.0.0 rport 0\r\n'
}
```


### License

This software is licensed under the MIT License.

Copyright Badger, 2024.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
