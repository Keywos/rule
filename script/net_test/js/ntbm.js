// @timestamp thenkey 2024-03-03 00:10:25
(()=>{
    var t=typeof globalThis<"u"?globalThis:typeof window<"u"?window:typeof global<"u"?global:typeof self<"u"?self:{};var e,r={exports:{}},n=function(t){if(t.__esModule)return t;var e=t.default;if("function"==typeof e){var r=function t(){return this instanceof t?Reflect.construct(e,arguments,this.constructor):e.apply(this,arguments)};r.prototype=e.prototype}else r={};return Object.defineProperty(r,"__esModule",{value:!0}),Object.keys(t).forEach((function(e){var n=Object.getOwnPropertyDescriptor(t,e);Object.defineProperty(r,e,n.get?n:{enumerable:!0,get:function(){return t[e]}})})),r}(Object.freeze(Object.defineProperty({__proto__:null,default:{}},Symbol.toStringTag,{value:"Module"})));function i(){return e||(e=1,r.exports=(i=i||function(e,r){var i;if(typeof window<"u"&&window.crypto&&(i=window.crypto),typeof self<"u"&&self.crypto&&(i=self.crypto),typeof globalThis<"u"&&globalThis.crypto&&(i=globalThis.crypto),!i&&typeof window<"u"&&window.msCrypto&&(i=window.msCrypto),!i&&void 0!==t&&t.crypto&&(i=t.crypto),!i)try{i=n}catch{}var o=function(){if(i){if("function"==typeof i.getRandomValues)try{return i.getRandomValues(new Uint32Array(1))[0]}catch{}if("function"==typeof i.randomBytes)try{return i.randomBytes(4).readInt32LE()}catch{}}throw new Error("Native crypto module could not be used to get secure random number.")},s=Object.create||function(){function t(){}return function(e){var r;return t.prototype=e,r=new t,t.prototype=null,r}}(),a={},c=a.lib={},f=c.Base={extend:function(t){var e=s(this);return t&&e.mixIn(t),e.hasOwnProperty("init")&&this.init!==e.init||(e.init=function(){e.$super.init.apply(this,arguments)}),e.init.prototype=e,e.$super=this,e},create:function(){var t=this.extend();return t.init.apply(t,arguments),t},init:function(){},mixIn:function(t){for(var e in t)t.hasOwnProperty(e)&&(this[e]=t[e]);t.hasOwnProperty("toString")&&(this.toString=t.toString)},clone:function(){return this.init.prototype.extend(this)}},u=c.WordArray=f.extend({init:function(t,e){t=this.words=t||[],this.sigBytes=null!=e?e:4*t.length},toString:function(t){return(t||p).stringify(this)},concat:function(t){var e=this.words,r=t.words,n=this.sigBytes,i=t.sigBytes;if(this.clamp(),n%4)for(var o=0;o<i;o++){var s=r[o>>>2]>>>24-o%4*8&255;e[n+o>>>2]|=s<<24-(n+o)%4*8}else for(var a=0;a<i;a+=4)e[n+a>>>2]=r[a>>>2];return this.sigBytes+=i,this},clamp:function(){var t=this.words,r=this.sigBytes;t[r>>>2]&=4294967295<<32-r%4*8,t.length=e.ceil(r/4)},clone:function(){var t=f.clone.call(this);return t.words=this.words.slice(0),t},random:function(t){for(var e=[],r=0;r<t;r+=4)e.push(o());return new u.init(e,t)}}),h=a.enc={},p=h.Hex={stringify:function(t){for(var e=t.words,r=t.sigBytes,n=[],i=0;i<r;i++){var o=e[i>>>2]>>>24-i%4*8&255;n.push((o>>>4).toString(16)),n.push((15&o).toString(16))}return n.join("")},parse:function(t){for(var e=t.length,r=[],n=0;n<e;n+=2)r[n>>>3]|=parseInt(t.substr(n,2),16)<<24-n%8*4;return new u.init(r,e/2)}},l=h.Latin1={stringify:function(t){for(var e=t.words,r=t.sigBytes,n=[],i=0;i<r;i++){var o=e[i>>>2]>>>24-i%4*8&255;n.push(String.fromCharCode(o))}return n.join("")},parse:function(t){for(var e=t.length,r=[],n=0;n<e;n++)r[n>>>2]|=(255&t.charCodeAt(n))<<24-n%4*8;return new u.init(r,e)}},d=h.Utf8={stringify:function(t){try{return decodeURIComponent(escape(l.stringify(t)))}catch{throw new Error("Malformed UTF-8 data")}},parse:function(t){return l.parse(unescape(encodeURIComponent(t)))}},y=c.BufferedBlockAlgorithm=f.extend({reset:function(){this._data=new u.init,this._nDataBytes=0},_append:function(t){"string"==typeof t&&(t=d.parse(t)),this._data.concat(t),this._nDataBytes+=t.sigBytes},_process:function(t){var r,n=this._data,i=n.words,o=n.sigBytes,s=this.blockSize,a=o/(4*s),c=(a=t?e.ceil(a):e.max((0|a)-this._minBufferSize,0))*s,f=e.min(4*c,o);if(c){for(var h=0;h<c;h+=s)this._doProcessBlock(i,h);r=i.splice(0,c),n.sigBytes-=f}return new u.init(r,f)},clone:function(){var t=f.clone.call(this);return t._data=this._data.clone(),t},_minBufferSize:0});c.Hasher=y.extend({cfg:f.extend(),init:function(t){this.cfg=this.cfg.extend(t),this.reset()},reset:function(){y.reset.call(this),this._doReset()},update:function(t){return this._append(t),this._process(),this},finalize:function(t){return t&&this._append(t),this._doFinalize()},blockSize:16,_createHelper:function(t){return function(e,r){return new t.init(r).finalize(e)}},_createHmacHelper:function(t){return function(e,r){return new v.HMAC.init(t,r).finalize(e)}}});var v=a.algo={};return a}(Math),i)),r.exports;var i}var o,s={exports:{}};var a,c={exports:{}},f={exports:{}},u={exports:{}};var h,p,l,d,y={exports:{}};function v(){return p||(p=1,f.exports=(t=i(),function(){return a||(a=1,u.exports=(e=(t=f=i()).lib,r=e.WordArray,n=e.Hasher,o=t.algo,s=[],c=o.SHA1=n.extend({_doReset:function(){this._hash=new r.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(t,e){for(var r=this._hash.words,n=r[0],i=r[1],o=r[2],a=r[3],c=r[4],f=0;f<80;f++){if(f<16)s[f]=0|t[e+f];else{var u=s[f-3]^s[f-8]^s[f-14]^s[f-16];s[f]=u<<1|u>>>31}var h=(n<<5|n>>>27)+c+s[f];h+=f<20?1518500249+(i&o|~i&a):f<40?1859775393+(i^o^a):f<60?(i&o|i&a|o&a)-1894007588:(i^o^a)-899497514,c=a,a=o,o=i<<30|i>>>2,i=n,n=h}r[0]=r[0]+n|0,r[1]=r[1]+i|0,r[2]=r[2]+o|0,r[3]=r[3]+a|0,r[4]=r[4]+c|0},_doFinalize:function(){var t=this._data,e=t.words,r=8*this._nDataBytes,n=8*t.sigBytes;return e[n>>>5]|=128<<24-n%32,e[14+(n+64>>>9<<4)]=Math.floor(r/4294967296),e[15+(n+64>>>9<<4)]=r,t.sigBytes=4*e.length,this._process(),this._hash},clone:function(){var t=n.clone.call(this);return t._hash=this._hash.clone(),t}}),t.SHA1=n._createHelper(c),t.HmacSHA1=n._createHmacHelper(c),f.SHA1)),u.exports;var t,e,r,n,o,s,c,f}(),h||(h=1,y.exports=(v=(d=i()).lib.Base,_=d.enc.Utf8,void(d.algo.HMAC=v.extend({init:function(t,e){t=this._hasher=new t.init,"string"==typeof e&&(e=_.parse(e));var r=t.blockSize,n=4*r;e.sigBytes>n&&(e=t.finalize(e)),e.clamp();for(var i=this._oKey=e.clone(),o=this._iKey=e.clone(),s=i.words,a=o.words,c=0;c<r;c++)s[c]^=1549556828,a[c]^=909522486;i.sigBytes=o.sigBytes=n,this.reset()},reset:function(){var t=this._hasher;t.reset(),t.update(this._iKey)},update:function(t){return this._hasher.update(t),this},finalize:function(t){var e=this._hasher,r=e.finalize(t);return e.reset(),e.finalize(this._oKey.clone().concat(r))}})))),y.exports,r=(e=t).lib,n=r.Base,o=r.WordArray,s=e.algo,c=s.MD5,l=s.EvpKDF=n.extend({cfg:n.extend({keySize:4,hasher:c,iterations:1}),init:function(t){this.cfg=this.cfg.extend(t)},compute:function(t,e){for(var r,n=this.cfg,i=n.hasher.create(),s=o.create(),a=s.words,c=n.keySize,f=n.iterations;a.length<c;){r&&i.update(r),r=i.update(t).finalize(e),i.reset();for(var u=1;u<f;u++)r=i.finalize(r),i.reset();s.concat(r)}return s.sigBytes=4*c,s}}),e.EvpKDF=function(t,e,r){return l.create(r).compute(t,e)},t.EvpKDF)),f.exports;var t,e,r,n,o,s,c,l,d,v,_}function _(){return l||(l=1,c.exports=(t=i(),v(),void(t.lib.Cipher||function(e){var r=t,n=r.lib,i=n.Base,o=n.WordArray,s=n.BufferedBlockAlgorithm,a=r.enc;a.Utf8;var c=a.Base64,f=r.algo.EvpKDF,u=n.Cipher=s.extend({cfg:i.extend(),createEncryptor:function(t,e){return this.create(this._ENC_XFORM_MODE,t,e)},createDecryptor:function(t,e){return this.create(this._DEC_XFORM_MODE,t,e)},init:function(t,e,r){this.cfg=this.cfg.extend(r),this._xformMode=t,this._key=e,this.reset()},reset:function(){s.reset.call(this),this._doReset()},process:function(t){return this._append(t),this._process()},finalize:function(t){return t&&this._append(t),this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(){function t(t){return"string"==typeof t?m:_}return function(e){return{encrypt:function(r,n,i){return t(n).encrypt(e,r,n,i)},decrypt:function(r,n,i){return t(n).decrypt(e,r,n,i)}}}}()});n.StreamCipher=u.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var h=r.mode={},p=n.BlockCipherMode=i.extend({createEncryptor:function(t,e){return this.Encryptor.create(t,e)},createDecryptor:function(t,e){return this.Decryptor.create(t,e)},init:function(t,e){this._cipher=t,this._iv=e}}),l=h.CBC=function(){var t=p.extend();function e(t,e,r){var n,i=this._iv;i?(n=i,this._iv=undefined):n=this._prevBlock;for(var o=0;o<r;o++)t[e+o]^=n[o]}return t.Encryptor=t.extend({processBlock:function(t,r){var n=this._cipher,i=n.blockSize;e.call(this,t,r,i),n.encryptBlock(t,r),this._prevBlock=t.slice(r,r+i)}}),t.Decryptor=t.extend({processBlock:function(t,r){var n=this._cipher,i=n.blockSize,o=t.slice(r,r+i);n.decryptBlock(t,r),e.call(this,t,r,i),this._prevBlock=o}}),t}(),d=(r.pad={}).Pkcs7={pad:function(t,e){for(var r=4*e,n=r-t.sigBytes%r,i=n<<24|n<<16|n<<8|n,s=[],a=0;a<n;a+=4)s.push(i);var c=o.create(s,n);t.concat(c)},unpad:function(t){var e=255&t.words[t.sigBytes-1>>>2];t.sigBytes-=e}};n.BlockCipher=u.extend({cfg:u.cfg.extend({mode:l,padding:d}),reset:function(){var t;u.reset.call(this);var e=this.cfg,r=e.iv,n=e.mode;this._xformMode==this._ENC_XFORM_MODE?t=n.createEncryptor:(t=n.createDecryptor,this._minBufferSize=1),this._mode&&this._mode.__creator==t?this._mode.init(this,r&&r.words):(this._mode=t.call(n,this,r&&r.words),this._mode.__creator=t)},_doProcessBlock:function(t,e){this._mode.processBlock(t,e)},_doFinalize:function(){var t,e=this.cfg.padding;return this._xformMode==this._ENC_XFORM_MODE?(e.pad(this._data,this.blockSize),t=this._process(!0)):(t=this._process(!0),e.unpad(t)),t},blockSize:4});var y=n.CipherParams=i.extend({init:function(t){this.mixIn(t)},toString:function(t){return(t||this.formatter).stringify(this)}}),v=(r.format={}).OpenSSL={stringify:function(t){var e=t.ciphertext,r=t.salt;return(r?o.create([1398893684,1701076831]).concat(r).concat(e):e).toString(c)},parse:function(t){var e,r=c.parse(t),n=r.words;return 1398893684==n[0]&&1701076831==n[1]&&(e=o.create(n.slice(2,4)),n.splice(0,4),r.sigBytes-=16),y.create({ciphertext:r,salt:e})}},_=n.SerializableCipher=i.extend({cfg:i.extend({format:v}),encrypt:function(t,e,r,n){n=this.cfg.extend(n);var i=t.createEncryptor(r,n),o=i.finalize(e),s=i.cfg;return y.create({ciphertext:o,key:r,iv:s.iv,algorithm:t,mode:s.mode,padding:s.padding,blockSize:t.blockSize,formatter:n.format})},decrypt:function(t,e,r,n){return n=this.cfg.extend(n),e=this._parse(e,n.format),t.createDecryptor(r,n).finalize(e.ciphertext)},_parse:function(t,e){return"string"==typeof t?e.parse(t,this):t}}),g=(r.kdf={}).OpenSSL={execute:function(t,e,r,n,i){if(n||(n=o.random(8)),i)s=f.create({keySize:e+r,hasher:i}).compute(t,n);else var s=f.create({keySize:e+r}).compute(t,n);var a=o.create(s.words.slice(e),4*r);return s.sigBytes=4*e,y.create({key:s,iv:a,salt:n})}},m=n.PasswordBasedCipher=_.extend({cfg:_.cfg.extend({kdf:g}),encrypt:function(t,e,r,n){var i=(n=this.cfg.extend(n)).kdf.execute(r,t.keySize,t.ivSize,n.salt,n.hasher);n.iv=i.iv;var o=_.encrypt.call(this,t,e,i.key,n);return o.mixIn(i),o},decrypt:function(t,e,r,n){n=this.cfg.extend(n),e=this._parse(e,n.format);var i=n.kdf.execute(r,t.keySize,t.ivSize,e.salt,n.hasher);return n.iv=i.iv,_.decrypt.call(this,t,e,i.key,n)}})}()))),c.exports;var t}var g,m={exports:{}},x={exports:{}};function B(){return g||(g=1,x.exports=(r=i(),e=(t=r).lib.WordArray,t.enc.Base64={stringify:function(t){var e=t.words,r=t.sigBytes,n=this._map;t.clamp();for(var i=[],o=0;o<r;o+=3)for(var s=(e[o>>>2]>>>24-o%4*8&255)<<16|(e[o+1>>>2]>>>24-(o+1)%4*8&255)<<8|e[o+2>>>2]>>>24-(o+2)%4*8&255,a=0;a<4&&o+.75*a<r;a++)i.push(n.charAt(s>>>6*(3-a)&63));var c=n.charAt(64);if(c)for(;i.length%4;)i.push(c);return i.join("")},parse:function(t){var r=t.length,n=this._map,i=this._reverseMap;if(!i){i=this._reverseMap=[];for(var o=0;o<n.length;o++)i[n.charCodeAt(o)]=o}var s=n.charAt(64);if(s){var a=t.indexOf(s);-1!==a&&(r=a)}return function(t,r,n){for(var i=[],o=0,s=0;s<r;s++)if(s%4){var a=n[t.charCodeAt(s-1)]<<s%4*2|n[t.charCodeAt(s)]>>>6-s%4*2;i[o>>>2]|=a<<24-o%4*8,o++}return e.create(i,o)}(t,r,i)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="},r.enc.Base64)),x.exports;var t,e,r}var w,k,S,b,A={exports:{}};var E,z=function(t){return t&&t.__esModule&&Object.prototype.hasOwnProperty.call(t,"default")?t.default:t}({exports:{}}.exports=function(t){return t}(i(),(o||(o=1,s.exports=(E=i(),function(){if("function"==typeof ArrayBuffer){var t=E.lib.WordArray,e=t.init,r=t.init=function(t){if(t instanceof ArrayBuffer&&(t=new Uint8Array(t)),(t instanceof Int8Array||typeof Uint8ClampedArray<"u"&&t instanceof Uint8ClampedArray||t instanceof Int16Array||t instanceof Uint16Array||t instanceof Int32Array||t instanceof Uint32Array||t instanceof Float32Array||t instanceof Float64Array)&&(t=new Uint8Array(t.buffer,t.byteOffset,t.byteLength)),t instanceof Uint8Array){for(var r=t.byteLength,n=[],i=0;i<r;i++)n[i>>>2]|=t[i]<<24-i%4*8;e.call(this,n,r)}else e.apply(this,arguments)};r.prototype=t}}(),E.lib.WordArray)),s.exports),d||(d=1,b=i(),_(),b.mode.ECB=((S=b.lib.BlockCipherMode.extend()).Encryptor=S.extend({processBlock:function(t,e){this._cipher.encryptBlock(t,e)}}),S.Decryptor=S.extend({processBlock:function(t,e){this._cipher.decryptBlock(t,e)}}),S),b.mode.ECB),function(){return k?m.exports:(k=1,m.exports=(t=i(),B(),function(){return w||(w=1,A.exports=(t=i(),function(e){var r=t,n=r.lib,i=n.WordArray,o=n.Hasher,s=r.algo,a=[];!function(){for(var t=0;t<64;t++)a[t]=4294967296*e.abs(e.sin(t+1))|0}();var c=s.MD5=o.extend({_doReset:function(){this._hash=new i.init([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(t,e){for(var r=0;r<16;r++){var n=e+r,i=t[n];t[n]=16711935&(i<<8|i>>>24)|4278255360&(i<<24|i>>>8)}var o=this._hash.words,s=t[e+0],c=t[e+1],l=t[e+2],d=t[e+3],y=t[e+4],v=t[e+5],_=t[e+6],g=t[e+7],m=t[e+8],x=t[e+9],B=t[e+10],w=t[e+11],k=t[e+12],S=t[e+13],b=t[e+14],A=t[e+15],E=o[0],z=o[1],C=o[2],O=o[3];E=f(E,z,C,O,s,7,a[0]),O=f(O,E,z,C,c,12,a[1]),C=f(C,O,E,z,l,17,a[2]),z=f(z,C,O,E,d,22,a[3]),E=f(E,z,C,O,y,7,a[4]),O=f(O,E,z,C,v,12,a[5]),C=f(C,O,E,z,_,17,a[6]),z=f(z,C,O,E,g,22,a[7]),E=f(E,z,C,O,m,7,a[8]),O=f(O,E,z,C,x,12,a[9]),C=f(C,O,E,z,B,17,a[10]),z=f(z,C,O,E,w,22,a[11]),E=f(E,z,C,O,k,7,a[12]),O=f(O,E,z,C,S,12,a[13]),C=f(C,O,E,z,b,17,a[14]),E=u(E,z=f(z,C,O,E,A,22,a[15]),C,O,c,5,a[16]),O=u(O,E,z,C,_,9,a[17]),C=u(C,O,E,z,w,14,a[18]),z=u(z,C,O,E,s,20,a[19]),E=u(E,z,C,O,v,5,a[20]),O=u(O,E,z,C,B,9,a[21]),C=u(C,O,E,z,A,14,a[22]),z=u(z,C,O,E,y,20,a[23]),E=u(E,z,C,O,x,5,a[24]),O=u(O,E,z,C,b,9,a[25]),C=u(C,O,E,z,d,14,a[26]),z=u(z,C,O,E,m,20,a[27]),E=u(E,z,C,O,S,5,a[28]),O=u(O,E,z,C,l,9,a[29]),C=u(C,O,E,z,g,14,a[30]),E=h(E,z=u(z,C,O,E,k,20,a[31]),C,O,v,4,a[32]),O=h(O,E,z,C,m,11,a[33]),C=h(C,O,E,z,w,16,a[34]),z=h(z,C,O,E,b,23,a[35]),E=h(E,z,C,O,c,4,a[36]),O=h(O,E,z,C,y,11,a[37]),C=h(C,O,E,z,g,16,a[38]),z=h(z,C,O,E,B,23,a[39]),E=h(E,z,C,O,S,4,a[40]),O=h(O,E,z,C,s,11,a[41]),C=h(C,O,E,z,d,16,a[42]),z=h(z,C,O,E,_,23,a[43]),E=h(E,z,C,O,x,4,a[44]),O=h(O,E,z,C,k,11,a[45]),C=h(C,O,E,z,A,16,a[46]),E=p(E,z=h(z,C,O,E,l,23,a[47]),C,O,s,6,a[48]),O=p(O,E,z,C,g,10,a[49]),C=p(C,O,E,z,b,15,a[50]),z=p(z,C,O,E,v,21,a[51]),E=p(E,z,C,O,k,6,a[52]),O=p(O,E,z,C,d,10,a[53]),C=p(C,O,E,z,B,15,a[54]),z=p(z,C,O,E,c,21,a[55]),E=p(E,z,C,O,m,6,a[56]),O=p(O,E,z,C,A,10,a[57]),C=p(C,O,E,z,_,15,a[58]),z=p(z,C,O,E,S,21,a[59]),E=p(E,z,C,O,y,6,a[60]),O=p(O,E,z,C,w,10,a[61]),C=p(C,O,E,z,l,15,a[62]),z=p(z,C,O,E,x,21,a[63]),o[0]=o[0]+E|0,o[1]=o[1]+z|0,o[2]=o[2]+C|0,o[3]=o[3]+O|0},_doFinalize:function(){var t=this._data,r=t.words,n=8*this._nDataBytes,i=8*t.sigBytes;r[i>>>5]|=128<<24-i%32;var o=e.floor(n/4294967296),s=n;r[15+(i+64>>>9<<4)]=16711935&(o<<8|o>>>24)|4278255360&(o<<24|o>>>8),r[14+(i+64>>>9<<4)]=16711935&(s<<8|s>>>24)|4278255360&(s<<24|s>>>8),t.sigBytes=4*(r.length+1),this._process();for(var a=this._hash,c=a.words,f=0;f<4;f++){var u=c[f];c[f]=16711935&(u<<8|u>>>24)|4278255360&(u<<24|u>>>8)}return a},clone:function(){var t=o.clone.call(this);return t._hash=this._hash.clone(),t}});function f(t,e,r,n,i,o,s){var a=t+(e&r|~e&n)+i+s;return(a<<o|a>>>32-o)+e}function u(t,e,r,n,i,o,s){var a=t+(e&n|r&~n)+i+s;return(a<<o|a>>>32-o)+e}function h(t,e,r,n,i,o,s){var a=t+(e^r^n)+i+s;return(a<<o|a>>>32-o)+e}function p(t,e,r,n,i,o,s){var a=t+(r^(e|~n))+i+s;return(a<<o|a>>>32-o)+e}r.MD5=o._createHelper(c),r.HmacMD5=o._createHmacHelper(c)}(Math),t.MD5)),A.exports;var t}(),v(),_(),function(){var e=t,r=e.lib.BlockCipher,n=e.algo,i=[],o=[],s=[],a=[],c=[],f=[],u=[],h=[],p=[],l=[];!function(){for(var t=[],e=0;e<256;e++)t[e]=e<128?e<<1:e<<1^283;var r=0,n=0;for(e=0;e<256;e++){var d=n^n<<1^n<<2^n<<3^n<<4;d=d>>>8^255&d^99,i[r]=d,o[d]=r;var y=t[r],v=t[y],_=t[v],g=257*t[d]^16843008*d;s[r]=g<<24|g>>>8,a[r]=g<<16|g>>>16,c[r]=g<<8|g>>>24,f[r]=g,g=16843009*_^65537*v^257*y^16843008*r,u[d]=g<<24|g>>>8,h[d]=g<<16|g>>>16,p[d]=g<<8|g>>>24,l[d]=g,r?(r=y^t[t[t[_^y]]],n^=t[t[n]]):r=n=1}}();var d=[0,1,2,4,8,16,32,64,128,27,54],y=n.AES=r.extend({_doReset:function(){if(!this._nRounds||this._keyPriorReset!==this._key){for(var t=this._keyPriorReset=this._key,e=t.words,r=t.sigBytes/4,n=4*((this._nRounds=r+6)+1),o=this._keySchedule=[],s=0;s<n;s++)s<r?o[s]=e[s]:(f=o[s-1],s%r?r>6&&s%r==4&&(f=i[f>>>24]<<24|i[f>>>16&255]<<16|i[f>>>8&255]<<8|i[255&f]):(f=i[(f=f<<8|f>>>24)>>>24]<<24|i[f>>>16&255]<<16|i[f>>>8&255]<<8|i[255&f],f^=d[s/r|0]<<24),o[s]=o[s-r]^f);for(var a=this._invKeySchedule=[],c=0;c<n;c++){if(s=n-c,c%4)var f=o[s];else f=o[s-4];a[c]=c<4||s<=4?f:u[i[f>>>24]]^h[i[f>>>16&255]]^p[i[f>>>8&255]]^l[i[255&f]]}}},encryptBlock:function(t,e){this._doCryptBlock(t,e,this._keySchedule,s,a,c,f,i)},decryptBlock:function(t,e){var r=t[e+1];t[e+1]=t[e+3],t[e+3]=r,this._doCryptBlock(t,e,this._invKeySchedule,u,h,p,l,o),r=t[e+1],t[e+1]=t[e+3],t[e+3]=r},_doCryptBlock:function(t,e,r,n,i,o,s,a){for(var c=this._nRounds,f=t[e]^r[0],u=t[e+1]^r[1],h=t[e+2]^r[2],p=t[e+3]^r[3],l=4,d=1;d<c;d++){var y=n[f>>>24]^i[u>>>16&255]^o[h>>>8&255]^s[255&p]^r[l++],v=n[u>>>24]^i[h>>>16&255]^o[p>>>8&255]^s[255&f]^r[l++],_=n[h>>>24]^i[p>>>16&255]^o[f>>>8&255]^s[255&u]^r[l++],g=n[p>>>24]^i[f>>>16&255]^o[u>>>8&255]^s[255&h]^r[l++];f=y,u=v,h=_,p=g}y=(a[f>>>24]<<24|a[u>>>16&255]<<16|a[h>>>8&255]<<8|a[255&p])^r[l++],v=(a[u>>>24]<<24|a[h>>>16&255]<<16|a[p>>>8&255]<<8|a[255&f])^r[l++],_=(a[h>>>24]<<24|a[p>>>16&255]<<16|a[f>>>8&255]<<8|a[255&u])^r[l++],g=(a[p>>>24]<<24|a[f>>>16&255]<<16|a[u>>>8&255]<<8|a[255&h])^r[l++],t[e]=y,t[e+1]=v,t[e+2]=_,t[e+3]=g},keySize:8});e.AES=r._createHelper(y)}(),t.AES));var t}())),C={words:[1698181731,1801809512,946104675,1751477816],sigBytes:16};function O(t){try{return t=z.AES.decrypt({ciphertext:z.lib.WordArray.create(t)},C,{mode:z.mode.ECB,padding:z.pad.Pkcs7}),JSON.parse(z.enc.Utf8.stringify(t))}catch(t){return null}}var M,D=Date.now();
    try {
        let url = typeof $request !== "undefined" && $request.url,od = false;
        let t = typeof $task < "u";
        if (url && url.includes("onlydata")) {
            od = true
        }
        M = !od ? O(t ? $request.bodyBytes : $request.body) : t ? $request.bodyBytes : $request.body;
        let e = Date.now();
        null === M && $done({});
        let r = (function (t) {
            if (od) return t;
            t = z.AES.encrypt(JSON.stringify(t), C, {
            mode: z.mode.ECB,
            padding: z.pad.Pkcs7,
            }).ciphertext;
            let e = new Uint8Array(t.sigBytes);
            for (let r = 0; r < t.sigBytes; r++)
            e[r] = (t.words[r >>> 2] >>> (24 - (r % 4) * 8)) & 255;
            return e;
        })(M),
        n = r.length,
        i =
            typeof Egern < "u"
            ? "Egern"
            : typeof $environment < "u" && $environment["surge-version"]
            ? "Surge"
            : typeof $environment < "u" && $environment["stash-version"]
            ? "Stash"
            : typeof module < "u" && module.exports
            ? "Node.js"
            : typeof $task < "u"
            ? "Quantumult X"
            : typeof $loon < "u"
            ? "Loon"
            : typeof $rocket < "u"
            ? "Shadowrocket"
            : void 0;
        if ("Loon" == i) {
        let t = $loon.split(" ");
        i = { device: t[0], ios: t[1], version: t[2], app: "Loon" };
        } else
        "Egern" == i
            ? ((i = Egern), (i.app = "Egern"))
            : "Surge" == i
            ? ((i = $environment), (i.app = "Surge"))
            : "Stash" == i && ((i = $environment), (i.app = "Stash"));
        if (t) {
        let t = $environment.version.split(" ");
        i = { device: t[0], ios: t[1], version: t[2], app: "Quantumult X" };
        }
        let o = { t1: D, t2: e, t3: Date.now(), device: i, length: n },
        s = {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST,GET,OPTIONS,PUT,DELETE",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Expose-Headers": "ntconfig",
            ntconfig: JSON.stringify(o),
        };
        t
        ? $done({
            status: "HTTP/1.1 200 OK",
            headers: s,
            bodyBytes: r.buffer.slice(r.byteOffset, r.byteLength + r.byteOffset),
            })
        : $done({ response: { status: 200, headers: s, body: r } });
    } catch (E) {
    } finally {
        $done({});
    }
})();
