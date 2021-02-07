const util = require('util');
window.crypto = require('crypto').webcrypto;
global.TextEncoder = util.TextEncoder;
global.TextDecoder = util.TextDecoder;
