var assert = require('assert');
var asmCrypto = require('../vendor/asmcrypto.js/asmcrypto.js');
var Promise = require('es6-promise').Promise;
var randomBytes = require('randombytes');

var KeyDerivation = require('./keyderivation');

var Encryption = {
    defaultSaltLen: 10, /* can permit changes, no more than 512 bit (128 bytes) */
    tagLenBits: 128, /* can permit changes */
    ivLenBits: 128,  /* fixed */
    ivLenWords: 128 / 32
};

Encryption.generateSalt = function() {
    return randomBytes(Encryption.defaultSaltLen);
};

Encryption.generateIV = function() {
    return randomBytes(Encryption.ivLenBits / 8);
};

Encryption.encrypt = function(pt, pw, iterations) {
    return Promise.resolve()
        .then(function() {
            var salt = Encryption.generateSalt();
            var iv = Encryption.generateIV();

            iterations = typeof iterations === 'undefined' ? KeyDerivation.defaultIterations : iterations;
            return Encryption.encryptWithSaltAndIV(pt, pw, salt, iv, iterations);
        });
};

Encryption.encryptWithSaltAndIV = function(pt, pw, saltBuf, iv, iterations) {
    return Promise.resolve()
        .then(function() {
            assert(pt instanceof Buffer, 'pt must be provided as a Buffer');
            assert(pw instanceof Buffer, 'pw must be provided as a Buffer');
            assert(iv instanceof Buffer, 'IV must be provided as a Buffer');
            assert(saltBuf instanceof Buffer, 'saltBuff must be provided as a Buffer');
            assert(iv.length === 16, 'IV must be exactly 16 bytes');

            var SL = (new Buffer(1));
            var S = saltBuf;
            var I = new Buffer(4);
            SL.writeUInt8(saltBuf.length);
            I.writeUInt32LE(iterations);
            var header = SL.toString('hex') + S.toString('hex') + I.toString('hex');

            return KeyDerivation.compute(pw, saltBuf, iterations)
                .then(function(keyBuf) {
                    var ct_t = asmCrypto.AES_GCM.encrypt(
                        new Uint8Array(pt),
                        new Uint8Array(keyBuf),
                        new Uint8Array(iv),
                        new Uint8Array(new Buffer(header, 'hex')),
                        Encryption.tagLenBits / 8
                    );
                    ct_t = (new Buffer(ct_t)).toString('hex');

                    // saltLen8 || salt || iter || iv || ct || tag
                    return new Buffer([header, iv.toString('hex'), ct_t].join(''), 'hex');
                });
        });
};

Encryption.decrypt = function(ct, pw) {
    return Promise.resolve()
        .then(function() {
            assert(ct instanceof Buffer, 'cipherText must be provided as a Buffer');
            assert(pw instanceof Buffer, 'password must be provided as a Buffer');
            var copy = new Buffer(ct, 'hex');
            var c = 0;

            var saltLen = copy.readUInt8(c); c += 1;
            var salt = copy.slice(1, c + saltLen); c += saltLen;
            var iterations = copy.readUInt32LE(c); c += 4;
            var header = copy.slice(0, c);

            var iv = copy.slice(c, 16 + c); c += 16;
            var ct_t = copy.slice(c);

            return KeyDerivation.compute(pw.slice(0), salt.slice(0), iterations)
                .then(function(keyBuf) {
                    var plainText = asmCrypto.AES_GCM.decrypt(
                        new Uint8Array(ct_t),
                        new Uint8Array(keyBuf),
                        new Uint8Array(iv),
                        new Uint8Array(new Buffer(header, 'hex')),
                        Encryption.tagLenBits / 8
                    );

                    return new Buffer(plainText);
                });
        });
};

module.exports = Encryption;
