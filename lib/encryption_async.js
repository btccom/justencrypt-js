var q = require('q');

var Encryption = require('./encryption');

var EncryptionAsync = {};

EncryptionAsync.encrypt = function(pt, pw, iterations) {
    return q.when()
        .then(function() {
            return Encryption.encryptSync(pt, pw, iterations);
        });
};

EncryptionAsync.encryptWithSaltAndIV = function(pt, pw, saltBuf, iv, iterations) {
    return q.when()
        .then(function() {
            return Encryption.encryptWithSaltAndIVSync(pt, pw, saltBuf, iv, iterations);
        });
};

EncryptionAsync.decrypt = function(ct, pw) {
    return q.when()
        .then(function() {
            return Encryption.decryptSync(ct, pw);
        });
};

module.exports = EncryptionAsync;
