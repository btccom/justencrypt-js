var assert = require('assert');
var justencrypt = require('../');
var _ = require('lodash');
var vectors = require('./vectors');

describe('key derivation', function() {
    _.forEach(vectors.keyderivation, function(vector, key) {
        it('vector ' + key + ' produces the right key', function() {
            var password = new Buffer(vector.password, 'hex');
            var salt = new Buffer(vector.salt, 'hex');
            var iterations = vector.iterations;
            var output = justencrypt.KeyDerivation.computeSync(password, salt, iterations);

            assert.equal(output.toString('hex'), vector.output);
        });
    });
});

describe('encryption', function() {
    _.forEach(vectors.encryption, function(vector, key) {
        it('vector ' + key + ' demonstrates properties of GCM', function() {
            var pw = new Buffer(vector.password, 'hex');
            var pt = new Buffer(vector.pt, 'hex');
            var salt = new Buffer(vector.salt, 'hex');
            var iv = new Buffer(vector.iv, 'hex');
            var iterations = vector.iterations;

            // test output given this pt/pw/salt/iv matches the test vector
            var firstEncrypt = justencrypt.Encryption.encryptWithSaltAndIVSync(pt, pw, salt, iv, iterations);
            assert.equal(firstEncrypt.toString('hex'), vector.full, 'gcm output should match given pt/pw/salt/iv');

            // test we can decrypt it again
            var firstDecrypt = justencrypt.Encryption.decryptSync(firstEncrypt, pw);
            assert.equal(firstDecrypt.toString(), pt.toString(), 'encryption/decryption should be consistent');
        });
    });
});

describe('mnemonic', function() {
    _.forEach(vectors.mnemonic, function(vector, key) {
        it('vector ' + key + ' can be encoded & decoded', function() {
            var data = new Buffer(vector.data, 'hex');
            var mnemonic = vector.mnemonic;
            assert.equal(justencrypt.EncryptionMnemonic.encode(data), mnemonic);
            assert.equal(justencrypt.EncryptionMnemonic.decode(mnemonic).toString(), data.toString());
        });
    });
});
