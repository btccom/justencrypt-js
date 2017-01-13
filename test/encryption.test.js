var assert = require('assert');
var _ = require('lodash');

var justencrypt = require('../');
var vectors = require('./vectors');

describe('encryption', function() {
    it('convience wrapper with specified iterations', function() {
        var plainText = new Buffer("6a1efab8b1f788fba9e5c23d36e9bb96cfe455c14ecfa59c7c887adea934bf38", "hex");
        var password = new Buffer("70617373776f7264", "hex");
        var cipherText = justencrypt.Encryption.encryptSync(plainText, password, 1);

        assert.equal(justencrypt.Encryption.decryptSync(cipherText, password).toString('hex'), plainText.toString('hex'));
    });

    it('convience wrapper with default iterations', function() {
        var plainText = new Buffer("6a1efab8b1f788fba9e5c23d36e9bb96cfe455c14ecfa59c7c887adea934bf38", "hex");
        var password = new Buffer("70617373776f7264", "hex");
        var cipherText = justencrypt.Encryption.encryptSync(plainText, password);

        assert.equal(justencrypt.Encryption.decryptSync(cipherText, password).toString('hex'), plainText.toString('hex'));
    });

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
            assert.equal(firstDecrypt.toString('hex'), pt.toString('hex'), 'encryption/decryption should be consistent');
        });
    });
});
