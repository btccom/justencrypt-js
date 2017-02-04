var assert = require('assert');
var _ = require('lodash');
var Promise = require('es6-promise').Promise;

var justencrypt = require('../');
var vectors = require('./vectors');

describe('encryption async', function() {
    it('convience wrapper with specified iterations', function() {
        var plainText = new Buffer("6a1efab8b1f788fba9e5c23d36e9bb96cfe455c14ecfa59c7c887adea934bf38", "hex");
        var password = new Buffer("70617373776f7264", "hex");

        return Promise.resolve()
            .then(function() {
                return justencrypt.Encryption.encrypt(plainText, password, 1)
                    .then(function(cipherText) {
                        return justencrypt.Encryption.decrypt(cipherText, password)
                            .then(function(_plainText) {
                                assert.equal(_plainText.toString('hex'), plainText.toString('hex'));
                            });
                    });
            });
    });

    it('convience wrapper with default iterations', function() {
        var plainText = new Buffer("6a1efab8b1f788fba9e5c23d36e9bb96cfe455c14ecfa59c7c887adea934bf38", "hex");
        var password = new Buffer("70617373776f7264", "hex");

        return Promise.resolve()
            .then(function() {
                return justencrypt.Encryption.encrypt(plainText, password)
                    .then(function(cipherText) {
                        return justencrypt.Encryption.decrypt(cipherText, password)
                            .then(function(_plainText) {
                                assert.equal(_plainText.toString('hex'), plainText.toString('hex'));
                            });
                    });
            });
    });

    it('encrypt throws errors through promise', function() {
        return Promise.resolve()
            .then(function() {
                return justencrypt.Encryption.encrypt()
                    .then(function() {
                        assert.fail("should throw error");
                    }, function(err) {
                        assert.equal("" + err, "AssertionError: pt must be provided as a Buffer");
                    });
            });
    });

    it('decrypt throws errors through promise', function() {
        return Promise.resolve()
            .then(function() {
                return justencrypt.Encryption.decrypt()
                    .then(function() {
                        assert.fail("should throw error");
                    }, function(err) {
                        assert.equal("" + err, "AssertionError: cipherText must be provided as a Buffer");
                    });
            });
    });

    _.forEach(vectors.encryption, function(vector, key) {
        it('vector ' + key + ' demonstrates properties of GCM', function() {
            var pw = new Buffer(vector.password, 'hex');
            var pt = new Buffer(vector.pt, 'hex');
            var salt = new Buffer(vector.salt, 'hex');
            var iv = new Buffer(vector.iv, 'hex');
            var iterations = vector.iterations;

            var firstEncrypt;

            return Promise.resolve()
                .then(function() {
                    // test output given this pt/pw/salt/iv matches the test vector
                    return justencrypt.Encryption.encryptWithSaltAndIV(pt, pw, salt, iv, iterations)
                        .then(function(_firstEncrypt) {
                            firstEncrypt = _firstEncrypt;

                            assert.equal(firstEncrypt.toString('hex'), vector.full, 'gcm output should match given pt/pw/salt/iv');
                        });
                })
                .then(function() {
                    // test we can decrypt it again
                    return justencrypt.Encryption.decrypt(firstEncrypt, pw)
                        .then(function(firstDecrypt) {
                            assert.equal(firstDecrypt.toString('hex'), pt.toString('hex'), 'encryption/decryption should be consistent');
                        });
                });
        });
    });
});
