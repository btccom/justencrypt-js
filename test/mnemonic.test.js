var assert = require('assert');
var justencrypt = require('../');
var _ = require('lodash');
var vectors = require('./vectors');
var bip39 = require('bip39');

describe('mnemonic', function() {
    it('asserts first byte when encoding', function() {
        assert.throws(function() {
            var data = new Buffer("81", 'hex');
            justencrypt.EncryptionMnemonic.encode(data);
        });

        // assert 0x80 is ok
        var data = new Buffer("80", 'hex');
        justencrypt.EncryptionMnemonic.encode(data);
    });

    it('asserts padding is ok when decoding', function() {
        var data = "47d86f8145d7e7c68f33b7c0b65562ae426a99abb3509ccbe553c340cdb386f0";

        // assert correct padding doesn't throw
        justencrypt.EncryptionMnemonic.decode(bip39.entropyToMnemonic("81818181" + data.toString('hex')));

        // assert wrong padding byte is detected
        assert.throws(function() {
            justencrypt.EncryptionMnemonic.decode(bip39.entropyToMnemonic("80808080" + data.toString('hex')));
        }, /There is only one way to pad a string/);

        // assert wrong padding length is detected
        //  note; we have to 4 bytes, otherwise mnemonic is invalid
        assert.throws(function() {
            justencrypt.EncryptionMnemonic.decode(bip39.entropyToMnemonic("8181818181818181" + data.toString('hex')));
        }, /There is only one way to pad a string/);
    });

    _.forEach(vectors.mnemonic, function(vector, key) {
        it('vector ' + key + ' can be encoded & decoded', function() {
            var data = new Buffer(vector.data, 'hex');
            var mnemonic = vector.mnemonic;
            assert.equal(justencrypt.EncryptionMnemonic.encode(data), mnemonic);
            assert.equal(justencrypt.EncryptionMnemonic.decode(mnemonic).toString('hex'), data.toString('hex'));
        });
    });
});
