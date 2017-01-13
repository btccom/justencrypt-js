var assert = require('assert');
var bip39 = require('bip39');
var _ = require('lodash');

var EncryptionMnemonic = {
    chunkSize: 4,
    paddingDummy: 0x81 /* because salts with length > 128 should be forbidden? */
};

var derivePadding = function(data) {
    if (data[0] > 0x80) {
        throw new Error('Mnemonic sanity check - first byte can never be above 0x80');
    }

    return _.repeat(EncryptionMnemonic.paddingDummy.toString(16), EncryptionMnemonic.chunkSize - data.length % EncryptionMnemonic.chunkSize);
};

EncryptionMnemonic.encode = function(data) {
    assert(data instanceof Buffer, 'Data must be provided as a Buffer');

    var padding = derivePadding(data);
    var mnemonic = bip39.entropyToMnemonic(padding + data.toString('hex'));

    try {
        bip39.mnemonicToEntropy(mnemonic);
    } catch (e) {
        throw new Error('BIP39 library produced an invalid mnemonic');
    }

    return mnemonic;
};

EncryptionMnemonic.decode = function(mnemonic) {
    assert(typeof mnemonic === 'string', 'Mnemonic must be provided as a string');

    var decoded = new Buffer(bip39.mnemonicToEntropy(mnemonic), 'hex');
    var padFinish = 0;
    while (decoded[padFinish] === this.paddingDummy) {
        padFinish++;
    }

    var data = decoded.slice(padFinish, decoded.length);
    if (derivePadding(data) !== decoded.slice(0, padFinish).toString('hex')) {
        throw new Error('There is only one way to pad a string');
    }

    return data;
};

module.exports = EncryptionMnemonic;
