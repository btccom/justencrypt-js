var assert = require('assert');
var _ = require('lodash');

var justencrypt = require('../');
var vectors = require('./vectors');

describe('key derivation', function() {
    var prevUseWebCrypto;
    var prevUseWebWorker;
    beforeEach(function() {
        // record state of config
        prevUseWebCrypto = justencrypt.KeyDerivation.useWebCrypto;
        prevUseWebWorker = justencrypt.KeyDerivation.useWebWorker;
    });
    afterEach(function() {
        // set back state to before test
        justencrypt.KeyDerivation.useWebCrypto = prevUseWebCrypto;
        justencrypt.KeyDerivation.useWebWorker = prevUseWebWorker;
    });

    it('asserts max length salt', function() {
        var password = new Buffer("70617373776f7264", 'hex');
        var iterations = 1;

        assert.throws(function() {
            var salt = new Buffer(_.repeat("ff", 129), 'hex');
            justencrypt.KeyDerivation.compute(password, salt, iterations)
                .done();
        });

        // assert it doesn't throw for 128
        var salt = new Buffer(_.repeat("ff", 128), 'hex');
        return justencrypt.KeyDerivation.compute(password, salt, iterations);
    });

    it('uses default iterations when not provided', function() {
        var password = new Buffer("74657374", 'hex');
        var salt = new Buffer("e73dc3b0ad0a8fba2128b3c991f7fb6961f085810e33c528103be38b7b193e38", 'hex');

        return justencrypt.KeyDerivation.compute(password, salt)
            .then(function(result) {
                assert.equal(result.toString('hex'), "54e4445ac677d0b5c2a8ccad171645107646ab1c110f8b5da8fbe936d02afd6a");
            });
    });

    var testVector = function(vector) {
        var password = vector.password_utf8 ? new Buffer(vector.password_utf8, 'utf-8') : new Buffer(vector.password, 'hex');
        var salt = new Buffer(vector.salt, 'hex');
        var iterations = vector.iterations;

        return justencrypt.KeyDerivation.compute(password, salt, iterations)
            .then(function(output) {
                assert.equal(output.toString('hex'), vector.output);
            });
    };

    _.forEach(vectors.keyderivation, function(vector, key) {
        it('compute vector ' + key + ' produces the right key', function() {
            return testVector(vector);
        });

        it('compute vector ' + key + ' produces the right key when webcrypto is disabled', function() {
            justencrypt.KeyDerivation.useWebCrypto = false;

            return testVector(vector);
        });

        it('compute vector ' + key + ' produces the right key when webcrypto & webworkers is disabled', function() {
            justencrypt.KeyDerivation.useWebCrypto = false;
            justencrypt.KeyDerivation.useWebWorker = false;

            return testVector(vector);
        });
    });
});
