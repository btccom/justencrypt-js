var assert = require('assert');
var _ = require('lodash');

var justencrypt = require('../');
var vectors = require('./vectors');

describe('key derivation', function() {
    it('asserts max length salt', function() {
        var password = new Buffer("70617373776f7264", 'hex');
        var iterations = 1;

        assert.throws(function() {
            var salt = new Buffer(_.repeat("ff", 129), 'hex');
            justencrypt.KeyDerivation.computeSync(password, salt, iterations);
        });

        // assert it doesn't throw for 128
        var salt = new Buffer(_.repeat("ff", 128), 'hex');
        justencrypt.KeyDerivation.computeSync(password, salt, iterations);
    });

    it('uses default iterations when not provided', function() {
        var password = new Buffer("74657374", 'hex');
        var salt = new Buffer("e73dc3b0ad0a8fba2128b3c991f7fb6961f085810e33c528103be38b7b193e38", 'hex');

        assert.equal(justencrypt.KeyDerivation.computeSync(password, salt).toString('hex'), "54e4445ac677d0b5c2a8ccad171645107646ab1c110f8b5da8fbe936d02afd6a");

    });

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
