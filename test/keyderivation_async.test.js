var assert = require('assert');
var _ = require('lodash');
var q = require('q');

var justencrypt = require('../');
var vectors = require('./vectors');

describe('key derivation async', function() {
    it('compute throws errors through promise', function() {
        return q.when()
            .then(function() {
                return justencrypt.KeyDerivationAsync.compute()
                    .then(function() {
                        assert.fail("should throw error");
                    }, function(err) {
                        assert.equal(err.message, "Password must be provided as a Buffer");
                    });
            });
    });

    _.forEach(vectors.keyderivation, function(vector, key) {
        it('vector ' + key + ' produces the right key', function() {
            var password = new Buffer(vector.password, 'hex');
            var salt = new Buffer(vector.salt, 'hex');
            var iterations = vector.iterations;

            return justencrypt.KeyDerivationAsync.compute(password, salt, iterations)
                .then(function(output) {
                    assert.equal(output.toString('hex'), vector.output);
                });
        });
    });
});
