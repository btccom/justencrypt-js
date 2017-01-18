var pbkdf2Sha512 = require('./pbkdf2_sha512');

module.exports = function(self) {
    self.addEventListener('message', function(e) {
        var data = e.data || {};

        switch (data.method) {
            case 'pbkdf2Sha512.digest':
                (function() {
                    try {
                        var pw = typeof data.pw !== "undefined" ? Buffer.from(data.pw.buffer) : undefined;
                        var salt = typeof data.salt !== "undefined" ? Buffer.from(data.salt.buffer) : undefined;
                        var iterations = typeof data.iterations !== "undefined" ? data.iterations : undefined;
                        var keySizeBytes = typeof data.keySizeBytes !== "undefined" ? data.keySizeBytes : undefined;

                        var result = pbkdf2Sha512.digest(pw, salt, iterations, keySizeBytes);
                        self.postMessage({id: data.id, result: result});
                    } catch (e) {
                        e.id = data.id;
                        throw e;
                    }
                })();
                break;

            default:
                e = new Error('Invalid method [' + e.method + ']');
                e.id = data.id;
                throw e;
        }
    }, false);
};
