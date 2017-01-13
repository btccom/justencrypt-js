var Encryption = require('./encryption');
var KeyDerivation = require('./keyderivation');

module.exports = function(self) {
    self.addEventListener('message', function(e) {
        var data = e.data || {};

        switch (data.method) {
            case 'Encryption.encryptWithSaltAndIV':
                (function() {
                    try {
                        if (!data.pt || !data.pw || !data.saltBuf || !data.iv || !data.iterations) {
                            throw new Error("Invalid input");
                        }

                        var pt = Buffer.from(data.pt.buffer);
                        var pw = Buffer.from(data.pw.buffer);
                        var saltBuf = Buffer.from(data.saltBuf.buffer);
                        var iv = Buffer.from(data.iv.buffer);
                        var iterations = data.iterations;

                        var result = Encryption.encryptWithSaltAndIVSync(pt,  pw, saltBuf, iv, iterations);

                        self.postMessage({id: data.id, result: result});
                    } catch (e) {
                        e.id = data.id;
                        throw e;
                    }
                })();
            break;

            case 'Encryption.decrypt':
                (function() {
                    try {
                        if (!data.ct || !data.pw) {
                            throw new Error("Invalid input");
                        }

                        var ct = Buffer.from(data.ct.buffer);
                        var pw = Buffer.from(data.pw.buffer);

                        var result = Encryption.decryptSync(ct,  pw);

                        self.postMessage({id: data.id, result: result});
                    } catch (e) {
                        e.id = data.id;
                        throw e;
                    }
                })();
                break;

            case 'KeyDerivation.computeSync':
                (function() {
                    try {
                        if (!data.pw || !data.salt || !data.iterations) {
                            throw new Error("Invalid input");
                        }

                        var pw = Buffer.from(data.pw.buffer);
                        var salt = Buffer.from(data.salt.buffer);
                        var iterations = data.iterations;

                        var result = KeyDerivation.computeSync(pw, salt, iterations);

                        self.postMessage({id: data.id, output: result});
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
