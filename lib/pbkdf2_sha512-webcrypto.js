/* global window */

var importKey = function (pw) {
    return window.crypto.subtle.importKey(
        "raw",
        pw,
        {name: "PBKDF2"},
        false,
        ["deriveBits"]
    );
};

var deriveBits = function (key, salt, iterations, bits) {
    return window.crypto.subtle.deriveBits(
        {
            "name": "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: {name: "SHA-512"}
        },
        key,
        bits || 256
    )
        .then(function (bits) {
            return Buffer.from(new Uint8Array(bits));
        });
};

var pbkdf2Sha512 = function (pw, salt, iterations, keySizeBytes) {
    return importKey(pw)
        .then(function(key) {
            return deriveBits(key, salt, iterations, keySizeBytes * 8)
        });
};

module.exports = {
    digest: pbkdf2Sha512
};
