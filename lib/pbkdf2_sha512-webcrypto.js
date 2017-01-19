/* global window */
var q = require('q');

var importKey = function(pw) {
    return window.crypto.subtle.importKey(
        "raw",
        pw,
        {name: "PBKDF2"},
        false,
        ["deriveBits"]
    );
};

var deriveBits = function(key, salt, iterations, bits) {
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
        .then(function(bits) {
            return Buffer.from(new Uint8Array(bits));
        });
};

var pbkdf2Sha512 = function(pw, salt, iterations, keySizeBytes) {
    return importKey(pw)
        .then(function(key) {
            return deriveBits(key, salt, iterations, keySizeBytes * 8)
        });
};

var isSupported = null;
var isSupportedPromise = null;

var isSupportedCheck = function() {
    var hasCryptoMethods = typeof window !== "undefined" &&
        typeof window.crypto !== "undefined" &&
        typeof window.crypto.subtle !== "undefined" &&
        typeof window.crypto.subtle.importKey !== "undefined" &&
        typeof window.crypto.subtle.deriveBits !== "undefined";

    if (!hasCryptoMethods) {
        return q.when(false);
    }

    return pbkdf2Sha512(new Buffer("password", "utf8"), new Buffer("salt", "utf8"), 1, 8)
        .then(function (r) {
            isSupported = r.toString('hex') === "867f70cf1ade02cf";
        }, function () {
            isSupported = false;
        })
        .then(function () {
            return isSupported;
        });
};

module.exports = {
    digest: pbkdf2Sha512,
    isSupported: function() {
        if (isSupported !== null) {
            return q.when(isSupported);
        } else {
            if (isSupportedPromise === null) {
                isSupportedPromise = isSupportedCheck();
            }

            return isSupportedPromise;
        }
    }
};
