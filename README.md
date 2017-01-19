JustEncrypt
===========
[![Latest Stable Version](https://badge.fury.io/js/justencrypt.svg)](https://www.npmjs.org/package/justencrypt)
[![Build Status](https://travis-ci.org/btccom/justencrypt.png?branch=master)](https://travis-ci.org/btccom/justencrypt)
[![Sauce Test Status](https://saucelabs.com/buildstatus/justencrypt-js)](https://saucelabs.com/u/team_blocktrail)

[![Sauce Test Status](https://saucelabs.com/browser-matrix/justencrypt-js.svg)](https://saucelabs.com/u/team_blocktrail)

This package is being tested against;  
 - NodeJS:
   - 0.11
   - 0.12
   - 5.11
   - 6.3.0
   - 7.1.0
 - Browser:
   - Google Chrome 48 / latest
   - Firefox 49 / latest
   - Safari 10.0 / latest
   - Edge 14.14393
   - IE 11.103
   - Android 4.4
   - Android 5.0
   - iPhone OS X 10.10

Usage
-----
All functions return promises to make it easy to automatically use webworkers or WebCrypto API in browsers that support it!

#### KeyDerivation
```
// iterations is optional and defaults to 35k iterations
justencrypt.KeyDerivation.computeSync(new Buffer(rawPassword, 'utf8'), saltBuffer, iterations)
    .then(function(keyBuffer) {
        console.log(keyBuffer.toString('base64'));
    });
```

#### Encryption
The result of `encrypt` is encoded as `iter || saltLen8 || salt || iv || tag || ct`,  
when this is fed into `decrypt` it will be able decode the salt and iterations used.

```
// iterations is optional and defaults to 35k iterations
justencrypt.Encryption.encryptSync(new Buffer(rawPassword, 'utf8'), dataBuffer, iterations)
    .then(function(encryptedBuffer) {
        console.log(encryptedBuffer.toString('base64'));
    });

justencrypt.Encryption.decryptSync(encryptedBuffer, new Buffer(rawPassword, 'utf8'))
    .then(function(decryptedDataBuffer) {
        console.log(decryptedDataBuffer.toString('base64'));
    });
```

#### EncryptionMnemonic
To make the result of `encrypt` human readable (so it is easier to write down) it's possible to encode it as an mnemonic.  
We're using the Bitcoin BIP39 way of encoding entropy to mnemonic, but ignoring the (weak) password protection BIP39 originally had.  
We also ensure the data is padded correctly.

**IMPORTANT:** This is only meant to be used to encode results of `encrypt`, don't use this for anything else!

```
var mnemonicString = justencrypt.EncryptionMnemonic.encode(encryptedBuffer);
var encryptedBuffer = justencrypt.EncryptionMnemonic.decode(mnemonicString);
```

Development / Contributing
--------------------------
You should have `mocha`, `istanbul` and `grunt-cli` installed globally, if not run `npm install -g mocha instanbul grunt-cli`.  
Also recommended to have `phantomjs >= 1.9.8` on `$PATH` to speed up the `asmcrypto.js` build; https//github.com/Medium/phantomjs/releases/download/v1.9.19/phantomjs-1.9.8-linux-x86_64.tar.bz2

Unit Tests are created with Mocha and can be ran with `npm test` (or `mocha`)

We also run jshint and jscs, these are automatically ran by [travis-ci](https://travis-ci.org/btccom/jusencrypt) for every commit and pull request.
```
jshint main.js lib/ test/ && jscs main.js lib/ test/
```
or simply `npm run-script lint`

Uglify
------
If you're planning to uglify/minify the javascript yourself, make sure to exclude the following variable names from being mangled:  
`['Buffer', 'sha512_asm', 'asm']`

License
-------
JustEncrypt is released under the terms of the MIT license. See LICENCE.md for more information or see http://opensource.org/licenses/MIT.
