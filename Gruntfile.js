module.exports = function (grunt) {

    /*
     * parse CLI args for saucelabs filtering
     */
    var platformsIdx = process.argv.indexOf('--platforms');
    var platforms = null;
    if (platformsIdx !== -1) {
        platforms = process.argv[platformsIdx + 1];
    }

    var browsersIdx = process.argv.indexOf('--browsers');
    var browsers = null;
    if (browsersIdx !== -1) {
        browsers = process.argv[browsersIdx + 1];
    }

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        /*
         * Connect (used to open connection for saucelabs)
         */
        connect: {
            server: {
                options: {
                    base: '',
                    port: 9999
                }
            }
        },

        /*
         * Saucelabs
         */
        'saucelabs-mocha': {
            with_webcrypto: {
                options: {
                    // username: 'saucelabs-user-name', // if not provided it'll default to ENV SAUCE_USERNAME (if applicable)
                    // key: 'saucelabs-key', // if not provided it'll default to ENV SAUCE_ACCESS_KEY (if applicable)
                    urls: [
                        // invert grep benchmarks + webcrypto=true
                        'http://127.0.0.1:9999/test/run-tests.html?grep=' + encodeURIComponent("benchmark") + '&invert=true&webcrypto=true'
                    ],
                    browsers: require('./saucelabs-browsers')
                                .filter(function(browser) { return browser.webcrypto; })
                                .filter(function(browser) { return !browsers || browsers.indexOf(browser.browserName) !== -1; }),
                    build: process.env.TRAVIS_JOB_ID || ('99' + ((new Date).getTime() / 1000).toFixed(0) + (Math.random() * 1000).toFixed(0)),
                    testname: 'mocha tests - webcrypto=true',
                    throttled: 2,
                    statusCheckAttempts: 360, // statusCheckAttempts * pollInterval = total time
                    pollInterval: 4000,
                    sauceConfig: {
                        'command-timeout': 600,
                        'idle-timeout': 360,
                        'max-duration': 900, // doesn't seem to take effect
                        'video-upload-on-pass': true
                    }
                }
            },
            without_webcrypto: {
                options: {
                    // username: 'saucelabs-user-name', // if not provided it'll default to ENV SAUCE_USERNAME (if applicable)
                    // key: 'saucelabs-key', // if not provided it'll default to ENV SAUCE_ACCESS_KEY (if applicable)
                    urls: [
                        // invert grep benchmarks + webcrypto=false
                        'http://127.0.0.1:9999/test/run-tests.html?grep=' + encodeURIComponent("benchmark") + '&invert=true&webcrypto=false'
                    ],
                    browsers: require('./saucelabs-browsers')
                                .filter(function(browser) { return !browser.webcrypto; })
                                .filter(function(browser) { return !browsers || browsers.indexOf(browser.browserName) !== -1; }),
                    build: process.env.TRAVIS_JOB_ID || ('99' + ((new Date).getTime() / 1000).toFixed(0) + (Math.random() * 1000).toFixed(0)),
                    testname: 'mocha tests - webcrypto=false',
                    throttled: 2,
                    statusCheckAttempts: 360, // statusCheckAttempts * pollInterval = total time
                    pollInterval: 4000,
                    sauceConfig: {
                        'command-timeout': 600,
                        'idle-timeout': 360,
                        'max-duration': 900, // doesn't seem to take effect
                        'video-upload-on-pass': true
                    }
                }
            }
        },


        /*
         * Exec
         */
        exec: {
            // does 'sources concat' as tasks, because we don't want it minified by the asmcrypto grunt
            //  make sure if you add algo's here you also add uglify wrangler excludes where necessary!
            asmcryptobuild: 'cd ./vendor/asmcrypto.js; npm install; grunt sources concat --with pbkdf2-hmac-sha512,aes-gcm'
        },

        /*
         * Uglify
         */
        uglify: {
            options: {
                mangle: {
                    except: ['Buffer', 'sha512_asm', 'asm']
                }
            },
            justencrypt: {
                files: {
                    'build/justencrypt.min.js': ['<%= browserify.justencrypt.dest %>']
                }
            },
            test: {
                files: {
                    'build/test.min.js': ['<%= browserify.test.dest %>']
                }
            }
        },

        /*
         * Browserify
         */
        browserify: {
            justencrypt: {
                options: {
                    browserifyOptions: {
                        standalone: 'justencrypt'
                    },
                    transform: ['brfs']
                },
                src: 'index.js',
                dest: 'build/justencrypt.js'
            },
            test: {
                options: {
                    browserifyOptions: {
                        standalone: 'justencryptTEST'
                    },
                    transform: ['brfs']
                },
                src: 'test.js',
                dest: 'build/test.js'
            }
        },

        /*
         * Watch
         */
        watch: {
            options: {},
            test: {
                files: ['test.js', 'index.js', 'test/*', 'test/**/*', 'lib/*', 'lib/**/*'],
                tasks: ['browserify:test', 'uglify:test']
            }
        }
    });

    grunt.loadNpmTasks('grunt-browserify');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-saucelabs');
    grunt.loadNpmTasks('grunt-exec');

    grunt.registerTask('asmcrypto', ['exec:asmcryptobuild']);
    grunt.registerTask('build', ['asmcrypto', 'browserify', 'uglify']);
    grunt.registerTask('default', ['build']);
    grunt.registerTask('test-browser', ['connect', 'saucelabs-mocha']);
};

