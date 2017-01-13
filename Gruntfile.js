module.exports = function (grunt) {

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        /*
         * Exec
         */
        exec: {
            asmcryptobuild: 'cd ./vendor/asmcrypto.js; npm install; grunt --with pbkdf2-hmac-sha512'
        },

        /*
         * Uglify
         */
        uglify : {
            options: {
                mangle: {
                    except: ['Buffer']
                }
            },
            dist : {
                files : {
                    'build/justencrypt.min.js' : ['<%= browserify.dest %>']
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
                src: 'main.js',
                dest: 'build/justencrypt.js'
            },
            test: {
                options : {
                    browserifyOptions : {
                        standalone: 'justencryptTEST'
                    },
                    transform : ['brfs']
                },
                src: 'test.js',
                dest: 'build/test.js'
            }
        },

        /*
         * Watch
         */
        watch : {
            options : {},
            browserifytest : {
                files : ['test.js', 'index.js', 'test/*', 'test/**/*', 'lib/*', 'lib/**/*'],
                tasks : ['browserify:test']
            }
        }
    });

    grunt.loadNpmTasks('grunt-browserify');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-exec');

    grunt.registerTask('asmcrypto', ['exec:asmcryptobuild']);
    grunt.registerTask('build', ['asmcrypto', 'browserify', 'uglify']);
    grunt.registerTask('default', ['build']);
};

