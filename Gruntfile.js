module.exports = function (grunt) {

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        exec: {
            asmcryptobuild: 'cd ./vendor/asmcrypto.js; npm install; grunt --with pbkdf2-hmac-sha512'
        },

        /*
         * Javascript uglifying
         */
        uglify : {
            options: {
                mangle: {
                    except: ['Buffer']
                }
            },
            dist : {
                files : {
                    'build/justencrypt.min.js'       : ['<%= browserify.dest %>']
                }
            }
        },

        /*
         *
         */
        browserify: {
            options : {
                browserifyOptions : {
                    standalone: 'justencrypt'
                },
                transform : ['brfs']
            },
            src: 'main.js',
            dest: 'build/justencrypt.js'
        },
    });

    grunt.loadNpmTasks('grunt-browserify');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-exec');

    grunt.registerTask('asmcrypto', ['exec:asmcryptobuild']);
    grunt.registerTask('build', ['asmcrypto', 'browserify', 'uglify']);
    grunt.registerTask('default', ['build']);
};

