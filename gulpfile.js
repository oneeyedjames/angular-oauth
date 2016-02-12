var del = require('del');

var gulp = require('gulp');

var concat = require('gulp-concat');
var rename = require('gulp-rename');
var jshint = require('gulp-jshint');
var uglify = require('gulp-uglify');

var paths = {
	js: {
		src: './src/js/',
		dest: './build/js/',
		root: 'angular-oauth.js'
	}
};

function all(path, ext) {
    return path.replace(/\/$/, '') + '/**/*.' + ext;
}

gulp.task('default', ['build', 'watch']);

gulp.task('build', ['build:js']);
gulp.task('clean', ['clean:js']);
gulp.task('watch', ['watch:js']);

gulp.task('build:js', ['clean:js'], function(done) {
	gulp.src(all(paths.js.src, 'js'))
	.pipe(jshint())
	.pipe(concat(paths.js.root))
	.pipe(gulp.dest(paths.js.dest))
	.pipe(uglify())
	.pipe(rename({ extname: '.min.js' }))
	.pipe(gulp.dest(paths.js.dest))
	.on('end', done);
});

gulp.task('clean:js', function() {
    return del(all(paths.js.dest, 'js'));
});

gulp.task('watch:js', function() {
    gulp.watch(all(paths.js.src, 'js'), ['build:js']);
});
