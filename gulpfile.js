const gulp = require("gulp");
const concat = require('gulp-concat');
const rename = require("gulp-rename");
const uglify = require('gulp-uglify-es').default;
const run = require('run-sequence');

gulp.task('uglify', () => {
  return gulp.src('./dist/wcrypto.js')
    .pipe(rename('wcrypto.min.js'))
    .pipe(uglify(/* options */))
    .pipe(gulp.dest('dist/'));
});

gulp.task('concat', () => {
  return gulp.src(['./src/util.js', './src/gcm.js', './src/wcrypto.js', './src/export.js'])
    .pipe(concat('wcrypto.js'))
    .pipe(gulp.dest('./dist/'));
});

gulp.task('build', (cb) => {
  run(
    'concat',
    'uglify',
    cb
  );
});
