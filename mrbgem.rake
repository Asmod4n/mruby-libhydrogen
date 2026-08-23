MRuby::Gem::Specification.new('mruby-libhydrogen') do |spec|
  spec.license = 'ISC'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'libhydrogen for mruby'

  hydro = "#{spec.dir}/deps/libhydrogen"
  unless File.exist? "#{hydro}/hydrogen.h"
    abort 'mruby-libhydrogen: deps/libhydrogen is empty - run: git submodule update --init'
  end
  # hydrogen.c is compiled into this gem (src/mrb_libhydrogen.h includes
  # it), so its symbols are already in every binary that links the gem;
  # exporting the include path lets a dependent gem `#include <hydrogen.h>`
  # and call the C API directly instead of going through Ruby.
  spec.export_include_paths << hydro

  spec.add_dependency 'mruby-string-ext'
  spec.add_dependency 'mruby-errno'
end
