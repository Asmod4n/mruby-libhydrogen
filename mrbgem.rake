MRuby::Gem::Specification.new('mruby-libhydrogen') do |spec|
  spec.license = 'ISC'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'libhydrogen for mruby'
  spec.add_conflict 'mruby-libsodium'
  spec.add_dependency 'mruby-string-ext'
  spec.add_dependency 'mruby-errno'
end
