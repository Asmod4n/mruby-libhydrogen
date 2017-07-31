MRuby::Gem::Specification.new('mruby-libhydrogen') do |spec|
  spec.license = 'ISC'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'libhydrogen for mruby'
  spec.add_conflict 'mruby-libsodium'
end
