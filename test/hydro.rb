ctx = "libtests"

assert("RandomBytes") do
  b = 0
  tmp = RandomBytes.buf(10000)
  tmp.bytesize.times do |i|
    b += ((tmp[i].ord) >> 0) & 1
  end
  assert_true(b > 4500 && b < 5500)

  dk = tmp[0...RandomBytes::SEEDBYTES]
  b = 0
  tmp = RandomBytes.buf_deterministic(10000, dk)
  tmp.bytesize.times do |i|
    b += ((tmp[i].ord) >> 0) & 1
  end
  assert_true(b > 4500 && b < 5500)

  bp = b
  b = 0
  tmp = RandomBytes.buf_deterministic(10000, dk)
  tmp.bytesize.times do |i|
    b += ((tmp[i].ord) >> 0) & 1
  end
  assert_equal(b, bp)
end

assert("Hydro::Hash") do
  dk = "\0" * RandomBytes::SEEDBYTES
  key =  RandomBytes.buf_deterministic(Hydro::Hash::KEYBYTES_MAX, dk)
  dk = Hydro.increment(dk)
  hydro_hash = Hydro::Hash.new(ctx, key)
  msg = nil
  1001.times do |i|
    msg = RandomBytes.buf_deterministic(i, dk)
    dk = Hydro.increment(dk)
    hydro_hash.update(msg)
  end
  h = hydro_hash.final(100)
  hex = Hydro.bin2hex(h)
  assert_equal("724ad200fb004eac02a229af7b3f61153d4ffed316f663e6092e6d2747a61be7803889b4caeed92959045233d937a5cc4cf20c8fd2cc13271e2ffd1f90e963b11a8d96d9c1fa7aabfc481db29f855f61234e1f6d010c34ed2a8ee5faf73c17062146c304", hex)
  h = Hydro::Hash.hash(100, msg, ctx, key)
  hex = Hydro.bin2hex(h)
  assert_equal("5cea1d0440f8e0fed6889205cd6b1dc92fe294d12e8266101c3516a846b3e3c18c13a5c67a177facb4033c7a38b3c3784e02ffd0bfbd7f745e60f50e5df888463259f09e65f7496b3ce069238a0ed95ddedc4b795e171c140d4d92cf16231b26f05419fb", hex)
  h = Hydro::Hash.hash(Hydro::Hash::BYTES, msg, ctx, key)
  hex = Hydro.bin2hex(h)
  assert_equal("8ff82f5bd3a37aa81695a0d977795b6b20c7ce71a3886e0b33af6ac7f261c26d", hex)
end

assert("Hydro::Kdf") do
  dk = "\0" * RandomBytes::SEEDBYTES
  key = RandomBytes.buf_deterministic(Hydro::Kdf::KEYBYTES, dk)
  subkey1 = Hydro::Kdf.derive_from_key(16, 1, ctx, key)
  subkey2 = Hydro::Kdf.derive_from_key(16, 2, ctx, key)
  subkey3 = Hydro::Kdf.derive_from_key(32, 0, ctx, key)
  subkey4 = Hydro::Kdf.derive_from_key(50, 0, ctx, key)
  subkey1_hex = Hydro.bin2hex(subkey1)
  subkey2_hex = Hydro.bin2hex(subkey2)
  subkey3_hex = Hydro.bin2hex(subkey3)
  subkey4_hex = Hydro.bin2hex(subkey4)
  assert_equal("53ae26f46924e9f0d9b9da098611d7f9", subkey1_hex)
  assert_equal("b8eb0a9117ea787afdee393e53a82911", subkey2_hex)
  assert_equal("5c732520d71c97bbf253f0c065e8f2aa2af15902cf2ce3973fbba51efc00a182", subkey3_hex)
  assert_equal("74a98824faf4137dfe52678b6e1f865eafa331f322422373f369d3796017b37be69b8813e13810014ad18aa34e4eae9a001d", subkey4_hex)
end

assert("Hydro::Kx") do
  client_static_kp = Hydro::Kx::Keypair.new
  server_static_kp = Hydro::Kx::Keypair.new

  st_client = Hydro::Kx.new
  st_server = Hydro::Kx.new
  response1 = st_client.xx_1
  response2 = st_server.xx_2(response1, server_static_kp)
  kp_client, response3, client_peer_pk = st_client.xx_3(response2, client_static_kp)
  kp_server, server_peer_pk = st_server.xx_4(response3)

  assert_equal(kp_client[:tx], kp_server[:rx])
  assert_equal(kp_client[:rx], kp_server[:tx])

  psk = RandomBytes.buf(Hydro::Kx::PSKBYTES)
  response1 = st_client.xx_1(psk)
  response2 = st_server.xx_2(response1, server_static_kp, psk)
  kp_client, response3, client_peer_pk = st_client.xx_3(response2, client_static_kp, psk)
  kp_server, server_peer_pk = st_server.xx_4(response3, psk)

  assert_equal(kp_client[:tx], kp_server[:rx])
  assert_equal(kp_client[:rx], kp_server[:tx])
  assert_equal(client_peer_pk, server_static_kp.pk)
  assert_equal(server_peer_pk, client_static_kp.pk)
end
