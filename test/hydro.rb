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
  assert_equal("19441568ff5a5c2ffc16d526854366e301ad80e603bfc0efb54df23e65df8f7fc558a36f56f0cb84fcf126f90c76543215be076e4ecb7996af93f15a22c77eb019ec3fadae52fa6d079cbc9700418f08d640a25f9178915e12de7bae68f0b0df2796d235", hex)
  h = Hydro::Hash.hash(msg, ctx, key, 100)
  hex = Hydro.bin2hex(h)
  assert_equal("8cb8e83d64dd81394494a0e0c96a03cf5ced3b6406336697625c9b236e92b4eae056721035dd88c6f9b74c91184fe9b6ce85e56e2fbc9f11face6c5d86f879ba725a7c3ce790f71865ed814db6da7a47f7b7af76824f0299ef942367ad96429f706e1544", hex)
  h = Hydro::Hash.hash(msg, ctx, key)
  hex = Hydro.bin2hex(h)
  assert_equal("ba2c074391fc996f49d0012a4b06300114205f217ca5549ec3256bff2ffc0d32", hex)
end

assert("Hydro::Kdf") do
  dk = "\0" * RandomBytes::SEEDBYTES
  key = RandomBytes.buf_deterministic(Hydro::Kdf::KEYBYTES, dk)
  subkey1 = Hydro::Kdf.derive_from_key(1, ctx, key, 16)
  subkey2 = Hydro::Kdf.derive_from_key(2, ctx, key, 16)
  subkey3 = Hydro::Kdf.derive_from_key(0, ctx, key, 32)
  subkey4 = Hydro::Kdf.derive_from_key(0, ctx, key, 50)
  subkey1_hex = Hydro.bin2hex(subkey1)
  subkey2_hex = Hydro.bin2hex(subkey2)
  subkey3_hex = Hydro.bin2hex(subkey3)
  subkey4_hex = Hydro.bin2hex(subkey4)
  assert_equal("001347faa33e009905dd3083b3714f5d", subkey1_hex)
  assert_equal("3d584c7e3f45c5736e859515a79c6b97", subkey2_hex)
  assert_equal("fbef6b234160b014bed8791e2b963bb6841948df667bc96c77721edc0f78e4cd", subkey3_hex)
  assert_equal("440057d9221ba0e8e7ca21d274650b475aa7c8cafc3eb2711407ec23593e1adb93912b0e38a0bca2749a211df980722bfc5d", subkey4_hex)
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
