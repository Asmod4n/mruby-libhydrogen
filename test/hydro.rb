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
  key =  RandomBytes.buf_deterministic(Hydro::Hash::KEYBYTES, dk)
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
  assert_equal("e5d2beb77a039965850ee76327e06b2fa6cb5121db8038b11bce4641a9c4bd843658104bdf07342570bb5fd1d72c0d31a8981b47c718fddaffbd4171605c873cbaf921bb57988dd814f3a3fbef9799ff7c762705c4bf37ab29815981bf0d8833d60afe14", hex)
  h = Hydro::Hash.hash(100, msg, ctx, key)
  hex = Hydro.bin2hex(h)
  assert_equal("724bd8883df73320ffd70923cb997f9a99bc670c4d78887be4975add0099fbf489b266a85d1f56743062d60a05590cbce47e45108367879bf4641cbaefe584e8618cbeb8c230ae956da22c7c5c4f11a8804ca576ec20fa5da239dde3d03a6018383c21f5", hex)
  h = Hydro::Hash.hash(Hydro::Hash::BYTES, msg, ctx, key)
  hex = Hydro.bin2hex(h)
  assert_equal("7dfa45ce18210e2422fd658bf7beccb6e534e44f99ae359f4af3ba41af8ca463", hex)
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
  assert_equal("af8019d3516d4ba6c80a7ea5a87e4d77", subkey1_hex)
  assert_equal("af8c4cba4e1f36c293631cc7001717dd", subkey2_hex)
  assert_equal("ff9345489dea1e4fe59194cea8794c9b0af9380c2d18c3ab38eeef2af95c1e26", subkey3_hex)
  assert_equal("a8dd79ca19d604d1487b82d76b8d4ad4138a29dfaeeb207b99b2e5904e7855555bb94a76070fa71871df6ed911661d99efec", subkey4_hex)
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
