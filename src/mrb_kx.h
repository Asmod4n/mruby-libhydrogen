static mrb_value
mrb_hydro_kx_state_new(mrb_state *mrb, mrb_value self)
{
  mrb_data_init(self, mrb_realloc(mrb, DATA_PTR(self), sizeof(hydro_kx_state)), &mrb_hydro_kx_state);

  return self;
}

static mrb_value
mrb_hydro_kx_xx_1(mrb_state *mrb, mrb_value self)
{
  char *psk = NULL;
  mrb_int psk_len = 0;
  mrb_get_args(mrb, "|s!", &psk, &psk_len);
  if (psk) {
    mrb_hydro_check_length(mrb, psk_len, hydro_kx_PSKBYTES, "psk");
  }

  mrb_value response1 = mrb_str_new(mrb, NULL, hydro_kx_RESPONSE1BYTES);
  int rc = hydro_kx_xx_1(DATA_GET_PTR(mrb, self, &mrb_hydro_kx_state, hydro_kx_state),
    (uint8_t *) RSTRING_PTR(response1),
    (const uint8_t *) psk);
  assert(rc == 0);
  return response1;
}

static mrb_value
mrb_hydro_kx_xx_2(mrb_state *mrb, mrb_value self)
{
  mrb_value response1;
  const hydro_kx_keypair *static_kp;
  char *psk = NULL;
  mrb_int psk_len = 0;
  mrb_get_args(mrb, "Sd|s!", &response1, &static_kp, &mrb_hydro_kx_keypair, &psk, &psk_len);
  mrb_hydro_check_length(mrb, RSTRING_LEN(response1), hydro_kx_RESPONSE1BYTES, "response1");
  if (psk) {
    mrb_hydro_check_length(mrb, psk_len, hydro_kx_PSKBYTES, "psk");
  }

  mrb_value response2 = mrb_str_new(mrb, NULL, hydro_kx_RESPONSE2BYTES);
  int rc = hydro_kx_xx_2(DATA_GET_PTR(mrb, self, &mrb_hydro_kx_state, hydro_kx_state),
    (uint8_t *) RSTRING_PTR(response2),
    (const uint8_t *) RSTRING_PTR(response1),
    (const uint8_t *) psk,
    static_kp);

  if (rc != 0) {
    mrb_raise(mrb, E_HYDRO_KX_ERROR, "Key Exchange Error");
  }

  return response2;
}

static mrb_value
mrb_hydro_kx_xx_3(mrb_state *mrb, mrb_value self)
{
  mrb_value response2;
  const hydro_kx_keypair *static_kp;
  char *psk = NULL;
  mrb_int psk_len = 0;
  mrb_get_args(mrb, "Sd|s!", &response2, &static_kp, &mrb_hydro_kx_keypair, &psk, &psk_len);
  mrb_hydro_check_length(mrb, RSTRING_LEN(response2), hydro_kx_RESPONSE2BYTES, "response2");
  if (psk) {
    mrb_hydro_check_length(mrb, psk_len, hydro_kx_PSKBYTES, "psk");
  }

  hydro_kx_session_keypair kp;
  mrb_value out = mrb_ary_new_capa(mrb, 3);
  mrb_value keypair = mrb_hash_new_capa(mrb, 2);
  mrb_value rx = mrb_str_new(mrb, NULL, hydro_kx_SESSIONKEYBYTES);
  mrb_value tx = mrb_str_new(mrb, NULL, hydro_kx_SESSIONKEYBYTES);
  mrb_value response3 = mrb_str_new(mrb, NULL, hydro_kx_RESPONSE3BYTES);
  mrb_value peer_static_pk = mrb_str_new(mrb, NULL, hydro_kx_PUBLICKEYBYTES);
  mrb_hash_set(mrb, keypair, mrb_symbol_value(mrb_intern_lit(mrb, "rx")), rx);
  mrb_hash_set(mrb, keypair, mrb_symbol_value(mrb_intern_lit(mrb, "tx")), tx);
  mrb_ary_push(mrb, out, keypair);
  mrb_ary_push(mrb, out, response3);
  mrb_ary_push(mrb, out, peer_static_pk);

  int rc = hydro_kx_xx_3(DATA_GET_PTR(mrb, self, &mrb_hydro_kx_state, hydro_kx_state),
    &kp,
   (uint8_t *) RSTRING_PTR(response3),
   (uint8_t *) RSTRING_PTR(peer_static_pk),
   (const uint8_t *) RSTRING_PTR(response2),
   (const uint8_t *) psk,
   static_kp);

  if (rc != 0) {
    mrb_raise(mrb, E_HYDRO_KX_ERROR, "Key Exchange Error");
  }

  memcpy(RSTRING_PTR(rx), kp.rx, hydro_kx_SESSIONKEYBYTES);
  memcpy(RSTRING_PTR(tx), kp.tx, hydro_kx_SESSIONKEYBYTES);

  return out;
}

static mrb_value
mrb_hydro_kx_xx_4(mrb_state *mrb, mrb_value self)
{
  mrb_value response3;
  char *psk = NULL;
  mrb_int psk_len = 0;
  mrb_get_args(mrb, "S|s!", &response3, &psk, &psk_len);
  mrb_hydro_check_length(mrb, RSTRING_LEN(response3), hydro_kx_RESPONSE3BYTES, "response3");
  if (psk) {
    mrb_hydro_check_length(mrb, psk_len, hydro_kx_PSKBYTES, "psk");
  }

  hydro_kx_session_keypair kp;
  mrb_value out = mrb_ary_new_capa(mrb, 2);
  mrb_value keypair = mrb_hash_new_capa(mrb, 2);
  mrb_value rx = mrb_str_new(mrb, NULL, hydro_kx_SESSIONKEYBYTES);
  mrb_value tx = mrb_str_new(mrb, NULL, hydro_kx_SESSIONKEYBYTES);
  mrb_value peer_static_pk = mrb_str_new(mrb, NULL, hydro_kx_PUBLICKEYBYTES);
  mrb_hash_set(mrb, keypair, mrb_symbol_value(mrb_intern_lit(mrb, "rx")), rx);
  mrb_hash_set(mrb, keypair, mrb_symbol_value(mrb_intern_lit(mrb, "tx")), tx);
  mrb_ary_push(mrb, out, keypair);
  mrb_ary_push(mrb, out, peer_static_pk);

  int rc = hydro_kx_xx_4(DATA_GET_PTR(mrb, self, &mrb_hydro_kx_state, hydro_kx_state),
    &kp,
    (uint8_t *) RSTRING_PTR(peer_static_pk),
    (const uint8_t *) RSTRING_PTR(response3),
    (const uint8_t *) psk);

  if (rc != 0) {
    mrb_raise(mrb, E_HYDRO_KX_ERROR, "Key Exchange Error");
  }

  memcpy(RSTRING_PTR(rx), kp.rx, hydro_kx_SESSIONKEYBYTES);
  memcpy(RSTRING_PTR(tx), kp.tx, hydro_kx_SESSIONKEYBYTES);

  return out;
}

static mrb_value
mrb_hydro_kx_keygen(mrb_state *mrb, mrb_value self)
{
  mrb_value seed = mrb_nil_value();
  mrb_get_args(mrb, "|S!", &seed);
  if (mrb_string_p(seed)) {
    mrb_hydro_check_length(mrb, RSTRING_LEN(seed), hydro_kx_SEEDBYTES, "seed");
    hydro_kx_keypair *keypair = (hydro_kx_keypair *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*keypair));
    mrb_data_init(self, keypair, &mrb_hydro_kx_keypair);
    hydro_kx_keygen_deterministic(keypair, (const uint8_t *) RSTRING_PTR(seed));
  } else {
    hydro_kx_keypair *keypair = (hydro_kx_keypair *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*keypair));
    mrb_data_init(self, keypair, &mrb_hydro_kx_keypair);
    hydro_kx_keygen(keypair);
  }

  return self;
}

static mrb_value
mrb_hydro_kx_keypair_pk(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new(mrb, (const char *) (DATA_GET_PTR(mrb, self, &mrb_hydro_kx_keypair, hydro_kx_keypair))->pk, hydro_kx_PUBLICKEYBYTES);
}

static mrb_value
mrb_hydro_kx_keypair_sk(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new(mrb, (const char *) (DATA_GET_PTR(mrb, self, &mrb_hydro_kx_keypair, hydro_kx_keypair))->sk, hydro_kx_SECRETKEYBYTES);
}

static void
mrb_hydro_kx_gem_init(mrb_state *mrb, struct RClass *hydro_mod, struct RClass *hydro_error_cl)
{
  struct RClass *hydro_kx_cl = mrb_define_class_under(mrb, hydro_mod, "Kx", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_kx_cl, MRB_TT_DATA);
  mrb_define_class_under(mrb, hydro_kx_cl, "Error", hydro_error_cl);
  mrb_define_const(mrb, hydro_kx_cl, "SESSIONKEYBYTES", mrb_fixnum_value(hydro_kx_SESSIONKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "PUBLICKEYBYTES", mrb_fixnum_value(hydro_kx_PUBLICKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "SECRETKEYBYTES", mrb_fixnum_value(hydro_kx_SECRETKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "PSKBYTES", mrb_fixnum_value(hydro_kx_PSKBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE1BYTES", mrb_fixnum_value(hydro_kx_RESPONSE1BYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE2BYTES", mrb_fixnum_value(hydro_kx_RESPONSE2BYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE3BYTES", mrb_fixnum_value(hydro_kx_RESPONSE3BYTES));
  mrb_define_method(mrb, hydro_kx_cl, "initialize", mrb_hydro_kx_state_new, MRB_ARGS_NONE());
  mrb_define_method(mrb, hydro_kx_cl, "xx_1", mrb_hydro_kx_xx_1, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, hydro_kx_cl, "xx_2", mrb_hydro_kx_xx_2, MRB_ARGS_ARG(2, 1));
  mrb_define_method(mrb, hydro_kx_cl, "xx_3", mrb_hydro_kx_xx_3, MRB_ARGS_ARG(2, 1));
  mrb_define_method(mrb, hydro_kx_cl, "xx_4", mrb_hydro_kx_xx_4, MRB_ARGS_ARG(1, 1));

  struct RClass *hydro_kx_keypair_cl = mrb_define_class_under(mrb, hydro_kx_cl, "Keypair", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_kx_keypair_cl, MRB_TT_DATA);
  mrb_define_method(mrb, hydro_kx_keypair_cl, "initialize", mrb_hydro_kx_keygen, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, hydro_kx_keypair_cl, "pk", mrb_hydro_kx_keypair_pk, MRB_ARGS_NONE());
  mrb_define_method(mrb, hydro_kx_keypair_cl, "sk", mrb_hydro_kx_keypair_sk, MRB_ARGS_NONE());
}
