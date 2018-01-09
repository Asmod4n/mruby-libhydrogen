static mrb_value
mrb_hydro_sign_create(mrb_state *mrb, mrb_value hydro_sign_class)
{
  mrb_value m_;
  const char *ctx;
  mrb_value sk;
  mrb_get_args(mrb, "SzS", &m_, &ctx, &sk);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_sign_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(sk), hydro_sign_SECRETKEYBYTES, "sk");

  mrb_value csig = mrb_str_new(mrb, NULL, hydro_sign_BYTES);
  int rc = hydro_sign_create((uint8_t *) RSTRING_PTR(csig),
    RSTRING_PTR(m_), RSTRING_LEN(m_),
    ctx,
    (const uint8_t *) RSTRING_PTR(sk));
  assert(rc == 0);

  return csig;
}

static mrb_value
mrb_hydro_sign_verify(mrb_state *mrb, mrb_value hydro_sign_class)
{
  mrb_value csig, m_;
  const char *ctx;
  mrb_value pk;
  mrb_get_args(mrb, "SSzS", &csig, &m_, &ctx, &pk);
  mrb_hydro_check_length(mrb, RSTRING_LEN(csig), hydro_sign_BYTES, "csig");
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_sign_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(pk), hydro_sign_PUBLICKEYBYTES, "pk");

  int rc = hydro_sign_verify((const uint8_t *) RSTRING_PTR(csig),
    RSTRING_PTR(m_), RSTRING_LEN(m_),
    ctx,
    (const uint8_t *) RSTRING_PTR(pk));

  return mrb_bool_value(rc == 0);
}

static mrb_value
mrb_hydro_sign_keygen(mrb_state *mrb, mrb_value hydro_sign_class)
{
  mrb_value seed = mrb_nil_value();
  mrb_get_args(mrb, "|S!", &seed);

  hydro_sign_keypair keypair;
  if (mrb_string_p(seed)) {
    mrb_hydro_check_length(mrb, RSTRING_LEN(seed), hydro_sign_SEEDBYTES, "seed");
    hydro_sign_keygen_deterministic(&keypair, (const uint8_t *) RSTRING_PTR(seed));
  } else {
    hydro_sign_keygen(&keypair);
  }

  mrb_value keypair_val = mrb_hash_new_capa(mrb, 2);
  mrb_value pk = mrb_str_new(mrb, (const char *) keypair.pk, hydro_sign_PUBLICKEYBYTES);
  mrb_value sk = mrb_str_new(mrb, (const char *) keypair.sk, hydro_sign_SECRETKEYBYTES);
  mrb_hash_set(mrb, keypair_val, mrb_symbol_value(mrb_intern_lit(mrb, "pk")), pk);
  mrb_hash_set(mrb, keypair_val, mrb_symbol_value(mrb_intern_lit(mrb, "sk")), sk);

  return keypair_val;
}

static void
mrb_hydro_sign_gem_init(mrb_state *mrb, struct RClass *hydro_mod)
{
  struct RClass *hydro_sign_cl = mrb_define_class_under(mrb, hydro_mod, "Sign", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_sign_cl, MRB_TT_DATA);
  mrb_define_const(mrb, hydro_sign_cl, "BYTES", mrb_fixnum_value(hydro_sign_BYTES));
  mrb_define_const(mrb, hydro_sign_cl, "CONTEXTBYTES", mrb_fixnum_value(hydro_sign_CONTEXTBYTES));
  mrb_define_const(mrb, hydro_sign_cl, "PUBLICKEYBYTES", mrb_fixnum_value(hydro_sign_PUBLICKEYBYTES));
  mrb_define_const(mrb, hydro_sign_cl, "SECRETKEYBYTES", mrb_fixnum_value(hydro_sign_SECRETKEYBYTES));
  mrb_define_const(mrb, hydro_sign_cl, "SEEDBYTES", mrb_fixnum_value(hydro_sign_SEEDBYTES));
  mrb_define_class_method(mrb, hydro_sign_cl, "keygen", mrb_hydro_sign_keygen, MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, hydro_sign_cl, "create", mrb_hydro_sign_create, MRB_ARGS_REQ(3));
  mrb_define_class_method(mrb, hydro_sign_cl, "verify?", mrb_hydro_sign_verify, MRB_ARGS_REQ(4));
}
