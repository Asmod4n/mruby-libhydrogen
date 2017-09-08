static mrb_value
mrb_hydro_hash_keygen(mrb_state *mrb, mrb_value hydro_hash_class)
{
  mrb_int key_len = hydro_hash_KEYBYTES;
  mrb_get_args(mrb, "|i", &key_len);
  mrb_hydro_check_length_between(mrb, key_len, hydro_hash_KEYBYTES_MIN, hydro_hash_KEYBYTES_MAX, "key_len");
  mrb_value key = mrb_str_new(mrb, NULL, key_len);

  hydro_hash_keygen((uint8_t *) RSTRING_PTR(key), key_len);

  return key;
}

static mrb_value
mrb_hydro_hash_init(mrb_state *mrb, mrb_value self)
{
  const char *ctx;
  mrb_value key;
  mrb_get_args(mrb, "zS", &ctx, &key);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_hash_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length_between(mrb, RSTRING_LEN(key), hydro_hash_KEYBYTES_MIN, hydro_hash_KEYBYTES_MAX, "key");

  hydro_hash_state *state = (hydro_hash_state *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*state));
  mrb_data_init(self, state, &mrb_hydro_hash_state);
  int rc = hydro_hash_init(state, ctx, (const uint8_t *) RSTRING_PTR(key), RSTRING_LEN(key));
  assert(rc == 0);

  return self;
}

static mrb_value
mrb_hydro_hash_update(mrb_state *mrb, mrb_value self)
{
  mrb_value in;
  mrb_get_args(mrb, "S", &in);

  int rc = hydro_hash_update(DATA_GET_PTR(mrb, self, &mrb_hydro_hash_state, hydro_hash_state),
    RSTRING_PTR(in), RSTRING_LEN(in));
  assert(rc == 0);

  return self;
}

static mrb_value
mrb_hydro_hash_final(mrb_state *mrb, mrb_value self)
{
  mrb_int out_len = hydro_hash_BYTES;
  mrb_get_args(mrb, "|i", &out_len);
  mrb_hydro_check_length_between(mrb, out_len, hydro_hash_BYTES_MIN, hydro_hash_BYTES_MAX, "out_len");
  mrb_value out = mrb_str_new(mrb, NULL, out_len);

  int rc = hydro_hash_final(DATA_GET_PTR(mrb, self, &mrb_hydro_hash_state, hydro_hash_state), (uint8_t *) RSTRING_PTR(out), out_len);
  assert(rc == 0);

  return out;
}

static mrb_value
mrb_hydro_hash_hash(mrb_state *mrb, mrb_value hydro_hash_class)
{
  mrb_value in;
  const char *ctx;
  mrb_value key;
  mrb_int out_len = hydro_hash_BYTES;
  mrb_get_args(mrb, "SzS|i", &in, &ctx, &key, &out_len);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_hash_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length_between(mrb, RSTRING_LEN(key), hydro_hash_KEYBYTES_MIN, hydro_hash_KEYBYTES_MAX, "key");
  mrb_hydro_check_length_between(mrb, out_len, hydro_hash_BYTES_MIN, hydro_hash_BYTES_MAX, "out");
  mrb_value out = mrb_str_new(mrb, NULL, out_len);

  int rc = hydro_hash_hash((uint8_t *) RSTRING_PTR(out), out_len,
    RSTRING_PTR(in), RSTRING_LEN(in),
    ctx,
    (const uint8_t *) RSTRING_PTR(key), RSTRING_LEN(key));
  assert(rc == 0);

  return out;
}

static void
mrb_hydro_hash_gem_init(mrb_state *mrb, struct RClass *hydro_mod)
{
  struct RClass *hydro_hash_cl = mrb_define_class_under(mrb, hydro_mod, "Hash", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_hash_cl, MRB_TT_DATA);
  mrb_define_const(mrb, hydro_hash_cl, "BYTES", mrb_fixnum_value(hydro_hash_BYTES));
  mrb_define_const(mrb, hydro_hash_cl, "BYTES_MAX", mrb_fixnum_value(hydro_hash_BYTES_MAX));
  mrb_define_const(mrb, hydro_hash_cl, "BYTES_MIN", mrb_fixnum_value(hydro_hash_BYTES_MIN));
  mrb_define_const(mrb, hydro_hash_cl, "CONTEXTBYTES", mrb_fixnum_value(hydro_hash_CONTEXTBYTES));
  mrb_define_const(mrb, hydro_hash_cl, "KEYBYTES", mrb_fixnum_value(hydro_hash_KEYBYTES));
  mrb_define_const(mrb, hydro_hash_cl, "KEYBYTES_MAX", mrb_fixnum_value(hydro_hash_KEYBYTES_MAX));
  mrb_define_const(mrb, hydro_hash_cl, "KEYBYTES_MIN", mrb_fixnum_value(hydro_hash_KEYBYTES_MIN));
  mrb_define_class_method(mrb, hydro_hash_cl, "keygen", mrb_hydro_hash_keygen, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, hydro_hash_cl, "initialize", mrb_hydro_hash_init, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, hydro_hash_cl, "update", mrb_hydro_hash_update, MRB_ARGS_REQ(1));
  mrb_define_alias(mrb, hydro_hash_cl, "<<", "update");
  mrb_define_method(mrb, hydro_hash_cl, "final", mrb_hydro_hash_final, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, hydro_hash_cl, "hash", mrb_hydro_hash_hash, MRB_ARGS_ARG(3, 1));
}
