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
