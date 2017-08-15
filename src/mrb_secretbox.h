static mrb_value
mrb_hydro_secretbox_keygen(mrb_state *mrb, mrb_value hydro_secretbox_class)
{
  mrb_value key = mrb_str_new(mrb, NULL, hydro_secretbox_KEYBYTES);
  hydro_secretbox_keygen((uint8_t *) RSTRING_PTR(key));
  return key;
}

static mrb_value
mrb_hydro_secretbox_encrypt(mrb_state *mrb, mrb_value hydro_secretbox_module)
{
  mrb_value m;
  const char *ctx;
  mrb_value key;
  mrb_int msg_id = 0;
  mrb_get_args(mrb, "SzS|i", &m, &ctx, &key, &msg_id);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_secretbox_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(key), hydro_secretbox_KEYBYTES, "key");
  mrb_assert_int_fit(mrb_int, msg_id, uint64_t, UINT64_MAX);
  mrb_int ciphertext_len;
  if(unlikely(mrb_int_add_overflow(RSTRING_LEN(m), hydro_secretbox_HEADERBYTES, &ciphertext_len))) {
    mrb_raise(mrb, E_RANGE_ERROR, "mlen is too large");
  }
  mrb_value ciphertext = mrb_str_new(mrb, NULL, ciphertext_len);

  int rc = hydro_secretbox_encrypt((uint8_t *) RSTRING_PTR(ciphertext),
    RSTRING_PTR(m), RSTRING_LEN(m),
    msg_id,
    ctx,
    (const uint8_t *) RSTRING_PTR(key));
  assert(rc == 0);

  return ciphertext;
}

static mrb_value
mrb_hydro_secretbox_decrypt(mrb_state *mrb, mrb_value hydro_secretbox_module)
{
  mrb_value c;
  const char *ctx;
  mrb_value key;
  mrb_int msg_id = 0;
  mrb_get_args(mrb, "SzS|i", &c, &ctx, &key, &msg_id);
  if (RSTRING_LEN(c) < hydro_secretbox_HEADERBYTES) {
    mrb_raise(mrb, E_RANGE_ERROR, "ciphertext is too short");
  }
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_secretbox_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(key), hydro_secretbox_KEYBYTES, "key");
  mrb_assert_int_fit(mrb_int, msg_id, uint64_t, UINT64_MAX);
  mrb_value m = mrb_str_new(mrb, NULL, RSTRING_LEN(c) - hydro_secretbox_HEADERBYTES);

  int rc = hydro_secretbox_decrypt(RSTRING_PTR(m),
    (const uint8_t *) RSTRING_PTR(c), RSTRING_LEN(c),
    msg_id,
    ctx,
    (const uint8_t *) RSTRING_PTR(key));

  if (rc != 0) {
    mrb_raise(mrb, E_HYDRO_ERROR, "message forged!");
  }

  return m;
}
