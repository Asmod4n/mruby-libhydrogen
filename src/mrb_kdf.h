static mrb_value
mrb_hydro_kdf_keygen(mrb_state *mrb, mrb_value hydro_kdf_module)
{
  mrb_value key = mrb_str_new(mrb, NULL, hydro_kdf_KEYBYTES);
  hydro_kdf_keygen((uint8_t *) RSTRING_PTR(key));
  return key;
}

static mrb_value
mrb_hydro_kdf_derive_from_key(mrb_state *mrb, mrb_value hydro_kdf_module)
{
  mrb_int subkey_id;
  const char *ctx;
  mrb_value key;
  mrb_int subkey_len = hydro_kdf_KEYBYTES;
  mrb_get_args(mrb, "izS|i", &subkey_id, &ctx, &key, &subkey_len);
  mrb_assert_int_fit(mrb_int, subkey_id, uint64_t, UINT64_MAX);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_kdf_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(key), hydro_kdf_KEYBYTES, "key");
  mrb_hydro_check_length_between(mrb, subkey_len, hydro_kdf_BYTES_MIN, hydro_kdf_BYTES_MAX, "subkey_len");
  mrb_value subkey = mrb_str_new(mrb, NULL, subkey_len);

  int rc = hydro_kdf_derive_from_key((uint8_t *) RSTRING_PTR(subkey), subkey_len,
    subkey_id,
    ctx,
    (const uint8_t *) RSTRING_PTR(key));
  assert(rc == 0);

  return subkey;
}
