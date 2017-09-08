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

static void
mrb_hydro_kdf_gem_init(mrb_state *mrb, struct RClass *hydro_mod)
{
  struct RClass *hydro_kdf_mod = mrb_define_class_under(mrb, hydro_mod, "Kdf", mrb->object_class);
  mrb_define_const(mrb, hydro_kdf_mod, "CONTEXTBYTES", mrb_fixnum_value(hydro_kdf_CONTEXTBYTES));
  mrb_define_const(mrb, hydro_kdf_mod, "KEYBYTES", mrb_fixnum_value(hydro_kdf_KEYBYTES));
  mrb_define_const(mrb, hydro_kdf_mod, "BYTES_MAX", mrb_fixnum_value(hydro_kdf_BYTES_MAX));
  mrb_define_const(mrb, hydro_kdf_mod, "BYTES_MIN", mrb_fixnum_value(hydro_kdf_BYTES_MIN));
  mrb_define_module_function(mrb, hydro_kdf_mod, "keygen", mrb_hydro_kdf_keygen, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, hydro_kdf_mod, "derive_from_key", mrb_hydro_kdf_derive_from_key, MRB_ARGS_ARG(3, 1));
}
