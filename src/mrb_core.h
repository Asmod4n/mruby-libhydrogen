static mrb_value
mrb_hydro_increment(mrb_state *mrb, mrb_value hydro_mod)
{
  mrb_value n;
  mrb_get_args(mrb, "S", &n);
  mrb_str_modify(mrb, RSTRING(n));

  hydro_increment((uint8_t *) RSTRING_PTR(n), RSTRING_LEN(n));

  return n;
}

static mrb_value
mrb_hydro_bin2hex(mrb_state *mrb, mrb_value hydro_mod)
{
  char *bin;
  mrb_int bin_len;
  mrb_get_args(mrb, "s", &bin, &bin_len);

  mrb_int hex_len;
  if(unlikely(mrb_int_mul_overflow(bin_len, 2, &hex_len))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "bin_len is too large");
  }

  mrb_value hex = mrb_str_new(mrb, NULL, hex_len);
  char *h = hydro_bin2hex(RSTRING_PTR(hex), RSTRING_LEN(hex) + 1,
    (const uint8_t *) bin, bin_len);
  assert(h);

  return hex;
}
