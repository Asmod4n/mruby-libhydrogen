static mrb_value
mrb_randombytes_random(mrb_state *mrb, mrb_value randombytes_module)
{
#if (MRB_INT_BIT >= 64)
  return mrb_fixnum_value(randombytes_random());
#else
  return mrb_float_value(mrb, randombytes_random());
#endif
}

static mrb_value
mrb_randombytes_uniform(mrb_state *mrb, mrb_value randombytes_module)
{
  mrb_int upper_bound;
  mrb_get_args(mrb, "i", &upper_bound);
  mrb_assert_int_fit(mrb_int, upper_bound, uint32_t, UINT32_MAX);

  return mrb_fixnum_value((mrb_int) randombytes_uniform((const uint32_t) upper_bound));
}

static mrb_value
mrb_randombytes_buf(mrb_state *mrb, mrb_value randombytes_module)
{
  mrb_int len;
  mrb_get_args(mrb, "i", &len);
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  mrb_value buf = mrb_str_new(mrb, NULL, len);

  randombytes_buf(RSTRING_PTR(buf), len);

  return buf;
}

static mrb_value
mrb_randombytes_buf_deterministic(mrb_state *mrb, mrb_value randombytes_module)
{
  mrb_int len;
  mrb_value seed;
  mrb_get_args(mrb, "iS", &len, &seed);
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  mrb_hydro_check_length(mrb, RSTRING_LEN(seed), randombytes_SEEDBYTES, "seed");
  mrb_value buf = mrb_str_new(mrb, NULL, len);

  randombytes_buf_deterministic(RSTRING_PTR(buf), len, (const uint8_t *) RSTRING_PTR(seed));

  return buf;
}
