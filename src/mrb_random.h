static mrb_value
mrb_hydro_random_u32(mrb_state *mrb, mrb_value hydro_random_module)
{
#if (MRB_INT_BIT >= 64)
  return mrb_fixnum_value(hydro_random_u32());
#else
  return mrb_float_value(mrb, hydro_random_u32());
#endif
}

static mrb_value
mrb_hydro_random_uniform(mrb_state *mrb, mrb_value hydro_random_module)
{
  mrb_int upper_bound;
  mrb_get_args(mrb, "i", &upper_bound);
  mrb_assert_int_fit(mrb_int, upper_bound, uint32_t, UINT32_MAX);

  return mrb_fixnum_value((mrb_int) hydro_random_uniform((const uint32_t) upper_bound));
}

static mrb_value
mrb_hydro_random_buf(mrb_state *mrb, mrb_value hydro_random_module)
{
  mrb_int len;
  mrb_get_args(mrb, "i", &len);
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  mrb_value buf = mrb_str_new(mrb, NULL, len);

  hydro_random_buf(RSTRING_PTR(buf), len);

  return buf;
}

static mrb_value
mrb_hydro_random_buf_deterministic(mrb_state *mrb, mrb_value hydro_random_module)
{
  mrb_int len;
  mrb_value seed;
  mrb_get_args(mrb, "iS", &len, &seed);
  mrb_assert_int_fit(mrb_int, len, size_t, SIZE_MAX);
  mrb_hydro_check_length(mrb, RSTRING_LEN(seed), hydro_random_SEEDBYTES, "seed");
  mrb_value buf = mrb_str_new(mrb, NULL, len);

  hydro_random_buf_deterministic(RSTRING_PTR(buf), len, (const uint8_t *) RSTRING_PTR(seed));

  return buf;
}

static void
mrb_hydro_random_gem_init(mrb_state *mrb)
{
  struct RClass *hydro_random_mod = mrb_define_module(mrb, "RandomBytes");
  mrb_define_const(mrb, hydro_random_mod, "SEEDBYTES", mrb_fixnum_value(hydro_random_SEEDBYTES));
  mrb_define_module_function(mrb, hydro_random_mod, "random", mrb_hydro_random_u32, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, hydro_random_mod, "uniform", mrb_hydro_random_uniform, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, hydro_random_mod, "buf", mrb_hydro_random_buf, MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, hydro_random_mod, "buf_deterministic", mrb_hydro_random_buf_deterministic, MRB_ARGS_ARG(2, 1));
}
