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
}
