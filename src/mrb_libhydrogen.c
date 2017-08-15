#include <mruby/hydrogen.h>
#include "mrb_libhydrogen.h"
#include "mrb_hash.h"
#include "mrb_kdf.h"
#include "mrb_kx.h"
#include "mrb_random.h"
#include "mrb_secretbox.h"

void
mrb_mruby_libhydrogen_gem_init(mrb_state* mrb)
{
  errno = 0;
  if (hydro_init() != 0) {
      mrb_sys_fail(mrb, "hydro_init");
  }

  struct RClass *randombytes_mod, *hydro_mod, *hydro_error_cl, *hydro_hash_cl, *hydro_secretbox_mod, *hydro_kdf_mod, *hydro_sign_cl, *hydro_kx_cl, *hydro_kx_keypair_cl;

  randombytes_mod = mrb_define_module(mrb, "RandomBytes");
  mrb_define_const(mrb, randombytes_mod, "SEEDBYTES", mrb_fixnum_value(randombytes_SEEDBYTES));
  mrb_define_module_function(mrb, randombytes_mod, "random", mrb_randombytes_random, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, randombytes_mod, "uniform", mrb_randombytes_uniform, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, randombytes_mod, "buf", mrb_randombytes_buf, MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, randombytes_mod, "buf_deterministic", mrb_randombytes_buf_deterministic, MRB_ARGS_ARG(2, 1));

  hydro_mod = mrb_define_module(mrb, "Hydro");
  hydro_error_cl = mrb_define_class_under(mrb, hydro_mod, "Error", E_RUNTIME_ERROR);

  hydro_hash_cl = mrb_define_class_under(mrb, hydro_mod, "Hash", mrb->object_class);
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

  hydro_secretbox_mod = mrb_define_module_under(mrb, hydro_mod, "SecretBox");
  mrb_define_const(mrb, hydro_secretbox_mod, "CONTEXTBYTES", mrb_fixnum_value(hydro_secretbox_CONTEXTBYTES));
  mrb_define_const(mrb, hydro_secretbox_mod, "HEADERBYTES", mrb_fixnum_value(hydro_secretbox_HEADERBYTES));
  mrb_define_const(mrb, hydro_secretbox_mod, "KEYBYTES", mrb_fixnum_value(hydro_secretbox_KEYBYTES));
  mrb_define_const(mrb, hydro_secretbox_mod, "PROBEBYTES", mrb_fixnum_value(hydro_secretbox_PROBEBYTES));
  mrb_define_module_function(mrb, hydro_secretbox_mod, "keygen", mrb_hydro_secretbox_keygen, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, hydro_secretbox_mod, "encrypt", mrb_hydro_secretbox_encrypt, MRB_ARGS_ARG(3, 1));
  mrb_define_module_function(mrb, hydro_secretbox_mod, "decrypt", mrb_hydro_secretbox_decrypt, MRB_ARGS_ARG(3, 1));

  hydro_kdf_mod = mrb_define_class_under(mrb, hydro_mod, "Kdf", mrb->object_class);
  mrb_define_const(mrb, hydro_kdf_mod, "CONTEXTBYTES", mrb_fixnum_value(hydro_kdf_CONTEXTBYTES));
  mrb_define_const(mrb, hydro_kdf_mod, "KEYBYTES", mrb_fixnum_value(hydro_kdf_KEYBYTES));
  mrb_define_const(mrb, hydro_kdf_mod, "BYTES_MAX", mrb_fixnum_value(hydro_kdf_BYTES_MAX));
  mrb_define_const(mrb, hydro_kdf_mod, "BYTES_MAX", mrb_fixnum_value(hydro_kdf_BYTES_MIN));
  mrb_define_module_function(mrb, hydro_kdf_mod, "keygen", mrb_hydro_kdf_keygen, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, hydro_kdf_mod, "derive_from_key", mrb_hydro_kdf_derive_from_key, MRB_ARGS_ARG(3, 1));

  hydro_sign_cl = mrb_define_class_under(mrb, hydro_mod, "Sign", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_sign_cl, MRB_TT_DATA);
  mrb_define_const(mrb, hydro_sign_cl, "BYTES", mrb_fixnum_value(hydro_sign_BYTES));
  mrb_define_const(mrb, hydro_sign_cl, "CONTEXTBYTES", mrb_fixnum_value(hydro_sign_CONTEXTBYTES));
  mrb_define_const(mrb, hydro_sign_cl, "PUBLICKEYBYTES", mrb_fixnum_value(hydro_sign_PUBLICKEYBYTES));
  mrb_define_const(mrb, hydro_sign_cl, "SECRETKEYBYTES", mrb_fixnum_value(hydro_sign_SECRETKEYBYTES));
  mrb_define_const(mrb, hydro_sign_cl, "SEEDBYTES", mrb_fixnum_value(hydro_sign_SEEDBYTES));

  hydro_kx_cl = mrb_define_class_under(mrb, hydro_mod, "Kx", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_kx_cl, MRB_TT_DATA);
  mrb_define_class_under(mrb, hydro_kx_cl, "Error", hydro_error_cl);
  mrb_define_const(mrb, hydro_kx_cl, "SESSIONKEYBYTES", mrb_fixnum_value(hydro_kx_SESSIONKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "PUBLICKEYBYTES", mrb_fixnum_value(hydro_kx_PUBLICKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "SECRETKEYBYTES", mrb_fixnum_value(hydro_kx_SECRETKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "PSKBYTES", mrb_fixnum_value(hydro_kx_PSKBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE1BYTES", mrb_fixnum_value(hydro_kx_RESPONSE1BYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE2BYTES", mrb_fixnum_value(hydro_kx_RESPONSE2BYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE3BYTES", mrb_fixnum_value(hydro_kx_RESPONSE3BYTES));
  mrb_define_method(mrb, hydro_kx_cl, "initialize", mrb_hydro_kx_state_new, MRB_ARGS_NONE());
  mrb_define_method(mrb, hydro_kx_cl, "xx_1", mrb_hydro_kx_xx_1, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, hydro_kx_cl, "xx_2", mrb_hydro_kx_xx_2, MRB_ARGS_ARG(2, 1));
  mrb_define_method(mrb, hydro_kx_cl, "xx_3", mrb_hydro_kx_xx_3, MRB_ARGS_ARG(2, 1));
  mrb_define_method(mrb, hydro_kx_cl, "xx_4", mrb_hydro_kx_xx_4, MRB_ARGS_ARG(1, 1));

  hydro_kx_keypair_cl = mrb_define_class_under(mrb, hydro_kx_cl, "Keypair", mrb->object_class);
  MRB_SET_INSTANCE_TT(hydro_kx_keypair_cl, MRB_TT_DATA);
  mrb_define_method(mrb, hydro_kx_keypair_cl, "initialize", mrb_hydro_kx_keygen, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, hydro_kx_keypair_cl, "pk", mrb_hydro_kx_keypair_pk, MRB_ARGS_NONE());
  mrb_define_method(mrb, hydro_kx_keypair_cl, "sk", mrb_hydro_kx_keypair_sk, MRB_ARGS_NONE());

}

void mrb_mruby_libhydrogen_gem_final(mrb_state* mrb) {}
