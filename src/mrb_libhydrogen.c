#include "mrb_libhydrogen.h"

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

  return mrb_fixnum_value((mrb_int) randombytes_uniform((uint32_t) upper_bound));
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

  randombytes_buf_deterministic(RSTRING_PTR(buf), len, (uint8_t *) RSTRING_PTR(seed));

  return buf;
}

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
  size_t key_len = mrb_hydro_check_length_between(mrb, RSTRING_LEN(key), hydro_hash_KEYBYTES_MIN, hydro_hash_KEYBYTES_MAX, "key");

  hydro_hash_state *state = mrb_realloc(mrb, DATA_PTR(self), sizeof(*state));
  mrb_data_init(self, state, &mrb_hydro_hash_type);

  int rc = hydro_hash_init(state, ctx, (uint8_t *) RSTRING_PTR(key), key_len);
  assert(rc == 0);

  return self;
}

static mrb_value
mrb_hydro_hash_update(mrb_state *mrb, mrb_value self)
{
  char *in;
  mrb_int in_len;
  mrb_get_args(mrb, "s", &in, &in_len);

  int rc = hydro_hash_update((hydro_hash_state *) DATA_PTR(self), (uint8_t *) in, in_len);
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

  int rc = hydro_hash_final((hydro_hash_state *) DATA_PTR(self), (uint8_t *) RSTRING_PTR(out), out_len);
  assert(rc == 0);

  return out;
}

static mrb_value
mrb_hydro_hash_hash(mrb_state *mrb, mrb_value hydro_hash_class)
{
  char *in;
  mrb_int in_len;
  const char *ctx;
  mrb_value key;
  mrb_int out_len = hydro_hash_BYTES;
  mrb_get_args(mrb, "szS|i", &in, &in_len, &ctx, &key, &out_len);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_hash_CONTEXTBYTES, "ctx");
  size_t key_len = mrb_hydro_check_length_between(mrb, RSTRING_LEN(key), hydro_hash_KEYBYTES_MIN, hydro_hash_KEYBYTES_MAX, "key");
  mrb_hydro_check_length_between(mrb, out_len, hydro_hash_BYTES_MIN, hydro_hash_BYTES_MAX, "out");
  mrb_value out = mrb_str_new(mrb, NULL, out_len);

  int rc = hydro_hash_hash((uint8_t *) RSTRING_PTR(out), out_len, in, in_len, ctx, (uint8_t *) RSTRING_PTR(key), key_len);
  assert(rc == 0);

  return out;
}

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
  char *m;
  mrb_int mlen;
  const char *ctx;
  mrb_value key;
  mrb_int msg_id = 0;
  mrb_get_args(mrb, "szS|i", &m, &mlen, &ctx, &key, &msg_id);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_secretbox_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(key), hydro_secretbox_KEYBYTES, "key");
  mrb_assert_int_fit(mrb_int, msg_id, uint64_t, UINT64_MAX);
  mrb_int ciphertext_len;
  if(unlikely(mrb_int_add_overflow(mlen, hydro_secretbox_HEADERBYTES, &ciphertext_len))) {
    mrb_raise(mrb, E_RANGE_ERROR, "mlen is too large");
  }
  mrb_value ciphertext = mrb_str_new(mrb, NULL, ciphertext_len);

  int rc = hydro_secretbox_encrypt((uint8_t *) RSTRING_PTR(ciphertext), m, mlen, msg_id, ctx, (uint8_t *) RSTRING_PTR(key));
  assert(rc == 0);

  return ciphertext;
}

static mrb_value
mrb_hydro_secretbox_decrypt(mrb_state *mrb, mrb_value hydro_secretbox_module)
{
  char *c;
  mrb_int clen;
  const char *ctx;
  mrb_value key;
  mrb_int msg_id = 0;
  mrb_get_args(mrb, "szS|i", &c, &clen, &ctx, &key, &msg_id);
  if (clen < hydro_secretbox_HEADERBYTES) {
    mrb_raise(mrb, E_RANGE_ERROR, "ciphertext is too short");
  }
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_secretbox_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(key), hydro_secretbox_KEYBYTES, "key");
  mrb_assert_int_fit(mrb_int, msg_id, uint64_t, UINT64_MAX);
  mrb_value m = mrb_str_new(mrb, NULL, clen - hydro_secretbox_HEADERBYTES);

  int rc = hydro_secretbox_decrypt(RSTRING_PTR(m), (uint8_t *) c, clen, msg_id, ctx, (uint8_t *) RSTRING_PTR(key));
  assert(rc == 0);

  return m;
}

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
  mrb_int subkey_len = 32;
  mrb_get_args(mrb, "izS|i", &subkey_id, &ctx, &key, &subkey_len);
  mrb_assert_int_fit(mrb_int, subkey_id, uint64_t, UINT64_MAX);
  mrb_hydro_check_length(mrb, strlen(ctx), hydro_kdf_CONTEXTBYTES, "ctx");
  mrb_hydro_check_length(mrb, RSTRING_LEN(key), hydro_kdf_KEYBYTES, "key");
  mrb_hydro_check_length_between(mrb, subkey_len, hydro_kdf_BYTES_MIN, hydro_kdf_BYTES_MAX, "subkey_len");
  mrb_value subkey = mrb_str_new(mrb, NULL, subkey_len);

  int rc = hydro_kdf_derive_from_key((uint8_t *) RSTRING_PTR(subkey), subkey_len, subkey_id, ctx, (uint8_t *) RSTRING_PTR(key));
  assert(rc == 0);

  return subkey;
}

void
mrb_mruby_libhydrogen_gem_init(mrb_state* mrb)
{
  errno = 0;
  if (hydro_init() != 0) {
      mrb_sys_fail(mrb, "hydro_init");
  }

  struct RClass *randombytes_mod, *hydro_mod, *hydro_hash_cl, *hydro_secretbox_mod, *hydro_kdf_mod, *hydro_sign_cl, *hydro_kx_cl;

  randombytes_mod = mrb_define_module(mrb, "RandomBytes");
  mrb_define_const(mrb, randombytes_mod, "SEEDBYTES", mrb_fixnum_value(randombytes_SEEDBYTES));
  mrb_define_module_function(mrb, randombytes_mod, "random", mrb_randombytes_random, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, randombytes_mod, "uniform", mrb_randombytes_uniform, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, randombytes_mod, "buf", mrb_randombytes_buf, MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, randombytes_mod, "buf_deterministic", mrb_randombytes_buf_deterministic, MRB_ARGS_ARG(2, 1));

  hydro_mod = mrb_define_module(mrb, "Hydro");

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
  mrb_define_const(mrb, hydro_kx_cl, "SESSIONKEYBYTES", mrb_fixnum_value(hydro_kx_SESSIONKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "PUBLICKEYBYTES", mrb_fixnum_value(hydro_kx_PUBLICKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "SECRETKEYBYTES", mrb_fixnum_value(hydro_kx_SECRETKEYBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "PSKBYTES", mrb_fixnum_value(hydro_kx_PSKBYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE1BYTES", mrb_fixnum_value(hydro_kx_RESPONSE1BYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE2BYTES", mrb_fixnum_value(hydro_kx_RESPONSE2BYTES));
  mrb_define_const(mrb, hydro_kx_cl, "RESPONSE3BYTES", mrb_fixnum_value(hydro_kx_RESPONSE3BYTES));
}

void mrb_mruby_libhydrogen_gem_final(mrb_state* mrb) {}
