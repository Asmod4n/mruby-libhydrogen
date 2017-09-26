#include <errno.h>
#include "../deps/libhydrogen/hydrogen.c"
#include <mruby/error.h>
#include <mruby/value.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <mruby/numeric.h>
#include <assert.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <string.h>

#if (__GNUC__ >= 3) || (__INTEL_COMPILER >= 800) || defined(__clang__)
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

MRB_INLINE void
mrb_hydro_check_length(mrb_state *mrb, mrb_int obj_size, int hydro_const, const char *type)
{
  if (unlikely(obj_size != hydro_const)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "expected a length == %S bytes %S, got %S bytes",
      mrb_fixnum_value(hydro_const),
      mrb_str_new_static(mrb, type, strlen(type)),
      mrb_fixnum_value(obj_size));
  }
}

MRB_INLINE void
mrb_hydro_check_length_between(mrb_state *mrb, mrb_int obj_size, int min, int max, const char *type)
{
  if (unlikely(obj_size < min||obj_size > max)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "expected a length between %S and %S (inclusive) bytes %S, got %S bytes",
      mrb_fixnum_value(min),
      mrb_fixnum_value(max),
      mrb_str_new_static(mrb, type, strlen(type)),
      mrb_fixnum_value(obj_size));
  }
}

static const struct mrb_data_type mrb_hydro_hash_state = {
  "$mrb_i_hydro_hash_state", mrb_free
};

static const struct mrb_data_type mrb_hydro_kx_keypair = {
  "$mrb_i_hydro_kx_keypair", mrb_free
};

static const struct mrb_data_type mrb_hydro_kx_state = {
  "$mrb_i_hydro_kx_state", mrb_free
};

static const struct mrb_data_type mrb_hydro_sign_state = {
  "$mrb_i_hydro_sign_state", mrb_free
};
