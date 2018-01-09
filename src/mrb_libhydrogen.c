#include <mruby/hydrogen.h>
#include "mrb_libhydrogen.h"
#include "mrb_core.h"
#include "mrb_hash.h"
#include "mrb_kdf.h"
#include "mrb_kx.h"
#include "mrb_random.h"
#include "mrb_secretbox.h"
#include "mrb_sign.h"

void
mrb_mruby_libhydrogen_gem_init(mrb_state* mrb)
{
  errno = 0;
  if (!hydro_random_context.initialized && hydro_init() != 0) {
      mrb_sys_fail(mrb, "hydro_init");
  }

  struct RClass *hydro_mod, *hydro_error_cl;
  hydro_mod = mrb_define_module(mrb, "Hydro");
  hydro_error_cl = mrb_define_class_under(mrb, hydro_mod, "Error", E_RUNTIME_ERROR);

  mrb_hydro_random_gem_init(mrb, hydro_mod);
  mrb_hydro_gem_init(mrb, hydro_mod);
  mrb_hydro_secretbox_gem_init(mrb, hydro_mod, hydro_error_cl);
  mrb_hydro_hash_gem_init(mrb, hydro_mod);
  mrb_hydro_kdf_gem_init(mrb, hydro_mod);
  mrb_hydro_kx_gem_init(mrb, hydro_mod, hydro_error_cl);
  mrb_hydro_sign_gem_init(mrb, hydro_mod);
}

void mrb_mruby_libhydrogen_gem_final(mrb_state* mrb) {}
