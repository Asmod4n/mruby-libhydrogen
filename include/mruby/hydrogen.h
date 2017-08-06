#ifndef MRUBY_HYDROGEN_H
#define MRUBY_HYDROGEN_H

#include <mruby.h>

MRB_BEGIN_DECL

#if (MRB_INT_BIT < 32)
#error "MRB_INT16 is to small for mruby-libhydrogen"
#endif

#define E_HYDRO_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Hydro"), "Error"))
#define E_HYDRO_KX_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_module_get(mrb, "Hydro"), "Kx"), "Error"))

MRB_END_DECL

#endif
