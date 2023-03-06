/** @file
  kAFL fuzzing agent definitions

**/

#ifndef _KAFL_AGENT_LIB_H_
#define _KAFL_AGENT_LIB_H_

#include <Base.h>
#include "NyxHypercalls.h"

VOID
EFIAPI
kafl_hprintf(
  IN  CONST CHAR8 *Msg
  );

#endif