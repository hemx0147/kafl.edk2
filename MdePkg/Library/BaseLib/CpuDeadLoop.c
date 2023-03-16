/** @file
  Base Library CPU Functions for all architectures.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/



#include <Base.h>
#include <Library/BaseLib.h>

/**
  Executes an infinite loop.

  Forces the CPU to execute an infinite loop. A debugger may be used to skip
  past the loop and the code that follows the loop must execute properly. This
  implies that the infinite loop must not cause the code that follow it to be
  optimized away.

**/
VOID
EFIAPI
CpuDeadLoop (
  VOID
  )
{
  volatile UINTN  Index;

#ifdef KAFL_ACTIVATE
  /* fuzz test return OK */
  kafl_hprintf("kAFL %a: Exit on CPU deadloop\n", __FUNCTION__);
  kafl_fuzz_event(KAFL_DONE);
#endif
  for (Index = 0; Index == 0;);
}
