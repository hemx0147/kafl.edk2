
#ifndef _MY_TEST_LIB_H_
#define _MY_TEST_LIB_H_

#include <Uefi/UefiBaseType.h>
#include <Uefi/UefiSpec.h>


VOID
EFIAPI
TestPrint (
  VOID
);

VOID
EFIAPI
ReadVar (
  VOID
);

VOID
EFIAPI
WriteVar (
  VOID
);

#endif