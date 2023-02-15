/** @file

  This file implements the entry point of the virtio-net driver.

  Copyright (C) 2013, Red Hat, Inc.
  Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/UefiLib.h>

#include "VirtioNet.h"

/**
  This is the declaration of an EFI image entry point. This entry point is the
  same for UEFI Applications, UEFI OS Loaders, and UEFI Drivers including both
  device drivers and bus drivers.

  @param  ImageHandle           The firmware allocated handle for the UEFI
                                image.
  @param  SystemTable           A pointer to the EFI System Table.

  @retval EFI_SUCCESS           The operation completed successfully.
  @retval Others                An unexpected error occurred.
**/

EFI_STATUS
EFIAPI
VirtioNetEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  DEBUG ((DEBUG_INFO, "%a:%d:%a called\n", __FILE__, __LINE__, __FUNCTION__));

  EFI_STATUS Status = EfiLibInstallDriverBindingComponentName2 (
           ImageHandle,
           SystemTable,
           &gVirtioNetDriverBinding,
           ImageHandle,
           &gVirtioNetComponentName,
           &gVirtioNetComponentName2
           );

  DEBUG ((DEBUG_INFO, "%a:%d:%a return with status %x\n", __FILE__, __LINE__, __FUNCTION__, Status));
  return Status;
}
