// SPDX-License-Identifier: MIT

#include <Uefi.h>
#include <Library/UefiLib.h>

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  (VOID)ImageHandle;
  (VOID)SystemTable;
  Print (L"[RUFUSARM64 TEST] ORIGINAL ARM64 FALLBACK CHAINLOADED\r\n");
  return EFI_SUCCESS;
}
