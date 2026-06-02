# Build a 1 GB ESP-style disk via diskpart (Windows native), put shellx64.efi
# at /EFI/BOOT/BOOTX64.EFI, then copy the raw disk image into the
# VMware-vdiskmanager-created extent.
#
# Larger disk (1 GB vs 64 MB) tested as workaround for VMware Workstation 17
# UEFI firmware quirk where smaller disks may not be picked up as boot
# candidates.

$ErrorActionPreference = 'Stop'

$VhdPath  = 'D:\veneer-esp.vhd'
$EfiSrc   = 'D:\dev\github\veneer\assets\shellx64.efi'
$FlatDst  = 'D:\dev\github\veneer\target\veneer-esp-flat.vmdk'
$DriveL   = 'V'
$DataMiB  = 1024  # must match -s passed to vmware-vdiskmanager

$dpCreate = @"
create vdisk file=$VhdPath maximum=$DataMiB type=fixed
select vdisk file=$VhdPath
attach vdisk
convert gpt
create partition efi size=100
format fs=fat32 quick label=ESP
assign letter=$DriveL
create partition primary
format fs=ntfs quick label=DATA
"@

$dpDetach = @"
select vdisk file=$VhdPath
detach vdisk
"@

if (Test-Path $VhdPath) { Remove-Item -Force $VhdPath }
Write-Host "[esp] creating $VhdPath (${DataMiB} MiB) via diskpart..."
$dpCreate | diskpart | Out-Null

Write-Host "[esp] copying .efi to ${DriveL}:\EFI\BOOT\BOOTX64.EFI"
New-Item -ItemType Directory -Force "${DriveL}:\EFI\BOOT" | Out-Null
Copy-Item $EfiSrc "${DriveL}:\EFI\BOOT\BOOTX64.EFI" -Force

Write-Host "[esp] detaching VHD..."
$dpDetach | diskpart | Out-Null

$DataBytes = $DataMiB * 1024 * 1024
Write-Host "[esp] copying $DataBytes bytes into $FlatDst"
$inS  = [System.IO.File]::OpenRead($VhdPath)
$outS = [System.IO.File]::OpenWrite($FlatDst)
$buf = New-Object byte[] (4 * 1024 * 1024)
$remaining = $DataBytes
while ($remaining -gt 0) {
    $want = [math]::Min($buf.Length, $remaining)
    $got = $inS.Read($buf, 0, $want)
    if ($got -le 0) { break }
    $outS.Write($buf, 0, $got)
    $remaining -= $got
}
$inS.Close()
$outS.Close()

Write-Host ""
Write-Host "DONE. 1 GB disk with ESP (100 MB FAT32) + DATA (~900 MB NTFS)."
Write-Host "shellx64.efi is at /EFI/BOOT/BOOTX64.EFI."
Write-Host ""
Write-Host "Power on the VM. If Shell prompt appears -> VMware UEFI accepted it."
Read-Host "Press Enter to close"
