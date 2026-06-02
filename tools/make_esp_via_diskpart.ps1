# Build an EFI System Partition (FAT32) using Windows' own diskpart/format,
# then copy the resulting raw disk image into the VMware-vdiskmanager-created
# extent file. Avoids hand-rolling FAT/GPT bytes — Windows formats it,
# we just place the .efi inside.

$ErrorActionPreference = 'Stop'

$VhdPath = 'D:\veneer-esp.vhd'
$EfiSrc  = 'D:\dev\github\veneer\target\x86_64-unknown-uefi\release\veneer-uefi.efi'
$FlatDst = 'D:\dev\github\veneer\target\veneer-esp-flat.vmdk'
$DriveL  = 'V'

# diskpart script: create fixed 64 MB VHD, mount, GPT, ESP, FAT32 quick
$dpCreate = @"
create vdisk file=$VhdPath maximum=64 type=fixed
select vdisk file=$VhdPath
attach vdisk
convert gpt
create partition efi size=63
format fs=fat32 quick label=ESP
assign letter=$DriveL
"@

$dpDetach = @"
select vdisk file=$VhdPath
detach vdisk
"@

# Wipe old VHD if present
if (Test-Path $VhdPath) { Remove-Item -Force $VhdPath }

Write-Host "[esp] creating $VhdPath via diskpart..."
$dpCreate | diskpart | Out-Null

Write-Host "[esp] copying .efi to ${DriveL}:\EFI\BOOT\BOOTX64.EFI"
New-Item -ItemType Directory -Force "${DriveL}:\EFI\BOOT" | Out-Null
Copy-Item $EfiSrc "${DriveL}:\EFI\BOOT\BOOTX64.EFI" -Force

Write-Host "[esp] detaching VHD..."
$dpDetach | diskpart | Out-Null

# Fixed VHD layout: 64 MiB of data + 512 byte footer at EOF.
# Copy the first 64 MiB into the VMware extent file.
$DataBytes = 64 * 1024 * 1024
Write-Host "[esp] copying $DataBytes bytes from VHD to $FlatDst"
$inS = [System.IO.File]::OpenRead($VhdPath)
$outS = [System.IO.File]::OpenWrite($FlatDst)
$buf = New-Object byte[] (1 * 1024 * 1024)
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

Write-Host "[esp] DONE. veneer-esp-flat.vmdk has a Windows-built GPT+FAT32 ESP."
Read-Host "Press Enter to close"
