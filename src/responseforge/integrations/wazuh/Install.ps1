# Generated package entry point. Default invocation is read-only dry-run.
# Windows execution/enrollment is unqualified until separately tested/authorized.
# Keep this directory: configured certificate paths refer to its private files.
#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Install,
    [string]$TargetName = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedManifestSha256 = '__MANIFEST_SHA256__'
$MsiName = 'wazuh-agent-4.14.10-1.msi'
$MsiSha512 = '54f83c01dd35573d8501eab553ebdd72ad4de75383636efb25f01e782521e83281065f8075a369239c13a5a5e3f3599a754eb3204ff56cfce2b2afd9ae911152'
$MsiUrl = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.10-1.msi'
$Streams = New-Object 'System.Collections.Generic.List[System.IDisposable]'
$Reserved = $false
$InstallerExitCode = $null
$ReceiptPath = Join-Path $PSScriptRoot 'install-receipt.json'

function Assert-PlainPath([string]$LiteralPath) {
    $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Unsupported linked path'
        }
        $linkProperty = $item.PSObject.Properties['LinkType']
        if ($null -ne $linkProperty -and $linkProperty.Value -eq 'HardLink') {
            throw 'Unsupported hard-linked package member'
        }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        else { $item = $item.Directory }
    }
}

function Open-ReadLocked([string]$LiteralPath, [long]$Maximum) {
    Assert-PlainPath $LiteralPath
    if ((Get-Item -LiteralPath $LiteralPath -Force).PSIsContainer) { throw 'Expected file' }
    # On Windows this sharing mode denies content writes/deletion while hashes,
    # signature checks and the native installer use the original file.
    $stream = New-Object IO.FileStream($LiteralPath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ($stream.Length -le 0 -or $stream.Length -gt $Maximum) {
        $stream.Dispose()
        throw 'Unsupported file size'
    }
    $Streams.Add($stream)
    return $stream
}

function Stream-Hash([IO.Stream]$Stream, [string]$Algorithm) {
    $Stream.Position = 0
    $value = (Get-FileHash -InputStream $Stream -Algorithm $Algorithm).Hash
    $Stream.Position = 0
    return $value
}

function Same-Text([string]$Left, [string]$Right) {
    return [string]::Equals($Left, $Right, [StringComparison]::Ordinal)
}

function Hash-Matches([string]$Left, [string]$Right) {
    return [string]::Equals($Left, $Right, [StringComparison]::OrdinalIgnoreCase)
}

function Protect-Bundle {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($current)
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @($current.Value, 'S-1-5-32-544', 'S-1-5-18')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $identity, [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit, $propagation, $allow)
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $PSScriptRoot -AclObject $security
    # Existing files may have inherited or explicit broad rules. Replace each
    # file's ACL rather than assuming a directory update removed its old access.
    foreach ($file in $Streams) {
        $fileSecurity = New-Object Security.AccessControl.FileSecurity
        $fileSecurity.SetOwner($current)
        $fileSecurity.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($current.Value, 'S-1-5-32-544', 'S-1-5-18')) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $identity, [Security.AccessControl.FileSystemRights]::FullControl, $allow)
            $fileSecurity.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $file.Name -AclObject $fileSecurity
    }
}

function Write-Receipt([string]$Status, [bool]$New, $ExitCode) {
    $value = [ordered]@{
        schema_version = '1.0'
        status = $Status
        target_machine = $manifest.target_machine
        artifact_sha512 = $MsiSha512
        verified_live = $false
        enrolled = $false
        service_started_by_script = $false
    }
    if ($null -ne $ExitCode) { $value['installer_exit_code'] = [int]$ExitCode }
    $encoded = [Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Depth 4) + "`n")
    $mode = [IO.FileMode]::CreateNew
    if (-not $New) { $mode = [IO.FileMode]::Truncate }
    $stream = New-Object IO.FileStream($ReceiptPath, $mode, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try { $stream.Write($encoded, 0, $encoded.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

try {
    Assert-PlainPath $PSScriptRoot
    $allowed = @('bundle.json', 'Install.ps1', 'root-ca.pem', 'agent-cert.pem',
        'agent-key.pem', $MsiName, 'install-receipt.json')
    foreach ($member in Get-ChildItem -LiteralPath $PSScriptRoot -Force) {
        if ($member.PSIsContainer -or $allowed -cnotcontains $member.Name) {
            throw 'Unexpected package member'
        }
        Assert-PlainPath $member.FullName
    }
    $scriptStream = Open-ReadLocked (Join-Path $PSScriptRoot 'Install.ps1') 131072
    $manifestStream = Open-ReadLocked (Join-Path $PSScriptRoot 'bundle.json') 65536
    if (-not (Hash-Matches (Stream-Hash $manifestStream 'SHA256') $ExpectedManifestSha256)) {
        throw 'Manifest integrity mismatch'
    }
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $reader = New-Object IO.StreamReader($manifestStream, $utf8, $false, 4096, $true)
    try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json }
    finally { $reader.Dispose(); $manifestStream.Position = 0 }
    if (-not (Same-Text $manifest.schema_version '1.0') -or
        -not (Same-Text $manifest.bundle_version 'rf07b-windows-v1') -or
        $manifest.verified_live -ne $false -or $manifest.enrolled -ne $false -or
        $manifest.windows_runtime_qualified -ne $false -or
        -not (Same-Text $manifest.artifact.filename $MsiName) -or
        -not (Same-Text $manifest.artifact.url $MsiUrl) -or
        -not (Same-Text $manifest.artifact.sha512 $MsiSha512) -or
        $manifest.target_machine -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$' -or
        $manifest.agent_name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or
        $manifest.manager_host -cnotmatch '^[A-Za-z0-9.-]{1,253}$' -or
        $manifest.signer_thumbprint -cnotmatch '^[0-9A-F]{40}$' -or
        [string]::IsNullOrWhiteSpace($manifest.signer_subject)) {
        throw 'Unsupported manifest contract'
    }
    foreach ($name in @('root-ca.pem', 'agent-cert.pem', 'agent-key.pem')) {
        $stream = Open-ReadLocked (Join-Path $PSScriptRoot $name) 65536
        if (-not (Hash-Matches (Stream-Hash $stream 'SHA256') $manifest.material.$name)) {
            throw 'Material integrity mismatch'
        }
    }
    if (-not $Install) {
        [ordered]@{ status = 'dry_run'; installed = $false; downloaded = $false;
            enrolled = $false; verified_live = $false; windows_runtime_qualified = $false
        } | ConvertTo-Json -Compress
        exit 0
    }

    # Every mutation gate precedes ACL/state/process changes. Do not emulate a
    # Windows positive path on another OS or treat package parsing as that proof.
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Installation requires separately authorized Windows target'
    }
    $processors = @(Get-CimInstance -ClassName Win32_Processor)
    if (-not [Environment]::Is64BitOperatingSystem -or $processors.Count -lt 1 -or
        @($processors | Where-Object { $_.Architecture -ne 9 }).Count -ne 0) {
        throw 'Only native Windows x64 target is supported for qualification'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator authorization is required'
    }
    if (-not [string]::Equals($TargetName, $manifest.target_machine, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([Environment]::MachineName, $manifest.target_machine, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Explicit target does not match this machine'
    }
    if (Test-Path -LiteralPath $ReceiptPath) {
        throw 'Prior installation reservation requires operator inspection'
    }
    $msiPath = Join-Path $PSScriptRoot $MsiName
    $msiStream = Open-ReadLocked $msiPath 67108864
    if (-not (Hash-Matches (Stream-Hash $msiStream 'SHA512') $MsiSha512)) {
        throw 'Installer integrity mismatch'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $msiPath
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        -not (Same-Text $signature.SignerCertificate.Subject $manifest.signer_subject) -or
        -not (Same-Text $signature.SignerCertificate.Thumbprint $manifest.signer_thumbprint)) {
        throw 'Independent publisher identity does not match'
    }
    # Check every file whose ACL will be changed, including the running script.
    # FileShare.Read handles remain held through hash/signature/ACL/MSI use.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RF07BFileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    public struct Info {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh;
        public uint WriteLow, WriteHigh, VolumeSerial, SizeHigh, SizeLow;
        public uint Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    public static bool IsSingleRegularFile(SafeFileHandle handle) {
        Info info;
        return GetFileInformationByHandle(handle, out info) && info.Links == 1
            && (info.Attributes & 0x10) == 0;
    }
}
'@
    foreach ($held in $Streams) {
        if (-not [RF07BFileIdentity]::IsSingleRegularFile($held.SafeFileHandle)) {
            throw 'Native package file identity is unsafe or unavailable'
        }
    }
    $executable = Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'
    Assert-PlainPath $executable
    Protect-Bundle
    Write-Receipt 'dispatching' $true $null
    $Reserved = $true
    $arguments = @('/i', ('"' + $msiPath + '"'), '/qn', '/norestart',
        ('WAZUH_MANAGER="' + $manifest.manager_host + '"'),
        ('WAZUH_AGENT_NAME="' + $manifest.agent_name + '"'),
        ('WAZUH_REGISTRATION_SERVER="' + $manifest.manager_host + '"'),
        ('WAZUH_REGISTRATION_CA="' + (Join-Path $PSScriptRoot 'root-ca.pem') + '"'),
        ('WAZUH_REGISTRATION_CERTIFICATE="' + (Join-Path $PSScriptRoot 'agent-cert.pem') + '"'),
        ('WAZUH_REGISTRATION_KEY="' + (Join-Path $PSScriptRoot 'agent-key.pem') + '"'))
    $process = Start-Process -FilePath $executable -ArgumentList $arguments -Wait -PassThru
    $InstallerExitCode = $process.ExitCode
    if ($process.ExitCode -notin @(0, 3010)) {
        Write-Receipt 'uncertain' $false $process.ExitCode
        throw 'Installer result requires operator inspection'
    }
    Write-Receipt 'installed_enrollment_unverified' $false $process.ExitCode
    [ordered]@{ status = 'installed_enrollment_unverified'; enrolled = $false;
        verified_live = $false; service_started_by_script = $false
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    if ($Reserved) {
        try { Write-Receipt 'uncertain' $false $InstallerExitCode } catch { }
    }
    [Console]::Error.WriteLine('Windows package refused or installation uncertain; inspect private state. No automatic retry.')
    exit 2
}
finally {
    foreach ($stream in $Streams) { $stream.Dispose() }
}
