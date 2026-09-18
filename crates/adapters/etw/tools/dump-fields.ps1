# List the data-field names each event template declares, per provider.
#
# This is the tool the translate table is built from. TDH addresses properties by
# name and the name has to match the provider's manifest exactly, so the only
# honest way to add a shape to `translate.rs` is to read the template off a real
# host first. `wevtutil gp` is not it: it prints the provider's channels, levels,
# opcodes and tasks, and says nothing about the data fields.
#
# Reading these manifests needs no elevation.
#
#   pwsh -ExecutionPolicy Bypass -File dump-fields.ps1 -Provider Microsoft-Windows-Kernel-Process
#   pwsh -ExecutionPolicy Bypass -File dump-fields.ps1 -Provider Microsoft-Windows-PowerShell -Id 4104
#
# `-ExecutionPolicy Bypass` scopes the permission to this process; the default
# policy on a stock machine refuses to run a script file at all.
#
# An event with no template carries no named fields at all: it can be counted,
# but it cannot be decoded by name.

param(
    [Parameter(Mandatory = $true)][string[]]$Provider,
    # A comma-separated list as one string, because `[int[]]` bound from a comma
    # argument does surprising things before the script sees it.
    [string]$Id = ""
)

foreach ($name in $Provider) {
    Write-Output "=== $name ==="

    $metadata = $null
    try {
        $metadata = Get-WinEvent -ListProvider $name -ErrorAction Stop
    } catch {
        Write-Output "  not registered on this machine"
        continue
    }

    # `-in` compares with PowerShell's coercion rules, which is how `-Id 1,5`
    # matches event 15. Parse to ints here and compare ints.
    $wanted = @()
    if ($Id.Trim()) {
        $wanted = $Id -split ',' | ForEach-Object { [int]$_.Trim() }
    }

    $events = $metadata.Events
    if ($wanted.Count -gt 0) {
        $events = $events | Where-Object { $wanted.Contains([int]$_.Id) }
    }
    if (-not $events) {
        Write-Output "  (no events matched)"
        continue
    }

    foreach ($event in $events) {
        # `Template` is the template XML as a string, not a parsed node, so the
        # field names come out with a regex rather than an XPath.
        $fields = @()
        if ($event.Template) {
            $fields = [regex]::Matches($event.Template, '<data\s+name="([^"]+)"') |
                ForEach-Object { $_.Groups[1].Value }
        }

        if ($fields.Count -gt 0) {
            Write-Output ("  id={0,-6} v={1}  {2}" -f $event.Id, $event.Version, ($fields -join ', '))
        } else {
            Write-Output ("  id={0,-6} v={1}  (no template: no named fields)" -f $event.Id, $event.Version)
        }
    }
}
