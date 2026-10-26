# Sentinel Windows folder scanner. Review before running.
# Reads only a folder selected by the user. No elevation, persistence or process inspection.
param([string]$ServerUrl = '__SERVER_URL__', [string]$Code = '')
$ErrorActionPreference = 'Stop'
try {
  $uri = [Uri]$ServerUrl
  if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $uri.IsLoopback)) { throw 'Use HTTPS, or localhost for development.' }
  $ServerUrl = $ServerUrl.TrimEnd('/')
  Write-Host 'CRIMSON PC CHECK / WINDOWS FOLDER CHECK' -ForegroundColor Green
  Write-Host 'This checks a folder you select. It does not establish that your PC is cheat-free.'
  Write-Host 'Only filenames, sizes and hashes may be sent. File contents stay on your PC.'
  $folder = Read-Host 'Full path of the folder to check'
  $root = Get-Item -LiteralPath $folder
  if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Select a regular folder, not a link or junction.' }
  if ((Read-Host 'Do you own these files or have permission, and want to scan this folder? Type YES') -cne 'YES') { Write-Host 'Cancelled. No files scanned.'; exit 0 }
  if (-not $Code) { $Code = Read-Host 'Six-digit session code from your staff member' }
  if ($Code -notmatch '^\d{6}$') { throw 'Invalid session code.' }
  $session = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/sessions/redeem" -ContentType 'application/json' -Body (@{ code = $Code } | ConvertTo-Json)
  $stack = New-Object 'System.Collections.Generic.Stack[string]'
  $stack.Push($root.FullName)
  $results = New-Object 'System.Collections.Generic.List[object]'
  $limited = $false
  while ($stack.Count -gt 0 -and $results.Count -lt 1000) {
    $directory = $stack.Pop()
    try { $entries = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) }
    catch { $limited = $true; continue }
    foreach ($entry in $entries) {
      if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $limited = $true; continue }
      if ($entry.PSIsContainer) { $stack.Push($entry.FullName); continue }
      if ($results.Count -ge 1000) { $limited = $true; break }
      $result = @{ name = $entry.Name; size = [long]$entry.Length }
      if ($entry.Length -le 209715200) {
        try { $result.sha256 = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        catch { $result.reason = 'Unreadable file'; $limited = $true }
      } else { $result.reason = 'Over 200 MB'; $limited = $true }
      $results.Add($result)
      Write-Progress -Activity 'Hashing selected folder' -Status "$($results.Count) files processed (limit 1000)" -PercentComplete -1
    }
  }
  Write-Progress -Activity 'Hashing selected folder' -Completed
  if ($stack.Count -gt 0) { $limited = $true }
  if ($results.Count -eq 0) { throw 'No readable file entries found. No report submitted.' }
  $report = @{ results = @($results.ToArray()); coverageLimited = $limited }
  $json = $report | ConvertTo-Json -Depth 8
  $localPath = Join-Path ([IO.Path]::GetTempPath()) "crimson-$($session.sessionId).json"
  [IO.File]::WriteAllText($localPath, $json, (New-Object Text.UTF8Encoding($false)))
  Write-Host "Local report saved: $localPath"
  Write-Host "$($results.Count) entries. Coverage limited: $limited"
  Write-Host 'Review the JSON file before sharing it. No file contents are included.'
  if ((Read-Host "Send this report to $ServerUrl for staff review? Type SEND") -cne 'SEND') { Write-Host 'Not sent. The local report remains on your device.'; exit 0 }
  $headers = @{ Authorization = "Bearer $($session.uploadToken)" }
  $bodyBytes = [Text.Encoding]::UTF8.GetBytes($json)
  $null = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/sessions/$($session.sessionId)/report" -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bodyBytes
  Write-Host 'Report submitted. Staff can now review it.' -ForegroundColor Green
} catch {
  Write-Error "Check stopped: $($_.Exception.Message)" -ErrorAction Continue
  exit 1
}
