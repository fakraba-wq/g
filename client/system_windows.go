//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func systemEvidence(ctx context.Context, boot, activity bool) evidence {
	result := evidence{}
	for _, pair := range []struct {
		key       string
		requested bool
	}{{"boot", boot}, {"activity", activity}} {
		if !pair.requested {
			result.Collection = append(result.Collection, collection{Key: pair.key, State: "not-requested", Note: "Not authorized in this scan."})
		}
	}
	if !boot && !activity {
		return result
	}
	script := `$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$answer=@{collection=@();executions=@()}
$os=$null
try{$os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop}catch{}
if($env:CRIMSON_COLLECT_BOOT -eq '1'){
 try{
 $bios=Get-CimInstance Win32_BIOS -ErrorAction Stop;$board=Get-CimInstance Win32_BaseBoard -ErrorAction Stop
 $fast=$null;try{$v=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled;$fast=[bool]$v}catch{}
 $last='';$caption='';if($os){$last=$os.LastBootUpTime.ToUniversalTime().ToString('o');$caption=[string]$os.Caption+' '+[string]$os.Version}
 $answer.boot=@{windowsVersion=$caption;biosVendor=[string]$bios.Manufacturer;biosVersion=[string]$bios.SMBIOSBIOSVersion;boardManufacturer=[string]$board.Manufacturer;boardProduct=[string]$board.Product;lastBootUTC=$last;fastBootEnabled=$fast}
 $answer.collection+=@{key='boot';state='collected';count=1;note='CIM metadata and Fast Startup setting; no serial numbers or account identifiers.'}
 }catch{$answer.collection+=@{key='boot';state='unavailable';count=0;note='Windows system metadata could not be read.'}}
}
if($env:CRIMSON_COLLECT_ACTIVITY -eq '1'){
 $start=(Get-Date).AddDays(-1);if($os){$start=$os.LastBootUpTime};$answer.windowStartUTC=$start.ToUniversalTime().ToString('o')
 $events=@();$readable=0
 foreach($config in @(@{log='Microsoft-Windows-Sysmon/Operational';id=1;field='Image'},@{log='Security';id=4688;field='NewProcessName'})){
  try{
   $null=Get-WinEvent -ListLog $config.log -ErrorAction Stop
   try{$items=@(Get-WinEvent -FilterHashtable @{LogName=$config.log;Id=$config.id;StartTime=$start} -MaxEvents 100 -ErrorAction Stop);$readable++}catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$items=@();$readable++}else{continue}}
   foreach($event in $items){
    $xml=[xml]$event.ToXml();$image='';foreach($field in $xml.Event.EventData.Data){if($field.Name -eq $config.field){$image=[string]$field.'#text'}}
    if(!$image){continue};$state='unknown';if($image -match '^[A-Za-z]:\\'){try{$drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot($image));if($drive.DriveType -eq 'Fixed' -or $drive.DriveType -eq 'Removable'){if(Test-Path -LiteralPath $image -PathType Leaf -ErrorAction Stop){$state='present'}else{$state='not-found'}}}catch{}}
    $events+=@{name=[IO.Path]::GetFileName($image);timeUTC=$event.TimeCreated.ToUniversalTime().ToString('o');source=$config.log;eventId=$config.id;pathState=$state}
   }
  }catch{}
 }
 $answer.executions=@($events|Sort-Object -Property timeUTC -Descending|Select-Object -First 100)
 $state='partial';if($readable -eq 0){$state='unavailable'}
 $answer.collection+=@{key='activity';state=$state;count=$answer.executions.Count;note='Available Sysmon/Security process-creation records only, capped at 100. Auditing is not enabled or changed. Paths, users and command lines are excluded.'}
}
$answer|ConvertTo-Json -Depth 7 -Compress`
	childCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	command := exec.CommandContext(childCtx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	command.Env = append(os.Environ(), "CRIMSON_COLLECT_BOOT="+strconv.Itoa(boolInt(boot)), "CRIMSON_COLLECT_ACTIVITY="+strconv.Itoa(boolInt(activity)))
	var output bytes.Buffer
	command.Stdout = &output
	err := command.Run()
	var parsed evidence
	if err == nil && output.Len() < 2*1024*1024 {
		err = json.Unmarshal(bytes.TrimPrefix(output.Bytes(), []byte{0xef, 0xbb, 0xbf}), &parsed)
	} else if err == nil {
		err = errors.New("oversized system metadata")
	}
	if err == nil {
		parsed.Collection = append(result.Collection, parsed.Collection...)
		return parsed
	}
	for _, pair := range []struct {
		key       string
		requested bool
	}{{"boot", boot}, {"activity", activity}} {
		if pair.requested {
			result.Collection = append(result.Collection, collection{Key: pair.key, State: "unavailable", Note: "Windows collection failed or timed out; no permission or policy changes attempted."})
		}
	}
	return result
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
