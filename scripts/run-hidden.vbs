' Launch a PowerShell script with no visible console window.
'
' PowerShell's own -WindowStyle Hidden still flashes a console on startup when
' run from a scheduled task. Going through wscript avoids that entirely.
'
' Installed next to rebuild.ps1 in C:\ProgramData\ClaudeKillSwitch, a directory
' only SYSTEM and Administrators can write, so a non-admin process cannot
' replace this launcher and inherit the task's HighestAvailable token.
'
' Usage from a scheduled task action:
'   Program:   C:\Windows\System32\wscript.exe
'   Arguments: //B //NoLogo "C:\ProgramData\ClaudeKillSwitch\run-hidden.vbs" "C:\ProgramData\ClaudeKillSwitch\rebuild.ps1"

Option Explicit

Dim shell, scriptPath, command

If WScript.Arguments.Count < 1 Then
    WScript.Quit 2
End If

scriptPath = WScript.Arguments(0)

command = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & """"

Set shell = CreateObject("WScript.Shell")

' 0 = hidden window, True = wait for it to exit so the task stays in the
' Running state for exactly as long as the rebuild runs.
shell.Run command, 0, True