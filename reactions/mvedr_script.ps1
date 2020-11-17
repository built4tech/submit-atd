$outfile = "$env:TEMP\Submit-Atd.ps1"
If (Test-Path $outfile){
	Remove-Item $outfile
}

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/built4tech/submit-atd/master/Submit-Atd.ps1" -Outfile $outfile
import-module $outfile

submit-atd -Atd_host {{atd-host}} -Atd_user {{atd-user}} -Atd_pass {{atd-pass}} -Fullname {{file-path}}
