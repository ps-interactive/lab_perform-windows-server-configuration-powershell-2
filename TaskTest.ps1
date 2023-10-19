New-Item -ItemType Directory -Path "C:\Temp"

$FilePath = "C:\Temp\Output.txt"

$time = (get-date).ToString("MM-dd-yyyy hh:mm:ss")
$Output = "$time - This is a test from scheduled task"

Out-File -InputObject $Output -FilePath $FilePath -Append