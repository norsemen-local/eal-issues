<#
    Stage 1 (START) - Insider tells: job-hunting + time-consuming browsing
    =====================================================================
    The departing employee spends the day on job boards and personal/streaming
    sites - the behavioural spike that flags a potential insider before any data
    leaves. Real sites (they resolve); the firewall categorises the traffic.

      EAL alerts: 'Increase in Job-Related Site Visits' (Recon T1593)
                  'A user accessed multiple time-consuming websites' (Recon T1593)
      NOTE: enable these detectors in Cortex if they are not already on.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1 (START): job-hunting + time-consuming browsing (insider tells)" "INFO"
$jobs = @("https://www.linkedin.com/jobs/","https://www.indeed.com/","https://www.glassdoor.com/Job/",
          "https://www.monster.com/jobs/","https://www.ziprecruiter.com/jobs","https://www.dice.com/jobs")
$time = @("https://www.youtube.com/","https://www.reddit.com/","https://www.netflix.com/",
          "https://www.twitch.tv/","https://www.facebook.com/","https://www.instagram.com/")
Write-Stage "Visiting $($jobs.Count) job sites..." "INFO"
foreach ($u in $jobs) { Invoke-Http -Url $u -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -Label "job site" }
Write-Stage "Visiting $($time.Count) time-consuming sites..." "INFO"
foreach ($u in $time) { Invoke-Http -Url $u -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -Label "time-consuming" }
Write-Stage "STAGE 1 done. Expect EAL: 'Increase in Job-Related Site Visits' + 'A user accessed multiple time-consuming websites'." "OK"
