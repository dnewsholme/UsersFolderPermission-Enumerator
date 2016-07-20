get-childitem $psscriptroot\*.ps1 -recurse | % {. $_.Fullname }
