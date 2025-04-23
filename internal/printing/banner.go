package printing

import (
	"github.com/ibrahimsql/aetherxss/v2/pkg/model"
)

// Banner
func Banner(options model.Options) {
	DalLog("", `
               ___,,___                       
          _,-='=- =-  -`"--.__,,.._           
       ,-;// /  - -       -   -= - "=.        
     ,'///    -     -   -   =  - ==-=\`.      
    |/// /  =    `. - =   == - =.=_,,._ `=/|  
   ///    -   -    \  - - = ,ndDMHHMM/\b  \\  
 ,' - / /        / /\ =  - /MM(,,._`YQMML  `| 
<_,=^Kkm / / / / ///H|wnWWdMKKK#""-;. `"0\  | 
       `""QkmmmmmnWMMM\""WHMKKMM\   `--. \> \ 
hjm          `""'  `->>>    ``WHMb,.    `-_<@)
                               `"QMM`.        
                                  `>>>         

        AetherXSS `+VERSION+`
         by ibrahimsql

  Advanced Modular XSS & Web Vulnerability Scanner
  "Sees every bug, hunts every night."
  Powerful, Fast, Automated, Open Source
`, options)
}
