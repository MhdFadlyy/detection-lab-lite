# Regenerate: `sudo vhs demo/detection.tape` with the stack up (`./lab up` + `./lab test` once).
# Output: docs/img/demo.gif

Output docs/img/demo.gif

Set Shell bash
Set FontSize 18
Set Width 1180
Set Height 430
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "export PS1='\033[1;32m$\033[0m ' && clear" Enter
Show

Sleep 800ms
Type "# launch a real attack in the victim container, then check the SOC caught it" Enter
Sleep 1s

Type "./lab attack T1059.004" Enter
Sleep 9s

Type "./lab verify T1059.004" Enter
Sleep 18s

Type "./lab report | tail -1" Enter
Sleep 5s
