# chrome_snatcher
Chrome (headless) cookie snatcher

For use in Red Team ops where you have a shell on a user's machine and want to (silently) dump their cookies, without needing to compromise their keychain on OSX (and risk alerting the user/setting off alarm bells).  (Ab)uses Chrome's ("remote") Debugger Protocol in headless mode to load up a site (and/or potentially their most recent browsing session so you can see what they were looking at, etc, although can be modified as needed), start crumb-snatchin', and obtain all of the l3wtz.  
