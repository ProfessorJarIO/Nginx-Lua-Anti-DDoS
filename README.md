# Nginx-Lua-Anti-DDoS

ALL CREDIT GOES TOWARDS THE ORIGINAL CREATOR: (https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS). This is simply a modified version of C0nw0nk's original script. I just made some modifications on the JS challenge

## Images
![Captcha Page](https://github.com/ProfessorJarIO/Nginx-Lua-Anti-DDoS/blob/main/Captcha1.jpg)
![Captcha Page Fail](https://github.com/ProfessorJarIO/Nginx-Lua-Anti-DDoS/blob/main/Captcha2.jpg)
![Captcha Page Success](https://github.com/ProfessorJarIO/Nginx-Lua-Anti-DDoS/blob/main/Captcha3.jpg)
![Captcha Cookies](https://github.com/ProfessorJarIO/Nginx-Lua-Anti-DDoS/blob/main/Cookies.jpg)


## What I changed:
- I changed the html/css layout of the page
- I added more JS checks to stop bots
- I used PoW (Proof of work) crypto challenge; I happen to believe that this is a better way of defending against bots than from the original script, but prove me wrong if you can; I would love to hear feedback on my work!
- I removed the WaF, because I don't think it's too necessary since there are other solutions out there that have better rules.
- I added a banning page (rate limit). I'm not too sure how effective this is, or if I should even include it at all. I may remove it in the future because it just doesn't really have a use.

## Install the necessary libraries
- openresty/lua-resty-string
- fffonion/lua-resty-openssl

## Changes you need to make in the nginx.conf file

Add this line; This implements the anti-ddos script itself:
`access_by_lua_file anti_ddos_challenge.lua`

Now we add the memory zones to keep track of user sessions:
```
lua_shared_dict client_temp_rayID 10m;
lua_shared_dict banIP 10m;
lua_shared_dict track_requests 10m;
```

The script is solely for Nginx users. The script also works on Linux, since it grabs from `/dev/urandom`

Mostly everything is the same, so if you want to modify the session length, then you can refer to C0nw0nk's original script guide.

If you find any problems, let me know, and I'll try to see any issues with the script. If you have any suggestions, let me know. 

