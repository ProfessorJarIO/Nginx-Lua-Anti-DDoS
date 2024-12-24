-- This script uses a nonce system for the JS challenge
-- I believe I've successfully mitigated the replay attack issue, thanks to memory zones.
-- I just need to clean up the script, add switches to enable logging, and other switches
-- I will NOT add a WAF because there are other products that have better rules. This is an anti-ddos tool, not a WAF

-- Shared memory we will be using: client_temp_rayID
local memory_zone = ngx.shared.client_temp_rayID
local banIP = ngx.shared.banIP
local track_requests = ngx.shared.track_requests

-- Import our necessary libraries
local resty_sha1 = require("resty.sha1")
local aes = require "resty.aes"
local str = require "resty.string"


-- Create our variables
local currenttime = ngx.time() --Current time on server
local expire_time = 3600 -- Time before client is issued another JS challenge
local default_charset = "UTF-8" -- Default charset
local expected_header_status = 200
local authentication_page_status_output = 503
--local remote_addr = ngx.var.remote_addr -- Get the IP of the client
local remote_addr = "auto" --Default Automatically get the Clients IP address
local binary_remote_addr = ngx.var.binary_remote_addr -- Get the binary IP of the client
local scheme = ngx.var.scheme --scheme is HTTP or HTTPS
local host = ngx.var.host --host is website domain name
local request_uri = ngx.var.request_uri --request uri is full URL link including query strings and arguements
local URL = scheme .. "://" .. host .. request_uri -- The full URL
local user_agent = ngx.var.http_user_agent --user agent of browser
local currenttime = ngx.time() --Current time on server

--automatically figure out the IP address of the connecting Client
if remote_addr == "auto" then
	if ngx.var.http_cf_connecting_ip ~= nil then
		remote_addr = ngx.var.http_cf_connecting_ip
	elseif ngx.var.http_x_forwarded_for ~= nil then
		remote_addr = ngx.var.http_x_forwarded_for
	else
		remote_addr = ngx.var.remote_addr
	end
end

-- Let's create our banning system
-- If a user were to make X requests in a X second timeframe, then ban the user...
-- These values WILL change. You SHOULD change them to fit your website
local requests_count_max = 5000;
local second_timeout = 60;

local ban_screen = [[
<!DOCTYPE html>
<html>
<head>
<title>You've been banned</title>
<style>
html, body { padding: 0; margin: 0; width: 100%; height: 100%; }
* {box-sizing: border-box;}
body { text-align: center; padding: 0; background: black; color: #FFF; font-family: Arial; }
h1 {text-align: center;}
body { text-align: left; display: -webkit-box; display: -ms-flexbox; display: flex; -webkit-box-pack: center; -ms-flex-pack: center; justify-content: center; -webkit-box-align: center; -ms-flex-align: center; align-items: center;}
article { display: block; width: 700px; padding: 50px; margin: 0 auto; }
a { color: #fff; font-weight: bold;}
a:hover { text-decoration: none; }
svg { width: 75px; margin-right: auto; margin-left: auto; width: 50%; }
.header { display: flex; align-items: center; }
p {color: #fff; font-weight: bold;}
</style>
</head>
<body>


<div class="header">
<center>
<h1>Your IP has been banned</h1>
<p>If you think this is a mistake, please contact the website owner</p>
<a href="#">DDoS Protection by ProfessorJarIO</a>
<center>
</div>


</body>
</html>
]]


-- see if IP is in banned DB
local isBanned = banIP:get(remote_addr)
if isBanned then
    ngx.exit(ngx.HTTP_CLOSE)
    --ngx.header["Content-Type"] = "text/html"
    --ngx.say(ban_screen)
    return
end

-- track IP and log request count
-- check if ip even exists in DB

local req_count_for_ip = track_requests:get(remote_addr)

-- if that ip does exist in records
if req_count_for_ip ~= nil then
    -- Get the client's request count
    local count = req_count_for_ip

    -- Check if this count is over the rate limit
    -- Implement iptables/netsh firewall detection, because that'll be more effective than our memory zones
    if count > requests_count_max then
	banIP:set(remote_addr, true) -- no expiration date, because we want client to be banned until server resets
        ngx.exit(ngx.HTTP_CLOSE)
	return

    end
    -- Increment request count
    count = req_count_for_ip + 1

    -- Get the remaining TTL
    local ttl = track_requests:ttl(remote_addr) 

    -- Set the client's new count with the remaining ttl
    track_requests:replace(remote_addr, count, ttl) 

-- if ip doesn't exist in records
else
    track_requests:set(remote_addr, 1, second_timeout) -- we want the expiration to be only as long as the per_second

end
-- END banning system




--[[
Caching Speed and Performance
]]
--[[
Enable Query String Sort

This will treat files with the same query strings as the same file, regardless of the order of the query strings.

Example :
Un-Ordered : .com/index.html?lol=1&char=2
Ordered : .com/index.html?char=2&lol=1

This will result in your backend applications and webserver having better performance because of a Higher Cache HIT Ratio.

0 = Disabled
1 = Enabled
]]
local query_string_sort_table = {
	{
		".*", --regex match any site / path
		1, --enable
	},
	{
		"domain.com/.*", --regex match this domain
		1, --enable
	},
}

--[[
Query String Expected arguments Whitelist only

So this is useful for those who know what URL arguments their sites use and want to whitelist those ONLY so any other arguments provided in the URL never reach the backend or web application and are dropped from the URL.
]]
local query_string_expected_args_only_table = {
--[[
	{
		".*", --any site
		{ --query strings to allow ONLY all others apart from those you list here will be removed from the URL
			"punch",
			"chickens",
		},
	},
	{
		"domain.com", --this domain
		{ --query strings to allow ONLY all others apart from those you list here will be removed from the URL
			"punch",
			"chickens",
		},
	},
]]
	--for all sites specific static files that should never have query strings on the end of the URL (This will improve Caching and performance)
	{
		"%/.*%.js",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.css",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ico",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.jpg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.jpeg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.bmp",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.gif",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.xml",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.txt",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.png",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.swf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.pdf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.zip",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.rar",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.7z",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.woff2",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.woff",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.wof",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.eot",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ttf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.svg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ejs",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ps",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.pict",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.webp",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.eps",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.pls",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.csv",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.mid",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.doc",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ppt",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.tif",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.xls",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.otf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.jar",
		{}, --no args to accept so any provided in the url will be removed.
	},
	--video file formats
	{
		"%/.*%.mp4",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.webm",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ogg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.flv",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.mov",
		{}, --no args to accept so any provided in the url will be removed.
	},
	--music file formats
	{
		"%/.*%.mp3",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.m4a",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.aac",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.oga",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.flac",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.wav",
		{}, --no args to accept so any provided in the url will be removed.
	},
}

--[[
Query String Remove arguments

To remove Query strings that bypass the cache Intentionally Facebook and Google is the biggest culprit in this. It is commonly known as Cache Busting.

Traffic to your site from facebook Posts / Shares the URL's will all contain this .com/index.html?fbclid=blah-blah-blah
]]
local query_string_remove_args_table = {
	{
		".*", --all sites
		{ --query strings to remove to improve Cache HIT Ratios and Stop attacks / Cache bypassing and Busting.
			--Cloudflare cache busting query strings (get added to url from captcha and javascript pages very naughty breaking sites caches)
			"__cf_chl_jschl_tk__",
			"__cf_chl_captcha_tk__",
			--facebook cache busting query strings
			"fb_action_ids",
			"fb_action_types",
			"fb_source",
			"fbclid",
			--google cache busting query strings
			"_ga",
			"gclid",
			"utm_source",
			"utm_campaign",
			"utm_medium",
			"utm_expid",
			"utm_term",
			"utm_content",
			--other cache busting query strings
			"cache",
			"caching",
			"age-verified",
			"ao_noptimize",
			"usqp",
			"cn-reloaded",
			"dos",
			"ddos",
			"lol",
			"rnd",
			"random",
			"v", --some urls use ?v1.2 as a file version causing cache busting
			"ver",
			"version",
		},
	},
	{
		"domain.com/.*", --this site
		{ --query strings to remove to improve Cache HIT Ratios and Stop attacks / Cache bypassing and Busting.
			--facebook cache busting query strings
			"fbclid",
		},
	},
}

--[[
To restore original visitor IP addresses at your origin web server this will send a request header to your backend application or proxy containing the clients real IP address
]]
local send_ip_to_backend_custom_headers = {
	{
		".*",
		{
			{"CF-Connecting-IP",}, --CF-Connecting-IP Cloudflare CDN
			{"True-Client-IP",}, --True-Client-IP Akamai CDN
			{"X-Client-IP",} --Amazon Cloudfront
		},
	},
	--[[
	{
		"%/.*%.mp4", --custom url paths
		{
			{"CF-Connecting-IP",}, --CF-Connecting-IP
			{"True-Client-IP",}, --True-Client-IP
		},
	},
	]]
}

--[[
Custom headers

To add custom headers to URLs paths to increase server performance and speed to cache items
and to remove headers for security purposes that could expose software the server is running etc
]]
local custom_headers = {
	{
		".*",
		{ --headers to improve server security for all websites
			{"Server",nil,}, --Server version / identity exposure remove
			{"X-Powered-By",nil,}, --PHP Powered by version / identity exposure remove
			{"X-Content-Encoded-By",nil,}, --Joomla Content encoded by remove
			{"X-Content-Type-Options","nosniff",}, --block MIME-type sniffing
			{"X-XSS-Protection","1; mode=block",}, --block cross-site scripting (XSS) attacks
			{"x-turbo-charged-by",nil,}, --remove x-turbo-charged-by LiteSpeed
		},
	},
	{
		"%/.*%.js",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.css",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ico",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.jpg",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.jpeg",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.bmp",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.gif",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.xml",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.txt",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.png",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.swf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.pdf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.zip",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.rar",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.7z",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.woff2",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.woff",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.wof",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.eot",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ttf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.svg",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ejs",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ps",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.pict",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.webp",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.eps",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.pls",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.csv",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.mid",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.doc",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ppt",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.tif",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.xls",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.otf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.jar",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	--video file formats
	{
		"%/.*%.mp4",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.webm",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ogg",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.flv",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.mov",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	--music file formats
	{
		"%/.*%.mp3",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.m4a",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.aac",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.oga",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.flac",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.wav",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
}

--[[
End Configuration


Users with little understanding don't edit beyond this point you will break the script most likely. (You should not need to be warned but now you have been told.) Proceed at own Risk!

Please do not touch anything below here unless you understand the code you read and know the consiquences.

This is where things get very complex. ;)

]]




--[[
Begin Required Functions
]]

--[[
Add to your nginx config http://nginx.org/en/docs/ngx_core_module.html#pcre_jit

pcre_jit on;

The options I enable to make regex cache for performance gains.
j = enable PCRE JIT compilation
o = compile-once mode (similar to Perl's /o modifier), to enable the worker-process-level compiled-regex cache
]]
local ngx_re_options = "jo" --boost regex performance by caching

--[[
Header Modifications
]]
local function header_modification()
	local custom_headers_length = #custom_headers
	for i=1,custom_headers_length do --for each host in our table
		local v = custom_headers[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			local table_length = #v[2]
			for first=1,table_length do --for each arg in our table
				local value1 = v[2][first][1]
				local value2 = v[2][first][2]
				if value1 ~= nil and value2 ~= nil then
					ngx.header[value1] = value2
				end
				if value2 == nil then
					ngx.header[value1] = nil --remove the header
				end
			end
		end
	end
end
header_modification()
--[[
End Header Modifications
]]

--[[
headers to restore original visitor IP addresses at your origin web server
]]
local function header_append_ip()
	local custom_headers_length = #send_ip_to_backend_custom_headers
	for i=1,custom_headers_length do --for each host in our table
		local v = custom_headers[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			local table_length = #v[2]
			for first=1,table_length do --for each arg in our table
				local value1 = v[2][first][1]
				if value1 ~= nil then
					ngx.req.set_header(value1, remote_addr)
				end
			end
		end
	end
end
header_append_ip()
--[[
End headers to restore original visitor IP addresses at your origin web server
]]


--[[
Query String Remove arguments
]]
local function query_string_remove_args()
	local args = ngx.req.get_uri_args() --grab our query string args and put them into a table
	local modified = nil

	local query_string_remove_args_table_length = #query_string_remove_args_table
	for i=1,query_string_remove_args_table_length do --for each host in our table
		local v = query_string_remove_args_table[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			local table_length = #v[2]
			for i=1,table_length do --for each arg in our table
				local value = v[2][i]
				args[value] = nil --remove the arguement from the args table
				modified = 1 --set args as modified
			end
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if modified == 1 then --need to set our args as our new modified one
		ngx.req.set_uri_args(args) --set the args on the server as our new ordered args check ngx.var.args
	else
		return --carry on script functions
	end
end
query_string_remove_args()
--[[
Query String Remove arguments
]]

--if a table has a value inside of it
local function has_value(table_, val)
	for key, value in next, table_ do
		if value == val then
			return true
		end
	end
	return false
end

--[[
Query String Expected arguments Whitelist only
]]
local function query_string_expected_args_only()
	local args = ngx.req.get_uri_args() --grab our query string args and put them into a table
	local modified = nil

	local query_string_expected_args_only_table_length = #query_string_expected_args_only_table
	for i=1,query_string_expected_args_only_table_length do --for each host in our table
		local v = query_string_expected_args_only_table[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			for key, value in next, args do
				if has_value(v[2], tostring(key)) == false then
					args[key] = nil --remove the arguement from the args table
					modified = 1 --set args as modified
				end
			end
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if modified == 1 then --need to set our args as our new modified one
		ngx.req.set_uri_args(args) --set the args on the server as our new ordered args check ngx.var.args
	else
		return --carry on script functions
	end
end
query_string_expected_args_only()
--[[
Query String Expected arguments Whitelist only
]]

--[[
Query String Sort
]]
local function query_string_sort()
	local allow_site = nil
	local query_string_sort_table_length = #query_string_sort_table
	for i=1,query_string_sort_table_length do --for each host in our table
		local v = query_string_sort_table[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			if v[2] == 1 then --run query string sort
				allow_site = 2 --run query string sort
			end
			if v[2] == 0 then --bypass
				allow_site = 1 --do not run query string sort
			end
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if allow_site == 2 then --sort our query string
		local args = ngx.req.get_uri_args() --grab our query string args and put them into a table
		table.sort(args) --sort our query string args table into order
		ngx.req.set_uri_args(args) --set the args on the server as our new ordered args check ngx.var.args
	else --allow_site was 1
		return --carry on script functions
	end
end
query_string_sort()
--[[
End Query String Sort
]]


-- AES 256 CBC with 5 rounds of SHA-512 for the key
-- and a salt of "MySalt!!"
-- Note: salt can be either nil or exactly 8 characters long
local secret_password = "AKeyForAES-256-CBC"
local secret_salt = "MySalt!!"
local calculate_signature = aes:new(secret_password, secret_salt, aes.cipher(256,"cbc"), aes.hash.sha512, 5)


--[[
Encrypt/Obfuscate Javascript output to prevent content scrappers and bots decrypting it to try and bypass the browser auth checks. Wouldn't want to make life to easy for them now would I.
0 = Random Encryption Best form of security and default
1 = No encryption / Obfuscation
2 = Base64 Data URI only
3 = Hex encryption
4 = Base64 Javascript Encryption
5 = Conor Mcknight's Javascript Scrambler (Obfuscate Javascript by putting it into vars and shuffling them like a deck of cards)
]]
local encrypt_javascript_output = 0

-- Javascript code that will detect common bots with obvious flags
local bot_detection = [[


if(window._phantom || window.callPhantom) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("PhantomJS detected, blocking execution");
    throw new Error("PhantomJS detected, script halted");

}
if (window.__phantomas) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Phantomas detected, blocking execution");
    throw new Error("Phantomas detected, script halted");
}
if (window.Buffer) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("NodeJS detected, blocking execution");
    throw new Error("NodeJS detected, script halted");
}
if (window.emit) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Couchjs detected, blocking execution");
    throw new Error("Couchjs detected, script halted");
}
if (window.spawn) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Rhino detected, blocking execution");
    throw new Error("Rhino detected, script halted");
}
if (window.domAutomation || window.domAutomationController) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Chromium based automation driver, blocking execution");
    throw new Error("Chromium based automation driver, script halted");
}
if (window.document.documentElement.getAttribute("webdriver")) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Could be using a webdriver, blocking execution");
    throw new Error("Could be using a webdriver, script halted");
}
if (/bot|curl|kodi|xbmc|wget|urllib|python|winhttp|httrack|alexa|ia_archiver|facebook|twitter|linkedin|pingdom/i.test(navigator.userAgent)) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Blacklisted User-Agent, blocking execution");
    throw new Error("Blacklisted User-Agent, script halted");
}
if (!navigator.pdfViewerEnabled) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("The browser does not support inline viewing of PDF files");
    throw new Error("The browser does not support inline viewing of PDF files");
}
if (!navigator.geolocation) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Cannot access geolocation");
    throw new Error("Cannot access geolocation");
}
//if (!navigator.connection) {
//    console.error("Cannot gather network connection info");
//    throw new Error("Cannot gather network connection info");
//}

if (!navigator.userActivation.hasBeenActive) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("User had never interacted with webpage");
    throw new Error("User had never interacted with webpage");
}
//if (!navigator.userActivation.isActive) {
//    console.error("User isn't interacting with webpage");
//    throw new Error("User isn't interacting with webpage");
//}


if(navigator.webdriver){
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Web automation tool detected, blocking execution");
    throw new Error("Web automation tool detected, script halted");
}
if (navigator.languages == "" || navigator.plugins.length == 0) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("No prefered language detected, blocking execution");
    throw new Error("No prefered language detected, script halted");
}
var canvas = document.createElement('canvas');
var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
if(!gl){
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Webgl not enabled, blocking execution");
    throw new Error("Webgl not enabled, script halted");

}
// waits for mouse movement before loading rest of JS script
// WILL ADD SOMETIME IN FUTURE

//Hidden Elements: Bots might interact with hidden elements.
var hiddenElem = document.createElement('div');
hiddenElem.style.display = 'none';
document.body.appendChild(hiddenElem);
hiddenElem.click();
if (document.activeElement === hiddenElem) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Hidden element clicked, blocking execution");
    throw new Error("Hidden element clicked, script halted");
}

//CSS Query: Check for specific browser quirks.
if (!(window.CSS && CSS.supports('(-webkit-appearance: none)'))) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("CSS is not supported, blocking execution");
    throw new Error("CSS is not supported, script halted");
}
// Audio Fingerprinting: Bots often skip handling audio.
if (!(window.AudioContext || window.webkitAudioContext)) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("CSS is not supported, blocking execution");
    throw new Error("CSS is not supported, script halted");
}
//Battery Status: Bots often skip battery status. - NOTE: This will only work with HTTPS
//navigator.getBattery().then(function(battery) {
//    console.log("Battery info available, continuing script...");
//    // Your script code here
//}).catch(function() {
//    console.error("Battery API not supported, stopping script");
//    throw new Error("Battery API not supported, script halted");
//});
// Font Detection: Detect if default fonts are used.
if (!document.fonts.check("12px Arial")) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("Default font isn't available, blocking execution");
    throw new Error("Default font isn't available, script halted");
}
//WebRTC: Check if WebRTC is enabled.
if (!window.RTCPeerConnection) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("WebRTC is disabled, blocking execution");
    throw new Error("WebRTC is disabled, script halted");
}
//History Length: Bots often have a short or no browsing history. 
// History.length is only counts the history PER TAB.
// Not too sure how the length is calculated, however, based on my own experimentation, opening a new tab by itself counts as a "1", then anything else
// is incremented upon that. 
// Therefore, any regular user will open up Chrome, then go to my website. However, if you are using something like selenium, UC, or even "firefox http://example.com", this will all count as a "1". In other words, you need to be like a regular user and open up a new tab, then go to the website
if (history.length < 2) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.log("history length: " + history.length)
    console.error("Little browsing history, blocking execution");
    throw new Error("Little browsing history, script halted");
}
//Clipboard Access: Bots may not handle clipboard access well. - NOTE THIS ONLY WORKS WITH HTTPS
//if (!(navigator.clipboard)) {
//    console.error("Clipboard API is not supported, blocking execution");
//    throw new Error("Clipboard API is not supported, script halted");
//}
//Device Memory: Bots might have unusual memory configurations.
if (navigator.deviceMemory < 2) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("unusual memory configs, blocking execution");
    throw new Error("unsual memory configs, script halted");
}
// Check cookies
if (!navigator.cookieEnabled) {
    document.getElementById("countdowntimer").textContent = "Failed CAPTCHA";
    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
    console.error("cookies disabled, blocking execution");
    throw new Error("Cookies disabled, script halted");
}

]]


-- You would use this function if you use str.to_hex() on another variable
function from_hex(hex)
    if hex == nil then
        return ""
    end
    return (hex:gsub('..', function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- Create sha1 hash
local function sha1(msg)
    local sha1 = resty_sha1:new()
    if not sha1 then
        return nil, "Failed to create SHA-1 object"
    end

    local ok = sha1:update(msg)
    if not ok then
        return nil, "Failed to update SHA-1 with message"
    end

    local digest = sha1:final()
    if not digest then
        return nil, "Failed to finalize SHA-1 hash"
    end

    return str.to_hex(digest)
end

-- math.randomseed(os.time()) seeds the random number generator at the start, which affects all subsequent calls to math.random() across your script. Think of it as setting the initial state of the random number generator to ensure you get different sequences each time the script runs.
-- IF YOU DON'T DO THIS, YOU WILL NOT GET RANDOM STRING. IF YOU RESTART OPENRESTY, YOU WILL GET THE SAME HASHES EVERY TIME

local function urandom()
	local seed = 1
	local devurandom = io.open("/dev/urandom", "r")
	local urandom = devurandom:read(40)
	devurandom:close()

	for i = 1, string.len(urandom) do
		local s = string.byte(urandom, i)
		seed = seed + s
	end
	return seed
end


--math.randomseed(os.time())
math.randomseed(urandom())
function randomString(length)
    local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    local result = ''
    for i = 1, length do
        local randIndex = math.random(#chars)
        result = result .. chars:sub(randIndex, randIndex)
    end
    --return string.upper(result)
    return result
end

--[[
Javascript variables generated by the script to be static in length or Dynamic setting this as dynamic is the best form of security

1 = Static
2 = Dynamic
]]
local dynamic_javascript_vars_length = 2 --dynamic default
local dynamic_javascript_vars_length_static = 10 --how many chars in length should static be
local dynamic_javascript_vars_length_start = 1 --for dynamic randomize min value to max this is min value
local dynamic_javascript_vars_length_end = 10 --for dynamic randomize min value to max this is max value


--generate random strings on the fly
--qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890
local charset = {}
local charset_table_length = 1
for i = 48,  57 do
charset[charset_table_length] = string.char(i)
charset_table_length=charset_table_length+1
end --0-9 numeric
--[[
for i = 65,  90 do
charset[charset_table_length] = string.char(i)
charset_table_length=charset_table_length+1
end --A-Z uppercase
]]
--[[
for i = 97, 122 do
charset[charset_table_length] = string.char(i)
charset_table_length=charset_table_length+1
end --a-z lowercase
]]
charset[charset_table_length] = string.char(95) --insert number 95 underscore
charset_table_length=charset_table_length+1
local stringrandom_table = {} --create table to store our generated vars to avoid duplicates
local stringrandom_table_new_length = 1
local function stringrandom(length)
	--math.randomseed(os.time())
	if length > 0 then
		local output = stringrandom(length - 1) .. charset[math.random(1, #charset)]
		local duplicate_found = 0 --mark if we find a duplicate or not
		local stringrandom_table_length = #stringrandom_table
		for i=1,stringrandom_table_length do --for each value in our generated var table
			if stringrandom_table[i] == output then --if a value in our table matches our generated var
				duplicate_found = 1 --mark as duplicate var
				output = "_" .. output --append an underscore to the duplicate var
				stringrandom_table[stringrandom_table_new_length] = output --insert to the table
				stringrandom_table_new_length=stringrandom_table_new_length+1
				break --break out of for each loop since we found a duplicate
			end
		end
		if duplicate_found == 0 then --if no duplicate found
			stringrandom_table[stringrandom_table_new_length] = output --insert the output to our table
			stringrandom_table_new_length=stringrandom_table_new_length+1
		end
		return output
	else
		return ""
	end
end
--stringrandom(10)

local stringrandom_length = "" --create our random length variable
if dynamic_javascript_vars_length == 1 then --if our javascript random var length is to be static
	stringrandom_length = dynamic_javascript_vars_length_static --set our length as our static value
else --it is to be dynamic
	stringrandom_length = math.random(dynamic_javascript_vars_length_start, dynamic_javascript_vars_length_end) --set our length to be our dynamic min and max value
end

--shuffle table function
function shuffle(tbl)
	local tbl_length = #tbl
	for i = tbl_length, 2, -1 do
		local j = math.random(i)
		tbl[i], tbl[j] = tbl[j], tbl[i]
	end
	return tbl
end

--for my javascript Hex output
local function sep(str, patt, re)
	local rstr = str:gsub(patt, "%1%" .. re)
	--local rstr = ngx.re.gsub(str, patt, "%1%" .. re, ngx_re_options) --this has a major issue no idea why need to investigate more
	return rstr:sub(1, #rstr - #re)
end

local function stringtohex(str)
	--return ngx.re.gsub(str, ".", function (c) print(tostring(c[0])) return string.format('%02X', string.byte(c[0])) end, ngx_re_options) --this has a major issue no idea why need to investigate more
	return str:gsub('.', function (c)
		return string.format('%02X', string.byte(c))
	end)
end


--encrypt_javascript function
local function encrypt_javascript(string1, type, defer_async, num_encrypt, encrypt_type, methods) --Function to generate encrypted/obfuscated output
	local output = "" --Empty var

	if type == 0 then
		type = math.random(3, 5) --Random encryption
	end

	if type == 1 or type == nil then --No encryption
		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
		if defer_async == "2" then --Async
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
	end

	--https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
	--pass other encrypted outputs through this too ?
	if type == 2 then --Base64 Data URI
		local base64_data_uri = string1

		if tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, #num_encrypt do --for each number
				string1 = ngx.encode_base64(base64_data_uri)
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. ngx.encode_base64(string1) .. "\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\"></script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. ngx.encode_base64(string1) .. "\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\"></script>"
		end
		if defer_async == "2" then --Async
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. ngx.encode_base64(string1) .. "\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\"></script>"
		end
	end

	if type == 3 then --Hex
		local hex_output = stringtohex(string1) --ndk.set_var.set_encode_hex(string1) --Encode string in hex
		local hexadecimal_x = "" --Create var
		local encrypt_type_origin = encrypt_type --Store var passed to function in local var

		if tonumber(encrypt_type) == nil or tonumber(encrypt_type) <= 0 then
			encrypt_type = math.random(2, 2) --Random encryption
		end
		--I was inspired by http://www.hightools.net/javascript-encrypter.php so i built it myself
		if tonumber(encrypt_type) == 1 then
			hexadecimal_x = "%" .. sep(hex_output, "%x%x", "%") --hex output insert a char every 2 chars %x%x
		end
		if tonumber(encrypt_type) == 2 then
			hexadecimal_x = string.char(92) .. "x" .. sep(hex_output, "%x%x", string.char(92) .. "x") --hex output insert a char every 2 chars %x%x
		end

		--TODO: Fix this.
		--num_encrypt = "3" --test var
		if tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, num_encrypt do --for each number
				if tonumber(encrypt_type) ~= nil then
					encrypt_type = math.random(1, 2) --Random encryption
					if tonumber(encrypt_type) == 1 then
						--hexadecimal_x = "%" .. sep(ndk.set_var.set_encode_hex("eval(decodeURIComponent('" .. hexadecimal_x .. "'))"), "%x%x", "%") --hex output insert a char every 2 chars %x%x
					end
					if tonumber(encrypt_type) == 2 then
						--hexadecimal_x = "\\x" .. sep(ndk.set_var.set_encode_hex("eval(decodeURIComponent('" .. hexadecimal_x .. "'))"), "%x%x", "\\x") --hex output insert a char every 2 chars %x%x
					end
				end
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			--https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
	end

	if type == 4 then --Base64 javascript decode
		local base64_javascript = "eval(decodeURIComponent(escape(window.atob('" .. ngx.encode_base64(string1) .. "'))))"

		if tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, num_encrypt do --for each number
				base64_javascript = "eval(decodeURIComponent(escape(window.atob('" .. ngx.encode_base64(base64_javascript) .. "'))))"
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
	end

	if type == 5 then --Conor Mcknight's Javascript Scrambler (Obfuscate Javascript by putting it into vars and shuffling them like a deck of cards)
		local base64_javascript = ngx.encode_base64(string1) --base64 encode our script

		local l = #base64_javascript --count number of chars our variable has
		local i = 0 --keep track of how many times we pass through
		local r = math.random(1, l) --randomize where to split string
		local chunks = {} --create our chunks table for string storage
		local chunks_table_length = 1
		local chunks_order = {} --create our chunks table for string storage that stores the value only
		local chunks_order_table_length = 1
		local random_var = nil --create our random string variable to use

		while i <= l do
			random_var = stringrandom(stringrandom_length) --create a random variable name to use
			chunks_order[chunks_order_table_length] = "_" .. random_var .. "" --insert the value into our ordered table
			chunks_order_table_length=chunks_order_table_length+1
			chunks[chunks_table_length] = 'var _' .. random_var .. '="' .. base64_javascript:sub(i,i+r).. '";' --insert our value into our table we will scramble
			chunks_table_length=chunks_table_length+1

			i = i+r+1
		end

		shuffle(chunks) --scramble our table

		output = table.concat(chunks, "") --put our scrambled table into string
		output = output .. "eval(decodeURIComponent(escape(window.atob(" .. table.concat(chunks_order, " + " ) .. "))));" --put our scrambled table and ordered table into a string
		
		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
	end

	return output
end

-- We have to do this (the if conditional) because we are creating a tempRayID cookie. If XHR req passes by, we will get a different rayID than that given to the user
local rayID
local req_headers2 = ngx.req.get_headers() --get all request headers
if req_headers2["X-Requested-with"] ~= "XMLHttpRequest" and request_uri ~= "/favicon.ico" then --if NOT XHR request and NOT favicon.ico. If the Anti-DDoS page somehow loads more external resources, we would also have to check if request_uri doesn't equal that resource, because that will intefere with our mechanism
    rayID = randomString(40) -- I believe the string should be dynamically made, so it's more secure
end
local rayHeader = "00000" -- This should always be lowercase. Also, we should make this random by using the DATE, just the year, month, an day. Also, it should also be just a number, with 5 characters, because letters are harder to find. 
rayHeader = string.lower(rayHeader)
local temp_rayID_expires = 60 -- 60 seconds


-- This is the main function that either gives us access or blocks us
local function grant_access()
    -- This is a fallback mechanism. If ngx.var[cookie_name] is nil or evaluates to false (meaning the cookie doesn't exist or its value isn't set), the expression will default to an empty string ("").
    
    -- our raySALT cookie
    local cookie_raySALT_name = "cookie_" .. "cf_raySALT"
    local cookie_raySALT_value = calculate_signature:decrypt(from_hex(ngx.var[cookie_raySALT_name])) or ""
    -- our rayID cookie
    local cookie_rayID_name = "cookie_" .. "cf_rayID"
    local cookie_rayID_value = calculate_signature:decrypt(from_hex(ngx.var[cookie_rayID_name])) or ""
    -- our cf_clearance cookie
    local cookie_cf_clearance_name = "cookie_" .. "cf_clearance"
    local cookie_cf_clearance_value = ngx.var[cookie_cf_clearance_name] or ""
    -- our end_date cookie
    local cookie_end_date_name = "cookie_" .. "cf_enddate"
    local cookie_end_date_value = ngx.var[cookie_end_date_name] or ""

    local req_headers = ngx.req.get_headers() --get all request headers

    if req_headers["X-Requested-with"] == "XMLHttpRequest" then --if request header matches request type of XMLHttpRequest
        local client_saltID = req_headers['X-Auth-I-Answer'] or ""
	local client_rayID = req_headers['X-Auth-Rayid'] or ""

	-- This should help prevent replay attacks, and we're making sure the user is telling the truth
	-- TempRayID value shouldn't be nothing, could be client doing cookie tampering
	  
        -- Memory zones are more efficient than HTTP cookies
	--local ip_name = ngx.var.binary_remote_addr -- Get IP address of user, this takes less space than remote_addr due to binary format
	local ip_name = remote_addr
	local get_rayID = memory_zone:get(ip_name) -- We retrieve information about rayID for an IP in memory zone

	-- If the rayID doesn't exist given the user's ip, this can be either 2 things:
	-- 1) The client failed to solve the JS challenge in under 1 minute
	-- 2) The user decided to do a REPLAY attack and not go through the necessary GET req first
	if get_rayID == nil then 
	    ngx.log(ngx.ERR,"Someone may be trying to do a relay attack: "..remote_addr) -- We may or may not want logging, I will add on/off switch
	    ngx.exit(ngx.HTTP_BAD_REQUEST)
            return; -- This technically shouldn't happen?
	else
	    if client_rayID ~= get_rayID then
		ngx.exit(ngx.HTTP_NO_CONTENT) -- If the client rayID doesn't equal that of the DB, then give them no content. Otherwise, this would give 500 bad req
                return;
	    end

        end

        client_hash = sha1(client_rayID..tostring(client_saltID))

	-- If the answer header provided by the browser equals what the server expects...
        if string.sub(client_hash, 1, #rayHeader) == rayHeader then
            -- Set the cookie if the hash is valid

	    -- Encrypt our cookie so it's impossible for the client to know and change cookie value
            challenge = str.to_hex(calculate_signature:encrypt(remote_addr..(currenttime..client_rayID)..(currenttime..client_saltID)..(currenttime+expire_time)))
            client_rayID = str.to_hex(calculate_signature:encrypt(currenttime..client_rayID))
	    client_saltID = str.to_hex(calculate_signature:encrypt(currenttime..client_saltID))

	    -- Setup our cookies; Also, we want to use HttpOnly because we don't want JS to interact with our cookies; Helps protect against XSS
	    local cookie = "cf_rayID".."="..client_rayID.."; path=/; expires="..ngx.cookie_time(currenttime+expire_time).."; Max-Age="..expire_time.."; HttpOnly"
            local cookie2 = "cf_raySALT".."="..client_saltID.."; path=/; expires="..ngx.cookie_time(currenttime+expire_time).."; Max-Age="..expire_time.."; HttpOnly"
	    local cookie3 = "cf_clearance="..challenge.."; path=/; expires=".. ngx.cookie_time(currenttime+expire_time) .."; Max-Age="..expire_time.."; HttpOnly"
	    local cookie4 = "cf_enddate="..(currenttime+expire_time).."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. "; HttpOnly" --end date cookie
	    ngx.header['Set-Cookie'] = {
                cookie,
                cookie2,
	        cookie3,
	        cookie4
            }
	    ngx.header["X-Content-Type-Options"] = "nosniff"
	    ngx.header["X-Frame-Options"] = "SAMEORIGIN"
	    ngx.header["X-XSS-Protection"] = "1; mode=block"
	    ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
	    ngx.header["Pragma"] = "no-cache"
	    ngx.header["Expires"] = "0"
	    ngx.header["Content-Type"] = "text/html; charset=" .. default_charset
	    ngx.status = expected_header_status
	    ngx.exit(ngx.HTTP_NO_CONTENT)
        end
    -- If request is not XHR
    else
	-- We will create a variable in memory that will be used to validate whether the X header the user sent was accurate
	-- Memory zones are more efficient than HTTP cookies
	--local ip_name = ngx.var.binary_remote_addr -- Get IP address of user, this takes less space than remote_addr due to binary format
	local ip_name = remote_addr
	local rayID_exists= memory_zone:get(ip_name) -- We retrieve information about IP in memory zone
	if rayID_exists then -- If IP does exist
            local success, err, forcible = memory_zone:replace(ip_name, rayID, temp_rayID_expires) -- Replace it's existing rayID with a new rayID given to client

	else -- If IP doesn-t exist
	    local success, err, forcible = memory_zone:set(ip_name, rayID, temp_rayID_expires) -- Set a new memory row with IP linked to rayID

        end

    end
    -- If this isn't an XHR request, then it must mean we are either visiting the page the first time, or we already passed and is a regular req
    -- Check if all of our cookies exist
    if cookie_raySALT_value ~= nil and cookie_rayID_value ~= nil and cookie_cf_clearance_value ~= nil and cookie_end_date_value ~= nil then -- if all our cookies exist

	local cookie_end_date_value_unix = tonumber(cookie_end_date_value) or nil --convert our cookie end date provided by the user into a unix time stamp
	if cookie_end_date_value_unix == nil or cookie_end_date_value_unix == "" then --if our cookie end date date in unix does not exist
	    return --return to refresh the page so it tries again
	end
        check_cookie = str.to_hex(calculate_signature:encrypt(remote_addr..cookie_rayID_value..cookie_raySALT_value..cookie_end_date_value_unix))
	if check_cookie ~= cookie_cf_clearance_value then
            return; --return to refresh the page so it tries again
        end
	if cookie_end_date_value_unix <= currenttime then --if our cookie end date is less than or equal to the current date meaning the users authentication time expired
	    return --return to refresh the page so it tries again
        end

    end
    --return to refresh the page so it tries again
    local output = ngx.exit(ngx.OK) --Go to content
    return output

end
grant_access()

-- Our JS challenge we give to the user
-- This is the clean version
javascript_challenge = [[
window.onload = function() {
    // SHA-1 hashing function
    !function(){"use strict";function t(t){t?(l[0]=l[16]=l[1]=l[2]=l[3]=l[4]=l[5]=l[6]=l[7]=l[8]=l[9]=l[10]=l[11]=l[12]=l[13]=l[14]=l[15]=0,this.blocks=l):this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],this.h0=1732584193,this.h1=4023233417,this.h2=2562383102,this.h3=271733878,this.h4=3285377520,this.block=this.start=this.bytes=this.hBytes=0,this.finalized=this.hashed=!1,this.first=!0}function r(r,e){var i,h=v(r);if(r=h[0],h[1]){var s,n=[],o=r.length,a=0;for(i=0;i<o;++i)(s=r.charCodeAt(i))<128?n[a++]=s:s<2048?(n[a++]=192|s>>>6,n[a++]=128|63&s):s<55296||s>=57344?(n[a++]=224|s>>>12,n[a++]=128|s>>>6&63,n[a++]=128|63&s):(s=65536+((1023&s)<<10|1023&r.charCodeAt(++i)),n[a++]=240|s>>>18,n[a++]=128|s>>>12&63,n[a++]=128|s>>>6&63,n[a++]=128|63&s);r=n}r.length>64&&(r=new t(!0).update(r).array());var f=[],u=[];for(i=0;i<64;++i){var c=r[i]||0;f[i]=92^c,u[i]=54^c}t.call(this,e),this.update(u),this.oKeyPad=f,this.inner=!0,this.sharedMemory=e}var e="input is invalid type",i="object"==typeof window,h=i?window:{};h.JS_SHA1_NO_WINDOW&&(i=!1);var s=!i&&"object"==typeof self,n=!h.JS_SHA1_NO_NODE_JS&&"object"==typeof process&&process.versions&&process.versions.node;n?h=global:s&&(h=self);var o=!h.JS_SHA1_NO_COMMON_JS&&"object"==typeof module&&module.exports,a="function"==typeof define&&define.amd,f=!h.JS_SHA1_NO_ARRAY_BUFFER&&"undefined"!=typeof ArrayBuffer,u="0123456789abcdef".split(""),c=[-2147483648,8388608,32768,128],y=[24,16,8,0],p=["hex","array","digest","arrayBuffer"],l=[],d=Array.isArray;!h.JS_SHA1_NO_NODE_JS&&d||(d=function(t){return"[object Array]"===Object.prototype.toString.call(t)});var b=ArrayBuffer.isView;!f||!h.JS_SHA1_NO_ARRAY_BUFFER_IS_VIEW&&b||(b=function(t){return"object"==typeof t&&t.buffer&&t.buffer.constructor===ArrayBuffer});var v=function(t){var r=typeof t;if("string"===r)return[t,!0];if("object"!==r||null===t)throw new Error(e);if(f&&t.constructor===ArrayBuffer)return[new Uint8Array(t),!1];if(!d(t)&&!b(t))throw new Error(e);return[t,!1]},_=function(r){return function(e){return new t(!0).update(e)[r]()}},A=function(t){var r,i=require("crypto"),s=require("buffer").Buffer;r=s.from&&!h.JS_SHA1_NO_BUFFER_FROM?s.from:function(t){return new s(t)};return function(h){if("string"==typeof h)return i.createHash("sha1").update(h,"utf8").digest("hex");if(null===h||void 0===h)throw new Error(e);return h.constructor===ArrayBuffer&&(h=new Uint8Array(h)),d(h)||b(h)||h.constructor===s?i.createHash("sha1").update(r(h)).digest("hex"):t(h)}},w=function(t){return function(e,i){return new r(e,!0).update(i)[t]()}};t.prototype.update=function(t){if(this.finalized)throw new Error("finalize already called");var r=v(t);t=r[0];for(var e,i,h=r[1],s=0,n=t.length||0,o=this.blocks;s<n;){if(this.hashed&&(this.hashed=!1,o[0]=this.block,this.block=o[16]=o[1]=o[2]=o[3]=o[4]=o[5]=o[6]=o[7]=o[8]=o[9]=o[10]=o[11]=o[12]=o[13]=o[14]=o[15]=0),h)for(i=this.start;s<n&&i<64;++s)(e=t.charCodeAt(s))<128?o[i>>>2]|=e<<y[3&i++]:e<2048?(o[i>>>2]|=(192|e>>>6)<<y[3&i++],o[i>>>2]|=(128|63&e)<<y[3&i++]):e<55296||e>=57344?(o[i>>>2]|=(224|e>>>12)<<y[3&i++],o[i>>>2]|=(128|e>>>6&63)<<y[3&i++],o[i>>>2]|=(128|63&e)<<y[3&i++]):(e=65536+((1023&e)<<10|1023&t.charCodeAt(++s)),o[i>>>2]|=(240|e>>>18)<<y[3&i++],o[i>>>2]|=(128|e>>>12&63)<<y[3&i++],o[i>>>2]|=(128|e>>>6&63)<<y[3&i++],o[i>>>2]|=(128|63&e)<<y[3&i++]);else for(i=this.start;s<n&&i<64;++s)o[i>>>2]|=t[s]<<y[3&i++];this.lastByteIndex=i,this.bytes+=i-this.start,i>=64?(this.block=o[16],this.start=i-64,this.hash(),this.hashed=!0):this.start=i}return this.bytes>4294967295&&(this.hBytes+=this.bytes/4294967296<<0,this.bytes=this.bytes%4294967296),this},t.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,r=this.lastByteIndex;t[16]=this.block,t[r>>>2]|=c[3&r],this.block=t[16],r>=56&&(this.hashed||this.hash(),t[0]=this.block,t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[14]=this.hBytes<<3|this.bytes>>>29,t[15]=this.bytes<<3,this.hash()}},t.prototype.hash=function(){var t,r,e=this.h0,i=this.h1,h=this.h2,s=this.h3,n=this.h4,o=this.blocks;for(t=16;t<80;++t)r=o[t-3]^o[t-8]^o[t-14]^o[t-16],o[t]=r<<1|r>>>31;for(t=0;t<20;t+=5)e=(r=(i=(r=(h=(r=(s=(r=(n=(r=e<<5|e>>>27)+(i&h|~i&s)+n+1518500249+o[t]<<0)<<5|n>>>27)+(e&(i=i<<30|i>>>2)|~e&h)+s+1518500249+o[t+1]<<0)<<5|s>>>27)+(n&(e=e<<30|e>>>2)|~n&i)+h+1518500249+o[t+2]<<0)<<5|h>>>27)+(s&(n=n<<30|n>>>2)|~s&e)+i+1518500249+o[t+3]<<0)<<5|i>>>27)+(h&(s=s<<30|s>>>2)|~h&n)+e+1518500249+o[t+4]<<0,h=h<<30|h>>>2;for(;t<40;t+=5)e=(r=(i=(r=(h=(r=(s=(r=(n=(r=e<<5|e>>>27)+(i^h^s)+n+1859775393+o[t]<<0)<<5|n>>>27)+(e^(i=i<<30|i>>>2)^h)+s+1859775393+o[t+1]<<0)<<5|s>>>27)+(n^(e=e<<30|e>>>2)^i)+h+1859775393+o[t+2]<<0)<<5|h>>>27)+(s^(n=n<<30|n>>>2)^e)+i+1859775393+o[t+3]<<0)<<5|i>>>27)+(h^(s=s<<30|s>>>2)^n)+e+1859775393+o[t+4]<<0,h=h<<30|h>>>2;for(;t<60;t+=5)e=(r=(i=(r=(h=(r=(s=(r=(n=(r=e<<5|e>>>27)+(i&h|i&s|h&s)+n-1894007588+o[t]<<0)<<5|n>>>27)+(e&(i=i<<30|i>>>2)|e&h|i&h)+s-1894007588+o[t+1]<<0)<<5|s>>>27)+(n&(e=e<<30|e>>>2)|n&i|e&i)+h-1894007588+o[t+2]<<0)<<5|h>>>27)+(s&(n=n<<30|n>>>2)|s&e|n&e)+i-1894007588+o[t+3]<<0)<<5|i>>>27)+(h&(s=s<<30|s>>>2)|h&n|s&n)+e-1894007588+o[t+4]<<0,h=h<<30|h>>>2;for(;t<80;t+=5)e=(r=(i=(r=(h=(r=(s=(r=(n=(r=e<<5|e>>>27)+(i^h^s)+n-899497514+o[t]<<0)<<5|n>>>27)+(e^(i=i<<30|i>>>2)^h)+s-899497514+o[t+1]<<0)<<5|s>>>27)+(n^(e=e<<30|e>>>2)^i)+h-899497514+o[t+2]<<0)<<5|h>>>27)+(s^(n=n<<30|n>>>2)^e)+i-899497514+o[t+3]<<0)<<5|i>>>27)+(h^(s=s<<30|s>>>2)^n)+e-899497514+o[t+4]<<0,h=h<<30|h>>>2;this.h0=this.h0+e<<0,this.h1=this.h1+i<<0,this.h2=this.h2+h<<0,this.h3=this.h3+s<<0,this.h4=this.h4+n<<0},t.prototype.hex=function(){this.finalize();var t=this.h0,r=this.h1,e=this.h2,i=this.h3,h=this.h4;return u[t>>>28&15]+u[t>>>24&15]+u[t>>>20&15]+u[t>>>16&15]+u[t>>>12&15]+u[t>>>8&15]+u[t>>>4&15]+u[15&t]+u[r>>>28&15]+u[r>>>24&15]+u[r>>>20&15]+u[r>>>16&15]+u[r>>>12&15]+u[r>>>8&15]+u[r>>>4&15]+u[15&r]+u[e>>>28&15]+u[e>>>24&15]+u[e>>>20&15]+u[e>>>16&15]+u[e>>>12&15]+u[e>>>8&15]+u[e>>>4&15]+u[15&e]+u[i>>>28&15]+u[i>>>24&15]+u[i>>>20&15]+u[i>>>16&15]+u[i>>>12&15]+u[i>>>8&15]+u[i>>>4&15]+u[15&i]+u[h>>>28&15]+u[h>>>24&15]+u[h>>>20&15]+u[h>>>16&15]+u[h>>>12&15]+u[h>>>8&15]+u[h>>>4&15]+u[15&h]},t.prototype.toString=t.prototype.hex,t.prototype.digest=function(){this.finalize();var t=this.h0,r=this.h1,e=this.h2,i=this.h3,h=this.h4;return[t>>>24&255,t>>>16&255,t>>>8&255,255&t,r>>>24&255,r>>>16&255,r>>>8&255,255&r,e>>>24&255,e>>>16&255,e>>>8&255,255&e,i>>>24&255,i>>>16&255,i>>>8&255,255&i,h>>>24&255,h>>>16&255,h>>>8&255,255&h]},t.prototype.array=t.prototype.digest,t.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(20),r=new DataView(t);return r.setUint32(0,this.h0),r.setUint32(4,this.h1),r.setUint32(8,this.h2),r.setUint32(12,this.h3),r.setUint32(16,this.h4),t},(r.prototype=new t).finalize=function(){if(t.prototype.finalize.call(this),this.inner){this.inner=!1;var r=this.array();t.call(this,this.sharedMemory),this.update(this.oKeyPad),this.update(r),t.prototype.finalize.call(this)}};var S=function(){var r=_("hex");n&&(r=A(r)),r.create=function(){return new t},r.update=function(t){return r.create().update(t)};for(var e=0;e<p.length;++e){var i=p[e];r[i]=_(i)}return r}();S.sha1=S,S.sha1.hmac=function(){var t=w("hex");t.create=function(t){return new r(t)},t.update=function(r,e){return t.create(r).update(e)};for(var e=0;e<p.length;++e){var i=p[e];t[i]=w(i)}return t}(),o?module.exports=S:(h.sha1=S,a&&define(function(){return S}))}();

    // Function to send the hash to the server
    function sendHashToServer() {

        const cookiePart = ']]..rayID..[[';
        let i = 0;
        let hash;
        while (true) {
            hash = sha1(cookiePart + i);

            if (hash.startsWith(']]..rayHeader..[[')) { // Replace this with your actual condition
                break;
            }
            i++;
        }

        const xhr = new XMLHttpRequest();
        const url = '192.168.56.135/'; // Replace with your server URL

        xhr.open("POST", ']]..request_uri..[[', true);

        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                location.reload(true);
            }
        };

        // javascript_REQUEST_headers
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader('X-Requested-with', 'XMLHttpRequest');
        xhr.setRequestHeader('X-Auth-RayID', cookiePart);
        xhr.setRequestHeader('X-Auth-i-Answer', i);
        xhr.withCredentials = true;

	const data = "2+2=4";
        xhr.send(data);
    }

    // Send the hash to the server
    //sendHashToServer(hash);


    var timeleft = ]]..temp_rayID_expires..[[;
    var downloadTimer = setInterval(function(){
        timeleft--;
	//document.getElementById("countdowntimer").textContent = timeleft;
	if(timeleft <= 0) {
	    clearInterval(downloadTimer);
	    document.getElementById("countdowntimer").textContent = "Unable to solve captcha on time";
	    var checkboxContainer = document.querySelector(".recaptcha-checkbox-container");
	    checkboxContainer.innerHTML = '<div class="x-mark"></div>';
        }

    },1000);


    // Ensure the checkbox is unchecked when the page loads
    document.getElementById("recaptcha-checkbox").checked = false;
    document.getElementById("recaptcha-checkbox").addEventListener("change", function() {
        if (this.checked) {
	    // Hide the button
            var checkboxContainer = document.querySelector(".recaptcha-checkbox-container");
            checkboxContainer.innerHTML = '<div class="captcha-loader"></div>';


            // Simulate a delay (e.g., waiting for a response)
            setTimeout(function() {

                // bot_detection
                ]]..bot_detection..[[

                // Change loader to checkmark
                checkboxContainer.innerHTML = '<div class="checkmark"></div>';
                    
                // Show the new text
                document.getElementById("newText").style.display = "block";
                  
                // Execute additional JavaScript code
                console.log("Checkbox was checked!");
                // Add more JS code here
                // xxx...

                window.setTimeout(function() {
                    sendHashToServer()
                }, 1000);

            }, 2000); // 2 seconds delay for demonstration

        }
    });


};
]]

-- This is our obfuscated JS challenge before it's encrypted using https://obfuscator.io/
javascript_challenge2 = [[





]]





--[[
encrypt/obfuscate the javascript output
]]
if encrypt_javascript_output == 1 then --No encryption/Obfuscation of Javascript so show Javascript in plain text
    javascript_challenge = [[<script type="text/javascript" charset="]] .. default_charset .. [[" data-cfasync="false">]] .. javascript_challenge .. [[</script>]]
else --some form of obfuscation has been specified so obfuscate the javascript output
    javascript_challenge = encrypt_javascript(javascript_challenge, encrypt_javascript_output) --run my function to encrypt/obfuscate javascript output
end

local style_sheet = [[

html, body { padding: 0; margin: 0; width: 100%; height: 100%; }
* {box-sizing: border-box;}
body { text-align: center; padding: 0; background: black; color: #FFF; font-family: Arial; }
h1 {text-align: center;}
body { text-align: left; display: -webkit-box; display: -ms-flexbox; display: flex; -webkit-box-pack: center; -ms-flex-pack: center; justify-content: center; -webkit-box-align: center; -ms-flex-align: center; align-items: center;}
article { display: block; width: 700px; padding: 50px; margin: 0 auto; }
a { color: #fff; font-weight: bold;}
a:hover { text-decoration: none; }
svg { width: 75px; margin-right: auto; margin-left: auto; width: 50%; }
.header { display: flex; align-items: center; }

/* Source: https://css-loaders.com/spinner/*/
/* HTML: <div class="loader"></div> */
.loader {  width: 50px;  aspect-ratio: 1;  display: grid;  border-radius: 50%;  background:    linear-gradient(0deg ,rgb(255 255 255/50%) 30%,#0000 0 70%,rgb(255 255 255/100%) 0) 50%/8% 100%,    linear-gradient(90deg,rgb(255 255 255/25%) 30%,#0000 0 70%,rgb(255 255 255/75% ) 0) 50%/100% 8%;  background-repeat: no-repeat;  animation: l23 1s infinite steps(12);  margin: 50px;}
.loader::before,.loader::after {   content: "";   grid-area: 1/1;   border-radius: 50%;   background: inherit;   opacity: 0.915;   transform: rotate(30deg);}
.loader::after {   opacity: 0.83;   transform: rotate(60deg);}
@keyframes l23 {  100% {transform: rotate(1turn)}}

#newText {display: none;} /* Initially hide the new text */

.captchaButton {width: 300px; height: 50px;}

.recaptcha-container {
    display: flex;
    align-items: center;
    border: 1px solid #d3d3d3;
    border-radius: 5px;
    background-color: #fff;
    box-shadow: 0 0 8px rgba(0, 0, 0, 0.1);
    padding: 0px 15px 0px 15px;
    width: 300px;
}

.recaptcha-error-container {
    position: fixed;
    margin-bottom: 40px; /* Add some space between the error message and checkbox */
}
#countdowntimer {
    color: red;
    /*display: none;*/ /* Initially hidden */
    font-size: 10px;
}

.recaptcha-checkbox-container {
    display: flex;
    align-items: center;
    padding-right: 10px;
}

.recaptcha-checkbox-container input[type="checkbox"] {
    width: 25px;
    height: 25px;
}

.recaptcha-text-container {
    margin-right: auto; /* Push the text to the right of the checkbox */
    font-size: 16px;
    color: black;
}

.recaptcha-info-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    font-size: 12px;
    margin-left: 10px; /* Add some space between text and info */
}

.recaptcha-info-container img {
    width: 60px;
    height: 60px;
    margin-bottom: 2px; /* Space between logo and text */
}

.recaptcha-privacy-terms {
    text-align: center;
    font-size: 10px;
    color: black;
}

.captcha-loader {
    width: 25px;
    height: 25px;
    border: 3px solid #f3f3f3;
    /*border-top: 3px solid #5cb85c;*/
    border-top: 3px solid #AF46FF;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    display: inline-block;
    vertical-align: middle;
}


@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.checkmark {
  position: relative;
  display: inline-block;
  width: 25px;
  height: 25px;
}

.checkmark::before {
  content: '';
  position: absolute;
  width: 7.5px;
  height: 18.75px;
  border-width: 0 5px 5px 0;
  border-style: solid;
  border-color: green;
  transform: rotate(45deg);
  right: 7px;
}


.x-mark {
  position: relative;
  width: 25px;
  height: 25px;
}

.x-mark::before,
.x-mark::after {
  content: '';
  position: absolute;
  width: 100%;
  height: 3px;
  background-color: red;
  top: 50%;
  left: 0;
  transform-origin: center;
}

.x-mark::before {
  transform: translateY(-50%) rotate(45deg);
}

.x-mark::after {
  transform: translateY(-50%) rotate(-45deg);
}



]]

-- Display our HTML
local anti_ddos_html_output = [[
<!DOCTYPE html>
<html>
<head>
<title>Just a moment...</title>
<style>
     ]]..style_sheet..[[
</style>

]]..javascript_challenge..[[

</head>
<body>


<div class="header">
<center>
<span class="loader"></span>

<noscript><h1>Please enable Javascript</h1></noscript>


    <div class="recaptcha-container">


        <div class="recaptcha-error-container">
            <p id="countdowntimer"></p>
        </div>


        <div class="recaptcha-checkbox-container">
	    <input type="checkbox" id="recaptcha-checkbox">
            <label for="recaptcha-checkbox"></label>
        </div>
        <div class="recaptcha-text-container">
            <p>I'm not a robot</p>
        </div>
        <div class="recaptcha-info-container">
            <img src="data:image/png;base64, 


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
AElFTkSuQmCC



	    " alt="reCAPTCHA Logo">
            <div class="recaptcha-privacy-terms">Privacy - Terms</div>
        </div>
    </div>




<p id="newText">Please allow up to 5 seconds...</p>
<b><p>Ray ID: ]]..rayID..[[</p></b>
<a href="#">DDoS Protection by ProfessorJarIO</a>



<center>
</div>


</body>
</html>
]]


--All previous checks failed and no access_granted permited so display authentication check page.
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["X-Frame-Options"] = "SAMEORIGIN"
ngx.header["X-XSS-Protection"] = "1; mode=block"
ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
ngx.header["Pragma"] = "no-cache"
ngx.header["Expires"] = "0"
ngx.header["Content-Type"] = "text/html; charset=" .. default_charset
ngx.status = authentication_page_status_output
ngx.say(anti_ddos_html_output)
ngx.exit(ngx.HTTP_OK)
