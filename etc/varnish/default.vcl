import std;

# Include the file with the host definitions in it (we'll call nzpost_extract_sitevars from it soon)
# include "nmr.store.vcl";

# Separate backends to allow for ratelimiting if required in future. Nginx still decides how to route the request.
backend default {
	.host = "localhost";
	.port = "8080";
}


# @TODO setup an access list for purges; for the time being, we allow
# from any requesting client
#acl purge {
#  
#}
 
# Handles new requests arriving from a client. At this point we haven't checked the cache.
# Here we:
#  1) Standardise the set of incoming headers to increase the chances of a cache hit
#  2) Detect specific circumstances that should bypass the cache
#  3) Extract cookies etc into X-Varnish-Client-[x] headers that can be "varied" on by the server to create different versions of the cache
sub vcl_recv {

  # TODO this is temporary; need to fix issue with cache on different remote hosts
  #set req.http.host = "localhost";
  set req.http.X-TEST-URL = req.http.host + req.url;

  # @TODO problem with below is that we are now tightly coupled
  # to PHPSESSID; look for a way to represent session without
  # explicitly referring to name
  set req.http.X-CLIENT-SESSIONID = regsub(
    req.http.Cookie, ".*?PHPSESSID=([a-z0-9]+).*", "\1"
  );

  # POST/DELETE/PUT requets should be passed directly to 
  # backend
  if (req.url ~ "wp-admin"  ||
      req.http.host ~ "api" ||
      req.request == "POST") {
    
    return(pass);
  }


  # check for purge request
  if (req.request == "PURGE") {
    return (lookup);
  }
 
  # Retrieve session ID and roles information (writes ANON into these if they're not available)
  # This is where most X-Varnish-Client-[x] headers come from.
  # call nzpost_extract_sitevars;
 
  # If the current request is for a site we don't recognise, pipe it immediately
  #if (!req.http.X-MATCHED-SITE) {
  #  return (pipe);
  #}
 
  # Load balancer check file should just pipe to avoid any cache interference
  if (req.url ~ "lb_check") {
    return (pipe);
  }
 
  # We only deal with GET, HEAD and POST requests. The rest pipe.
  if (req.request != "GET"  && 
      req.request != "HEAD" && 
      req.request != "POST") {
    return (pipe);
  }
 
  # Allow a grace period for offering "stale" cache data while we're fetching a new copy from the backend
  set req.grace = 5m;
 
  # Remove HTTP auth header, if present (web server level only)
  if (req.http.Authorization) {
    unset req.http.Authorization;
  }
 
  # If there's ETag (If-None-Match) and If-Modified-Since, just use ETag. Varnish isn't very good at 304ing If-Modified-Since.
  #if (req.http.If-Modified-Since && req.http.If-None-Match) {
  #  unset req.http.If-Modified-Since;
  #}
 
  # Normalise Accept-Encoding header (we only care about gzip)
  if (req.http.Accept-Encoding) {
    if (req.http.Accept-Encoding ~ "gzip" && req.http.user-agent !~ "MSIE 6") {
      set req.http.Accept-Encoding = "gzip";
    } else {
      # don't care - remove
      unset req.http.Accept-Encoding;
    }
  }
 
  # Force a cache miss if the request is a force-refresh request from the client
  # When an "admin" user does this, it causes a purge of alternative variants as well. See vcl_miss.
  # We only allow this in dev or if an "nzpost_allow_purge" cookie exists, otherwise bots and malicious users
  # use this against us.
  # need to define/abstract "dev"
  #if (req.http.Cache-Control ~ "no-cache" && (req.http.Cookie ~ "secret_cookie=1" || req.http.host ~ "localhost")) {
    # Use this special flag to denote an explicit force refresh. When an admin does this, it
    # clears the cache for everyone (all variants). See vcl_hit/vcl_miss.
    #set req.http.X-Force-Refresh = 1;
    #set req.http.X-Force-Miss-Reason = "force-refresh";
    #set req.hash_always_miss = true;
    # don't set X-Varnish-Force-Pass, this prevents the replacement page from entering the cache
  #}
 
  # nzpost_cache adds a suffix of "ADMIN" to the roles hash if the user is a special Admin user, who should
  # never hit cache. These users may also perform a purge by sending a force refresh.
  #if (req.http.X-Varnish-Client-Roles ~ "ADMIN$") {
  #  set req.http.X-Varnish-Client-IsAdmin = 1;
  #  set req.http.X-Force-Miss-Reason = "admin";
  #  set req.http.X-Varnish-Force-Pass = 1;
  #}
 
  # If the user has a persistent_login cookie but not a session, we need to drop them into Drupal
  # to get their session back. This case will be included in the hash to allow other users to still hit in parallel.
  #if (req.esi_level == 0 && req.http.X-Varnish-Client-PersistentLogin && req.http.X-Varnish-Client-SID == "ANON") {
  #  set req.http.X-Varnish-Force-Pass = 1;
  #  set req.http.X-Force-Miss-Reason = "persistent-login-needs-validate";
  #}
 
  # If the user has a CAS cookie but not a session, we need to drop them into Drupal
  # to get their session back. This case will be included in the hash to allow other users to still hit in parallel.
  #if (req.esi_level == 0 && req.http.X-Varnish-Client-CASLogin && (req.http.X-Varnish-Client-SID == "ANON" || req.http.X-Varnish-Client-Roles == "ANON")) {
    #set req.http.X-Varnish-Force-Pass = 1;
    #set req.http.X-Force-Miss-Reason = "CAS-login-needs-validate";
  #}
 
  # HTTP POST requests should not be cached, but they still pass through the normal mechanism
  # so ESI can happen on the response (eg. form errors).
  if (req.request == "POST") {
    set req.http.X-Varnish-Force-Pass = 1;
    set req.http.X-Force-Miss-Reason = "http-post";
  }
 
  # If the user has cookies, we will look for some flags of interest in them
  if (req.http.Cookie) {
    # Static files don't need cookies
    if (req.url ~ "^/sites/default/files") {
      unset req.http.cookie;
    }
 
    # Respect the NO_CACHE header set by cookie_cache_bypass. This is included in the hash by vcl_hash.
    if (req.http.Cookie ~ "NO_CACHE" && req.esi_level == 0) {
      set req.http.X-Varnish-Force-Pass = 1;
      set req.http.X-Force-Miss-Reason = "cookie-cache-bypass";
    }
 
    # Scan for and extract any A/B cookies found (for now we just put these in one big cookie. Later we might separate them.)
    #if (req.http.Cookie ~ "NZPOST_DEFAULT_") {
    #  set req.http.X-Varnish-Client-ToolPrefs = regsuball(req.http.Cookie, "(NZPOST_DEFAULT_.*?=[^;]+)", "\1");
    #}
 
    # Allow varying on Javascript support
    if (req.http.Cookie ~ "has_js=1") {
      set req.http.X-Varnish-Client-HasJS = 1;
    }
  }
 
  # If this request has restarted, inform the server in case it cares
  if (req.restarts > 0) {
    set req.http.X-Varnish-Restarts = req.restarts;
  }
 
  # Unless X-Varnish-Force-Pass has been set, we just perform a standard cache lookup. A pass can never hit.
  if (req.http.X-Varnish-Force-Pass) {
    set req.hash_always_miss = true;
    return (pass);
  
  } else {
    return (lookup);
  }
}
 
# Our hash is kept simple - just the host, port and path, plus the miss reason if we're sure we don't
# want the current request to meddle with the already cached version.
# We use server-provided Vary headers combined with X-Varnish-Client-* headers for cache variations rather than hashes.
sub vcl_hash {

  # Default URL and host hash
  hash_data(req.http.host);
  hash_data(req.url);
  hash_data(req.http.x-forwarded-scheme);

  return (hash);

}
 
# Called after the backend request has arrived, here we override TTLs, detect ESIs, and add some headers for later.
sub vcl_fetch {

  set beresp.http.X-CACHE-ON  = req.http.host + req.url;
  set beresp.http.X-SERVER-ID = server.hostname;

  # Read the X-VARNISH-TTL header from the backend (if present) and use it to set the Varnish TTL only
  # See http://open.blogs.nytimes.com/tag/varnish/
  if (beresp.http.X-VARNISH-TTL) {
    set beresp.ttl = std.duration(beresp.http.X-VARNISH-TTL, 5m);
  }
 
  # Check for errors we'd like to catch locally (you may want to disable this on dev)
  if (beresp.status == 500 || beresp.status == 501 || beresp.status == 502 || beresp.status == 504 || beresp.status == 400) {
    #return (error);
  }
 
  # Enable ESI parsing only if the server specifies it
  #if (beresp.http.X-Varnish-ESI == "on") {
  if (true) {
    set beresp.do_esi = true;
  }
  else {
    set beresp.do_esi = false;
  }
 
  if (req.esi_level > 0) {
    if (beresp.http.set-cookie) {
      # ESI responses can't set cookies
      unset beresp.http.set-cookie;
    }
    if (beresp.status != 200) {
      return (error);
    }
  }
 
  set beresp.http.X-Test = beresp.http.Vary;

  # Leave the Vary header as it is for now, but store what should be sent to the client and debug headers here
  if (beresp.http.vary) {
    set beresp.http.X-Test-Vary = 1;

    # This is based on the cookie strip example on https://www.varnish-cache.org/trac/wiki/VCLExampleRemovingSomeCookies
    # It works by putting a space in front of entries we want to keep, then purging any that don't start with a space
    set beresp.http.X-Varnish-Debug-CustomVary = "," + beresp.http.Vary;
    set beresp.http.X-Varnish-Debug-CustomVary = regsuball(beresp.http.X-Varnish-Debug-CustomVary, ", +", ",");
    set beresp.http.X-Varnish-Debug-CustomVary = regsuball(beresp.http.X-Varnish-Debug-CustomVary, ",(X-Varnish-Client-[^,]+)", ", \1");
    set beresp.http.X-Varnish-Debug-CustomVary = regsuball(beresp.http.X-Varnish-Debug-CustomVary, ",[^ ][^,]*", "");
    set beresp.http.X-Varnish-Debug-CustomVary = regsuball(beresp.http.X-Varnish-Debug-CustomVary, "^[, ]+|[, ]+$", "");
    if (beresp.http.X-Varnish-Debug-CustomVary == "") {
      unset beresp.http.X-Varnish-Debug-CustomVary;
    }
 
    # Now extract all the cookies that aren't X-Varnish-Client-* as the set of Vary headers to send to the client
    # This is swapped out in vcl_deliver
    set beresp.http.X-Varnish-Client-Vary = regsuball(beresp.http.Vary, "(^|, ?) *X-Varnish-Client-[^,]+,? *", "\1");
    if (beresp.http.X-Varnish-Client-Vary == "") {
      # Just set a sensible default
      set beresp.http.X-Varnish-Client-Vary = "Accept-Encoding";
    }
  } else {
    set beresp.http.X-Test = "not set vary";
  }
 
  # Static files have fixed cache lifetimes in Varnish (not too long, don't want to clog ourselves up)
  # This is mostly to hold gzip'd css/js in cache to avoid having to zip it multiple times.
  if (req.url ~ "\.(jpe?g|gif|png)(\?.*)?$") {
    set beresp.ttl = 60s;
  }
  else if (req.url ~ "\.(css|js)(\?.*)?$") {
    set beresp.ttl = 1h;
  }
 
  # 200 requests are cached as per the server's advice
  # 301 requests are cached for 10 minutes
  # 404 responses are cached for 1 minute
  # Any other code is never cached
  # Non-200 ESI blocks are never cached
  if (beresp.status == 200) {
    # Do nothing special
  }
  else if (beresp.status == 301 && req.esi_level == 0) {
    set beresp.ttl = 10m;
  }
  else if (beresp.status == 404 && req.esi_level == 0) {
    set beresp.ttl = 60s;
  }
  else {
    # Don't cache
    set beresp.ttl = 0s;
  }
 
  if (beresp.http.Set-cookie) {
    if (beresp.http.Set-cookie == "") {
      unset beresp.http.Set-cookie;
    }
    else {
      # If the request sets a cookie, caching this is a very bad idea.
      # @NOTE this actually doesnt apply in our use case
      # set beresp.ttl = 0s;
      #set beresp.http.X-Varnish-Refuse-Cache = "set-cookie";
    }
  }
 
  set beresp.http.X-Varnish-Debug-TTL = beresp.ttl;
 
  # For ban lurker-friendly cache entries (for the Varnish module)
  # The x-sid variable is just for us, to purge per-user ESIs easier.
  set beresp.http.x-url = req.url;
  set beresp.http.x-host = req.http.host;
  if (req.http.X-Varnish-Client-SID && beresp.http.vary ~ "X-Varnish-Client-SID") {
    set beresp.http.x-sid = req.http.X-Varnish-Client-SID;
  }
 
  # Force the gzipping of responses that could benefit that nginx has neglected to gzip for some reason.
  # This is quite important, due to https://www.varnish-cache.org/trac/ticket/1029 as otherwise Varnish
  # will cache an uncached version of the page against the Accept-encoding: gzip header, so any request for
  # the resources gzipped will be ungzipped. When combined with ESIs, this can mean a non-gzipped page with gzipped
  # ESIs is rendered, which is really ugly. See Fog#4054.
  # It's now important in vcl_recv to discover cases where clients shouldn't get gzip and remove accept-encoding.
  if (beresp.http.content-type ~ "^text/.+") {
    set beresp.do_gzip = true;
  }
 
  # To finish up, we need to carefully determine whether to use hit_for_pass to allow
  # concurrent requests for the same URL to stack up waiting for this one to finish, or
  # to simply go in paralell with us. It doesn't make sense for client requests to a page
  # that is never cacheable to have to go serially all the time, so a hit_for_pass is required
  # in this case.

  set beresp.http.TTL-Was = beresp.ttl;

  if (beresp.ttl <= 0s && req.http.X-Varnish-Force-Pass) {
    # Force-refresh or other force-fallthrough shouldn't set hit_for_pass as the 0 TTL may be only for this request.
    #std.log("Force-pass -> deliver");
    #std.log(req.http.X-Varnish-Force-Pass);
    #return (deliver);
  }
  else if (beresp.ttl <= 0s) {
    # Normal uncacheable page - cache that it's uncacheable to allow parallel requests for the next 2 minutes
    #std.log("Normal uncacheable -> hit_for_pass");
    set beresp.ttl = 120s;
    return (hit_for_pass);
  }
  else {
    # Normal cacheable page, stack requests up to avoid cache slam.
    #std.log("Normal cacheable -> deliver");
    return (deliver);
  }
}
 
# This is called on both cache hit and miss to do any final preparations to the reponse before blatting it
# to the client. Here we swap some headers around and write some debugging information about the request.
sub vcl_deliver {
  if (obj.hits > 0) {
    set resp.http.X-Varnish = "HIT";
  }
  else {
    set resp.http.X-Varnish = "MISS";
  }
 
  if (resp.http.X-Varnish-Client-Vary) {
    # Swap back the Vary header that we want the client to see, clearing the internal-only Vary headers
    # This was initially set back in vcl_fetch. The internal-only Vary headers are copied to X-Varnish-Debug-CustomVary
    set resp.http.Vary = resp.http.X-Varnish-Client-Vary;
    unset resp.http.X-Varnish-Client-Vary;
  }
 
  if (req.http.X-Force-Miss-Reason) {
    set resp.http.X-Force-Miss-Reason = req.http.X-Force-Miss-Reason;
  }
 
  # Unset some crufty headers the user doesn't need
  unset resp.http.x-url;
  unset resp.http.x-host;
  unset resp.http.x-sid;
}
 
# If we found a match in the cache, this is called.
sub vcl_hit {
  #if (req.http.X-Force-Refresh && req.http.X-Varnish-Client-IsAdmin) {
  #  # When an admin user performs a force-refresh, we should purge all variants of the current page for all users.
  #  purge;
  #}

  if (req.request == "PURGE") {
    purge;
    error 200 "Purge Hit.";
  }
}
 
# If we didn't find a match in the cache, this is called shortly before fetching from the backend.
sub vcl_miss {
  #if (req.http.X-Force-Refresh && req.http.X-Varnish-Client-IsAdmin) {
  #  # When an admin user performs a force-refresh, we should purge all variants of the current page for all users.
  #  purge;
  #}

  if (req.request == "PURGE") {
    purge;
    error 200 "Purge Missed on " + req.http.host + req.url;
  }
 
  # Force accept-encoding: gzip on all requests, regardless of whether the client can do it.
  #set req.http.accept-encoding = "gzip";
}
 
# This is called when we ask for the connection to pipe in vcl_recv. We just make sure it shuts the connection.
sub vcl_pipe {
   # If we don't set the Connection: close header, any following
   # requests from the client will also be piped through and
   # left untouched by varnish. We don't want that.
   set req.http.connection = "close";
 
   # Note: no "pipe" action here - we'll fall back to the default
   # pipe method so that when any changes are made there, we
   # still inherit them.
}
 
# Called when an error occurs
sub vcl_error {
  if (obj.status == 750) {
    # This is a redirect
    set obj.http.Location = "http://" + req.http.host + req.http.redirect_to;
    set obj.http.X-Redirected-By = "Varnish";
    set obj.status = 302;
    return (deliver);
  }
 
  if (req.esi_level > 0) {
    # Retry the request once if there's an error before giving up
    if (req.restarts < 2) {
      set req.grace = 60s;
      return (restart);
    }
    set obj.http.content-type = "text/plain";
    synthetic {"<!-- ESI error "} + obj.status + {" -->"};
  }
  else {
    set obj.http.content-type = "text/html";
    synthetic {"
<!-- Error from Varnish -->
<!doctype html>
<!-- paulirish.com/2008/conditional-stylesheets-vs-css-hacks-answer-neither/ -->
<!--[if lt IE 7]> <html class="no-js lt-ie9 lt-ie8 lt-ie7" lang="en"> <![endif]-->
<!--[if IE 7]>    <html class="no-js lt-ie9 lt-ie8" lang="en"> <![endif]-->
<!--[if IE 8]>    <html class="no-js lt-ie9" lang="en"> <![endif]-->
<!-- Consider adding a manifest.appcache: h5bp.com/d/Offline -->
<!--[if gt IE 8]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta content="IE=edge,chrome=1" http-equiv="X-UA-Compatible">
    <meta name="viewport" content="width=device-width">
    <title>Technical difficulties | New Zealand Post</title>
    <link type="text/css" rel="stylesheet" href="/error-documents/assets/errorStyles.min.css" media="screen" />
</head>
<body>
<div id="main-wrapper">
    <div id="header">
        <a id="logo" href="http://www.nzpost.co.nz" title="Home" rel="home">
         <span id="nzpost-logo"><img width="207" height="40" src="/error-documents/assets/nzpost.png" alt="New Zealand Post" /></span>
        </a>
    </div>
    <div id="main">
        <h2>Our New Zealand Post website is experiencing technical difficulties. We apologise for the inconvenience.
        </h2>
        <p>Please try your request again later, or if you need assistance you can call us on <strong>0800 782 677</strong>.</p>
        <p>Visit our <a href="http://status.nzpost.co.nz/" title="View New Zealand Post Performance and Status page">Performance and Status</a> page to see details on the current status of this website.</p>
    </div>
 </div>
<!-- Technical difficulties analytics -->
<script type="text/javascript">
<!--//--><![CDATA[//><!--
if (document.location.hostname == 'www.nzpost.co.nz' && !document.location.pathname.match(new RegExp('^/admin'))) {
  var _gaq = _gaq || [];_gaq.push(["_setAccount", "UA-3139598-1"]);_gaq.push(["_setDomainName", ".nzpost.co.nz"]);(function() {var ga = document.createElement("script");ga.type = "text/javascript";ga.async = true;ga.src = ("https:" == document.location.protocol ? "https://ssl" : "http://www") + ".google-analytics.com/ga.js";var s = document.getElementsByTagName("script")[0];s.parentNode.insertBefore(ga, s);})();
  window._gaq.push(['_trackEvent', 'Technical difficulties', 'Varnish', document.location.pathname.replace(new RegExp('^/user/\\d+'), '/user/me')]);
}
//--><!]]>
</script>
</body>
</html>
    "};
   }
  return (deliver);
}
