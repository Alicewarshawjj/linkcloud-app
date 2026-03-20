# Help Request: Instagram In-App Browser Escape on iOS

## The Problem

I have a link-in-bio landing page (like Linktree) at `cmehere.net`. When users click links from social media apps, they open in the app's in-app browser instead of Safari. I need to escape to Safari because users are logged into OnlyFans there.

**Current status:**
- ✅ Twitter/X - WORKING (auto-opens Safari)
- ✅ Reddit - WORKING (auto-opens Safari)
- ✅ Threads - WORKING (auto-opens Safari)
- ✅ Snapchat - WORKING (with 3-second delay)
- ✅ TikTok - WORKING
- ❌ Instagram - NOT WORKING (business/creator accounts only)
- ❌ Facebook - NOT WORKING

## The Strange Behavior

On Instagram:
- Personal accounts: The escape works fine
- Business/Creator accounts: The escape methods are blocked

When I test from a business account, all these methods show a white flash and return to the page:
- `x-safari-https://` scheme
- `googlechrome://` scheme
- `window.open()` with `_blank`
- `location.href` redirect
- Anchor element click simulation
- Meta refresh redirect

## Current Architecture

### Two escape flows:

**Flow 1: Routes in SOURCE_PLATFORM_MAP (Reddit, Threads, Snapchat)**
These routes show an auto-escape page that immediately tries to open Safari on page load:

```javascript
const SOURCE_PLATFORM_MAP = {
  'seemorer': 'reddit',
  'th': 'threads',
  'seemoresc': 'snapchat'
};

function generateAutoOpenPage(source, platform) {
  // Shows spinner, then auto-runs:
  if(isIOS){
    setTimeout(function(){
      location.href='x-safari-https://'+url.replace(/^https?:\/\//,'')
    }, 100);
    setTimeout(function(){
      location.href='googlechrome://'+url.replace(/^https?:\/\//,'')
    }, 300);
  }
}
```

**Flow 2: Main page with overlay (Instagram, TikTok, etc.)**
These show the landing page with a blurred overlay and "Open in Safari" button:

```javascript
// Client-side detection
window.__IS_INAPP__ = ua.indexOf('Instagram') !== -1 ||
                       ua.indexOf('FBAN') !== -1 ||
                       ua.indexOf('TikTok') !== -1 || ...

// If in-app browser detected, show overlay
if(window.__IS_INAPP__) {
  overlay.classList.add('active');
}

// Button click handler
function handleiOSClick(){
  var canonicalUrl = addBrowserParam(window.location.href);
  var stripped = canonicalUrl.replace(/^https?:\/\//, '');
  var xSafariUrl = 'x-safari-https://' + stripped;
  window.open(xSafariUrl, '_blank');
}
```

## What I've Tried

1. `x-safari-https://` - blocked on IG business accounts
2. `googlechrome://` - blocked
3. `window.open(url, '_blank')` - shows white screen, returns
4. `location.href = url` - same behavior
5. Anchor click simulation - same behavior
6. Meta refresh redirect - same behavior
7. `intent://` (Android) - not relevant for iOS
8. Universal Links - didn't work

## Debug Results

I created a test page at `/debug-escape` with buttons to test each method.

From Instagram Business account on iOS:
- Button "meta refresh redirect" - showed flash, returned
- Button "anchor click" - showed flash, returned
- All URL schemes - blocked completely

From Instagram Personal account on iOS:
- Everything works fine

From the ROOT URL `cmehere.net/` (no path):
- Works even on business accounts!

## The Question

Why does `cmehere.net/` (root) escape successfully on Instagram business accounts, but `cmehere.net/mememe` does not?

Both pages use the same escape logic. The only difference is the route.

**What method can I use to escape Instagram's in-app browser on iOS for business/creator accounts?**

## Technical Details

- Server: Node.js/Express on Railway
- Domain: cmehere.net (HTTPS)
- Target: iOS Safari
- Problem accounts: Instagram Business/Creator accounts

## Code References

The full escape logic is in `server.js`:
- Lines 1592-1661: `generateAutoOpenPage()` for auto-escape
- Lines 1929-1932: Client-side overlay and button handlers
- Lines 1663-1688: Route handler that decides which flow to use
