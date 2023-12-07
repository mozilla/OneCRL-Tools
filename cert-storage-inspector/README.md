# cert-storage-inspector

 Compares the OneCRL data in a given Firefox profile against 
 the OneCRL data in [DEFAULT_ONECRL_URL](https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records).
 
## Build
```sh
cargo build
```

## Run
```sh
cargo run -- --profile-path <your firefox support folder>/Profiles/<your profile directory>
```

To find your Firefox profile:
1. In the Firefox browser bar type:  about:profiles
2. Then find the profile for which it says “This is the profile in use and it cannot be deleted.”
3. Then map that Root Directory to your actual directory, being sure to escape special characters such as spaces. 
(e.g. on Mac OS change Library/Caches/Firefox/Profiles to Library/Application\ Support/Firefox/Profiles)

Example:
```sh
cargo run -- --profile-path ~/Library/Application\ Support/Firefox/Profiles/4q9eeccp.yourFFprofileName
```

## Output
current OneCRL revocations:      
revocations in profile:      
revocations in OneCRL but not in profile:     
revocations in profile but not in OneCRL:     
     
**current OneCRL revocations** is the number of entries in DEFAULT_ONECRL_URL.     
**revocations in profile** is the number of entries in your Firefox profile.      
In steady-state the above two numbers should match. They will vary when DEFAULT_ONECRL_URL has been updated, but the change has not yet propagated to your Firefox profile.      
     
**revocations in OneCRL but not in profile** is the list of entries that are in DEFAULT_ONECRL_URL that have not yet propagated to your Firefox profile.     
**revocations in profile but not in OneCRL** should be empty, but some older Firefox profiles may have entries that are no longer in OneCRL.     

## Errors
** directory does not exist or not a directory** means that the path to your Firefox profile is not correct.     
** safe mode backend error: DbNotFoundError (safe mode)** means that your Firefox profile is so new that OneCRL has not propagated to it yet. Either use an older profile, or wait for 24 to 48 hours, then try again.     

