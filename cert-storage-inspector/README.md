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
3. Then map that directory to your actual directory. 
(e.g. on Mac OS change Library/Caches/Firefox/Profiles to Library/Application\ Support/Firefox/Profiles)

Example:
```sh
cargo run -- --profile-path ~/Library/Application\ Support/Firefox/Profiles/4q9eeccp.yourFFprofileName
```

## Output

duplicate entry in OneCRL? 
* Some older profiles may have a duplicate entry or two.
\  
current OneCRL revocations: 
* The number of entries in DEFAULT_ONECRL_URL.
\  
revocations in profile: 
* The number of entries in your Firefox profile. In steady-state the above two numbers should match.They will vary when DEFAULT_ONECRL_URL has been updated, but the change has not yet propagated to your Firefox profile. They may also vary if you have a Firefox profile that has entries that are no longer in OneCRL (should only happen for older profiles).
\  
revocations in OneCRL but not in profile:
* The list of entries that are in DEFAULT_ONECRL_URL that have not yet propagated to your Firefox profile.
\  
revocations in profile but not in OneCRL:
* Should be empty, but some older Firefox profiles may have entries that are no longer in OneCRL.
