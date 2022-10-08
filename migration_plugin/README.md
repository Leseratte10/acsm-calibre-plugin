# What is this?

The original name of the plugin, when I first introduced it in 2021, was "DeACSM" - similar to how the popular DRM removal plugin is called "DeDRM". However, later I realized that this is a terrible name, and I'd rather have the plugin be named "ACSM Input", similar to other file type plugins like "LCPL Input", "KFX Input", "DOC Input" and "KePub Input". 

However, the Calibre plugin updater doesn't support replacing an existing plugin A with a differently-named plugin B. 

This is where this helper plugin comes in. It's a dummy plugin that doesn't have any actual functionality, and will be released under the old name ("DeACSM") with a higher version number (0.0.18 or something like that). 

Then, all this plugin is going to be doing is, without using the Calibre updater, automatically download the renamed plugin ("ACSM Input") from my Github page, installs it into Calibre, the uninstalls itself. This will have no impact on the plugin data, that will still be stored at the same location and will be read from the same location. But it means that the plugin will get auto-renamed to its new name and can still continue to receive plugin updates through the Calibre plugin updater. 

# Process details

I have asked on MobileRead whether it is possible [to rename a Calibre Plugin](https://www.mobileread.com/forums/showthread.php?t=348941), but I was told that that's not easily possible. Kovid suggested just making a new MobileRead thread for the "new" plugin, mark the old one as "deprecated", and then manually tell users of the old plugin somehow that they need to re-download the new one - but I didn't want to have to do that. 

The "old" plugin's versions go up to 0.0.16 for the latest release, and 0.0.17 for the latest beta. 
The migration plugin you can find in this folder will have the same name "DeACSM" as the old plugin, but a higher version number (0.0.20). 
Then, I will create a new dummy thread at MobileRead and upload this migration plugin to that thread. 

What this migration plugin does on first start is it downloads the "new" "ACSM Input" plugin from the MobileRead forum thread which is named "ACSM Input" with version number 0.1.0. This circumvents the Calibre Plugin updater which would refuse to update a plugin if that were to change a plugin's name. 

Once that's happened, future updates can go through the plugin updater again. 

So, the chain of versions is going to be the following: 

DeACSM 0.0.16 -> "DeACSM" migration plugin 0.0.20 -> Replaces itself with "ACSM Input 0.1.0" -> more updates in the future to ACSM Input 0.1.1 and so on. 

# MobileRead forum plugin index

Right now, the thread for my ACSM Input plugin contains the "old" DeACSM 0.0.16 plugin. 
Once I release ACSM Input 0.1.0, I will put that version into the MobileRead thread, and I will put the migration build into another dummy thread. 

Then I will have a moderator update the Calibre plugin index with two entries: 

- "DeACSM", pointing to [the dummy thread](https://www.mobileread.com/forums/showthread.php?t=348941) with the migration build. The comment will mention not to install this manually.
- "ACSM Input", pointing to the well-known [ACSM Input plugin thread](https://www.mobileread.com/forums/showthread.php?t=341975). 

This means that users are not going to see any change in behaviour in the forum thread - they're not going to notice the dummy thread, and the well-known thread that's linked everywhere will continue to point to the newest plugin updates. 

After a couple months once everyone has updated to the newest versions, the dummy thread and the old "DeACSM" entry in the plugin index can then be removed. 

