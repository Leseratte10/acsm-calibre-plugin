
#@@CALIBRE_COMPAT_CODE_START@@
import sys, os

# Compatibility code taken from noDRM's DeDRM fork. 
# This fixes the weird import issues with Calibre 2, 
# and it allows me to get rid of a ton of try-except blocks.

if "calibre" in sys.modules:

    # Explicitly allow importing everything ...
    if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    # Bugfix for Calibre < 5:
    if sys.version_info[0] == 2:
        from calibre.utils.config import config_dir
        if os.path.join(config_dir, "plugins", "DeACSM.zip") not in sys.path:
            sys.path.insert(0, os.path.join(config_dir, "plugins", "DeACSM.zip"))

#@@CALIBRE_COMPAT_CODE_END@@
