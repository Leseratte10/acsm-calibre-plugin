
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
        for filename in ["ACSM Input.zip", "DeACSM.zip"]:
            __zip_path = os.path.join(config_dir, "plugins", filename)
            if __zip_path not in sys.path and os.path.exists(__zip_path):
                sys.path.insert(0, __zip_path)

            if os.path.exists(__zip_path):
                # If we already included the new ZIP, don't also include the new one. 
                # Maybe that helps with the update issues?
                continue

#@@CALIBRE_COMPAT_CODE_END@@
