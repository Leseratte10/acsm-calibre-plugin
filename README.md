# Calibre ACSM Input plugin

This is a Calibre plugin that allows you to turn ACSM files into EPUB or PDF files without the need for Adobe Digital Editions. 

<details>
  <summary>ACSM Input Plugin for Calibre - Copyright (c) 2021-2026 Leseratte10</summary>

```
ACSM Input Plugin for Calibre / acsm-calibre-plugin
Formerly known as "DeACSM"
Copyright (c) 2021-2026 Leseratte10

This software is based on a Python reimplementation of the C++ library 
"libgourou" by Grégory Soutadé which is under the LGPLv3 or later 
license (http://indefero.soutade.fr/p/libgourou/).

I have no idea whether a reimplementation in another language counts 
as "derivative use", so just in case it does, I'm putting this project 
under the GPLv3 (which is allowed in the LGPLv3 license) to prevent any 
licensing issues. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

See the "LICENSE" file for a full copy of the GNU GPL v3.
```

</details>

## Important news

In 2026, ByteBooks (by Wipro Connected Services) has taken over operation of the ADE and ACS platforms from Adobe. As of June 23rd, 2026, new authorizations using Adobe Digital Editions, ByteBooks Digital Editions, or my Calibre plugin require the usage of a ByteBooks account instead of an Adobe account. If you do not yet have one, you can create one by going to [the ByteBooks webpage](https://dtsbytebooks.com/register). 

If you're migrating from an existing AdobeID, make sure to select the checkbox that says "I have an existing Adobe account to migrate" so that all your eBook licenses will be migrated to the new account. 

Also, according to the [ByteBooks Transition FAQ](https://dtsbytebooks.com/products/digital-edition/faq), all current versions of ADE and also all previous versions of my Calibre plugin (including the 0.1.0 beta) will stop working after December 2026. 

I will be providing a new updated version of my Calibre plugin before this cutoff date that will continue to be compatible with ByteBooks from 2027 onward. This change will require you to wipe the old plugin, reinstall the new updated plugin once it is available, and re-login into your ByteBooks ID account.


## Setup

Download the plugin's ZIP file from Releases and import it into Calibre. You must import the plugin as a ZIP file, do not import the extracted files. Once imported, open the Plugin settings by selecting 'Customize plugin'. The plugin should display "Not authorized for any ID". You now have multiple options to authorize the plugin: 

- You can click on "Link to Digital Editions account" and enter your ByteBooks ID credentials to link your Calibre installation to your ByteBooks account. This uses up one of your available activations. 
- You can click on "Create anonymous authorization" to create an anonymous authorization. Make sure to create backups of that authorization. 
- If you have ADE or BDE installed and activated on your machine, you can click "Import activation from Digital Editions" to clone the existing activation from your installation. 
- If you have used this plugin before, you can click on "Import existing activation backup" to import a previously created activation backup (ZIP) file to restore an activation. This functionality can also be used to clone one activation to multiple computers. Note that this will only work with backups that have been created with ByteBooks-compatible plugin versions - with the change to ByteBooks a full new authorization with the ByteBooks servers will be required for full compatibility.

After you've activated the plugin, make a backup of the activation using the "Export account activation data". Then click "Export account encryption key" and import the resulting file into the DeDRM plugin for DRM removal, if necessary. If you don't have the DeDRM plugin set up properly you will not be able to read the downloaded books in Calibre due to the DRM.

Once that's done, download an ACSM file from [ByteBooks' test library](https://dtsbytebooks.com/products/digital-edition/sample-library) and see if you can import it into Calibre successfully.

IMPORTANT: 

- Since I created this plugin back in 2021, there have been absolutely no reports of Adobe taking any action against users of this plugin, like banning or deleting accounts. Still, this is software not approved by Adobe or ByteBooks, and I am not responsible if Adobe or ByteBooks do decide to ban people using this plugin in the future. 
- If losing your main ByteBooks account would cause issues for you (because you have DRMed books linked to your account), I would suggest creating a new dummy account to use for Calibre, combined with the DeDRM plugin, so just in case Adobe or ByteBooks decides to ban you in the future you can just make a new account.
- If you use an anonymous authorization, make sure you make backups of the activation data. 
- If you use an anonymous authorization, you have the ability to copy that authorization into a new ByteBooks account at a later time (by clicking "Connect anonymous auth to ByteBooks account"). This is useful if you have books linked to your authorization that you want to read elsewhere. Same restrictions as with BDE apply - you can only do this ONCE per Bytebooks ID, and only if the ID hasn't been in use elsewhere yet. Also, this has not been fully tested yet since the migration from Adobe to ByteBooks, so please do not rely on this feature being available.

## Returning books

If a book is marked as returnable (like a library book), you can "return" it to the library using this plugin. 
Just open the plugin settings, click "Show loaned books" (the option is only visible if you have at least one loaned book that's been downloaded with this plugin), select the book, then click the arrow button to return. Or click the "X" button to just remove the loan record from the list without returning the book.

This makes the book available for someone else again, but it does not automatically get deleted from your Calibre library - you are responsible for doing that after returning a book.

Note: You can only return books that you downloaded with this plugin. You cannot return books downloaded with Digital Editions or other tools.

## Authorizing eReaders

The plugin can also authorize an eReader connected to the Computer through USB. For now, this only works with devices that export their `.adobe-digital-editions` folder through USB. In order to authorize such an eReader, just open the plugin settings and click "Authorize eReader over USB" (only available if the plugin is authorized with an AdobeID). Then select the eReader in the folder selection dialog. This process does not work with eReaders relying on a specific USB driver for the  connection such as the Sony PRS-T2 (and probably some other older Sony devices). 

Right now, this process is fairly experimental, and I've only tested this with a Pocketbook reader so far.

Note that this process will use up one of your authorizations on your ByteBooks ID. While it is possible to clone a computer activation by exporting it on one computer and importing it on another, this is not possible with eReader authorizations. 

## Standalone version

In the folder "calibre-plugin" in this repo (or inside the Calibre plugin ZIP file) there's some scripts that can also be used standalone without Calibre. If you want to use these, you need to extract the whole ZIP file. 

- `register_ADE_account.py` can be used to authorize a computer with a ByteBooks account. This creates the three files `activation.xml`, `device.xml` and `devicesalt`. These files are in the same format as the ones for the Calibre computer authorization (inside the `plugins/ACSMInput/account` folder). A ZIP activation export from Calibre will also contain these three files.
- `fulfill.py` can be used - with valid ByteBooks account files in the same folder - to turn an URLLink.acsm file into an eBook. 
- `get_key_from_Adobe.py` can be used to contact the ByteBooks server and download the DER key file for a given AdobeID / ByteBooks ID to import into a DeDRM plugin. Just input your credentials and this script will output the DER file that can be used with DeDRM to decrypt books for this ID. This works independantly from the account activation files or from this plugin, so it's a good way to get your decryption key, especially if you're on Linux and it's too difficult to export the keys from ADE or BDE running inside Wine. This process does not use up one of your available device activations.

Though, generally it's recommended to use the Calibre plugin instead of these standalone scripts. Except for maybe the `get_key_from_Adobe.py` script if you want to remove DRM from existing eBooks without having to extract the key from Digital Editions.

## Building from source

If you want to run this plugin from source code (because you want to modify something or run a newer version from the master branch), it is not enough to simply ZIP up the "calibre-plugin" folder. You need to checkout the repository, then execute the "bundle_calibre_plugin.sh" script (which works on Linux and macOS; on macOS install the Windows cross-compiler first with `brew install mingw-w64`). 

This will create the "calibre-plugin.zip" file which you can import into Calibre as a plugin.

## To-Do list for the future (in no particular order)

- Support to copy an authorization from the plugin to an ADE install
- Support for multiple independant authorizations (with an easy way to switch between them)
- Import a JoinedAccount authorization from ADE (ADE2.0+)
- Import multiple account authorizations from ADE (ADE2.0+)
- Support to add an AdobeID to an eReader without replacing the existing one
- Support to return books loaned with other tools (like ADE)
- Support for Adobe's "auth" download method instead of the "simple" method (ADE2.0+)
- Support the JoinAccounts, ActivateLinkedAccounts and GetCredentialList functions to allow for merged AdobeIDs (ADE2.0+)
- Support the SyncToDevice function to auto-download new books from ADE into Calibre (ADE4.0+)
- Add small link in settings window that will open a popup with all the expert stuff like de-auth and account joining.
- ...
