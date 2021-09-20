# Calibe ACSM plugin (Linux only)

This is a Linux-only Calibre plugin that allows you to turn ACSM files into EPUBs without the need for ADE. 
It's based on libgourou by Grégory Soutadé (http://indefero.soutade.fr/p/libgourou/).

## Setup

You need to have the following packages installed to use this plugin (Debian Bullseye / Ubuntu 20.04):
make, g++, libssl-dev, pkg-config, qtbase5-dev, libzip-dev

Import the calibre plugin into Calibre, open the plugin settings, then click "Compile" to compile the library into a useable binary. 

Once that's done (takes a couple seconds), click "Link to ADE account" and enter your ADE account credentials. 

NOTE: This software is not approved by Adobe. I am not responsible if Adobe detects that you're using nonstandard software and bans your account. I suggest using a new, unused Adobe ID for this plugin, and combine that with a certain other Calibre Plugin (Alf) to immediately make the epubs "useable" so it's not a big deal if the account does get banned. 

Do not complain to me if Adobe bans your main ADE account - you have been warned. 

Once you've successfully linked your ADE account, click on "Export account activation data" and save the ZIP file somewhere safe. You'll need this to restore your activation after a re-install without wasting one of your six possible account activations. 
After that, click on "Export account encryption key" and save the DER file somewhere safe, too. (This is the key file for Alf).

## Combining with Alf

In order to combine this plugin with Alf, you'll need to go to Alf's settings and import the DER file you've just exported from this plugin. 

Also, there's a small code change needed to Alf's plugin to make it work together with this one. Open up the `__init__.py` file in Alf's ZIP file and search for "file_types". You'll find a list of supported file types. Add "acsm" to that list, save the file, put it back into the ZIP file, then re-import the Alf plugin into Calibre. 