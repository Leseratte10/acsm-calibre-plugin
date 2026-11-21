#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2024 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

# Standard Python modules.
import os
import threading
import time
import traceback

from calibre.utils.config import JSONConfig, config_dir  # type: ignore


# JSONConfig writes the whole file every time a single key is set, and there is no lock
# between reading and writing it. Calibre runs import plugins in worker processes, so a loan
# record added during an ACSM import gets overwritten as soon as another process (like the
# GUI with the plugin settings open) saves the copy it read earlier. So every change
# goes through _PrefsWriteLock: re-read the file, change it, write it, all under one lock.

# Cross-process lock name. This is a different lock from the one run() holds during
# fulfillment; never wait for that one while holding this one.
_PREFS_LOCK_NAME = "__acsm_plugin_prefs_write"
_PREFS_LOCK_TIMEOUT = 10    # seconds

# On MacOS, SingleInstance doesn't keep two threads of the same process apart, so also use
# a thread lock. It's reentrant, so a locked section can call set() without deadlocking.
_prefs_thread_lock = threading.RLock()
_prefs_lock_depth = 0


def _acquire_prefs_mutex():
    try:
        from calibre.utils.lock import SingleInstance       # type: ignore
    except ImportError:
        from calibre_plugins.deacsm.singleinstance_helper import SingleInstance     # type: ignore

    deadline = time.time() + _PREFS_LOCK_TIMEOUT
    while True:
        mutex = SingleInstance(_PREFS_LOCK_NAME)
        if mutex.__enter__():
            return mutex
        if time.time() > deadline:
            # Better to risk the old behaviour than to hang Calibre.
            print("ACSM Input: Timed out waiting for the settings file lock, continuing without it.")
            return None
        time.sleep(0.05)


class _PrefsWriteLock(object):

    def __enter__(self):
        global _prefs_lock_depth
        _prefs_thread_lock.acquire()
        _prefs_lock_depth += 1
        self.mutex = None
        if _prefs_lock_depth == 1:
            try:
                self.mutex = _acquire_prefs_mutex()
            except Exception:
                # No cross-process lock available - the thread lock still helps.
                traceback.print_exc()
        return self

    def __exit__(self, *args):
        global _prefs_lock_depth
        try:
            if self.mutex is not None:
                self.mutex.__exit__(None, None, None)
        finally:
            _prefs_lock_depth -= 1
            _prefs_thread_lock.release()


class ACSMInput_Prefs():
    def __init__(self):

        JSON_PATH = os.path.join("plugins", "ACSMInput", "ACSMInput.json")

        self.acsmprefs = JSONConfig(JSON_PATH)

        self.acsmprefs.defaults['configured'] = False

        self.acsmprefs.defaults['notify_fulfillment'] = True
        self.acsmprefs.defaults['detailed_logging'] = False
        self.acsmprefs.defaults['delete_acsm_after_fulfill'] = False

        self.acsmprefs.defaults['list_of_rented_books'] = []
        # Never change the list returned by self["list_of_rented_books"] in place: as long as
        # the file doesn't contain a loan list yet, that's the default list above, which is never
        # written to the file. Use update_loan_list(), add_loan() or remove_loan() instead.



        self.__pluginsdir = os.path.join(config_dir,"plugins")

        success = False
        # Try to find an existing account folder in ACSMInput
        self.__maindir = os.path.join(self.__pluginsdir, "ACSMInput")
        self.__accountdir = os.path.join(self.__maindir,"account")

        if os.path.exists(self.__accountdir):
            self.acsmprefs.defaults['path_to_account_data'] = self.__accountdir
            success = True

        if not success:
            # We did not find an account folder. Creating it.
            if os.path.exists(self.__maindir):
                os.mkdir(self.__accountdir)
                self.acsmprefs.defaults['path_to_account_data'] = self.__accountdir
                success = True

        if not success:        
            raise Exception("Why does the account folder not exist?")
            

    def refresh(self):
        return self.acsmprefs.refresh()

    def __getitem__(self,kind = None):
        if kind is not None:
            return self.acsmprefs[kind]
        return self.acsmprefs

    def set(self, kind, value):
        # Re-read the file first, otherwise this would also write back old values
        # for every other key, undoing changes made elsewhere in the meantime.
        with _PrefsWriteLock():
            self.acsmprefs.refresh()
            self.acsmprefs[kind] = value

    def writeprefs(self,value = True):
        self.set('configured', value)

    def update_loan_list(self, modify):
        # type: (callable) -> list
        # Replaces the loan list with modify(current list), where the current list is read
        # from the file while holding the lock. modify gets a copy and returns the new list.
        # Returns the new list.
        with _PrefsWriteLock():
            self.acsmprefs.refresh()
            old_list = list(self.acsmprefs['list_of_rented_books'])
            new_list = modify(list(old_list))
            if new_list != old_list:
                self.acsmprefs['list_of_rented_books'] = new_list
        return new_list

    def add_loan(self, new_loan_record):
        # Adds a loan record, replacing any existing record for the same loan.
        loan_id = new_loan_record["loanID"]
        return self.update_loan_list(lambda books: [b for b in books if b["loanID"] != loan_id] + [new_loan_record])

    def remove_loan(self, loan_id):
        # type: (str) -> bool
        # Removes the record(s) for that loan. Returns True if there was one.
        removed = []
        def modify(books):
            kept = [b for b in books if b["loanID"] != loan_id]
            removed.append(len(kept) != len(books))
            return kept
        self.update_loan_list(modify)
        return removed[0]

    def addnamedvaluetoprefs(self, prefkind, keyname, keyvalue):
        try:
            if keyvalue not in self.acsmprefs[prefkind].values():
                # ensure that the keyname is unique
                # by adding a number (starting with 2) to the name if it is not
                namecount = 1
                newname = keyname
                while newname in self.acsmprefs[prefkind]:
                    namecount += 1
                    newname = "{0:s}_{1:d}".format(keyname,namecount)
                # add to the preferences
                self.acsmprefs[prefkind][newname] = keyvalue
                return (True, newname)
        except:
            traceback.print_exc()
            pass
        return (False, keyname)

    def addvaluetoprefs(self, prefkind, prefsvalue):
        # ensure the keyvalue isn't already in the preferences
        try:
            if prefsvalue not in self.acsmprefs[prefkind]:
                self.acsmprefs[prefkind].append(prefsvalue)
                return True
        except:
            traceback.print_exc()
        return False

