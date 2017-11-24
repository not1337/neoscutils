#neoscutils
Utilities for the YubiKey NEO(-N)/4 (nano)

===============================================================================

neosc-appselect is a tool that allows you to switch to a specified
applet on a YubiKey NEO(-N).
This helps you to return the YubiKey to a state applications using
the YubiKey and not being aware that a token may offer mutiple
applets (i.e. nearly every application I know of).

Example: You use ssh-agent with the PKCS11 option and in between use
the Yubico python based OATH utility. The result of this is that
ssh-agent will no loner be able to access its keys - and this is due
to the simple fact that the YubiKey is now runing the OATH applet
instead of the PIV applet.

Switch back to the PIV applet using neosc-appselect and everything is
fine again, ssh-agent can continue to access the PIV keys.

Usage: neosc-appselect [-s <serial>|-u|-n] -N|-d|-o|-O|-p

-N             select NEO applet
-d             select NDEF applet
-o             select OATH applet
-O             select OpenPGP applet
-p             select PIV applet
-s <serial>    use YubiKey with given serial number
-u             use first USB attached YubiKey without serial number
-n             use first NFC attached YubiKey
-U             use first U2F enabled YubiKey 4 (nano)
-C             use first U2F disabled YubiKey 4 (nano)

===============================================================================

neosc-shell is a configuration shell for the YubiKey NEO(-N). The major
difference to Yubico's original tools is the ability to specify a
device serial number and the unionize CCID and HID access through
a single utility.

Note that for PIV Yubico's yubico-piv-tool must be used. This is fine
as the tool doesn't depend on a slew of libraries and allows for
device selection on the command line (open source, grab it from
GitHub and: happy compiling).

For the OpenPGP applet refer to gnupg. Hopefully you enjoy reading
incomplete man pages and like to search the code to gather missing
information.

Usage: neosc-shell <options>

-s <serial>     use YubiKey with given serial number
-u              use first USB attached YubiKey without serial number
-n              use first NFC attached YubiKey
-U              use first U2F enabled YubiKey 4 (nano)
-C              use first U2F disabled YubiKey 4 (nano)
-f              enable commands that reset all configuration data
-F              enable commands that may brick your device (requires -f too)
-q              be more quiet
-v              be more verbose
-e              terminate in case of error
-N              do not print a prompt
-h              this help text

For more help start neosc-shell and enter 'help' at the prompt.
