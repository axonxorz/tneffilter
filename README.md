tneffilter
==========

Script for filtering winmail.dat.

Currently used as a postfix filter. Will expand any attachments encapsulated in a winmail.dat file.

WARNING
===============
So far, this has not caused any issues for me, but as I'm sure I don't fully realize the function of the winmail.dat format, this could have unintended side-effects.


Setup
===============

 * Configuration is in the script, change `RUNAS_USER` and `RUNAS_GROUP` as necessary, but they should probably stay as `nobody.nogroup` or equivalent
 * Run `tneffilter` as root in daemon mode with `./tneffilter -d`
 * Default configuration assumes postfix will send to `amavis`, which will then relay to `tneffilter`

<!-- -->

    Postfix ---------> Amavis ---------> tneffilter --
       ^    Port 10024        Port 10025             |
       |                                             |
       |----------------------------------------------
                       Port 20025
