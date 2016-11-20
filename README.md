Kolab Multi-Factor Authentication Plugin
========================================

The plugin is designed to be a generic container for different 2nd factor 
authentication mechanisms paired with different ways to store the related 
data for Roundcube user accounts. Both drivers and storage backends are derived 
from abstract classes which define the common interface and are configurable.

Drivers
-------

Multiple methods for 2nd factor authentication can be enabled for the users 
to select from. The basic implementation covers TOTP, HOTP and Yubikey methods.

TOTP (RFC 6238) and HOTP (RFC 4226) can be used in conjunction with freely available 
mobile phone apps like FreeOTP (TOTP only!) or Google Authenticator. To provision 
the app with your account settings, a QR code is displayed which can be scanned 
with the mobile phone camera.

The Yubikey driver uses the Yubico Validation Service either by using the public 
YubiCloud API or another locally hosted verification server. The host(s) to use 
for validation are configurable.


Storage Backends
----------------

Some authentication methods require to store secret data per user account on the 
server. For this, one of different storage backends can be selected:

**Roundcube**

The simplest way is to store authentication secrets and configuration in the 
user preferences of Roundcube itself.

**LDAP**

For an external storage option, the LDAP module can be used. This keeps the 
authentication data separated from the Roundcube user database. See //LDAP Storage// 
below for more information. The LDAP connection parameters are defined through the 
`kolab_2fa_storage_config` config option.


Installation
------------

After placing the plugin contents into Roundcube's plugins directory, the 3rd party 
libraries need to be installed using Composer:

```
$ composer require "endroid/qrcode" "~1.5.0" --no-update
$ composer require "spomky-labs/otphp" "~5.0.0" --no-update
$ composer require "enygma/yubikey" "~3.2"
```

See the `composer.json` file for the actual module names and versions.


Configuration
-------------

Copy the sample `config.inc.php.dist` file into `config.inc.php` and adjust the 
settings according to your desired setup. All options are described with inline 
comments directly in the sample file.

When using the LDAP storage together with a Kolab installation, you may want to save 
an additional LDAP lookup for authentication factors on every login, the LDAP driver 
can assign roles to the user record when registering authentication factors
(see `user_roles` storage config option). With the following additions to the 
`kolab_auth` plugin config, these roles can be used to determine whether the user 
has multi-factor authentication enabled:

```
// Disable lokkups by default:
$config['kolab_2fa_check'] = false;

// Enable 2nd factor lookup on a role-by-role basis
$config['kolab_auth_role_settings'] = array(
    'cn=totp-user,dc=example,dc=org' => array(
        'kolab_2fa_check' => array(
            'mode' => 'override',
            'value' => true,
        ),
    ),
);
```

LDAP Storage
------------

Define an `organizationalunit` with DN `ou=Tokens,dc=example,dc=org` to store 
all authentication tokens.

For token records, the [[https://git.fedorahosted.org/cgit/freeipa.git/tree/install/share/70ipaotp.ldif | FreeIPA OTP schema]] 
can be used. Please install this schema in your Kolab LDAP directory.

This is an example record for a TOTP token registered to user doe@example.org:

```
dn: ipatokenUniqueID=totp:c4a1ced768a0da55df662e73,ou=Tokens,dc=example,dc=org
objectClass: top
objectClass: ipaToken
objectClass: ipatokenTOTP
objectClass: ldapSubEntry
cn: Mobile App (TOTP)
ipatokenUniqueID: totp:c4a1ced768a0da55df662e73
ipatokenOwner: uid=doe,ou=People,dc=example,dc=org
ipatokenNotBefore: 201506110211Z
ipatokenOTPkey: 4T5CI7SOKWYQ5JTM
ipatokenDisabled: TRUE
```


