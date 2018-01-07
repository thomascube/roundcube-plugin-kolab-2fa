<?php

/**
 * Kolab 2-Factor-Authentication plugin configuration
 *
 * Copyright (C) 2015, Kolab Systems AG <contact@kolabsys.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// available methods/providers. Supported methods are: 'totp','hotp','yubikey'
$config['kolab_2fa_drivers'] = array('totp');

// backend for storing 2-factor-auth related per-user settings
// available backends are: 'roundcube', 'ldap', 'sql'
$config['kolab_2fa_storage'] = 'roundcube';

// additional config options for the above storage backend
// here an example for the LDAP backend:
$config['kolab_2fa_storage_config'] = array(
    'debug'     => false,
    'hosts'     => array('localhost'),
    'port'      => 389,
    'bind_dn'   => 'uid=kolab-auth-service,ou=Special Users,dc=example,dc=org',
    'bind_pass' => 'Welcome2KolabSystems',
    'base_dn'   => 'ou=Tokens,dc=example,dc=org',
    // filter used to list stored factors for a user
    'filter'    => '(&(objectClass=ipaToken)(objectclass=ldapSubEntry)(ipatokenOwner=%fu))',
    'scope'     => 'sub',
    // translates driver properties to LDAP attributes
    'fieldmap'  => array(
        'label'    => 'cn',
        'id'       => 'ipatokenUniqueID',
        'active'   => 'ipatokenDisabled',
        'created'  => 'ipatokenNotBefore',
        'userdn'   => 'ipatokenOwner',
        'secret'   => 'ipatokenOTPkey',
        // HOTP attributes
        'counter'  => 'ipatokenHOTPcounter',
        'digest'   => 'ipatokenOTPalgorithm',
        'digits'   => 'ipatokenOTPdigits',
    ),
    // LDAP object classes derived from factor IDs (prefix)
    // will be translated into the %c placeholder
    'classmap' => array(
        'totp:' => 'ipatokenTOTP',
        'hotp:' => 'ipatokenHOTP',
        '*'     => 'ipaToken',
    ),
    // translates property values into LDAP attribute values and vice versa
    'valuemap' => array(
        'active' => array(
            false   => 'TRUE',
            true    => 'FALSE',
        ),
    ),
    // specify non-string data types for properties for implicit conversion
    'attrtypes' => array(
        'created' => 'datetime',
        'counter' => 'integer',
        'digits'  => 'integer',
    ),
    // apply these default values to factor records if not specified by the drivers
    'defaults' => array(
        'active' => false,
        // these are required for ipatokenHOTP records and should match the kolab_2fa_hotp parameters
        'digest' => 'sha1',
        'digits' => 6,
    ),
    // use this LDAP attribute to compose DN values for factor entries
    'rdn'       => 'ipatokenUniqueID',
    // assign these object classes to new factor entries
    'objectclass' => array(
        'top',
        'ipaToken',
        '%c',
        'ldapSubEntry',
    ),
    // add these roles to the user's LDAP record if key prefix-matches a factor entry
    'user_roles' => array(
        'totp:' => 'cn=totp-user,dc=example,dc=org',
        'hotp:' => 'cn=hotp-user,dc=example,dc=org',
    ),
);

// force a lookup for active authentication factors for this user.
// to be set by another plugin (e.g. kolab_auth based on LDAP roles)
// $config['kolab_2fa_check'] = true;

// timeout for 2nd factor auth submission (in seconds)
$config['kolab_2fa_timeout'] = 120;

// configuration parameters for TOTP (uncomment to adjust)
$config['kolab_2fa_totp'] = array(
    // 'digits'   => 6,
    // 'interval' => 30,
    // 'digest'   => 'sha1',
    // 'issuer'   => 'Roundcube',
);

// configuration parameters for HOTP (uncomment to adjust)
$config['kolab_2fa_hotp'] = array(
    // 'digits' => 6,
    // 'window' => 4,
    // 'digest' => 'sha1',
);

// configuration parameters for Yubikey (uncomment to adjust)
$config['kolab_2fa_yubikey'] = array(
    'clientid' => '123456',
    'apikey' => '<your-server-api-key>',
    // 'hosts'  => array('api.myhost1.com','api2.myhost.com'),
    'use_https' => true,  // connect via https if set to true
);