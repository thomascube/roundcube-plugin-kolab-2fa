<?php

/**
 * Storage backend to store 2-Factor-Authentication settings in LDAP
 *
 * @author Thomas Bruederli <bruederli@kolabsys.com>
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

namespace Kolab2FA\Storage;

use \Net_LDAP3;
use \Kolab2FA\Log\Logger;

class LDAP extends Base
{
    public $userdn;

    private $cache = array();
    private $ldapcache = array();
    private $conn;
    private $error;

    public function init(array $config)
    {
        parent::init($config);

        $this->conn = new Net_LDAP3($config);
        $this->conn->config_set('log_hook', array($this, 'log'));

        $this->conn->connect();

        $bind_pass = $this->config['bind_pass'];
        $bind_user = $this->config['bind_user'];
        $bind_dn   = $this->config['bind_dn'];

        $this->ready = $this->conn->bind($bind_dn, $bind_pass);

        if (!$this->ready) {
            throw new Exception("LDAP storage not ready: " . $this->error);
        }
    }

    /**
     * List/set methods activated for this user
     */
    public function enumerate($active = true)
    {
        $filter  = $this->parse_vars($this->config['filter'],  '*');
        $base_dn = $this->parse_vars($this->config['base_dn'], '*');
        $scope   = $this->config['scope'] ?: 'sub';
        $ids     = array();

        if ($this->ready && ($result = $this->conn->search($base_dn, $filter, $scope, array($this->config['fieldmap']['id'], $this->config['fieldmap']['active'])))) {
            foreach ($result as $dn => $entry) {
                $rec = $this->field_mapping($dn, Net_LDAP3::normalize_entry($entry, true));
                if (!empty($rec['id']) && ($active === null || $active == $rec['active'])) {
                    $ids[] = $rec['id'];
                }
            }
        }

        // TODO: cache this in memory

        return $ids;
    }

    /**
     * Read data for the given key
     */
    public function read($key)
    {
        if (!isset($this->cache[$key])) {
            $this->cache[$key] = $this->get_ldap_record($this->username, $key);
        }

        return $this->cache[$key];
    }

    /**
     * Save data for the given key
     */
    public function write($key, $value)
    {
        $success = false;
        $ldap_attrs = array();

        if (is_array($value)) {
            // add some default values
            $value += (array)$this->config['defaults'] + array('active' => false, 'username' => $this->username, 'userdn' => $this->userdn);

            foreach ($value as $k => $val) {
                if ($attr = $this->config['fieldmap'][$k]) {
                    $ldap_attrs[$attr] = $this->value_mapping($k, $val, false);
                }
            }
        }
        else {
            // invalid data structure
            return false;
        }

        // update existing record
        if ($rec = $this->get_ldap_record($this->username, $key)) {
            $old_attrs = $rec['_raw'];
            $new_attrs = array_merge($old_attrs, $ldap_attrs);

            $result = $this->conn->modify_entry($rec['_dn'], $old_attrs, $new_attrs);
            $success = !empty($result);
        }
        // insert new record
        else if ($this->ready) {
            $entry_dn = $this->get_entry_dn($this->username, $key);

            // add object class attribute
            $me = $this;
            $ldap_attrs['objectclass'] = array_map(function($cls) use ($me, $key) {
                return $me->parse_vars($cls, $key);
            }, (array)$this->config['objectclass']);

            $success = $this->conn->add_entry($entry_dn, $ldap_attrs);
        }

        if ($success) {
            $this->cache[$key] = $value;
            $this->ldapcache = array();

            // cleanup: remove disabled/inactive/temporary entries
            if ($value['active']) {
                foreach ($this->enumerate(false) as $id) {
                    if ($id != $key) {
                        $this->remove($id);
                    }
                }

                // set user roles according to active factors
                $this->set_user_roles();
            }
        }

        return $success;
    }

    /**
     * Remove the data stored for the given key
     */
    public function remove($key)
    {
        if ($this->ready) {
            $entry_dn = $this->get_entry_dn($this->username, $key);
            $success = $this->conn->delete_entry($entry_dn);

            // set user roles according to active factors
            if ($success) {
                $this->set_user_roles();
            }

            return $success;
        }

        return false;
    }

    /**
     * Set username to store data for
     */
    public function set_username($username)
    {
        parent::set_username($username);

        // reset cached values
        $this->cache = array();
        $this->ldapcache = array();
    }

    /**
     *
     */
    protected function set_user_roles()
    {
        if (!$this->ready || !$this->userdn || empty($this->config['user_roles'])) {
            return false;
        }

        $auth_roles = array();
        foreach ($this->enumerate(true) as $id) {
            foreach ($this->config['user_roles'] as $prefix => $role) {
                if (strpos($id, $prefix) === 0) {
                    $auth_roles[] = $role;
                }
            }
        }

        $role_attr = $this->config['fieldmap']['roles'] ?: 'nsroledn';
        if ($user_attrs = $this->conn->get_entry($this->userdn, array($role_attr))) {
            $internals = array_values($this->config['user_roles']);
            $new_attrs = $old_attrs = Net_LDAP3::normalize_entry($user_attrs);
            $new_attrs[$role_attr] = array_merge(
                array_unique($auth_roles),
                array_filter((array)$old_attrs[$role_attr], function($f) use ($internals) { return !in_array($f, $internals); })
            );

            $result = $this->conn->modify_entry($this->userdn, $old_attrs, $new_attrs);
            return !empty($result);
        }

        return false;
    }

    /**
     * Fetches user data from LDAP addressbook
     */
    protected function get_ldap_record($user, $key)
    {
        $entry_dn = $this->get_entry_dn($user, $key);

        if (!isset($this->ldapcache[$entry_dn])) {
            $this->ldapcache[$entry_dn] = array();

            if ($this->ready && ($entry = $this->conn->get_entry($entry_dn, array_values($this->config['fieldmap'])))) {
                $this->ldapcache[$entry_dn] = $this->field_mapping($entry_dn, Net_LDAP3::normalize_entry($entry, true));
            }
        }

        return $this->ldapcache[$entry_dn];
    }

    /**
     * Compose a full DN for the given record identifier
     */
    protected function get_entry_dn($user, $key)
    {
        $base_dn = $this->parse_vars($this->config['base_dn'], $key);
        return sprintf('%s=%s,%s', $this->config['rdn'], Net_LDAP3::quote_string($key, true), $base_dn);
    }

    /**
     * Maps LDAP attributes to defined fields
     */
    protected function field_mapping($dn, $entry)
    {
        $entry['_dn'] = $dn;
        $entry['_raw'] = $entry;

        // fields mapping
        foreach ($this->config['fieldmap'] as $field => $attr) {
            $attr_lc = strtolower($attr);
            if (isset($entry[$attr_lc])) {
                $entry[$field] = $this->value_mapping($field, $entry[$attr_lc], true);
            }
            else if (isset($entry[$attr])) {
                $entry[$field] = $this->value_mapping($field, $entry[$attr], true);
            }
        }

        return $entry;
    }

    /**
     *
     */
    protected function value_mapping($attr, $value, $reverse = false)
    {
        if ($map = $this->config['valuemap'][$attr]) {
            if ($reverse) {
                $map = array_flip($map);
            }

            if (is_array($value)) {
                $value = array_filter(array_map(function($val) use ($map) {
                    return $map[$val];
                }, $value));
            }
            else {
                $value = $map[$value];
            }
        }

        // convert (date) type
        switch ($this->config['attrtypes'][$attr]) {
            case 'datetime':
                $ts = is_numeric($value) ? $value : strtotime($value);
                if ($ts) {
                    $value = gmdate($reverse ? 'U' : 'YmdHi\Z', $ts);
                }
                break;

            case 'integer':
                $value = intval($value);
                break;
        }

        return $value;
    }

    /**
     * Prepares filter query for LDAP search
     */
    protected function parse_vars($str, $key)
    {
        $user = $this->username;

        if (strpos($user, '@') > 0) {
            list($u, $d) = explode('@', $user);
        }
        else if ($this->userdn) {
            $u = $this->userdn;
            $d = trim(str_replace(',dc=', '.', substr($u, strpos($u, ',dc='))), '.');
        }

        if ($this->userdn) {
            $user = $this->userdn;
        }

        // build hierarchal domain string
        $dc = $this->conn->domain_root_dn($d);

        $class = $this->config['classmap'] ? $this->config['classmap']['*'] : '*';

        // map key to objectclass
        if (is_array($this->config['classmap'])) {
            foreach ($this->config['classmap'] as $k => $c) {
                if (strpos($key, $k) === 0) {
                    $class = $c;
                    break;
                }
            }
        }

        $replaces = array('%dc' => $dc, '%d' => $d, '%fu' => $user, '%u' => $u, '%c' => $class);

        return strtr($str, $replaces);
    }

}
