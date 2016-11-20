<?php

/**
 * Storage backend to use the Roundcube user prefs to store 2-Factor-Authentication settings
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

use \rcmail;
use \rcube_user;

class RcubeUser extends Base
{
    // sefault config
    protected $config = array(
        'keymap' => array(),
    );

    private $cache = array();
    private $user;

    public function init(array $config)
    {
        parent::init($config);

        $rcmail = rcmail::get_instance();
        $this->config['hostname'] = $rcmail->user->ID ? $rcmail->user->data['mail_host'] : $_SESSION['hostname'];
    }

    /**
     * List/set methods activated for this user
     */
    public function enumerate()
    {
        if ($factors = $this->get_factors()) {
            return array_keys(array_filter($factors, function($prop) {
                return !empty($prop['active']);
            }));
        }

        return array();
    }

    /**
     * Read data for the given key
     */
    public function read($key)
    {
        if (!isset($this->cache[$key])) {
            $factors = $this->get_factors();
            $this->log(LOG_DEBUG, 'RcubeUser::read() ' . $key);
            $this->cache[$key] = $factors[$key];
        }

        return $this->cache[$key];
    }

    /**
     * Save data for the given key
     */
    public function write($key, $value)
    {
        $this->log(LOG_DEBUG, 'RcubeUser::write() ' . @json_encode($value));

        if ($user = $this->get_user($this->username)) {
            $this->cache[$key] = $value;

            $factors = $this->get_factors();
            $factors[$key] = $value;

            $pkey = $this->key2property('blob');
            $save_data = array($pkey => $factors);
            $update_index = false;

            // remove entry
            if ($value === null) {
                unset($factors[$key]);
                $update_index = true;
            }
            // remove non-active entries
            else if (!empty($value['active'])) {
                $factors = array_filter($factors, function($prop) {
                    return !empty($prop['active']);
                });
                $update_index = true;
            }

            // update the index of active factors
            if ($update_index) {
                $save_data[$this->key2property('factors')] = array_keys(
                    array_filter($factors, function($prop) {
                        return !empty($prop['active']);
                    })
                );
            }

            $success = $user->save_prefs($save_data, true);

            if (!$success) {
                $this->log(LOG_WARNING, sprintf('Failed to save prefs for user %s', $this->username));
            }

            return $success;
        }

        return false;
    }

    /**
     * Remove the data stored for the given key
     */
    public function remove($key)
    {
        return $this->write($key, null);
    }

    /**
     * Set username to store data for
     */
    public function set_username($username)
    {
        parent::set_username($username);

        // reset cached values
        $this->cache = array();
        $this->user = null;
    }

    /**
     * Helper method to get a rcube_user instance for storing prefs
     */
    private function get_user($username)
    {
        // use global instance if we have a valid Roundcube session
        $rcmail = rcmail::get_instance();
        if ($rcmail->user->ID && $rcmail->user->get_username() == $username) {
            return $rcmail->user;
        }

        if (!$this->user) {
            $this->user = rcube_user::query($username, $this->config['hostname']);
        }

        if (!$this->user) {
            $this->log(LOG_WARNING, sprintf('No user record found for %s @ %s', $username, $this->config['hostname']));
        }

        return $this->user;
    }

    /**
     *
     */
    private function get_factors()
    {
        if ($user = $this->get_user($this->username)) {
            $prefs = $user->get_prefs();
            return (array)$prefs[$this->key2property('blob')];
        }

        return null;
    }

    /**
     *
     */
    private function key2property($key)
    {
        // map key to configured property name
        if (is_array($this->config['keymap']) && isset($this->config['keymap'][$key])) {
            return $this->config['keymap'][$key];
        }

        // default
        return 'kolab_2fa_' . $key;
    }

}
