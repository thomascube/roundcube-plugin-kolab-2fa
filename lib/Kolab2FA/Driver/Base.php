<?php

/**
 * Kolab 2-Factor-Authentication Driver base class
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

namespace Kolab2FA\Driver;

abstract class Base
{
    public $method;
    public $id;
    public $storage;

    protected $config          = array();
    protected $props           = array();
    protected $user_props      = array();
    protected $pending_changes = false;
    protected $temporary       = false;
    protected $allowed_props   = array('username');

    public $user_settings = array(
        'active' => array(
            'type'     => 'boolean',
            'editable' => false,
            'hidden'   => false,
            'default'  => false,
        ),
        'label' => array(
            'type'      => 'text',
            'editable'  => true,
            'label'     => 'label',
            'generator' => 'default_label',
        ),
        'created' => array(
            'type'      => 'datetime',
            'editable'  => false,
            'hidden'    => false,
            'label'     => 'created',
            'generator' => 'time',
        ),
    );

    /**
     * Static factory method
     */
    public static function factory($id, $config)
    {
        list($method) = explode(':', $id);

        $classmap = array(
            'totp'    => '\\Kolab2FA\\Driver\\TOTP',
            'hotp'    => '\\Kolab2FA\\Driver\\HOTP',
            'yubikey' => '\\Kolab2FA\\Driver\\Yubikey',
        );

        $cls = $classmap[strtolower($method)];
        if ($cls && class_exists($cls)) {
            return new $cls($config, $id);
        }

        throw new Exception("Unknown 2FA driver '$method'");
    }

    /**
     * Default constructor
     */
    public function __construct($config = null, $id = null)
    {
        $this->init($config);

        if (!empty($id) && $id != $this->method) {
            $this->id = $id;
        }
        else { // generate random ID
            $this->id = $this->method . ':' . bin2hex(openssl_random_pseudo_bytes(12));
            $this->temporary = true;
        }
    }

    /**
     * Initialize the driver with the given config options
     */
    public function init($config)
    {
        if (is_array($config)) {
            $this->config = array_merge($this->config, $config);
        }

        if ($config['storage']) {
            $this->storage = \Kolab2FA\Storage\Base::factory($config['storage'], $config['storage_config']);
        }
    }

    /**
     * Verify the submitted authentication code
     *
     * @param string $code The 2nd authentication factor to verify
     * @param int    $timestamp  Timestamp of authentication process (window start)
     * @return boolean True if valid, false otherwise
     */
    abstract function verify($code, $timestamp = null);

    /**
     * Getter for user-visible properties
     */
    public function props($force = false)
    {
        $data = array();

        foreach ($this->user_settings as $key => $p) {
            if ($p['private']) {
                continue;
            }

            $data[$key] = array(
                'type'     => $p['type'],
                'editable' => $p['editable'],
                'hidden'   => $p['hidden'],
                'label'    => $p['label'],
                'value'    => $this->get($key, $force),
            );

            // format value into text
            switch ($p['type']) {
                case 'boolean':
                    $data[$key]['value'] = (bool)$data[$key]['value'];
                    $data[$key]['text'] = $data[$key]['value'] ? 'yes' : 'no';
                    break;

                case 'datetime':
                    if (is_numeric($data[$key]['value'])) {
                        $data[$key]['text'] = date('c', $data[$key]['value']);
                        break;
                    }

                default:
                    $data[$key]['text'] = $data[$key]['value'];
            }
        }

        return $data;
    }

    /**
     * Implement this method if the driver can be prpvisioned via QR code
     */
    /* abstract function get_provisioning_uri(); */

    /**
     * Generate a random secret string
     */
    public function generate_secret($length = 16)
    {
        // Base32 characters
        $chars = array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        );

        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= $chars[array_rand($chars)];
        }
        return $secret;
    }

    /**
     * Generate the default label based on the method
     */
    public function default_label()
    {
        if (class_exists('\\rcmail', false)) {
            return \rcmail::get_instance()->gettext($this->method, 'kolab_2fa');
        }

        return strtoupper($this->method);
    }

    /**
     * Getter for read-only access to driver properties
     */
    public function get($key, $force = false)
    {
        // this is a per-user property: get from persistent storage
        if (isset($this->user_settings[$key])) {
            $value = $this->get_user_prop($key);

            // generate property value
            if (!isset($value) && $force && $this->user_settings[$key]['generator']) {
                $func = $this->user_settings[$key]['generator'];
                if (is_string($func) && !is_callable($func)) {
                    $func = array($this, $func);
                }
                if (is_callable($func)) {
                    $value = call_user_func($func);
                }
                if (isset($value)) {
                    $this->set_user_prop($key, $value);
                }
            }
        }
        else {
            $value = $this->props[$key];
        }

        return $value;
    }

    /**
     * Setter for restricted access to driver properties
     */
    public function set($key, $value, $persistent = true)
    {
        // store as per-user property
        if (isset($this->user_settings[$key])) {
            if ($persistent) {
                return $this->set_user_prop($key, $value);
            }
            $this->user_props[$key] = $value;
        }

        $setter = 'set_' . $key;
        if (method_exists($this, $setter)) {
            call_user_func(array($this, $setter), $value);
        }
        else if (in_array($key, $this->allowed_props)) {
            $this->props[$key] = $value;
        }

        return true;
    }

    /**
     * Commit changes to storage
     */
    public function commit()
    {
        if (!empty($this->user_props) && $this->storage && $this->pending_changes) {
            if ($this->storage->write($this->id, $this->user_props)) {
                $this->pending_changes = false;
                $this->temporary = false;
            }
        }

        return !$this->pending_changes;
    }

    /**
     * Dedicated setter for the username property
     */
    public function set_username($username)
    {
        $this->props['username'] = $username;

        if ($this->storage) {
            $this->storage->set_username($username);
        }

        return true;
    }

    /**
     * Clear data stored for this driver
     */
    public function clear()
    {
        if ($this->storage) {
            return $this->storage->remove($this->id);
        }

        return false;
    }

    /**
     * Getter for per-user properties for this method
     */
    protected function get_user_prop($key)
    {
        if (!isset($this->user_props[$key]) && $this->storage && !$this->pending_changes && !$this->temporary) {
            $this->user_props = (array)$this->storage->read($this->id);
        }

        return $this->user_props[$key];
    }

    /**
     * Setter for per-user properties for this method
     */
    protected function set_user_prop($key, $value)
    {
        $this->pending_changes |= ($this->user_props[$key] !== $value);
        $this->user_props[$key] = $value;
        return true;
    }

    /**
     * Magic getter for read-only access to driver properties
     */
    public function __get($key)
    {
        // this is a per-user property: get from persistent storage
        if (isset($this->user_settings[$key])) {
            return $this->get_user_prop($key);
        }

        return $this->props[$key];
    }

    /**
     * Magic setter for restricted access to driver properties
     */
    public function __set($key, $value)
    {
        $this->set($key, $value, false);
    }

    /**
     * Magic check if driver property is defined
     */
    public function __isset($key)
    {
        return isset($this->props[$key]);
    }
}
