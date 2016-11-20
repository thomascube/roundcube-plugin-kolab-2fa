<?php

/**
 * Kolab 2-Factor-Authentication Yubikey driver implementation
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

class Yubikey extends Base
{
    public $method = 'yubikey';

    protected $backend;

    /**
     *
     */
    public function init(array $config)
    {
        parent::init($config);

        $this->user_settings += array(
            'yubikeyid' => array(
                'type'     => 'text',
                'editable' => true,
                'label'    => 'secret',
            ),
        );

        // initialize validator
        $this->backend = new \Yubikey\Validate($this->config['apikey'], $this->config['clientid']);

        // set configured validation hosts
        if (!empty($this->config['hosts'])) {
            $this->backend->setHosts((array)$this->config['hosts']);
        }

        if (isset($this->config['use_https'])) {
            $this->backend->setUseSecure((bool)$this->config['use_https']);
        }
    }

    /**
     *
     */
    public function verify($code, $timestamp = null)
    {
        // get my secret from the user storage
        $keyid = $this->get('yubikeyid');
        $pass  = false;

        if (!strlen($keyid)) {
            // LOG: "no key registered for user $this->username"
            return false;
        }

        // check key prefix with associated Yubikey ID
        if (strpos($code, $keyid) === 0) {
            try {
                $response = $this->backend->check($code);
                $pass     = $response->success() === true;
            }
            catch (\Exception $e) {
                // TODO: log exception
            }
        }

        // rcube::console('VERIFY Yubikey', $this->username, $keyid, $code, $pass);
        return $pass;
    }

    /**
     * @override
     */
    public function set($key, $value)
    {
        if ($key == 'yubikeyid' && strlen($value) > 12) {
            // verify the submitted code
            try {
                $response = $this->backend->check($value);
                if ($response->success() !== true) {
                    // TODO: report error
                    return false;
                }
            }
            catch (\Exception $e) {
                return false;
            }

            // truncate the submitted yubikey code to 12 characters
            $value = substr($value, 0, 12);
        }

        return parent::set($key, $value);
    }

    /**
     * @override
     */
    protected function set_user_prop($key, $value)
    {
        // set created timestamp
        if ($key !== 'created' && !isset($this->created)) {
            parent::set_user_prop('created', $this->get('created', true));
        }

        return parent::set_user_prop($key, $value);
    }
}
