<?php

/**
 * Kolab 2-Factor-Authentication TOTP driver implementation
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

class TOTP extends Base
{
    public $method = 'totp';

    protected $config = array(
        'digits'   => 6,
        'interval' => 30,
        'digest'   => 'sha1',
    );

    protected $backend;

    /**
     *
     */
    public function init($config)
    {
        parent::init($config);

        $this->user_settings += array(
            'secret' => array(
                'type'      => 'text',
                'private'   => true,
                'label'     => 'secret',
                'generator' => 'generate_secret',
            ),
        );

        // copy config options
        $this->backend = new \Kolab2FA\OTP\TOTP();
        $this->backend
            ->setDigits($this->config['digits'])
            ->setInterval($this->config['interval'])
            ->setDigest($this->config['digest'])
            ->setIssuer($this->config['issuer'])
            ->setIssuerIncludedAsParameter(true);
    }

    /**
     *
     */
    public function verify($code, $timestamp = null)
    {
        // get my secret from the user storage
        $secret = $this->get('secret');

        if (!strlen($secret)) {
            // LOG: "no secret set for user $this->username"
            // rcube::console("VERIFY TOTP: no secret set for user $this->username");
            return false;
        }

        $this->backend->setLabel($this->username)->setSecret($secret);

        // PHP gets a string, but we're comparing integers.
        $code = (int)$code;

        // Pass a window to indicate the maximum timeslip between client (mobile
        // device) and server.
        $pass = $this->backend->verify($code, $timestamp, 150);

        // try all codes from $timestamp till now
        if (!$pass && $timestamp) {
            $now = time();
            while (!$pass && $timestamp < $now) {
                $pass = $code === $this->backend->at($timestamp);
                $timestamp += $this->config['interval'];
            }
        }

        // rcube::console('VERIFY TOTP', $this->username, $secret, $code, $timestamp, $pass);
        return $pass;
    }

    /**
     *
     */
    public function get_provisioning_uri()
    {
        // rcube::console('PROV', $this->secret);
        if (!$this->secret) {
            // generate new secret and store it
            $this->set('secret', $this->get('secret', true));
            $this->set('created', $this->get('created', true));
            // rcube::console('PROV2', $this->secret);
            $this->commit();
        }

        // TODO: deny call if already active?

        $this->backend->setLabel($this->username)->setSecret($this->secret);
        return $this->backend->getProvisioningUri();
    }

}
