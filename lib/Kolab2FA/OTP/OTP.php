<?php

/**
 * Kolab OTP trait based on Spomky-Labs/otphp
 *
 * This basically follows the exmaple implementation from
 * https://github.com/Spomky-Labs/otphp/tree/master/examples
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

namespace Kolab2FA\OTP;

trait OTP
{
    protected $secret = null;
    protected $issuer = null;
    protected $issuer_included_as_parameter = false;
    protected $label = null;
    protected $digest = 'sha1';
    protected $digits = 6;

    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    public function getSecret()
    {
        return $this->secret;
    }

    public function setLabel($label)
    {
        if ($this->hasSemicolon($label)) {
            throw new \Exception('Label must not contain a semi-colon.');
        }
        $this->label = $label;

        return $this;
    }

    public function getLabel()
    {
        return $this->label;
    }

    public function setIssuer($issuer)
    {
        if ($this->hasSemicolon($issuer)) {
            throw new \Exception('Issuer must not contain a semi-colon.');
        }
        $this->issuer = $issuer;

        return $this;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function isIssuerIncludedAsParameter()
    {
        return $this->issuer_included_as_parameter;
    }

    public function setIssuerIncludedAsParameter($issuer_included_as_parameter)
    {
        $this->issuer_included_as_parameter = $issuer_included_as_parameter;

        return $this;
    }

    public function setDigits($digits)
    {
        if (!is_numeric($digits) || $digits < 1) {
            throw new \Exception('Digits must be at least 1.');
        }
        $this->digits = $digits;

        return $this;
    }

    public function getDigits()
    {
        return $this->digits;
    }

    public function setDigest($digest)
    {
        if (!in_array($digest, array('md5', 'sha1', 'sha256', 'sha512'))) {
            throw new \Exception("'$digest' digest is not supported.");
        }
        $this->digest = $digest;

        return $this;
    }

    public function getDigest()
    {
        return $this->digest;
    }

    private function hasSemicolon($value)
    {
        $semicolons = array(':', '%3A', '%3a');
        foreach ($semicolons as $semicolon) {
            if (false !== strpos($value, $semicolon)) {
                return true;
            }
        }

        return false;
    }
}