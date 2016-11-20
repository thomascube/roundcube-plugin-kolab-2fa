<?php

/**
 * Kolab TOTP implementation based on Spomky-Labs/otphp
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

use OTPHP\TOTP as Base;

class TOTP extends Base
{
    use OTP;
    protected $interval = 30;

    public function setInterval($interval)
    {
        if (!is_integer($interval) || $interval < 1) {
            throw new \Exception('Interval must be at least 1.');
        }
        $this->interval = $interval;

        return $this;
    }

    public function getInterval()
    {
        return $this->interval;
    }
}