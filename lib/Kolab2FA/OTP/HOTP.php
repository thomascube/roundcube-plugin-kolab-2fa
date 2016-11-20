<?php

/**
 * Kolab HOTP implementation based on Spomky-Labs/otphp
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

use OTPHP\HOTP as Base;

class HOTP extends Base
{
    use OTP;
    protected $counter = 0;

    public function setCounter($counter)
    {
        if (!is_integer($counter) || $counter < 0) {
            throw new \Exception('Counter must be at least 0.');
        }
        $this->counter = $counter;

        return $this;
    }

    public function getCounter()
    {
        return $this->counter;
    }

    public function updateCounter($counter)
    {
        $this->counter = $counter;

        return $this;
    }
}