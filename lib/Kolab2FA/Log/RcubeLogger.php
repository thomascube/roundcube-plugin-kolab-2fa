<?php

/**
 * Kolab 2-Factor-Authentication Logging class to log messages
 * through the Roundcube logging facilities.
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

namespace Kolab2FA\Log;

use \rcube;

class RcubeLogger implements Logger
{
    protected $name = null;
    protected $level = LOG_DEBUG;

    public function __construct($name = null)
    {
        if ($name !== null) {
            $this->set_name($name);
        }
    }

    public function set_name($name)
    {
        $this->name = $name;
    }

    public function set_level($name)
    {
        $this->level = $level;
    }

    public function log($level, $message)
    {
        if (!is_string($message)) {
            $message = var_export($message, true);
        }

        switch ($level) {
        case LOG_DEBUG:
        case LOG_INFO:
        case LOG_NOTICE:
            if ($level >= $this->level) {
                rcube::write_log($this->name ?: 'console', $message);
            }
            break;

        case LOG_EMERGE:
        case LOG_ALERT:
        case LOG_CRIT:
        case LOG_ERR:
        case LOG_WARNING:
            rcube::raise_error(array(
                'code' => 600,
                'type' => 'php',
                'message' => $message,
            ), true, false);
            break;
        }
    }
}

