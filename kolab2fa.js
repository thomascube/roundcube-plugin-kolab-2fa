/**
 * Kolab 2-Factor-Authentication plugin client functions
 *
 * @author Thomas Bruederli <bruederli@kolabsys.com>
 *
 * @licstart  The following is the entire license notice for the
 * JavaScript code in this page.
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
 *
 * @licend  The above is the entire license notice
 * for the JavaScript code in this page.
 */

window.rcmail && rcmail.addEventListener('init', function(evt) {
    var highsec_call_stack = [];
    var highsec_dialog;
    var factor_dialog;

    if (!rcmail.env.kolab_2fa_factors) {
        rcmail.env.kolab_2fa_factors = {};
    }

    /**
     * Equivalend of PHP time()
     */
    function time() {
        return Math.round(new Date().getTime() / 1000);
    }

    /**
     * Render the settings UI
     */
    function render() {
        var table = $('#kolab2fa-factors tbody');
        table.html('');

        var rows = 0;
        $.each(rcmail.env.kolab_2fa_factors, function(id, props) {
            if (props.active) {
                var tr = $('<tr>').addClass(props.method).appendTo(table);
                $('<td>').addClass('name').text(props.label || props.name).appendTo(tr);
                $('<td>').addClass('created').text(props.created || '??').appendTo(tr);
                $('<td>').addClass('actions').html('<a class="button delete" rel="'+id+'">' + rcmail.get_label('remove','kolab_2fa') + '</a>').appendTo(tr);
                rows++;
            }
        });

        table.parent()[(rows > 0 ? 'show' : 'hide')]();
    }

    /**
     * Open dialog to add the given authentication factor
     */
    function add_factor(method) {
        var lock, form = $('#kolab2fa-prop-' + method),
            props = rcmail.env.kolab_2fa_factors[method];

        if (form.length) {
            form.get(0).reset();
            form.find('img.qrcode').attr('src', 'data:image/gif;base64,R0lGODlhDwAPAIAAAMDAwAAAACH5BAEAAAAALAAAAAAPAA8AQAINhI+py+0Po5y02otnAQA7');
            form.off('submit');

            factor_dialog = rcmail.show_popup_dialog(
                form.show(),
                rcmail.get_label('addfactor', 'kolab_2fa'),
                [
                    {
                        text: rcmail.gettext('save', 'kolab_2fa'),
                        'class': 'mainaction',
                        click: function(e) {
                            save_data(method);
                        }
                    },
                    {
                        text: rcmail.gettext('cancel'),
                        click: function() {
                            factor_dialog.dialog('close');
                        }
                    }
                ],
                {
                    open: function(event, ui) {
                        $(event.target).find('input[name="_verify_code"]').keypress(function(e) {
                            if (e.which == 13) {
                                $(e.target).closest('.ui-dialog').find('.ui-button.mainaction').click();
                            }
                        });
                    },
                    close: function(event, ui) {
                        form.hide().appendTo(document.body);
                        factor_dialog = null;
                    }
                }
            )
            .addClass('propform')
            .data('method', method)
            .data('timestamp', time());

            form.on('submit', function(e) {
                save_data(method);
                return false;
            });

            // load generated data
            lock = rcmail.set_busy(true, 'loading');
            rcmail.http_post('plugin.kolab-2fa-data', { _method: method }, lock);
        }
    }

    /**
     * Remove the given factor from the account
     */
    function remove_factor(id) {
        if (rcmail.env.kolab_2fa_factors[id]) {
            rcmail.env.kolab_2fa_factors[id].active = false;
        }
        render();

        var lock = rcmail.set_busy(true, 'saving');
        rcmail.http_post('plugin.kolab-2fa-save', { _method: id, _data: 'false' }, lock);
    }

    /**
     * Submit factor settings form
     */
    function save_data(method) {
        var lock, data, form = $('#kolab2fa-prop-' + method),
            verify = form.find('input[name="_verify_code"]');

        if (verify.length && !verify.val().length) {
            alert(rcmail.get_label('verifycodemissing','kolab_2fa'));
            verify.select();
            return false;
        }

        data = form_data(form);
        lock = rcmail.set_busy(true, 'saving');
        rcmail.http_post('plugin.kolab-2fa-save', {
            _method: data.id || method,
            _data: JSON.stringify(data),
            _verify_code: verify.val(),
            _timestamp: factor_dialog ? factor_dialog.data('timestamp') : null
        }, lock);
    }

    /**
     * Collect all factor properties from the form
     */
    function form_data(form)
    {
        var data = {};
        form.find('input, select').each(function(i, elem) {
            if (elem.name.indexOf('_prop') === 0) {
                k = elem.name.match(/\[([a-z0-9_.-]+)\]$/i) ? RegExp.$1 : null;
                if (k) {
                    data[k] = elem.tagName == 'SELECT' ? $('option:selected', elem).val() : $(elem).val();
                }
            }
        });

        return data;
    }

    /**
     * Execute the given function after the user authorized the session with a 2nd factor
     */
    function require_high_security(func, exclude)
    {
        // request 2nd factor auth
        if (!rcmail.env.session_secured || rcmail.env.session_secured < time() - 120) {
            var method, name;

            // find an active factor
            $.each(rcmail.env.kolab_2fa_factors, function(id, prop) {
                if (prop.active && !method || method == exclude) {
                    method = id;
                    name = prop.label || prop.name;
                    if (!exclude || id !== exclude) {
                        return true;
                    }
                }
            });

            // we have a registered factor, use it
            if (method) {
                highsec_call_stack.push(func);

                // TODO: list all active factors to choose from
                var html = String($('#kolab2fa-highsecuritydialog').html()).replace('$name', name);

                highsec_dialog = rcmail.show_popup_dialog(
                    html,
                    rcmail.get_label('highsecurityrequired', 'kolab_2fa'),
                    [
                        {
                            text: rcmail.gettext('enterhighsecurity', 'kolab_2fa'),
                            click: function(e) {
                                var lock, code = highsec_dialog.find('input[name="_code"]').val();

                                if (code && code.length) {
                                    lock = rcmail.set_busy(true, 'verifying');
                                    rcmail.http_post('plugin.kolab-2fa-verify', {
                                        _method: method,
                                        _code: code,
                                        _session: 1,
                                        _timestamp: highsec_dialog.data('timestamp')
                                    }, lock);
                                }
                                else {
                                    highsec_dialog.find('input[name="_code"]').select();
                                }
                            },
                            'class': 'mainaction'
                        },
                        {
                            text: rcmail.gettext('cancel'),
                            click: function() {
                                highsec_dialog.dialog('close');
                            }
                        }
                    ],
                    {
                        open: function(event, ui) {
                            // submit code on <Enter>
                            $(event.target).find('input[name="_code"]').keypress(function(e) {
                                if (e.which == 13) {
                                    $(e.target).closest('.ui-dialog').find('.ui-button.mainaction').click();
                                }
                            }).select();
                        },
                        close: function(event, ui) {
                            $(this).remove();
                            highsec_dialog = null;
                            highsec_call_stack.pop();
                        }
                    }
                ).data('timestamp', time());

                return false;
            }
        }

        // just trigger the callback
        func.call(this);
    };

    // callback for factor data provided by the server
    rcmail.addEventListener('plugin.render_data', function(data) {
        var method = data.method,
            form = $('#kolab2fa-prop-' + method);

        if (form.length) {
            $.each(data, function(field, value) {
                form.find('[name="_prop[' + field + ']"]').val(value);
            });

            if (data.qrcode) {
                $('img.qrcode[rel='+method+']').attr('src', "data:image/png;base64," + data.qrcode);
            }
        }
        else if (window.console) {
            console.error("Cannot assign auth data", data);
        }
    });

    // callback for save action
    rcmail.addEventListener('plugin.save_success', function(data) {
        if (!data.active && rcmail.env.kolab_2fa_factors[data.id]) {
            delete rcmail.env.kolab_2fa_factors[data.id];
        }
        else if (rcmail.env.kolab_2fa_factors[data.id]) {
            $.extend(rcmail.env.kolab_2fa_factors[data.id], data);
        }
        else {
            rcmail.env.kolab_2fa_factors[data.id] = data;
        }

        if (factor_dialog) {
            factor_dialog.dialog('close');
        }

        render();
    });

    // callback for verify action
    rcmail.addEventListener('plugin.verify_response', function(data) {
        // execute high-security call stack and close dialog
        if (data.success && highsec_dialog && highsec_dialog.is(':visible')) {
            var func;
            while (highsec_call_stack.length) {
                func = highsec_call_stack.pop();
                func();
            }

            highsec_dialog.dialog('close');
            rcmail.env.session_secured = time();
        }
        else {
            rcmail.display_message(data.message, data.success ? 'confirmation' : 'warning');

            if (highsec_dialog && highsec_dialog.is(':visible')) {
                highsec_dialog.find('input[name="_code"]').val('').select();
            }
            else {
                $('#kolab2fa-prop-' + data.method + ' input.k2fa-verify').val('').select();
            }
        }
    });

    // callback for save failure
    rcmail.addEventListener('plugin.reset_form', function(method) {
        if (rcmail.env.kolab_2fa_factors[method]) {
            rcmail.env.kolab_2fa_factors[method].active = false;
        }

        render();
    });

    // handler for selections
    $('#kolab2fa-add').change(function() {
        var method = $('option:selected', this).val();

        // require auth verification
        require_high_security(function() {
            add_factor(method);
        });

        this.selectedIndex = 0;
    });

    // handler for delete button clicks
    $('#kolab2fa-factors tbody').on('click', '.button.delete', function(e) {
        var id = $(this).attr('rel');

        // require auth verification
        require_high_security(function() {
            if (confirm(rcmail.get_label('authremoveconfirm', 'kolab_2fa'))) {
                remove_factor(id);
            }
        }, id);

        return false;
    });

    // submit verification code on <Enter>
    $('.propform input.k2fa-verify').keypress(function(e) {
        if (e.which == 13) {
            $(this).closest('.propform').find('.button.verify').click();
        }
    });

    // render list initially
    render();
});