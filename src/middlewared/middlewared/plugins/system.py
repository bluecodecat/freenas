from datetime import datetime
from middlewared.schema import accepts, Bool, Dict, Int, IPAddr, Str
from middlewared.service import ConfigService, no_auth_required, job, private, Service, ValidationErrors
from middlewared.utils import Popen, sw_version
from middlewared.validators import Range

import os
import re
import socket
import struct
import subprocess
import sys
import sysctl
import syslog
import time

from licenselib.license import ContractType

# FIXME: Temporary imports until debug lives in middlewared
if '/usr/local/www' not in sys.path:
    sys.path.append('/usr/local/www')
from freenasUI.support.utils import get_license
from freenasUI.system.utils import debug_get_settings, debug_run

# Flag telling whether the system completed boot and is ready to use
SYSTEM_READY = False


class SystemService(Service):

    @no_auth_required
    @accepts()
    async def is_freenas(self):
        """
        Returns `true` if running system is a FreeNAS or `false` is Something Else.
        """
        # This is a stub calling notifier until we have all infrastructure
        # to implement in middlewared
        return await self.middleware.call('notifier.is_freenas')

    @accepts()
    def version(self):
        return sw_version()

    @accepts()
    def ready(self):
        """
        Returns whether the system completed boot and is ready to use
        """
        return SYSTEM_READY

    @accepts()
    async def info(self):
        """
        Returns basic system information.
        """
        uptime = (await (await Popen(
            "env -u TZ uptime | awk -F', load averages:' '{ print $1 }'",
            stdout=subprocess.PIPE,
            shell=True,
        )).communicate())[0].decode().strip()

        serial = (await(await Popen(
            ['dmidecode', '-s', 'system-serial-number'],
            stdout=subprocess.PIPE,
        )).communicate())[0].decode().strip() or None

        product = (await(await Popen(
            ['dmidecode', '-s', 'system-product-name'],
            stdout=subprocess.PIPE,
        )).communicate())[0].decode().strip() or None

        manufacturer = (await(await Popen(
            ['dmidecode', '-s', 'system-manufacturer'],
            stdout=subprocess.PIPE,
        )).communicate())[0].decode().strip() or None

        license = get_license()[0]
        if license:
            license = {
                "system_serial": license.system_serial,
                "system_serial_ha": license.system_serial_ha,
                "contract_type": ContractType(license.contract_type).name.upper(),
                "contract_end": license.contract_end,
            }

        return {
            'version': self.version(),
            'hostname': socket.gethostname(),
            'physmem': sysctl.filter('hw.physmem')[0].value,
            'model': sysctl.filter('hw.model')[0].value,
            'cores': sysctl.filter('hw.ncpu')[0].value,
            'loadavg': os.getloadavg(),
            'uptime': uptime,
            'uptime_seconds': time.clock_gettime(5),  # CLOCK_UPTIME = 5
            'system_serial': serial,
            'system_product': product,
            'license': license,
            'boottime': datetime.fromtimestamp(
                struct.unpack('l', sysctl.filter('kern.boottime')[0].value[:8])[0]
            ),
            'datetime': datetime.utcnow(),
            'timezone': (await self.middleware.call('datastore.config', 'system.settings'))['stg_timezone'],
            'system_manufacturer': manufacturer,
        }

    @accepts(Dict('system-reboot', Int('delay', required=False), required=False))
    @job()
    async def reboot(self, job, options=None):
        """
        Reboots the operating system.

        Emits an "added" event of name "system" and id "reboot".
        """
        if options is None:
            options = {}

        self.middleware.send_event('system', 'ADDED', id='reboot', fields={
            'description': 'System is going to reboot',
        })

        delay = options.get('delay')
        if delay:
            time.sleep(delay)

        await Popen(["/sbin/reboot"])

    @accepts(Dict('system-shutdown', Int('delay', required=False), required=False))
    @job()
    async def shutdown(self, job, options=None):
        """
        Shuts down the operating system.

        Emits an "added" event of name "system" and id "shutdown".
        """
        if options is None:
            options = {}

        self.middleware.send_event('system', 'ADDED', id='shutdown', fields={
            'description': 'System is going to shutdown',
        })

        delay = options.get('delay')
        if delay:
            time.sleep(delay)

        await Popen(["/sbin/poweroff"])

    @accepts()
    @job(lock='systemdebug')
    def debug(self, job):
        # FIXME: move the implementation from freenasUI
        mntpt, direc, dump = debug_get_settings()
        debug_run(direc)
        return dump


class SystemGeneralService(ConfigService):

    class Config:
        namespace = 'system.general'
        datastore = 'system.settings'
        datastore_prefix = 'stg_'
        datastore_extend = 'system.general.general_system_extend'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._languages = self._initialize_system_languages()
        self._time_zones_list = None
        self._kbdmap_choices = None

    @private
    def general_system_extend(self, data):
        keys = data.keys()
        for key in keys:
            if key.startswith('gui'):
                data['ui_' + key[3:]] = data.pop(key)
        return data

    @accepts()
    def get_system_languages(self):
        return self._languages

    def _initialize_system_languages(self):
        languagues = [
            ('af', 'Afrikaans'),
            ('ar', 'Arabic'),
            ('ast', 'Asturian'),
            ('az', 'Azerbaijani'),
            ('bg', 'Bulgarian'),
            ('be', 'Belarusian'),
            ('bn', 'Bengali'),
            ('br', 'Breton'),
            ('bs', 'Bosnian'),
            ('ca', 'Catalan'),
            ('cs', 'Czech'),
            ('cy', 'Welsh'),
            ('da', 'Danish'),
            ('de', 'German'),
            ('dsb', 'Lower Sorbian'),
            ('el', 'Greek'),
            ('en', 'English'),
            ('en-au', 'Australian English'),
            ('en-gb', 'British English'),
            ('eo', 'Esperanto'),
            ('es', 'Spanish'),
            ('es-ar', 'Argentinian Spanish'),
            ('es-co', 'Colombian Spanish'),
            ('es-mx', 'Mexican Spanish'),
            ('es-ni', 'Nicaraguan Spanish'),
            ('es-ve', 'Venezuelan Spanish'),
            ('et', 'Estonian'),
            ('eu', 'Basque'),
            ('fa', 'Persian'),
            ('fi', 'Finnish'),
            ('fr', 'French'),
            ('fy', 'Frisian'),
            ('ga', 'Irish'),
            ('gd', 'Scottish Gaelic'),
            ('gl', 'Galician'),
            ('he', 'Hebrew'),
            ('hi', 'Hindi'),
            ('hr', 'Croatian'),
            ('hsb', 'Upper Sorbian'),
            ('hu', 'Hungarian'),
            ('ia', 'Interlingua'),
            ('id', 'Indonesian'),
            ('io', 'Ido'),
            ('is', 'Icelandic'),
            ('it', 'Italian'),
            ('ja', 'Japanese'),
            ('ka', 'Georgian'),
            ('kab', 'Kabyle'),
            ('kk', 'Kazakh'),
            ('km', 'Khmer'),
            ('kn', 'Kannada'),
            ('ko', 'Korean'),
            ('lb', 'Luxembourgish'),
            ('lt', 'Lithuanian'),
            ('lv', 'Latvian'),
            ('mk', 'Macedonian'),
            ('ml', 'Malayalam'),
            ('mn', 'Mongolian'),
            ('mr', 'Marathi'),
            ('my', 'Burmese'),
            ('nb', 'Norwegian Bokmål'),
            ('ne', 'Nepali'),
            ('nl', 'Dutch'),
            ('nn', 'Norwegian Nynorsk'),
            ('os', 'Ossetic'),
            ('pa', 'Punjabi'),
            ('pl', 'Polish'),
            ('pt', 'Portuguese'),
            ('pt-br', 'Brazilian Portuguese'),
            ('ro', 'Romanian'),
            ('ru', 'Russian'),
            ('sk', 'Slovak'),
            ('sl', 'Slovenian'),
            ('sq', 'Albanian'),
            ('sr', 'Serbian'),
            ('sr-latn', 'Serbian Latin'),
            ('sv', 'Swedish'),
            ('sw', 'Swahili'),
            ('ta', 'Tamil'),
            ('te', 'Telugu'),
            ('th', 'Thai'),
            ('tr', 'Turkish'),
            ('tt', 'Tatar'),
            ('udm', 'Udmurt'),
            ('uk', 'Ukrainian'),
            ('ur', 'Urdu'),
            ('vi', 'Vietnamese'),
            ('zh-hans', 'Simplified Chinese'),
            ('zh-hant', 'Traditional Chinese'),
        ]
        return dict(languagues)

    async def _initialize_timezones_list(self):
        pipe = os.popen('find /usr/share/zoneinfo/ -type f -not -name zone.tab -not -regex \'.*/Etc/GMT.*\'')
        self._time_zones_list = pipe.read().strip().split('\n')
        self._time_zones_list = [x[20:] for x in self._time_zones_list]
        self._time_zones_list.sort()

    @accepts()
    async def get_timezones(self):
        if not self._time_zones_list:
            await self._initialize_timezones_list()
        return self._time_zones_list

    async def _initialize_kbdmap_choices(self):
        """Populate choices from /usr/share/vt/keymaps/INDEX.keymaps"""
        index = "/usr/share/vt/keymaps/INDEX.keymaps"

        if not os.path.exists(index):
            return []
        with open(index, 'rb') as f:
            d = f.read().decode('utf8', 'ignore')
        _all = re.findall(r'^(?P<name>[^#\s]+?)\.kbd:en:(?P<desc>.+)$', d, re.M)
        self._kbdmap_choices = [(name, desc) for name, desc in _all]

    @accepts()
    async def get_kbdmap_choices(self):
        if not self._kbdmap_choices:
            await self._initialize_kbdmap_choices()
        return self._kbdmap_choices

    async def validate_general_settings(self, data, schema):
        verrors = ValidationErrors()

        language = data.get('language')
        if language:
            system_languages = self.get_system_languages()
            if language not in system_languages.keys():
                verrors.add(
                    f'{schema}.language',
                    f'Specified "{language}" language not found, kindly correct it'
                )

        # kbd map needs work

        timezone = data.get('timezone')
        if not timezone:
            verrors.add(
                f'{schema}.timezone',
                'This field is required'
            )
        else:
            timezones = await self.get_timezones()
            if timezone not in timezones:
                verrors.add(
                    f'{schema}.timezone',
                    'Please select a correct timezone'
                )

        ip_addresses = await self.middleware.call(
            'interfaces.ip_in_use'
        )
        ip4_addresses_list = [alias_dict['address'] for alias_dict in ip_addresses if alias_dict['type'] == 'INET']
        ip6_addresses_list = [alias_dict['address'] for alias_dict in ip_addresses if alias_dict['type'] == 'INET6']

        ip4_address = data.get('ui_address')
        if (
            ip4_address and
            ip4_address != '0.0.0.0' and
            ip4_address not in ip4_addresses_list
        ):
            verrors.add(
                f'{schema}.ui_address',
                'Selected ipv4 address is not associated with this machine'
            )

        ip6_address = data.get('ui_v6address')
        if (
            ip6_address and
            ip6_address != '::' and
            ip6_address not in ip6_addresses_list
        ):
            verrors.add(
                f'{schema}.ui_v6address',
                'Selected ipv6 address is not associated with this machine'
            )

        syslog_level = data.get('sysloglevel')
        if not syslog_level:
            verrors.add(
                f'{schema}.sysloglevel',
                'This field is required'
            )

        syslog_server = data.get('syslogserver')
        if not syslog_server:
            verrors.add(
                f'{schema}.syslogserver',
                'This field is required'
            )
        else:
            match = re.match("^[\w\.\-]+(\:\d+)?$", syslog_server)
            if not match:
                verrors.add(
                    f'{schema}.syslogserver',
                    'Invalid syslog server format'
                )
            elif ':' in syslog_server:
                port = int(syslog_server.split(':')[-1])
                if port < 0 or port > 65535:
                    verrors.add(
                        f'{schema}.syslogserver',
                        'Port specified should be between 0 - 65535'
                    )

        protocol = data.get('ui_protocol')
        if not protocol:
            verrors.add(
                f'{schema}.ui_protocol',
                'This field is required'
            )
        else:
            if protocol != 'http':
                certificate_id = data.get('ui_certificate')
                if not certificate_id:
                    verrors.add(
                        f'{schema}.ui_certificate',
                        'Protocol has been selected as HTTPS, certificate is required'
                    )
                else:
                    # getting fingerprint for certificate
                    fingerprint = await self.middleware.call(
                        'certificate.get_fingerprint',
                        certificate_id
                    )
                    if fingerprint:
                        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
                        syslog.syslog(syslog.LOG_ERR, 'Fingerprint of the certificate used in UI : ' + fingerprint)
                        syslog.closelog()
                    else:
                        # Two reasons value is None - certificate not found - error while parsing the certifcate for
                        # fingerprint
                        verrors.add(
                            f'{schema}.ui_certificate',
                            'Kindly check if the certificate has been added to the system and it is a valid certificate'
                        )
        return verrors

    @accepts(
        Dict(
            'general_settings',
            IPAddr('ui_address'),
            Int('ui_certificate'),
            Int('ui_httpsport', validators=[Range(min=1, max=65535)]),
            Bool('ui_httpsredirect'),
            Int('ui_port', validators=[Range(min=1, max=65535)]),
            Str('ui_protocol', enum=['HTTP', 'HTTPS', 'HTTPHTTPS']),
            IPAddr('ui_v6address'),
            Str('kbdmap'),
            Str('language'),
            Str('sysloglevel', enum=['F_EMERG', 'F_ALERT', 'F_CRIT', 'F_ERR', 'F_WARNING', 'F_NOTICE',
                                     'F_INFO', 'F_DEBUG', 'F_IS_DEBUG']),
            Str('syslogserver', required=True),
            Str('timezone')
        )
    )
    async def do_update(self, data):
        data['sysloglevel'] = data['sysloglevel'].lower()
        data['ui_protocol'] = data['ui_protocol'].lower()

        config = await self.config()
        new_config = config.copy()
        new_config.update(data)
        verrors = await self.validate_general_settings(new_config, 'general_settings_update')
        if verrors:
            raise verrors

        keys = new_config.keys()
        for key in keys:
            if key.startswith('ui_'):
                new_config['gui' + key[3:]] = new_config.pop(key)

        await self.middleware.call('datastore.update', 'system.settings', config['id'], new_config, {'prefix': 'stg_'})

        if (
            config['sysloglevel'] != new_config['sysloglevel'] or
                config['syslogserver'] != new_config['syslogserver']
        ):
            await self.middleware.call('service.restart', 'syslogd')

        await self.middleware.call('service.reload', 'timeservices')

        if config['timezone'] != new_config['timezone']:
            await self.middleware.call('service.restart', 'cron')

        config['ui_certificate'] = config['ui_certificate']['id'] if config['ui_certificate'] else None
        new_config = {
            ('ui_' + key[3:] if key.startswith('gui') else key): value for key, value in new_config.items()
        }
        if len(set(new_config.items()) ^ set(config.items())) > 0:
            await self.middleware.call('service._start_ssl', 'nginx')
        return await self.config()


async def _event_system_ready(middleware, event_type, args):
    """
    Method called when system is ready, supposed to enable the flag
    telling the system has completed boot.
    """
    global SYSTEM_READY
    if args['id'] == 'ready':
        SYSTEM_READY = True


def setup(middleware):
    middleware.event_subscribe('system', _event_system_ready)
