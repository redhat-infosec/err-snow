import datetime as dt

import pytz
import re
import requests
from errbot import BotPlugin, botcmd


class ServiceNow(BotPlugin):
    """
    ServiceNow Integration
    """

    def get_configuration_template(self):
        return {
            'url': 'https://service-now.com',
            'user': 'username',
            'pwd': 'password',
            'assignment_group': 'MyGroup',
            'bot_tz': 'UTC',
            'api_tz': 'UTC'
        }

    def activate(self):
        super().activate()
        # Run 'new_issues' callback every 5 minutes
        self.start_poller(60, self.new_issues)

    def get(self, table, params=None):
        """
        Get the base url for a given ServiceNow table

        :param table: Name of the ServiceNow table to query
        :param params: Query string parameters
        """
        url = '{url}{table}'.format(url=self.config['url'], table=table)
        return requests.get(url, auth=(self.config['user'], self.config['pwd']), params=params)

    def new_issues(self):
        """
        Sends notifications about new issues received in ServiceNow
        """
        try:
            last_run = self['LAST_RUN']
        except KeyError:
            # This is the first run. Set the last run time and watch for incoming tickets starting now
            self.set_last_run()
            last_run = self['LAST_RUN']

        sysparm_query = 'sys_updated_on>{}^assigned_toISEMPTY'.format(last_run)

        params = {
            'sysparm_display_value': 'true',
            'assignment_group': 'Information Security',
            'sysparm_query': sysparm_query
        }

        response = self.get(table='incident', params=params)

        if response.status_code != 200:
            self.log.debug('could not retrieve new issues')
            return

        results = response.json()['result']
        self.log.debug('{} results returned'.format(len(results)))
        for issue in results:
            message = 'Incoming: ' + self.issue_details(issue)
            for room in self.rooms():
                self.send(room, message)

        # Update the last run time
        self.set_last_run()

    def set_last_run(self):
        """
        Keep track of the last time this callback was run
        """
        # Timezone that the bot is running in
        bot_tz = pytz.utc  # pytz.timezone('Australia/Brisbane')
        utc = pytz.utc

        now = dt.datetime.now()
        last_run = self.convert_tz(now, bot_tz, utc)
        self['LAST_RUN'] = last_run.strftime('%Y%m%d%H%M%S')

    @botcmd
    def sn(self, message, args):
        """
        Retrieves information about an issue in ServiceNow. Provide a single INC or TASK number as an argument.
        """
        # Issue number is given as the only argument
        number = args

        # Incidents and Service Catalog Tasks are stored in separate tables
        inc_re = re.compile('^INC\d{7}$')
        task_re = re.compile('^TASK\d{7}$')

        if inc_re.match(number):
            table = 'incident'
        elif task_re.match(number):
            table = 'sc_task'
        else:
            return 'Invalid issue number'

        url = '{url}{table}?sysparm_display_value=true&number={number}'.format(
            url=self.config['url'], table=table, number=number)

        response = requests.get(url, auth=(self.config['user'], self.config['pwd']))

        if response.status_code != 200:
            return 'Could not get information about {number} from ServiceNow'.format(number=number)

        data = response.json()
        # There should be 1 result
        if len(data['result']) == 1:
            issue = data['result'][0]
            return self.issue_details(issue)
        return '{number} was not found'.format(number=number)

    def issue_details(self, issue):
        """
        Return the relevant details formatted for output
        """
        short_url = 'https://url.corp.redhat.com/' + issue['number']
        # Convert sys_updated_on time field to UTC
        api_tz = pytz.timezone('US/Eastern')  # API account timezone
        utc = pytz.utc
        date_format = '%Y-%m-%d %H:%M:%S'
        sys_updated_on = dt.datetime.strptime(issue['sys_updated_on'], date_format)
        utc_sys_updated_on = self.convert_tz(sys_updated_on, api_tz, utc)

        return ' | '.join([
            short_url,
            issue['short_description'],
            issue['sys_created_by'],
            issue['state'],
            '{} {}'.format(utc_sys_updated_on.strftime(date_format), utc_sys_updated_on.tzname())
        ])

    @staticmethod
    def convert_tz(date, from_tz, to_tz):
        """Convert a datetime from one timezone to another"""
        local_date = from_tz.localize(date)
        return local_date.astimezone(to_tz)
