#!/usr/bin/env python
import rest
import platform
import cups
import hashlib
import time
import urllib2
import tempfile
import shutil
import os
import json
import getpass
import stat
import sys
import getopt
import logging
import logging.handlers
import httplib2
import oauth2client.tools
import oauth2client.client
import oauth2client.file

import xmpp

XMPP_SERVER_HOST = 'talk.google.com'
XMPP_USE_SSL = True
XMPP_SERVER_PORT = 5223
PRINT_CLOUD_URL = '/cloudprint/'

# period in seconds with which we should poll for new jobs via the HTTP api,
# when xmpp is connecting properly.
# 'None' to poll only on startup and when we get XMPP notifications.
POLL_PERIOD=30.0

# wait period to retry when xmpp fails
FAIL_RETRY=60

# how often, in seconds, to send a keepalive character over xmpp
KEEPALIVE=600.0

# details of our application; this affects the details of the
# application when the user is prompted to allow access.
OAUTH2_CLIENT_ID='424432966449.apps.googleusercontent.com'
OAUTH2_CLIENT_SECRET='AKIstXAkCskDYCHm2J-mvS5m'

ROOT_LOGGER=logging.getLogger()
ROOT_LOGGER.setLevel(logging.INFO)
#httplib2.debuglevel=1

LOGGER = logging.getLogger('cloudprint')

# cloudprint service sends back 403s when our token has expired -
# we must include that in the list of response codes which prompt
# a refresh.
oauth2client.client.REFRESH_STATUS_CODES=[401,403]


class CloudPrintProxy(object):

    def __init__(self, auth_path):
        self.printer_id = None
        self.cups= cups.Connection()
        self.proxy =  platform.node() + '-Armooo-PrintProxy'
        self.http = None
        self.username = None
        self.oauth2_storage = oauth2client.file.Storage(auth_path)

    def _get_new_oauth(self,storage):
        """Request new access for our application. This will prompt
        the user to follow a link, which will ask them to log in to
        their google account, then allow access for us to the required
        services.

        This will give them an auth code, which they will be prompted to
        paste in here.
        """
        class Flags:
            pass

        flags=Flags()
        flags.logging_level = 'DEBUG'

        # one option is to run a local webserver, and redirect the user's
        # browser back to it with the code. That relies on the browser being
        # on the same machine as cloudprint, though, so disable that, and
        # just prompt the user to paset it in.
        flags.noauth_local_webserver = True

        flow = oauth2client.client.OAuth2WebServerFlow(
            client_id=OAUTH2_CLIENT_ID,
            client_secret=OAUTH2_CLIENT_SECRET,
            scope=['https://www.googleapis.com/auth/cloudprint',
                   'https://www.googleapis.com/auth/userinfo.email',
                   'https://www.googleapis.com/auth/googletalk'])
        return oauth2client.tools.run_flow(flow, storage, flags)

    def get_oauth2_credentials(self):
        """Get the oauth2client credentials object

        If we don't have valid credentials, we will call _get_new_oauth(),
        which will set up new ones.
        """
        credentials = self.oauth2_storage.get()
        if credentials is None:
            credentials = self._get_new_oauth(self.oauth2_storage)
        return credentials

    def get_http(self):
        """get an authenticated httplib2 object

        The resultant httplib2 object is then cached for the lifetime of the
        proxy.
        """
        if self.http is not None:
            return self.http

        credentials = self.get_oauth2_credentials()
        #print "OAuth2 creds:"
        #print "access token: ",credentials.access_token
        #print "token expiry: ",credentials.token_expiry
        http = httplib2.Http()
        self.http = credentials.authorize(http)
        return self.http

    def get_username(self):
        credentials = self.get_oauth2_credentials()
        return credentials.id_token["email"]

    def check_auth(self):
        self.get_printers()

    def del_saved_auth(self):
        self.oauth2_storage.delete()

    def get_rest(self,url='https://www.google.com'):
        return rest.REST(url, http=self.get_http())

    def get_printers(self):
        r = self.get_rest()
        printers = r.post(
            PRINT_CLOUD_URL + 'list',
            {
                'output': 'json',
                'proxy': self.proxy,
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM'},
        )
        return [ PrinterProxy(self, p['id'], p['name']) for p in printers['printers'] ]

    def delete_printer(self, printer_id):
        r = self.get_rest()
        docs = r.post(
            PRINT_CLOUD_URL + 'delete',
            {
                'output' : 'json',
                'printerid': printer_id,
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM'},
        )
        LOGGER.debug('Deleted printer '+ printer_id)

    def add_printer(self, name, description, ppd):
        r = self.get_rest()
        r.post(
            PRINT_CLOUD_URL + 'register',
            {
                'output' : 'json',
                'printer' : name,
                'proxy' :  self.proxy,
                'capabilities' : ppd.encode('utf-8'),
                'defaults' : ppd.encode('utf-8'),
                'status' : 'OK',
                'description' : description,
                'capsHash' : hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM'},
        )
        LOGGER.debug('Added Printer ' + name)

    def update_printer(self, printer_id, name, description, ppd):
        r = self.get_rest()
        r.post(
            PRINT_CLOUD_URL + 'update',
            {
                'output' : 'json',
                'printerid' : printer_id,
                'printer' : name,
                'proxy' : self.proxy,
                'capabilities' : ppd.encode('utf-8'),
                'defaults' : ppd.encode('utf-8'),
                'status' : 'OK',
                'description' : description,
                'capsHash' : hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM'},
        )
        LOGGER.debug('Updated Printer ' + name)

    def get_jobs(self, printer_id):
        r = self.get_rest()
        docs = r.post(
            PRINT_CLOUD_URL + 'fetch',
            {
                'output' : 'json',
                'printerid': printer_id,
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM'},
        )

        if not 'jobs' in docs:
            return []
        else:
            return docs['jobs']

    def finish_job(self, job_id):
        r = self.get_rest()
        r.post(
            PRINT_CLOUD_URL + 'control',
            {
                'output' : 'json',
                'jobid': job_id,
                'status': 'DONE',
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM' },
        )

    def fail_job(self, job_id):
        r = self.get_rest()
        r.post(
            PRINT_CLOUD_URL + 'control',
            {
                'output' : 'json',
                'jobid': job_id,
                'status': 'ERROR',
            },
            'application/x-www-form-urlencoded',
            { 'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM' },
        )

class PrinterProxy(object):
    def __init__(self, cpp, printer_id, name):
        self.cpp = cpp
        self.id = printer_id
        self.name = name

    def get_jobs(self):
        LOGGER.info('Polling for jobs on ' + self.name)
        return self.cpp.get_jobs(self.id)

    def update(self, description, ppd):
        return self.cpp.update_printer(self.id, self.name, description, ppd)

    def delete(self):
        return self.cpp.delete_printer(self.id)

class App(object):
    def __init__(self, cups_connection=None, cpp=None, printers=None, pidfile_path=None):
        self.cups_connection = cups_connection
        self.cpp = cpp
        self.printers = printers
        self.pidfile_path = pidfile_path
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_timeout = 5

    def run(self):
        process_jobs(self.cups_connection, self.cpp, self.printers)


def sync_printers(cups_connection, cpp):
    local_printer_names = set(cups_connection.getPrinters().keys())
    remote_printers = dict([(p.name, p) for p in cpp.get_printers()])
    remote_printer_names = set(remote_printers)

    #New printers
    for printer_name in local_printer_names - remote_printer_names:
        try:
            ppd_file = open(cups_connection.getPPD(printer_name))
            ppd = ppd_file.read()
            ppd_file.close()
            #This is bad it should use the LanguageEncoding in the PPD
            #But a lot of utf-8 PPDs seem to say they are ISOLatin1
            ppd = ppd.decode('utf-8')
            description = cups_connection.getPrinterAttributes(printer_name)['printer-info']
            cpp.add_printer(printer_name, description, ppd)
        except (cups.IPPError, UnicodeDecodeError):
            LOGGER.info('Skipping ' + printer_name)

    #Existing printers
    for printer_name in local_printer_names & remote_printer_names:
        ppd_file = open(cups_connection.getPPD(printer_name))
        ppd = ppd_file.read()
        ppd_file.close()
        #This is bad it should use the LanguageEncoding in the PPD
        #But a lot of utf-8 PPDs seem to say they are ISOLatin1
        try:
            ppd = ppd.decode('utf-8')
        except UnicodeDecodeError:
            pass
        description = cups_connection.getPrinterAttributes(printer_name)['printer-info']
        remote_printers[printer_name].update(description, ppd)

    #Printers that have left us
    for printer_name in remote_printer_names - local_printer_names:
        remote_printers[printer_name].delete()

def process_job(cups_connection, cpp, printer, job):
    job_title=job['title'].encode('unicode-escape')
    request_headers={
        'X-CloudPrint-Proxy' : 'ArmoooIsAnOEM',
        }
    cpp.get_oauth2_credentials().apply(request_headers)

    LOGGER.debug("handling %s", job_title)

    request = urllib2.Request(job['fileUrl'], headers=request_headers)

    try:
        pdf = urllib2.urlopen(request)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        shutil.copyfileobj(pdf, tmp)
        tmp.flush()

        request = urllib2.Request(job['ticketUrl'], headers=request_headers)
        options = json.loads(urllib2.urlopen(request).read())
        if 'request' in options: del options['request']
        options = dict( (str(k), str(v)) for k, v in options.items() )

        cpp.finish_job(job['id'])

        cups_connection.printFile(printer.name, tmp.name, job['title'], options)
        os.unlink(tmp.name)
        LOGGER.info('SUCCESS %s', job_title)

    except:
        cpp.fail_job(job['id'])
        LOGGER.exception('ERROR %s', job_title)

def process_jobs(cups_connection, cpp, printers):
    username = cpp.get_username()
    oauth_token = cpp.get_oauth2_credentials().access_token
    xmpp_conn = xmpp.XmppConnection(keepalive_period=KEEPALIVE)

    while True:
        try:
            for printer in printers:
                for job in printer.get_jobs():
                    process_job(cups_connection, cpp, printer, job)
            sleeptime = POLL_PERIOD

            if not xmpp_conn.is_connected():
                xmpp_conn.connect(XMPP_SERVER_HOST,XMPP_SERVER_PORT,
                                  XMPP_USE_SSL,username,oauth_token)

            xmpp_conn.await_notification(sleeptime)

        except KeyboardInterrupt:
            raise

        except:
            global FAIL_RETRY
            LOGGER.exception('ERROR: Could not Connect to Cloud Service. Will Try again in %d Seconds' % FAIL_RETRY)
            time.sleep(FAIL_RETRY)


def usage():
    print sys.argv[0] + ' [-d][-l][-c][-h] [-p pid_file] [-t auth_tokens_file]'
    print '-d\t\t: enable daemon mode (requires the daemon module)'
    print '-l\t\t: logout of the google account'
    print '-p pid_file\t: path to write the pid to (default cloudprint.pid)'
    print '-C auth_tokens_file\t: where to store authentication tokens (default ~/.cloudprintauthtokens)'
    print '-c\t\t: establish and store login credentials, then exit'
    print '-h\t\t: display this help'

def main():
    opts, args = getopt.getopt(sys.argv[1:], 'dlht:a:cv')
    daemon = False
    logout = False
    pidfile = None
    authfile = None
    authonly = False
    verbose = False
    for o, a in opts:
        if o == '-d':
            daemon = True
        elif o == '-l':
            logout = True
        elif o == '-p':
            pidfile = a
        elif o == '-t':
            authfile = a
        elif o == '-c':
            authonly = True
        elif o == '-v':
            verbose = True
        elif o =='-h':
            usage()
            sys.exit()
    if not pidfile:
        pidfile = 'cloudprint.pid'
    if not authfile:
        authfile = os.path.expanduser('~/.cloudprintauthtokens')

    # if daemon, log to syslog, otherwise log to stdout
    if daemon:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        handler.setFormatter(logging.Formatter(fmt='cloudprint.py: %(message)s'))
    else:
        handler = logging.StreamHandler(sys.stdout)
    ROOT_LOGGER.addHandler(handler)

    if verbose:
        ROOT_LOGGER.setLevel(logging.DEBUG)

    cups_connection = cups.Connection()
    cpp = CloudPrintProxy(auth_path=authfile)

    if logout:
        cpp.del_saved_auth()
        LOGGER.info('logged out')
        return

    #try to login
    cpp.check_auth()

    if authonly:
        sys.exit(0)

    sync_printers(cups_connection, cpp)
    printers = cpp.get_printers()

    if daemon:
        try:
            from daemon import runner
        except ImportError:
            print 'daemon module required for -d'
            print '\tyum install python-daemon, or apt-get install python-daemon, or pip install python-daemon'
            sys.exit(1)
        
        app = App(cups_connection=cups_connection,
                  cpp=cpp, printers=printers,
                  pidfile_path=os.path.abspath(pidfile))
        sys.argv=[sys.argv[0], 'start']
        daemon_runner = runner.DaemonRunner(app)
        daemon_runner.do_action()
    else:
        process_jobs(cups_connection, cpp, printers)

if __name__ == '__main__':
    main()
