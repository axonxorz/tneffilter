#!/usr/bin/env python2
import sys
import os
import tempfile
import asyncore
import time
import hashlib
import shutil
import subprocess
import pwd, grp
import traceback
from functools import wraps

import mimetypes
import base64
from smtpd import SMTPServer
import smtplib
import email.utils
from email.parser import Parser
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import logging

from daemonize import Daemonize

logger = None
pidfile = None

RUNAS_USER = 'nobody'
RUNAS_GROUP = 'nogroup'

LOCAL_ADDRESS = ('localhost', 10025)
SMTP_RELAY = ('localhost', 20025)
TMP_BASE = '/tmp'
SPOOL_TNEF = True

ADMIN_ADDRESS = 'admin@example.com'

def wraptext(text, wraplen=80):
    parts = []
    l = len(text)
    for i in xrange(1+(l/wraplen)):
        parts.append(text[(i-1)*wraplen:(i)*wraplen])
    if l % wraplen > 0:
        start = l - (l % wraplen)
        parts.append(text[start:])
    return '\r\n'.join(parts)

class ErrorHandler(object):
    def __init__(self, handler):
        self.handler = handler

    def __call__(self, function):
        @wraps(function)
        def returnfunction(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception, e:
                tb = traceback.format_exc()
                self.handler(e, tb)
                raise
        return returnfunction

def mail_exception(e, tb):
    """Spool an exception message into the SMTP relay. Don't resubmit to a base
    SMTP server as this could cause a recursive loop handling messages if there's a
    serious enough error"""
    smtp = smtplib.SMTP(SMTP_RELAY[0], SMTP_RELAY[1])
    text = 'Text'
    message = MIMEText(tb)
    message['Subject'] = 'tneffilter.py Exception'
    message['From'] = ADMIN_ADDRESS
    message['To'] = ADMIN_ADDRESS
    smtp.sendmail(ADMIN_ADDRESS, ADMIN_ADDRESS, message.as_string())

class TNEFFilter(SMTPServer):
    @ErrorHandler(mail_exception)
    def process_message(self, peer, mailfrom, rcpttos, data):

        if SPOOL_TNEF and not os.path.exists('/tmp/tnefspool'):
            os.mkdir('/tmp/tnefspool')

        parser = Parser()
        message = parser.parsestr(data)
        new_message = parser.parsestr(data)

        new_message.set_payload('')
        new_message_container = MIMEMultipart()

        has_tnef = False
        for idx, payload in enumerate(message.get_payload()):
            if(isinstance(payload, basestring)):
                # Wasn't a multipart message
                break

            if SPOOL_TNEF and 'application/ms-tnef' in payload.get_content_type():
                message_id = hashlib.md5(str(time.time())).hexdigest()[:8]
                spoolfd = open(os.path.join('/tmp/tnefspool', 'msg-%s' % (message_id,)), 'wb')
                spoolfd.write(data)
                spoolfd.close()

            if 'application/ms-tnef' not in payload.get_content_type():
                new_message_container.attach(payload)
                if 'X-MS-TNEF-Correlator' in payload:
                    del payload['X-MS-TNEF-Correlator']
                    logger.debug('Removed X-MS-TNEF-Correlator header')
                continue

            has_tnef = True

            message_id = hashlib.md5(str(time.time())).hexdigest()[:8]
            logger.debug('MessageID: %s' % (message_id,))

            tmp_path = os.path.join(TMP_BASE, 'tnef-%s' % (message_id,))
            os.mkdir(tmp_path)
            fd = open(os.path.join(tmp_path, 'winmail.dat'), 'wb')
            fd.write(base64.b64decode(payload.get_payload()))
            fd.close()
            logger.debug('TNEF at: %s' % (os.path.join(tmp_path, 'winmail.dat')))

            attachments = self.tnef_list(os.path.join(tmp_path, 'winmail.dat'))
            logger.debug(str(attachments))
            self.tnef_extract(os.path.join(tmp_path, 'winmail.dat'))

            for attachment in attachments:
                if attachment.strip() == '':
                    logger.warning('Empty attachment filename in %s' % tmp_path)

                attachment_path = os.path.join(tmp_path, attachment)
                mimetype = mimetypes.guess_type(attachment_path)
                if mimetype[0] is not None:
                    mimetype = mimetype[0].split('/')
                else:
                    mimetype = ('text', 'plain')
                size = os.path.getsize(attachment_path)
                logger.debug('TNEF Attachment: %s - %s - %s bytes' % (attachment, mimetype, size))
                fd = open(attachment_path, 'rb')
                mime_container = MIMEBase(mimetype[0], mimetype[1])
                mime_container.set_payload(wraptext(base64.b64encode(fd.read())))
                mime_container['Content-Transfer-Encoding'] = 'base64'
                mime_container['Content-Disposition'] = 'attachment; filename="%s"' % (email.utils.quote(attachment),)
                new_message_container.attach(mime_container)
                fd.close()

            # Make sure to clean-up
            logger.debug('Cleaning up temporary files at %s' % tmp_path)
            shutil.rmtree(tmp_path)

        server = smtplib.SMTP()
        server.connect(self._remoteaddr[0], self._remoteaddr[1])
        if has_tnef:
            logger.debug('Sending TNEF parsed message (%s -> %s)' % (mailfrom, ','.join(rcpttos)))
            new_message.set_payload(new_message_container)
            server.sendmail(mailfrom, rcpttos, new_message.as_string())
        else:
            logger.debug('Sending original message (%s -> %s)' % (mailfrom, ','.join(rcpttos)))
            server.sendmail(mailfrom, rcpttos, data)
        server.quit()

    @staticmethod
    def tnef_list(filename):
        pd = subprocess.Popen('tnef -t "%s"' % (filename,), shell=True, stdout=subprocess.PIPE)
        pd.wait()
        (stdout, stderr) = pd.communicate()
        attachments = []
        for attachment in stdout.strip().split('\n'):
            try:
                att = attachment.split('|')[1].strip()
                if att.strip() != '':
                    attachments.append(att)
            except IndexError:
                # No internal parts from the TNEF file
                pass
        return attachments

    @staticmethod
    def tnef_extract(filename):
        pd = subprocess.Popen('tnef --number-backups -C %s %s' % (os.path.dirname(filename), filename), shell=True)
        pd.wait()

def main():
    group = grp.getgrnam(RUNAS_GROUP)
    os.setgid(group.gr_gid)
    user = pwd.getpwnam(RUNAS_USER)
    os.setuid(user.pw_uid)
    server = TNEFFilter(LOCAL_ADDRESS, SMTP_RELAY)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        print 'Quitting...'


if __name__ == '__main__':
    pidfile_path = '/var/run/tneffilter.pid'
    logger = logging.getLogger('tneffilter')
    logger.setLevel(logging.DEBUG)
    logging_formatter = logging.Formatter('%(asctime)s %(levelname)-5.5s [%(name)s] %(message)s')
    logging_handler = logging.FileHandler('/var/log/tneffilter.log', 'a')
    logging_handler.setLevel(logging.DEBUG)
    logging_handler.setFormatter(logging_formatter)
    logger.addHandler(logging_handler)

    logging_fd = logging_handler.stream.fileno()

    keep_fds = [logging_fd]

    if '-s' in sys.argv:
        SPOOL_TNEF = True

    if '-d' in sys.argv:
        daemon = Daemonize(app='tneffilter', pid=pidfile_path, action=main, keep_fds=keep_fds)
        daemon.start()
    else:

        console_logging = logging.StreamHandler(sys.stdout)
        console_logging.setFormatter(logging_formatter)
        console_logging.setLevel(logging.DEBUG)
        logger.addHandler(console_logging)

        pidfile = open(pidfile_path, 'wb')
        pidfile.write(str(os.getpid()))
        pidfile.close()

        main()
