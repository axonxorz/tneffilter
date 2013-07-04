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

def wraptext(text, wraplen=80):
    parts = []
    l = len(text)
    for i in xrange(1+(l/wraplen)):
        parts.append(text[(i-1)*wraplen:(i)*wraplen])
    if l % wraplen > 0:
        start = l - (l % wraplen)
        parts.append(text[start:])
    return '\r\n'.join(parts)

class TNEFFilter(SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data):

        parser = Parser()
        message = parser.parsestr(data)
        new_message = parser.parsestr(data)

        new_message.set_payload('')
        new_message_container = MIMEMultipart()

        has_tnef = False
        for idx, payload in enumerate(message.get_payload()):
            if 'application/ms-tnef' not in payload['Content-Type']:
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
            self.tnef_extract(os.path.join(tmp_path, 'winmail.dat'))

            for attachment in attachments:
                attachment_path = os.path.join(tmp_path, attachment)
                mimetype = mimetypes.guess_type(attachment_path)[0].split('/')
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
            logger.debug('Sending TNEF parsed message')
            new_message.set_payload(new_message_container)
            server.sendmail(mailfrom, rcpttos, new_message.as_string())
        else:
            logger.debug('Sending original message')
            server.sendmail(mailfrom, rcpttos, data)
        server.quit()

    @staticmethod
    def tnef_list(filename):
        pd = subprocess.Popen('tnef -t "%s"' % (filename,), shell=True, stdout=subprocess.PIPE)
        pd.wait()
        (stdout, stderr) = pd.communicate()
        attachments = []
        for attachment in stdout.strip().split('\n'):
            attachments.append(attachment.split('|')[0].strip())
        return attachments

    @staticmethod
    def tnef_extract(filename):
        pd = subprocess.Popen('tnef -C %s %s' % (os.path.dirname(filename), filename), shell=True)
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
    logging_handler = logging.FileHandler('/var/log/tneffilter.log', 'a')
    logging_handler.setLevel(logging.NOTSET)
    logger.addHandler(logging_handler)

    logging_fd = logging_handler.stream.fileno()

    keep_fds = [logging_fd]

    if '-d' in sys.argv:
        daemon = Daemonize(app='tneffilter', pid=pidfile_path, action=main, keep_fds=keep_fds)
        daemon.start()
    else:
        pidfile = open(pidfile_path, 'wb')
        pidfile.write(str(os.getpid()))
        pidfile.close()
        main()
