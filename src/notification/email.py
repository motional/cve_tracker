from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from typing import List, Dict
from src.notification.notifier import Notifier
import config




def create_cve_message(new_cves: List[Dict[str, str]]) -> str:
    message_body = ''
    note = 'Please download the attached report to view properly'
    for cve in new_cves:
        message_body += cve['ID'] + '\t' + cve['ModuleName'] + '\t' + \
                        str(cve['BaseScore']) + '\n' + cve['URL'] + '\n' + \
                        cve['Description'] + '\n\n'

        return message_body + note


class EmailNotifier(Notifier):
    """ This class implements a notifier that sends an email to configured stakeholders
        when CVEs are found that were not seen by previous runs of CVE Tracker.

        To use email notifications, you must configure the following fields in config.py:

        * HOST - the address of the SMTP server to use to send the email
        * SENDER - the email address to appear in the 'from' field of the email
        * RECIPIENT - a list of email addresses that should recieve the notication,
            with addresses separated by a comma (,)
        """

    def send_notification(self, new_cves: List[Dict[str, str]], report_name: str):
        if not new_cves:
            raise ValueError('Call to send_notification with no new CVEs.')

        msg = MIMEMultipart()
        msg['Subject'] = 'New CVEs Found'
        msg['From'] = config.Config.SENDER
        msg['To'] = config.Config.RECIPIENT

        body = MIMEText(create_cve_message(new_cves))
        msg.attach(body)

        with open(report_name, 'r') as report_file:
            attachment = MIMEText(report_file.read())
            attachment.add_header("Content-Disposition", "attachment", filename=report_name)
            msg.attach(attachment)

        smtp = smtplib.SMTP(config.Config.HOST)
        smtp.ehlo()
        smtp.send_message(msg)
        smtp.quit()
