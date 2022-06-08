"""
Notifiers are used to provide an alert, such as an email, to configured stakeholders
to inform them of newly discovered CVEs.
"""

from abc import abstractmethod, ABCMeta
from typing import List, Dict


class Notifier(metaclass=ABCMeta):
    """ Abstract base class for notification classes that alert stakeholders to
        CVEs that were not seen by previous runs of CVE Tracker. """

    @abstractmethod
    def send_notification(self, new_cves: List[Dict[str, str]], report_name: str):
        """
        Used to send a notification to configured stakeholders when new CVEs are
        discovered.

        Args:
            new_cves (List[Dict[str, str]): The newly discovered CVEs and their metadata.
                Notifiers can choose whether or not to include this data in the notification.
            report_name (str): The name of the report file generated when the new CVEs were
                discovered. This is provided so the report may also be included in the
                notification if necessary.
        """
        raise NotImplementedError("You did not implement the send_notification method")
