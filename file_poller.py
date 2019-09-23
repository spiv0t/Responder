import os
import time
from threading import Thread
import logging


class FilePoller(Thread):
    def __init__(self, watchFilesWithCallbacks):
        """
        watchFilesWithCallbacks is a dict of filename: callback_function
        the callback_function is the function that should update the info from the changed file contents
        """
        Thread.__init__(self)
        self.watchFilesWithCallbacks = watchFilesWithCallbacks
        for filename in watchFilesWithCallbacks:
            setattr(self, filename + '_mtime', 0)

    def run(self):
        while True:
            for filename, update_function in self.watchFilesWithCallbacks.items():
                try:
                    mtime = os.stat(filename).st_mtime
                except Exception as e:
                    mtime = 0
                if mtime > getattr(self, filename + '_mtime'):
                    logging.info('%s file modified - refreshing' % filename)
                    setattr(self, filename + '_mtime', mtime)
                    update_function(filename)
            time.sleep(1.0)
