#!/usr/bin/python3

import urllib3
import traceback
import json
import string
import pandas as pd
import dateutil.parser as dateparser

from datetime import datetime, date, timedelta


class utils:
    def display(input):
        pd.set_option("display.max_colwidth", None,
                      "display.max_rows", None)
        if isinstance(input, dict):
            print(pd.DataFrame(list(input.items()), columns=['Key', 'Value']))
        return

    def rm_duplicate_in_list(dup_list: list):
        return list(dict.fromkeys(dup_list))

    def compare_expired_date(date_str: string, range: int = 20):
        """
        Check whether the certificate nearly to expired in the given range or not

        Params:
        - date_str: Ex: Mar 28 01:01:59 2023 GMT
        - range: days wants to check from the expired

        Return:
        - True: Not expired
        - False: Will or already expired with the given range
        """
        currentDate = date.today() + timedelta(days=range)
        expired_date = dateparser.parse(date_str).date()

        if (currentDate < expired_date):
            return True
        else:
            return False

    def slack_notification(webhook_url, message: dict):
        try:
            # slack_message = {'text': message}

            http = urllib3.PoolManager()
            response = http.request('POST',
                                    webhook_url,
                                    body=json.dumps(
                                        message),
                                    headers={
                                        'Content-Type': 'application/json'},
                                    retries=False)
        except:
            traceback.print_exc()
        return True

class color():
    COLOR_SUCCESS = "#13ed34"
    COLOR_ERROR = "#d10206"
    COLOR_NOTI = "#00a3e0"
    COLOR_WARNING = "#eba709"
