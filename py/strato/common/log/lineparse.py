import datetime
import re
import calendar
import time


def seperateTimestamp(message, timestampFormat='(\d{4}[-/]\d{2}[-/]\d{2} \d{2}[:]\d{2}[:]\d{2})'):
    # default regex matches date pattern in timestampFormat "yyyy/dd/mm hh:mm:ss"
    dateRegex = re.compile(timestampFormat)
    date = dateRegex.findall(message.strip())[0]
    # remove everything at the beggining of the line that isn't letters and "[" (for consul logs)
    msg = '\n'.join([re.sub("^[^a-zA-Z\[]*", "                ", line) for line in message.split('\n')])
    return msg, date


def translateToEpoch(timeStamp, timestampFormat="%Y/%m/%d %H:%M:%S"):
    timeObject = datetime.datetime.strptime(timeStamp, timestampFormat)
    return calendar.timegm(timeObject. timetuple())


def getTimezoneOffset():
    return time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
